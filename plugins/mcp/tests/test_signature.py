"""Signature-verification tests: the client must refuse tampered responses.

The _http seam is overridden to mutate bodies/headers in flight; every
mutation must produce a fail-closed ApiError, never the data.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import McpTestCase  # noqa: E402
from npc_verify_mcp.api_client import VerifiedClient, ApiError  # noqa: E402


class TamperingClient(VerifiedClient):
    """Wraps a real client, mutating the raw HTTP layer in flight."""

    def __init__(self, base, mutate):
        super().__init__(base_url=base, api_key="unused")
        self._mutate = mutate
        self._real_http = None

    def attach(self, real_client):
        self.api_key = real_client.api_key
        self._real_http = real_client._http

    def _http(self, method, path, body_bytes=None, extra_headers=None):
        status, headers, data = self._real_http(
            method, path, body_bytes=body_bytes, extra_headers=extra_headers)
        return self._mutate(status, headers, data)


class TestSignatureVerification(McpTestCase):
    def _tampered(self, mutate):
        c = TamperingClient(f"http://127.0.0.1:{self.port}", mutate)
        c.attach(self.client)
        return c

    def test_tampered_body_rejected(self):
        def flip_body(status, headers, data):
            obj = json.loads(data)
            obj["status"] = "valid"  # attacker upgrades the verdict
            return status, headers, json.dumps(obj).encode()

        client = self._tampered(flip_body)
        with self.assertRaises(ApiError) as ctx:
            client.verify_credential("cred_test_002")  # actually revoked
        self.assertIn("canonical", str(ctx.exception).lower())

    def test_swapped_signature_rejected(self):
        # take a valid signature from /v1/health and staple it onto a
        # credential response — key_id/body mismatch must fail.
        captured = {}

        def capture(status, headers, data):
            if b'"status":"ok"' in data or b'"status": "ok"' in data:
                captured["sig"] = headers.get("X-NPC-Signature")
            return status, headers, data

        probe = self._tampered(capture)
        probe.health()
        self.assertIn("sig", captured)

        def swap(status, headers, data):
            headers = dict(headers)
            headers["X-NPC-Signature"] = captured["sig"]
            return status, headers, data

        client = self._tampered(swap)
        with self.assertRaises(ApiError):
            client.verify_credential("cred_test_001")

    def test_stripped_signature_rejected(self):
        def strip(status, headers, data):
            headers = dict(headers)
            headers.pop("X-NPC-Signature", None)
            return status, headers, data

        client = self._tampered(strip)
        with self.assertRaises(ApiError) as ctx:
            client.verify_credential("cred_test_001")
        self.assertIn("signature", str(ctx.exception).lower())

    def test_unknown_key_id_rejected(self):
        def rekey(status, headers, data):
            headers = dict(headers)
            headers["X-NPC-Key-ID"] = "npc-api_signing-evil"
            return status, headers, data

        client = self._tampered(rekey)
        with self.assertRaises(ApiError) as ctx:
            client.verify_credential("cred_test_001")
        self.assertIn("not published", str(ctx.exception).lower())

    def test_tool_surfaces_tamper_as_error(self):
        # end-to-end through the tool layer: tamper must become isError,
        # and the tampered payload must never reach the caller.
        from npc_verify_mcp.server import McpServer

        def flip_body(status, headers, data):
            try:
                obj = json.loads(data)
            except ValueError:
                return status, headers, data
            obj["status"] = "valid"
            return status, headers, json.dumps(obj).encode()

        client = self._tampered(flip_body)
        mcp = McpServer(client=client)
        reply = mcp.handle({"jsonrpc": "2.0", "id": 7,
                            "method": "tools/call",
                            "params": {"name": "verify_credential",
                                       "arguments": {
                                           "credential_id": "cred_test_002"}}})
        result = reply["result"]
        self.assertTrue(result.get("isError"))
        text = result["content"][0]["text"].lower()
        self.assertIn("verificat", text)
        self.assertNotIn('"status": "valid"', result["content"][0]["text"])
