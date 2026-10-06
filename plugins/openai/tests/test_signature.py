"""Signature tests for the OpenAI plugin helper.

The crypto and verification logic are reused (npc_verify_mcp.api_client ->
npc_verify.*), so these tests prove the reuse is real: a tampered response
flying through the OpenAI plugin helper must be rejected fail-closed, and a
valid signed response must pass through untouched. All fixtures are
fictional; keys are the API's own ephemeral test keys.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import OpenAITestCase  # noqa: E402
from npc_verify_openai.client import (  # noqa: E402
    make_client, run_operation)


class TamperingClientMixin:
    def _tampered(self, mutate):
        real = self.client
        client = make_client(base_url=f"http://127.0.0.1:{self.port}",
                             api_key=real.api_key)
        real_http = real._http

        def fake_http(method, path, body_bytes=None, extra_headers=None):
            status, headers, data = real_http(
                method, path, body_bytes=body_bytes,
                extra_headers=extra_headers)
            return mutate(status, headers, data)

        client._http = fake_http
        return client

    def _assert_tamper_rejected(self, client, op, args, forbidden):
        """Tamper must surface as (is_error=True) with no tampered data."""
        is_err, text = run_operation(client, op, args)
        self.assertTrue(is_err, f"tampered {op} was not rejected")
        self.assertIn("Verification failed", text)
        self.assertNotIn(forbidden, text)


class TestSignatureThroughPluginHelper(OpenAITestCase, TamperingClientMixin):
    def test_signed_response_passes(self):
        is_err, text = self.run_op(
            "verify_credential", {"credential_id": "cred_test_001"})
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertEqual(body["status"], "valid")

    def test_tampered_body_rejected(self):
        def flip(status, headers, data):
            obj = json.loads(data)
            obj["status"] = "valid"  # attacker upgrades a revoked credential
            return status, headers, json.dumps(obj).encode()

        client = self._tampered(flip)
        self._assert_tamper_rejected(
            client, "verify_credential", {"credential_id": "cred_test_002"},
            '"status": "valid"')

    def test_stripped_signature_rejected(self):
        def strip(status, headers, data):
            headers = dict(headers)
            headers.pop("X-NPC-Signature", None)
            return status, headers, data

        client = self._tampered(strip)
        self._assert_tamper_rejected(
            client, "verify_product", {"tag_id": "tag_test_authentic"},
            '"status": "authentic"')

    def test_unknown_key_id_rejected(self):
        def rekey(status, headers, data):
            headers = dict(headers)
            headers["X-NPC-Key-ID"] = "npc-api_signing-evil"
            return status, headers, data

        client = self._tampered(rekey)
        self._assert_tamper_rejected(
            client, "verify_agent", {"agent_id": "agent_test_scout"},
            '"verdict": "verified"')

    def test_404_unknown_is_signed_too(self):
        # Even the fail-closed unknown shape is signature-verified: an
        # attacker flipping unknown -> not_verified must be rejected.
        def corrupt_404(status, headers, data):
            if status == 404:
                obj = json.loads(data)
                obj["verdict"] = "not_verified"
                data = json.dumps(obj).encode()
            return status, headers, data

        client = self._tampered(corrupt_404)
        self._assert_tamper_rejected(
            client, "verify_product", {"tag_id": "tag_nope_xyz"},
            '"verdict": "not_verified"')

    def test_missing_api_key_fails_closed(self):
        client = make_client(base_url=f"http://127.0.0.1:{self.port}",
                             api_key="")
        is_err, text = run_operation(
            client, "verify_product", {"tag_id": "tag_test_authentic"})
        self.assertTrue(is_err)
        self.assertIn("NPC_VERIFY_API_KEY", text)
        self.assertNotIn('"status"', text)
