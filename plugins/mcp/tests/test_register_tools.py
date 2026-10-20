"""Registration tool tests: register_agent + register_content against
the live fixture API (real signatures, real caps, real intake checks).

Registration is not verification: a success returns the signed
registration record at "registered, checks pending" — record ID,
status, the checks that ran and those still pending — and never a
verdict. API rejections (validation, the submission caps) surface
faithfully as errors, never as a successful registration. The
submitter's email is an abuse minimum counted server-side; it never
appears in the signed record.
"""
import base64
import hashlib
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import McpTestCase  # noqa: E402
from tests.test_signature import TamperingClient  # noqa: E402
from npc_verify import pact  # noqa: E402
from npc_verify_mcp.api_client import VerifiedClient, ApiError  # noqa: E402
from npc_verify_mcp.server import McpServer  # noqa: E402

AGENT_ARGS = {
    "agent_name": "Ledger Lark",
    "owner_name": "Wren Okafor",
    "owner_email": "wren@example.org",
    "homepage": "https://example.org/ledger-lark",
    "description": "Reconciles small-business ledgers overnight.",
}

CONTENT_ARGS = {
    "title": "Harbor at first light (audio notes)",
    "kind": "audio",
    "locator": "sha256:" + "ab" * 32,
    "creator_name": "Wren Okafor",
    "creator_email": "wren.audio@example.org",
}

# A 1x1 transparent PNG: valid image bytes with no Content
# Credentials, so the intake read reports them not present.
_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
    "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")


def _checks(body, field):
    return [c.get("check") for c in body[field]]


class TestRegisterAgent(McpTestCase):
    def test_success_shape(self):
        is_err, text = self.call_tool("register_agent", dict(AGENT_ARGS))
        self.assertFalse(is_err, text)
        body = json.loads(text)
        self.assertEqual(body["record_type"],
                         "npc.registry.agent_registration")
        self.assertTrue(body["record_id"].startswith("reg_"))
        self.assertEqual(body["kind"], "agent")
        self.assertEqual(body["status"], "registered_checks_pending")
        self.assertEqual(body["status_label"], "registered, checks pending")
        self.assertEqual(body["agent_name"], "Ledger Lark")
        self.assertEqual(body["owner_name"], "Wren Okafor")
        self.assertEqual(body["homepage"],
                         "https://example.org/ledger-lark")
        self.assertEqual(_checks(body, "checks_run"),
                         ["named_owner", "registration_claim"])
        self.assertEqual(_checks(body, "checks_not_run"),
                         ["scope_review", "human_review",
                          "verification_decision"])
        # the record itself is signed, and the signature verifies
        self.assertIn("signature", body)
        self.assertIn("key_id", body)
        self.assertTrue(pact.verify_record(self.app.keys, body))
        # no verdict exists anywhere in a registration
        self.assertNotIn("verdict", body)

    def test_owner_email_never_in_record(self):
        is_err, text = self.call_tool("register_agent", dict(AGENT_ARGS))
        self.assertFalse(is_err, text)
        body = json.loads(text)
        self.assertNotIn("owner_email", body)
        self.assertNotIn("wren@example.org", text)

    def test_description_only_no_homepage(self):
        args = dict(AGENT_ARGS)
        del args["homepage"]
        args["owner_email"] = "wren.desc@example.org"
        is_err, text = self.call_tool("register_agent", args)
        self.assertFalse(is_err, text)
        body = json.loads(text)
        self.assertIsNone(body["homepage"])
        self.assertEqual(body["description"], AGENT_ARGS["description"])

    def test_missing_args_fail_closed(self):
        is_err, text = self.call_tool("register_agent", {})
        self.assertTrue(is_err)
        for field in ("agent_name", "owner_name", "owner_email"):
            self.assertIn(field, text)
        self.assertIn("nothing was registered", text)

    def test_homepage_or_description_required(self):
        args = dict(AGENT_ARGS)
        del args["homepage"]
        del args["description"]
        args["owner_email"] = "wren.neither@example.org"
        is_err, text = self.call_tool("register_agent", args)
        self.assertTrue(is_err)
        self.assertIn("homepage or a description", text)

    def test_invalid_email_surfaces_api_validation(self):
        args = dict(AGENT_ARGS)
        args["owner_email"] = "not-an-email"
        is_err, text = self.call_tool("register_agent", args)
        self.assertTrue(is_err)
        self.assertIn("Registration failed", text)
        self.assertIn("422", text)
        self.assertIn("owner_email is required (a valid email address)",
                      text)
        self.assertNotIn("record_id", text)


class TestRegisterContent(McpTestCase):
    def test_success_shape_hash_locator_audio(self):
        is_err, text = self.call_tool("register_content", dict(CONTENT_ARGS))
        self.assertFalse(is_err, text)
        body = json.loads(text)
        self.assertEqual(body["record_type"],
                         "npc.registry.content_registration")
        self.assertTrue(body["record_id"].startswith("reg_"))
        self.assertEqual(body["kind"], "content")
        self.assertEqual(body["content_kind"], "audio")
        self.assertEqual(body["status"], "registered_checks_pending")
        self.assertEqual(body["status_label"], "registered, checks pending")
        self.assertEqual(body["locator_kind"], "content_hash")
        run = body["checks_run"]
        self.assertEqual(len(run), 1)
        self.assertEqual(run[0]["check"], "content_hash")
        self.assertEqual(run[0]["status"], "provided_by_creator")
        # Cycle completion (2026-10-15): audio registrations now
        # name their media checks as not run when no file bytes were
        # fetched (probe, C2PA carriage read, AI signal), ahead of
        # the standing review pair.
        self.assertEqual(_checks(body, "checks_not_run"),
                         ["media_probe", "c2pa_credentials",
                          "ai_generation_signal", "human_review",
                          "verification_decision"])
        self.assertTrue(pact.verify_record(self.app.keys, body))
        self.assertNotIn("creator_email", body)
        self.assertNotIn("wren.audio@example.org", text)

    def test_url_image_intake_runs_first_checks(self):
        png = _PNG

        class ImgHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(png)))
                self.end_headers()
                self.wfile.write(png)

            def log_message(self, *a):
                pass

        img_server = ThreadingHTTPServer(("127.0.0.1", 0), ImgHandler)
        threading.Thread(target=img_server.serve_forever,
                         daemon=True).start()
        old = os.environ.get("NPC_ALLOW_LOOPBACK_FETCH")
        os.environ["NPC_ALLOW_LOOPBACK_FETCH"] = "1"
        try:
            is_err, text = self.call_tool("register_content", {
                "title": "One pixel, honestly",
                "kind": "image",
                "locator": "http://127.0.0.1:%d/img.png"
                           % img_server.server_address[1],
                "creator_name": "Wren Okafor",
                "creator_email": "wren.image@example.org",
            })
        finally:
            if old is None:
                os.environ.pop("NPC_ALLOW_LOOPBACK_FETCH", None)
            else:
                os.environ["NPC_ALLOW_LOOPBACK_FETCH"] = old
            img_server.shutdown()
        self.assertFalse(is_err, text)
        body = json.loads(text)
        self.assertEqual(body["locator_kind"], "url")
        run = {c["check"]: c for c in body["checks_run"]}
        self.assertEqual(run["content_fetch"]["status"], "fetched")
        self.assertEqual(run["content_fetch"]["bytes"], len(png))
        self.assertEqual(run["content_fetch"]["sha256"],
                         hashlib.sha256(png).hexdigest())
        self.assertEqual(run["c2pa_credentials"]["status"], "not_present")
        not_run = _checks(body, "checks_not_run")
        self.assertIn("c2pa_cryptographic_validation", not_run)
        self.assertIn("ai_generation_signal", not_run)
        self.assertIn("verification_decision", not_run)

    def test_invalid_kind_surfaces_api_validation(self):
        args = dict(CONTENT_ARGS)
        args["kind"] = "hologram"
        args["creator_email"] = "wren.kind@example.org"
        is_err, text = self.call_tool("register_content", args)
        self.assertTrue(is_err)
        self.assertIn("Registration failed", text)
        self.assertIn("422", text)
        self.assertIn("kind must be one of", text)
        self.assertNotIn("record_id", text)

    def test_bad_locator_surfaces_api_validation(self):
        args = dict(CONTENT_ARGS)
        args["locator"] = "somewhere on a shelf"
        args["creator_email"] = "wren.locator@example.org"
        is_err, text = self.call_tool("register_content", args)
        self.assertTrue(is_err)
        self.assertIn("locator must be an http(s) URL or a content hash",
                      text)

    def test_missing_args_fail_closed(self):
        is_err, text = self.call_tool("register_content", {})
        self.assertTrue(is_err)
        for field in ("title", "kind", "locator", "creator_name",
                      "creator_email"):
            self.assertIn(field, text)
        self.assertIn("nothing was registered", text)


class TestRegisterRateLimit(McpTestCase):
    """The API's per-email submission cap (10 per rolling 24h) reaches
    the caller as a rate-limit error with the API's retry guidance —
    never as a registered record."""

    def test_email_cap_surfaces_as_rate_limit(self):
        base = {
            "title": "Cap probe",
            "kind": "text",
            "creator_name": "Cap Probe",
            "creator_email": "cap@example.org",
        }
        for i in range(10):
            args = dict(base)
            args["locator"] = "sha256:" + ("%064x" % (i + 1))
            is_err, text = self.call_tool("register_content", args)
            self.assertFalse(is_err, text)
        args = dict(base)
        args["locator"] = "sha256:" + ("%064x" % 99)
        is_err, text = self.call_tool("register_content", args)
        self.assertTrue(is_err)
        self.assertIn("Registration failed", text)
        self.assertIn("429", text)
        self.assertIn("3600", text)  # the API's retry_after_seconds
        self.assertNotIn("record_id", text)
        # the cap is per email: a different creator still registers
        args["creator_email"] = "other@example.org"
        is_err, text = self.call_tool("register_content", args)
        self.assertFalse(is_err, text)


class TestRegisterNeedsNoKey(McpTestCase):
    """The registration endpoints are public on the API: the tools work
    with no API key configured (the verify tools still fail closed)."""

    def test_registration_works_without_api_key(self):
        client = VerifiedClient(base_url=f"http://127.0.0.1:{self.port}",
                                api_key="")
        mcp = McpServer(client=client)
        reply = mcp.handle({"jsonrpc": "2.0", "id": 11,
                            "method": "tools/call",
                            "params": {"name": "register_agent",
                                       "arguments": dict(AGENT_ARGS)}})
        result = reply["result"]
        self.assertFalse(result.get("isError"))
        body = json.loads(result["content"][0]["text"])
        self.assertEqual(body["status_label"], "registered, checks pending")


class TestRegisterSignature(McpTestCase):
    """A tampered registration response is refused like any other:
    ApiError at the client, isError at the tool, record never shown."""

    def _tampered(self, mutate):
        client = TamperingClient(f"http://127.0.0.1:{self.port}", mutate)
        client.attach(self.client)
        return client

    def test_tampered_record_rejected_at_client(self):
        def flip(status, headers, data):
            try:
                obj = json.loads(data)
            except ValueError:
                return status, headers, data
            if isinstance(obj, dict) and obj.get("record_id"):
                obj["agent_name"] = "Mallory's Agent"
            return status, headers, json.dumps(obj).encode()

        client = self._tampered(flip)
        with self.assertRaises(ApiError):
            client.register_agent("Ledger Lark", "Wren Okafor",
                                  "wren.tamper@example.org",
                                  description="Reconciles ledgers.")

    def test_tampered_record_never_reaches_tool_caller(self):
        def flip(status, headers, data):
            try:
                obj = json.loads(data)
            except ValueError:
                return status, headers, data
            if isinstance(obj, dict) and obj.get("record_id"):
                obj["agent_name"] = "Mallory's Agent"
            return status, headers, json.dumps(obj).encode()

        mcp = McpServer(client=self._tampered(flip))
        reply = mcp.handle({"jsonrpc": "2.0", "id": 12,
                            "method": "tools/call",
                            "params": {"name": "register_agent",
                                       "arguments": dict(AGENT_ARGS)}})
        result = reply["result"]
        self.assertTrue(result.get("isError"))
        self.assertNotIn("Mallory", result["content"][0]["text"])
        self.assertNotIn("record_id", result["content"][0]["text"])
