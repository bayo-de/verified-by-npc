"""Helper tests: signature verification (pass/tamper/fail-closed) and
Proofline-style contracts per action (correct endpoint, well-formed args,
fail-closed errors).

All fixtures are fictional. Every live call below travels through the
API's real Ed25519 signatures, so a passing call proves the signature
check passed; tampered calls must raise ApiError.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import ActionTestCase, RecordingClient  # noqa: E402
from npc_verify_gemini.client import (  # noqa: E402
    ApiError, make_client)
from npc_verify.canonical import canonicalize  # noqa: E402

# Proofline: the endpoint each action must hit.
EXPECTED_ENDPOINTS = {
    "verify_product": ("GET", "/v1/products/tag_test_authentic"),
    "verify_credential": ("GET", "/v1/credentials/cred_test_001"),
    "verify_claim": ("POST", "/v1/claims/verify"),
    "verify_agent": ("GET", "/v1/agents/agent_test_scout/attestation"),
}

ACTION_ARGS = {
    "verify_product": {"tag_id": "tag_test_authentic"},
    "verify_credential": {"credential_id": "cred_test_001"},
    "verify_claim": {"claim_text": "The test widget passes drop testing"},
    "verify_agent": {"agent_id": "agent_test_scout"},
}


class TestSignaturePass(ActionTestCase):
    """Live calls succeed only because the signature verifies."""

    def test_verify_product_signature_pass(self):
        is_err, text = self.run_action(
            "verify_product", tag_id="tag_test_authentic")
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["status"], "authentic")

    def test_verify_credential_signature_pass(self):
        is_err, text = self.run_action(
            "verify_credential", credential_id="cred_test_001")
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["status"], "valid")

    def test_verify_claim_signature_pass(self):
        is_err, text = self.run_action(
            "verify_claim",
            claim_text="The test widget passes drop testing")
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertTrue(body["matched"])
        self.assertEqual(body["attestation"]["verdict"], "verified")

    def test_verify_agent_signature_pass(self):
        is_err, text = self.run_action(
            "verify_agent", agent_id="agent_test_scout")
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["verdict"], "verified")


class TestTamperFailClosed(ActionTestCase):
    """Any tamper with a signed response must raise, never return data."""

    def _signed_product_response(self):
        status, headers, data = self.client._http(
            "GET", "/v1/products/tag_test_authentic",
            extra_headers={"Authorization": f"Bearer {self.verifier_key}"})
        self.assertEqual(status, 200)
        return status, headers, data

    def test_tampered_body_rejected(self):
        status, headers, data = self._signed_product_response()
        parsed = json.loads(data)
        parsed["status"] = "tampered-value"
        tampered = canonicalize(parsed)  # valid JSON, broken signature
        with self.assertRaises(ApiError):
            self.client._verify_response(status, headers, tampered)

    def test_missing_signature_headers_rejected(self):
        status, headers, data = self._signed_product_response()
        bare = {k: v for k, v in headers.items()
                if k not in ("X-NPC-Signature", "X-NPC-Key-ID")}
        with self.assertRaises(ApiError):
            self.client._verify_response(status, bare, data)

    def test_unknown_key_id_rejected(self):
        status, headers, data = self._signed_product_response()
        forged = dict(headers, **{"X-NPC-Key-ID": "npc-unknown-key"})
        with self.assertRaises(ApiError):
            self.client._verify_response(status, forged, data)

    def test_non_canonical_body_rejected(self):
        status, headers, data = self._signed_product_response()
        pretty = json.dumps(json.loads(data), indent=2).encode("utf-8")
        with self.assertRaises(ApiError):
            self.client._verify_response(status, headers, pretty)

    def test_unreachable_api_fails_closed(self):
        dead = make_client(base_url="http://127.0.0.1:1", api_key="x",
                           timeout=1)
        from npc_verify_gemini.client import run_action
        is_err, text = run_action(dead, "verify_product",
                                  {"tag_id": "tag_test_authentic"})
        self.assertTrue(is_err)
        self.assertNotIn("authentic", text)


class TestUnknownFailClosed(ActionTestCase):
    """Unknown subjects return 'unknown', never a fabricated verdict."""

    def test_unknown_product(self):
        is_err, text = self.run_action("verify_product", tag_id="tag_nope")
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["verdict"], "unknown")

    def test_unknown_credential(self):
        is_err, text = self.run_action(
            "verify_credential", credential_id="cred_nope")
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["verdict"], "unknown")

    def test_unknown_claim(self):
        is_err, text = self.run_action(
            "verify_claim",
            claim_text="The moon is made of cheese, definitely")
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["verdict"], "unknown")

    def test_unknown_agent(self):
        is_err, text = self.run_action("verify_agent", agent_id="agent_nope")
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["verdict"], "unknown")


class TestProoflineContracts(ActionTestCase):
    """Per action: correct endpoint, well-formed args, fail-closed errors."""

    def test_correct_endpoint_per_action(self):
        for name, (method, path) in EXPECTED_ENDPOINTS.items():
            with self.subTest(action=name):
                rec = RecordingClient(self.client)
                try:
                    is_err, _ = self.run_action(name, **ACTION_ARGS[name])
                finally:
                    # restore the real transport for other tests
                    del self.client._http
                self.assertFalse(is_err)
                self.assertIn((method, path), rec.calls)

    def test_missing_args_fail_closed(self):
        cases = {
            "verify_product": {"tag_id": ""},
            "verify_credential": {"credential_id": ""},
            "verify_claim": {"claim_text": "", "claim_hash": ""},
            "verify_agent": {"agent_id": ""},
        }
        for name, args in cases.items():
            with self.subTest(action=name):
                is_err, text = self.run_action(name, **args)
                self.assertTrue(is_err)
                self.assertIn("nothing was verified", text.lower())

    def test_unknown_action_rejected(self):
        from npc_verify_gemini.client import run_action
        with self.assertRaises(KeyError):
            run_action(self.client, "issue_attestation", {})


class TestExplainVerification(ActionTestCase):
    def test_explains_the_why(self):
        is_err, text = self.run_action("explain_verification")
        self.assertFalse(is_err)
        self.assertIn("Verified by NPC", text)
        self.assertIn("unknown", text.lower())

    def test_reveals_no_methodology(self):
        _, text = self.run_action("explain_verification")
        lowered = text.lower()
        for secret_word in ("methodology", "private key", "seed"):
            self.assertNotIn(secret_word, lowered)


if __name__ == "__main__":
    unittest.main()
