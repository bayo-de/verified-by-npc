"""Per-tool tests against the seeded fixtures.

Every tool result travels through the API's Ed25519 signatures, so these
tests exercise the full thin-call + verify path.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import McpTestCase  # noqa: E402


class TestVerifyClaim(McpTestCase):
    def test_verified_claim(self):
        is_err, text = self.call_tool(
            "verify_claim",
            {"claim_text": "The test widget passes drop testing"})
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertTrue(body["matched"])
        self.assertEqual(body["attestation"]["verdict"], "verified")

    def test_verified_with_caveats_claim(self):
        is_err, text = self.call_tool(
            "verify_claim",
            {"claim_text": "Test Farms honey is single-origin"})
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertTrue(body["matched"])
        self.assertEqual(body["attestation"]["verdict"],
                         "verified_with_caveats")

    def test_unknown_claim_fail_closed(self):
        is_err, text = self.call_tool(
            "verify_claim",
            {"claim_text": "The moon is made of cheese, definitely"})
        self.assertFalse(is_err)  # unknown is a result, not a transport error
        body = json.loads(text)
        self.assertEqual(body["verdict"], "unknown")

    def test_missing_args_fail_closed(self):
        is_err, text = self.call_tool("verify_claim", {})
        self.assertTrue(is_err)
        self.assertIn("claim_text", text)


class TestVerifyCredential(McpTestCase):
    def test_valid_credential(self):
        is_err, text = self.call_tool(
            "verify_credential", {"credential_id": "cred_test_001"})
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertEqual(body["status"], "valid")
        self.assertEqual(body["holder_name"], "Test Holder")

    def test_revoked_credential(self):
        is_err, text = self.call_tool(
            "verify_credential", {"credential_id": "cred_test_002"})
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["status"], "revoked")

    def test_private_holder_hidden(self):
        is_err, text = self.call_tool(
            "verify_credential", {"credential_id": "cred_test_003"})
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertEqual(body["status"], "expired")
        self.assertIsNone(body["holder_name"])

    def test_unknown_credential_fail_closed(self):
        is_err, text = self.call_tool(
            "verify_credential", {"credential_id": "cred_nope"})
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["verdict"], "unknown")

    def test_missing_args_fail_closed(self):
        is_err, text = self.call_tool("verify_credential", {})
        self.assertTrue(is_err)


class TestVerifyProduct(McpTestCase):
    def test_authentic_product(self):
        is_err, text = self.call_tool(
            "verify_product", {"tag_id": "tag_test_authentic"})
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["status"], "authentic")

    def test_counterfeit_product(self):
        is_err, text = self.call_tool(
            "verify_product", {"tag_id": "tag_test_counterfeit"})
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["status"], "counterfeit")

    def test_unknown_tag_fail_closed(self):
        is_err, text = self.call_tool(
            "verify_product", {"tag_id": "tag_nope"})
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["verdict"], "unknown")

    def test_missing_args_fail_closed(self):
        is_err, text = self.call_tool("verify_product", {})
        self.assertTrue(is_err)


class TestVerifyAgent(McpTestCase):
    def test_verified_agent(self):
        is_err, text = self.call_tool(
            "verify_agent", {"agent_id": "agent_test_scout"})
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertEqual(body["verdict"], "verified")
        self.assertIn("scope", body)

    def test_verified_with_caveats_agent(self):
        is_err, text = self.call_tool(
            "verify_agent", {"agent_id": "agent_test_herald"})
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["verdict"],
                         "verified_with_caveats")

    def test_unknown_agent_fail_closed(self):
        is_err, text = self.call_tool(
            "verify_agent", {"agent_id": "agent_nope"})
        self.assertFalse(is_err)
        self.assertEqual(json.loads(text)["verdict"], "unknown")

    def test_missing_args_fail_closed(self):
        is_err, text = self.call_tool("verify_agent", {})
        self.assertTrue(is_err)


class TestExplainVerification(McpTestCase):
    def test_explains_the_why(self):
        is_err, text = self.call_tool("explain_verification", {})
        self.assertFalse(is_err)
        self.assertIn("Verified by NPC", text)
        self.assertIn("unknown", text.lower())

    def test_reveals_no_methodology(self):
        _, text = self.call_tool("explain_verification", {})
        lowered = text.lower()
        for secret_word in ("methodology", "private key", "seed"):
            self.assertNotIn(secret_word, lowered)
