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


class TestToolAnnotations(McpTestCase):
    """Every tool declares the three MCP annotation hints as explicit
    booleans. OpenAI's plugin tool scan flags any tool missing them
    ("does not provide explicit boolean values for readOnlyHint,
    destructiveHint, and openWorldHint") and leaves it "Not live"
    (observed 2026-10-15 against the hosted endpoint). The values are
    truthful per tool: the five lookups are pure registry reads; the
    two registration tools create a record (never read-only, never
    destructive), and register_content is open-world because a URL
    locator makes the API fetch that address at intake."""

    EXPECTED = {"readOnlyHint": True,
                "destructiveHint": False,
                "openWorldHint": False}
    REGISTER_EXPECTED = {
        "register_agent": {"readOnlyHint": False,
                           "destructiveHint": False,
                           "openWorldHint": False},
        "register_content": {"readOnlyHint": False,
                             "destructiveHint": False,
                             "openWorldHint": True},
    }

    def _expected_for(self, name):
        return self.REGISTER_EXPECTED.get(name, self.EXPECTED)

    def test_registry_entries_carry_explicit_boolean_annotations(self):
        from npc_verify_mcp.tools import TOOLS
        self.assertEqual(len(TOOLS), 7)
        for t in TOOLS:
            ann = t.get("annotations")
            self.assertIsInstance(ann, dict, t["name"])
            self.assertEqual(set(ann), set(self.EXPECTED), t["name"])
            for key, value in self._expected_for(t["name"]).items():
                self.assertIs(ann[key], value,
                              f"{t['name']}.{key} must be {value!r}")
                self.assertIs(type(ann[key]), bool,
                              f"{t['name']}.{key} must be a boolean")

    def test_tools_list_output_carries_annotations(self):
        reply = self.mcp.handle({"jsonrpc": "2.0", "id": 1,
                                 "method": "tools/list"})
        tools = reply["result"]["tools"]
        self.assertEqual(len(tools), 7)
        for t in tools:
            ann = t.get("annotations")
            self.assertIsInstance(ann, dict, t["name"])
            self.assertEqual(ann, self._expected_for(t["name"]), t["name"])
            for key in self.EXPECTED:
                self.assertIs(type(ann[key]), bool,
                              f"{t['name']}.{key} must be a boolean")


class TestToolTitles(McpTestCase):
    """Every tool carries a plain human-readable `title` (the
    protocol's Tool.title), projected into tools/list. Anthropic's
    Connectors Directory review requires a title on every tool
    alongside the annotation hints (submission checklist + review
    criteria, read 2026-10-15)."""

    EXPECTED_TITLES = {
        "verify_claim": "Verify a claim",
        "verify_credential": "Verify a credential",
        "verify_product": "Verify a product",
        "verify_agent": "Verify an agent",
        "register_agent": "Register an agent",
        "register_content": "Register content",
        "explain_verification": "Explain a verification result",
    }

    def test_registry_entries_carry_titles(self):
        from npc_verify_mcp.tools import TOOLS
        self.assertEqual(len(TOOLS), 7)
        for t in TOOLS:
            self.assertEqual(t.get("title"),
                             self.EXPECTED_TITLES[t["name"]], t["name"])

    def test_tools_list_output_carries_titles(self):
        reply = self.mcp.handle({"jsonrpc": "2.0", "id": 1,
                                 "method": "tools/list"})
        tools = reply["result"]["tools"]
        self.assertEqual(len(tools), 7)
        for t in tools:
            self.assertEqual(t.get("title"),
                             self.EXPECTED_TITLES[t["name"]], t["name"])


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
