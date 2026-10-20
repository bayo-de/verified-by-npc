"""Wrong-type tool arguments get an actionable error, never the
generic "internal error" (Claude Connectors Directory review
criteria: generic errors with no detail fail review).

The MCP server validates arguments against each tool's inputSchema
at the tools/call layer, so the hosted endpoint and this package
agree: a number where a string belongs is answered with a message
naming the field and the expected type, and nothing is verified.
"""
import unittest

from tests.helpers import McpTestCase
from npc_verify_mcp.tools import validate_tool_arguments


class WrongTypeArgumentsTest(McpTestCase):
    def assert_actionable(self, name, args, field):
        is_error, text = self.call_tool(name, args)
        self.assertTrue(is_error, f"{name} should error: {text}")
        self.assertIn(field, text)
        self.assertIn("must be a string", text)
        self.assertIn("Nothing was verified.", text)
        self.assertNotIn("internal error", text)

    def test_verify_claim_claim_text_wrong_type(self):
        self.assert_actionable("verify_claim", {"claim_text": 123},
                               "claim_text")

    def test_verify_claim_claim_hash_wrong_type(self):
        self.assert_actionable("verify_claim", {"claim_hash": 7},
                               "claim_hash")

    def test_verify_credential_wrong_type(self):
        self.assert_actionable("verify_credential",
                               {"credential_id": 42}, "credential_id")

    def test_verify_product_wrong_type(self):
        self.assert_actionable("verify_product",
                               {"tag_id": ["demo-tag-001"]}, "tag_id")

    def test_verify_agent_wrong_type(self):
        self.assert_actionable("verify_agent",
                               {"agent_id": {"id": "demo-agent-001"}},
                               "agent_id")

    def assert_actionable_registration(self, name, args, field):
        is_error, text = self.call_tool(name, args)
        self.assertTrue(is_error, f"{name} should error: {text}")
        self.assertIn(field, text)
        self.assertIn("must be a string", text)
        self.assertIn("Nothing was registered.", text)
        self.assertNotIn("internal error", text)

    def test_register_agent_wrong_type(self):
        self.assert_actionable_registration(
            "register_agent", {"agent_name": 42}, "agent_name")

    def test_register_content_wrong_type(self):
        self.assert_actionable_registration(
            "register_content", {"locator": ["https://example.org/x"]},
            "locator")

    def test_explain_verification_has_no_typed_fields(self):
        # explain_verification declares an empty properties map, so
        # there is no typed field to violate: extra arguments are
        # ignored by design, and the explainer still answers (and
        # never produces an internal error).
        is_error, text = self.call_tool("explain_verification",
                                        {"note": 123})
        self.assertFalse(is_error)
        self.assertIn("Verified by NPC means", text)

    def test_valid_arguments_still_work(self):
        is_error, text = self.call_tool(
            "verify_product", {"tag_id": "demo-tag-001"})
        self.assertFalse(is_error)
        self.assertIn("demo-tag-001", text)


class ValidateToolArgumentsUnitTest(unittest.TestCase):
    TOOL = {
        "name": "synthetic",
        "inputSchema": {
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
                "flag": {"type": "boolean"},
                "label": {"type": "string"},
            },
        },
    }

    def test_integer_rejects_bool_and_string(self):
        self.assertIn("count must be an integer",
                      validate_tool_arguments(self.TOOL, {"count": True}))
        self.assertIn("count must be an integer",
                      validate_tool_arguments(self.TOOL, {"count": "3"}))
        self.assertIsNone(
            validate_tool_arguments(self.TOOL, {"count": 3}))

    def test_boolean_and_string(self):
        self.assertIn("flag must be a boolean",
                      validate_tool_arguments(self.TOOL, {"flag": 1}))
        self.assertIsNone(
            validate_tool_arguments(self.TOOL, {"flag": False}))
        self.assertIn("label must be a string",
                      validate_tool_arguments(self.TOOL, {"label": None}))

    def test_undeclared_and_missing_are_not_type_errors(self):
        self.assertIsNone(validate_tool_arguments(self.TOOL, {}))
        self.assertIsNone(
            validate_tool_arguments(self.TOOL, {"extra": object()}))


if __name__ == "__main__":
    unittest.main()
