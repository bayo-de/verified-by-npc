"""Proofline-style contract suite for the MCP server.

Contracts: correct endpoint routing per tool, well-formed argument
validation, fail-closed error shapes, and no fabricated verdicts.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import McpTestCase  # noqa: E402
from npc_verify_mcp.api_client import VerifiedClient  # noqa: E402
from npc_verify_mcp.server import McpServer  # noqa: E402
from npc_verify_mcp.tools import TOOLS  # noqa: E402


class TestToolContracts(McpTestCase):
    def test_five_tools_listed(self):
        reply = self.mcp.handle({"jsonrpc": "2.0", "id": 1,
                                 "method": "tools/list", "params": {}})
        tools = reply["result"]["tools"]
        self.assertEqual(
            sorted(t["name"] for t in tools),
            ["explain_verification", "verify_agent", "verify_claim",
             "verify_credential", "verify_product"])

    def test_descriptions_carry_trigger_phrasing(self):
        triggers = ["is this real?", "verify this", "is this authentic?"]
        descs = {t["name"]: t["description"] for t in TOOLS}
        for name in ("verify_claim", "verify_credential", "verify_product"):
            self.assertTrue(
                any(p in descs[name] for p in triggers),
                f"{name} description lacks trigger phrasing")

    def test_input_schemas_are_valid_json_schema(self):
        for t in TOOLS:
            schema = t["inputSchema"]
            self.assertEqual(schema.get("type"), "object")
            self.assertIsInstance(schema.get("properties"), dict)

    def test_required_args_declared(self):
        by_name = {t["name"]: t for t in TOOLS}
        self.assertEqual(by_name["verify_credential"]["inputSchema"]["required"],
                         ["credential_id"])
        self.assertEqual(by_name["verify_product"]["inputSchema"]["required"],
                         ["tag_id"])
        self.assertEqual(by_name["verify_agent"]["inputSchema"]["required"],
                         ["agent_id"])

    def test_unknown_tool_rejected(self):
        reply = self.mcp.handle({"jsonrpc": "2.0", "id": 2,
                                 "method": "tools/call",
                                 "params": {"name": "mint_money",
                                            "arguments": {}}})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)

    def test_non_object_arguments_rejected(self):
        reply = self.mcp.handle({"jsonrpc": "2.0", "id": 3,
                                 "method": "tools/call",
                                 "params": {"name": "verify_claim",
                                            "arguments": ["not", "an",
                                                          "object"]}})
        self.assertIn("error", reply)

    def test_no_fabricated_verdicts(self):
        # unknown inputs must surface exactly "unknown"
        for tool, args in [
                ("verify_claim", {"claim_text": "nothing like this exists"}),
                ("verify_credential", {"credential_id": "cred_nope"}),
                ("verify_product", {"tag_id": "tag_nope"}),
                ("verify_agent", {"agent_id": "agent_nope"})]:
            is_err, text = self.call_tool(tool, args)
            self.assertFalse(is_err)
            body = json.loads(text)
            self.assertEqual(body["verdict"], "unknown")
            # the unknown envelope must not invent a status/verdict
            self.assertNotIn("valid", text)
            self.assertNotIn("authentic", text)
            self.assertNotIn("verified", text.replace(
                "verification record", ""))

    def test_whitespace_only_args_rejected(self):
        is_err, text = self.call_tool(
            "verify_credential", {"credential_id": "   "})
        self.assertTrue(is_err)


class TestClientContracts(McpTestCase):
    def test_missing_api_key_fail_closed(self):
        client = VerifiedClient(base_url=f"http://127.0.0.1:{self.port}",
                                api_key="")
        mcp = McpServer(client=client)
        reply = mcp.handle({"jsonrpc": "2.0", "id": 4,
                            "method": "tools/call",
                            "params": {"name": "verify_credential",
                                       "arguments": {
                                           "credential_id": "cred_test_001"}}})
        result = reply["result"]
        self.assertTrue(result.get("isError"))
        self.assertIn("NPC_VERIFY_API_KEY",
                      result["content"][0]["text"])

    def test_unreachable_api_fail_closed(self):
        client = VerifiedClient(base_url="http://127.0.0.1:1",
                                api_key="npc_test_dummy", timeout=2)
        mcp = McpServer(client=client)
        reply = mcp.handle({"jsonrpc": "2.0", "id": 5,
                            "method": "tools/call",
                            "params": {"name": "verify_claim",
                                       "arguments": {
                                           "claim_text": "anything"}}})
        result = reply["result"]
        self.assertTrue(result.get("isError"))
        self.assertIn("unreachable",
                      result["content"][0]["text"].lower())

    def test_health_needs_no_key(self):
        client = VerifiedClient(base_url=f"http://127.0.0.1:{self.port}",
                                api_key="")
        body = client.health()
        self.assertEqual(body["status"], "ok")
