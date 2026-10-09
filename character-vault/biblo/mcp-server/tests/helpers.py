"""Shared fixtures: MCP server with no external dependencies.

The Biblo character tools are local and deterministic, so tests drive the
real dispatch layer directly with no backend to spin up.
"""
import os
import sys
import unittest

MCP_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MCP_BASE)

from biblo_character_mcp.server import McpServer  # noqa: E402


class McpTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mcp = McpServer()

    def call_tool(self, name, arguments):
        """Drive a tool through the MCP dispatch layer. Returns
        (is_error, text)."""
        reply = self.mcp.handle({"jsonrpc": "2.0", "id": 1,
                                 "method": "tools/call",
                                 "params": {"name": name,
                                            "arguments": arguments}})
        self.assertIn("result", reply)
        result = reply["result"]
        text = result["content"][0]["text"]
        return result.get("isError", False), text
