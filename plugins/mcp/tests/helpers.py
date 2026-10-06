"""Shared fixtures: live API on loopback + MCP server wired to it.

Mirrors the API's own test pattern (in-process app, ephemeral port) so the
MCP tools are exercised against a real, signature-verifying backend.
"""
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

MCP_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MCP_BASE)

# The API reference implementation lives at ../api relative to the program
# root. Put it on sys.path before importing npc_verify (the MCP client
# bootstraps this itself at runtime; tests need it up front).
_API_DIR = os.path.normpath(os.path.join(
    MCP_BASE, "..", "..", "api"))
if os.path.isfile(os.path.join(_API_DIR, "npc_verify", "__init__.py")):
    sys.path.insert(0, _API_DIR)

# npc_verify_mcp.api_client bootstraps the ../api package itself.
from npc_verify.server import create_app, Handler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify_mcp.api_client import VerifiedClient  # noqa: E402
from npc_verify_mcp.server import McpServer  # noqa: E402


class McpTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_mcp_test_")
        cls.app = create_app(os.path.join(cls.tmp, "t.db"),
                             os.path.join(cls.tmp, "keys"))
        seeded = seed_all(cls.app.store, cls.app.keys)
        cls.verifier_key = seeded["verifier_key"]
        Handler.app = cls.app
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.client = VerifiedClient(
            base_url=f"http://127.0.0.1:{cls.port}",
            api_key=cls.verifier_key)
        cls.mcp = McpServer(client=cls.client)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.app.store.close()

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
