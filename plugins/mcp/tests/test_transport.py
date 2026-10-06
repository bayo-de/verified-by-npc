"""Transport tests: JSON-RPC over stdio.

Drives the real serve() loop with in-memory streams — initialize handshake,
tools/list, tools/call, notifications (no reply), and malformed input.
"""
import io
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import McpTestCase  # noqa: E402
from npc_verify_mcp.server import McpServer  # noqa: E402


def run_session(mcp, messages):
    """Feed raw lines through serve(); return the reply lines."""
    stdin = io.StringIO("".join(m + "\n" for m in messages))
    stdout = io.StringIO()
    mcp.serve(stdin=stdin, stdout=stdout)
    stdout.seek(0)
    return [json.loads(line) for line in stdout if line.strip()]


class TestTransport(McpTestCase):
    def _init(self):
        return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2024-11-05",
                                      "capabilities": {},
                                      "clientInfo": {"name": "t",
                                                     "version": "0"}}})

    def test_initialize_handshake(self):
        replies = run_session(self.mcp, [self._init()])
        self.assertEqual(len(replies), 1)
        result = replies[0]["result"]
        self.assertEqual(result["protocolVersion"], "2024-11-05")
        self.assertIn("tools", result["capabilities"])
        self.assertEqual(result["serverInfo"]["name"], "npc-verify")

    def test_notification_gets_no_reply(self):
        replies = run_session(self.mcp, [
            self._init(),
            json.dumps({"jsonrpc": "2.0", "method":
                        "notifications/initialized"}),
        ])
        self.assertEqual(len(replies), 1)  # only the initialize reply

    def test_full_session(self):
        replies = run_session(self.mcp, [
            self._init(),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "explain_verification",
                                   "arguments": {}}}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                        "params": {"name": "verify_credential",
                                   "arguments": {
                                       "credential_id": "cred_test_001"}}}),
        ])
        self.assertEqual(len(replies), 4)
        self.assertEqual(len(replies[1]["result"]["tools"]), 5)
        self.assertIn("Verified by NPC",
                      replies[2]["result"]["content"][0]["text"])
        cred = json.loads(replies[3]["result"]["content"][0]["text"])
        self.assertEqual(cred["status"], "valid")

    def test_parse_error_recoverable(self):
        replies = run_session(self.mcp, ["{not json", self._init()])
        self.assertEqual(replies[0]["error"]["code"], -32700)
        self.assertIn("result", replies[1])  # session continues

    def test_unknown_method(self):
        replies = run_session(self.mcp, [
            json.dumps({"jsonrpc": "2.0", "id": 9,
                        "method": "tools/dance"})])
        self.assertEqual(replies[0]["error"]["code"], -32601)
