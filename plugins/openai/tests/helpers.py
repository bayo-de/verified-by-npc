"""Shared fixtures: live API on loopback + OpenAI plugin client.

Mirrors the MCP test pattern (in-process app, ephemeral port) so the
plugin helper is exercised against a real, signature-verifying backend.
"""
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

OPENAI_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, OPENAI_BASE)

# The API reference implementation lives at ../api relative to the program
# root. The client module bootstraps ../mcp itself at runtime; tests need
# both on the path up front.
_API_DIR = os.path.normpath(os.path.join(
    OPENAI_BASE, "..", "..", "api"))
if os.path.isfile(os.path.join(_API_DIR, "npc_verify", "__init__.py")):
    sys.path.insert(0, _API_DIR)
_MCP_DIR = os.path.normpath(os.path.join(
    OPENAI_BASE, "..", "mcp"))
if os.path.isfile(os.path.join(_MCP_DIR, "npc_verify_mcp", "__init__.py")):
    sys.path.insert(0, _MCP_DIR)

from npc_verify.server import create_app, Handler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify_openai.client import (  # noqa: E402
    make_client, run_operation, OPERATIONS)


class OpenAITestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_openai_test_")
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
        cls.client = make_client(
            base_url=f"http://127.0.0.1:{cls.port}",
            api_key=cls.verifier_key)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.app.store.close()

    def run_op(self, name, args):
        """Drive an operation through the plugin helper layer. Returns
        (is_error, text)."""
        return run_operation(self.client, name, args)
