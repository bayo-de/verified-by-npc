"""Shared fixtures: live API on loopback + Gemini helper wired to it.

Mirrors the API's own test pattern (in-process app, ephemeral port) so the
helper's five actions are exercised against a real, signature-verifying
backend.
"""
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

GEMINI_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, GEMINI_BASE)

# The API reference implementation lives at ../../api relative to the
# program root. Put it on sys.path before importing npc_verify (the helper
# bootstraps this itself at runtime; tests need it up front).
_API_DIR = os.path.normpath(os.path.join(
    GEMINI_BASE, "..", "..", "api"))
if os.path.isfile(os.path.join(_API_DIR, "npc_verify", "__init__.py")):
    sys.path.insert(0, _API_DIR)

# npc_verify_gemini.client bootstraps the ../../api package itself.
from npc_verify.server import create_app, Handler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify_gemini.client import (  # noqa: E402
    make_client, run_action, ACTIONS, ApiError)


class ActionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_gemini_test_")
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

    def run_action(self, name, **kwargs):
        """Drive an action through the helper dispatch. Returns
        (is_error, text)."""
        return run_action(self.client, name, kwargs)


class RecordingClient:
    """Wraps a VerifiedClient, recording (method, path) of each call."""

    def __init__(self, client):
        self._client = client
        self.calls = []
        orig_http = client._http

        def recording(method, path, body_bytes=None, extra_headers=None):
            self.calls.append((method, path))
            return orig_http(method, path, body_bytes=body_bytes,
                             extra_headers=extra_headers)

        client._http = recording

    def __getattr__(self, name):
        return getattr(self._client, name)
