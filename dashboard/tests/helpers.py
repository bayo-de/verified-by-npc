"""Shared fixtures: seeded API v1 + dashboard on ephemeral loopback ports."""
import http.client
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)                       # dashboard package contents
sys.path.insert(0, os.path.dirname(BASE))      # the `dashboard` package itself
sys.path.insert(0, os.path.normpath(os.path.join(BASE, "..", "api")))

from npc_verify.server import create_app, Handler as ApiHandler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from dashboard.server import make_handler  # noqa: E402


class DashTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="dash_test_")
        cls.api_app = create_app(os.path.join(cls.tmp, "t.db"),
                                 os.path.join(cls.tmp, "keys"))
        seeded = seed_all(cls.api_app.store, cls.api_app.keys)
        cls.verifier_key = seeded["verifier_key"]

        ApiHandler.app = cls.api_app
        cls.api_server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
        cls.api_port = cls.api_server.server_address[1]
        cls.api_thread = threading.Thread(
            target=cls.api_server.serve_forever, daemon=True)
        cls.api_thread.start()

        api_url = "http://127.0.0.1:%d" % cls.api_port
        cls.api_url = api_url
        handler = make_handler(api_url, cls.verifier_key)
        cls.dash_server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.dash_port = cls.dash_server.server_address[1]
        cls.dash_thread = threading.Thread(
            target=cls.dash_server.serve_forever, daemon=True)
        cls.dash_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.dash_server.shutdown()
        cls.dash_server.server_close()
        cls.api_server.shutdown()
        cls.api_server.server_close()
        cls.api_app.store.close()

    # -- http helpers --------------------------------------------------
    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.dash_port,
                                          timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        status = resp.status
        conn.close()
        return status, data

    def post_form(self, path, fields):
        body = urllib.parse.urlencode(fields).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.dash_port,
                                          timeout=10)
        conn.request("POST", path, body=body,
                     headers={"Content-Type":
                              "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        status = resp.status
        conn.close()
        return status, data
