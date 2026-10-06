"""Fail-closed rendering: unknown subjects render unknown; errors render
unavailable; no data is ever invented."""
import socket
import threading
from http.server import ThreadingHTTPServer

try:
    from tests.helpers import DashTestCase
except ImportError:  # pragma: no cover - direct invocation
    from helpers import DashTestCase

import http.client

from dashboard.server import make_handler  # noqa: E402 (path set by helpers)


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FailClosedTest(DashTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # A second dashboard pointed at a dead API: everything must degrade.
        dead_url = "http://127.0.0.1:%d" % _closed_port()
        handler = make_handler(dead_url, "dead-key")
        cls.dead_server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.dead_port = cls.dead_server.server_address[1]
        cls.dead_thread = threading.Thread(
            target=cls.dead_server.serve_forever, daemon=True)
        cls.dead_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.dead_server.shutdown()
        cls.dead_server.server_close()
        super().tearDownClass()

    def dead_get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.dead_port,
                                          timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        status = resp.status
        conn.close()
        return status, data

    # -- unknown subjects: "unknown", never a guess ---------------------
    def test_unknown_credential(self):
        status, body = self.get("/credentials?id=cred_nope_999")
        self.assertEqual(status, 200)
        self.assertIn("Unknown", body)
        self.assertIn("never guess", body)
        self.assertNotIn("Test Artisan Certificate", body)

    def test_unknown_product(self):
        status, body = self.get("/products?tag=tag_nope_999")
        self.assertEqual(status, 200)
        self.assertIn("Unknown", body)
        self.assertIn("We have no record of this tag", body)
        # no invented product data, and no verdict pill rendered
        self.assertNotIn("Test Widget", body)
        self.assertNotIn('<span class="pill verified">', body)
        self.assertNotIn('<span class="pill bad">', body)

    def test_unknown_claim(self):
        status, body = self.post_form(
            "/records", {"claim_text": "definitely not an attested claim"})
        self.assertEqual(status, 200)
        self.assertIn("Unknown", body)

    # -- dead API: "unavailable", pages still render ---------------------
    def test_dead_api_home_still_renders(self):
        status, body = self.dead_get("/")
        self.assertEqual(status, 200)
        self.assertIn("Verified by NPC", body)

    def test_dead_api_records_unavailable(self):
        status, body = self.dead_get("/records")
        self.assertEqual(status, 200)
        self.assertIn("could not be confirmed", body)
        self.assertNotIn("Mechanical drop test", body)

    def test_dead_api_keys_unavailable(self):
        status, body = self.dead_get("/keys")
        self.assertEqual(status, 200)
        self.assertIn("Unavailable", body)
        self.assertNotIn("npc-api_signing", body)

    def test_dead_api_credential_unavailable(self):
        status, body = self.dead_get("/credentials?id=cred_test_001")
        self.assertEqual(status, 200)
        self.assertIn("Unavailable", body)
        self.assertNotIn("Test Artisan Certificate", body)

    def test_dead_api_product_unavailable(self):
        status, body = self.dead_get("/products?tag=tag_test_authentic")
        self.assertEqual(status, 200)
        self.assertIn("Unavailable", body)
        self.assertNotIn("Test Widget", body)
