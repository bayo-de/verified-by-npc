"""Intake-fetch SSRF guard (audit item D3).

registry.fetch_url_bytes fetches a submitter-supplied URL server-side.
The guard refuses literal private / loopback / link-local hosts and
re-validates every redirect target the same way. The local fixtures
serve over loopback, so a test-mode allowance
(NPC_ALLOW_LOOPBACK_FETCH=1, set by the test harness) permits
loopback throughout a fixture fetch; private and link-local ranges
stay refused under every setting, and without the allowance (the
production configuration) loopback is refused at every hop.
"""
import contextlib
import http.server
import os
import sys
import threading
import unittest
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import registry  # noqa: E402
from tests.helpers import ApiTestCase  # noqa: E402

FIXTURE_BYTES = b"guard-fixture-bytes"


class _GuardFixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_address[1]
        if self.path == "/ok":
            body = FIXTURE_BYTES
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        targets = {
            "/to-private": "http://169.254.169.254/latest/meta-data",
            "/to-private-range": "http://192.168.10.20/secret",
            "/to-loopback": "http://127.0.0.1:%d/ok" % port,
            "/hop": "/ok",
        }
        target = targets.get(self.path)
        if target is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(302)
        self.send_header("Location", target)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


@contextlib.contextmanager
def _allowance(value):
    with mock.patch.dict(os.environ):
        if value is None:
            os.environ.pop("NPC_ALLOW_LOOPBACK_FETCH", None)
        else:
            os.environ["NPC_ALLOW_LOOPBACK_FETCH"] = value
        yield


class FetchGuardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _GuardFixtureHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever,
                         daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def url(self, path):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def test_public_fetch_still_works(self):
        # Loopback stands in for a public host under the test-mode
        # allowance the harness sets for its fixtures.
        with _allowance("1"):
            self.assertEqual(registry.fetch_url_bytes(self.url("/ok")),
                             FIXTURE_BYTES)

    def test_loopback_refused_without_the_allowance(self):
        with _allowance(None):
            self.assertIsNone(registry.fetch_url_bytes(self.url("/ok")))

    def test_private_and_link_local_literals_refused(self):
        # Even WITH the allowance: it covers loopback fixtures only,
        # never private or link-local ranges.
        refused = [
            "http://192.168.1.10/admin",
            "http://10.1.2.3/admin",
            "http://172.16.0.9/admin",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/admin",
            "http://localhost/admin",
            "http://printer.localhost/admin",
            "http://127.1/admin",          # inet_aton loopback form
            "http://0x7f000001/admin",     # hex loopback form
            "http://0.0.0.0/admin",
        ]
        with _allowance("1"):
            for url in refused:
                self.assertIsNone(
                    registry.fetch_url_bytes(url, timeout=2), url)

    def test_redirect_to_private_refused(self):
        with _allowance("1"):
            self.assertIsNone(
                registry.fetch_url_bytes(self.url("/to-private")))
            self.assertIsNone(
                registry.fetch_url_bytes(self.url("/to-private-range")))

    def test_redirect_to_loopback_refused_without_allowance(self):
        # Production configuration (no allowance): the submitted URL
        # carries a DNS name the guard permits, the name resolves to
        # the loopback fixture, and the fixture tries to bounce the
        # fetch into a loopback literal. The hop is re-validated and
        # refused. The resolver is patched in-process so the DNS name
        # deterministically maps to the fixture.
        import socket
        real_gai = socket.getaddrinfo

        def fake_gai(host, port, *args, **kwargs):
            if host == "fixture.test":
                return real_gai("127.0.0.1", port, *args, **kwargs)
            return real_gai(host, port, *args, **kwargs)

        with _allowance(None), \
                mock.patch.object(socket, "getaddrinfo", fake_gai):
            self.assertIsNone(registry.fetch_url_bytes(
                "http://fixture.test:%d/to-loopback" % self.port))

    def test_redirect_within_permitted_host_still_works(self):
        with _allowance("1"):
            self.assertEqual(
                registry.fetch_url_bytes(self.url("/hop")),
                FIXTURE_BYTES)
            # A fixture redirect that stays on the fixture host is
            # validated the same way and followed under the allowance.
            self.assertEqual(
                registry.fetch_url_bytes(self.url("/to-loopback")),
                FIXTURE_BYTES)


class FetchGuardHttpTest(ApiTestCase):
    """End to end: a registration pointing at a link-local address
    mints its record with the fetch honestly recorded as not run."""

    def test_private_literal_locator_is_not_fetched(self):
        body = {
            "title": "Metadata attempt",
            "kind": "image",
            "locator": "http://169.254.169.254/latest/meta-data",
            "creator_name": "Guard Tester",
            "creator_email": "guard@example.com",
        }
        status, _, data = self.post("/v1/register/content", body=body)
        self.assertEqual(status, 201)
        import json
        rec = json.loads(data)
        fetch = [c for c in rec["checks_run"]
                 if c["check"] == "content_fetch"]
        self.assertEqual(fetch[0]["status"], "not_fetched")


if __name__ == "__main__":
    unittest.main()
