"""Social connections view (social profiles lane, phase 1.5):
the dashboard half.

Pins: the renderer prints the API overview payload's own facts
(platform, account, state, last scan, batch outcomes) and the
provenance sentence exactly as the records carry it, and never
renders a connection as verification; the page ships only while
NPC_SOCIAL_PROFILES=1, with the flag off there is no nav entry,
no script, and /social is the 404 it has always been; the page
offers no write action (its script reads the connections list
and the per-connection overview, nothing else).
"""
import http.client
import os
import threading
import unittest
from http.server import ThreadingHTTPServer

try:
    from tests import helpers  # noqa: F401  (puts the package on path)
except ImportError:  # pragma: no cover - direct invocation
    import helpers  # noqa: F401

from dashboard import views  # noqa: E402
from dashboard.server import make_handler  # noqa: E402

FLAG = views.SOCIAL_PROFILES_ENV

OVERVIEW = {
    "connection": {
        "connection_id": "conn_test1",
        "platform": "youtube",
        "platform_account_id": "UCtestchannel123",
        "account_display_name": "Bayo Creates",
        "scopes": "https://www.googleapis.com/auth/youtube.readonly",
        "status": "active",
        "created_at": "2026-10-19T10:00:00+00:00",
        "updated_at": "2026-10-19T10:00:00+00:00",
    },
    "provenance": "The account controls this content on the "
                  "platform.",
    "last_scan": {"scan_id": "scan_test1",
                  "enumerated_at": "2026-10-19T11:00:00+00:00",
                  "item_count": 3},
    "scan_count": 1,
    "batches": [{
        "batch_id": "batch_0123456789abcdef01234567",
        "registered_at": "2026-10-19T11:05:00+00:00",
        "counts": {"total": 3, "registered": 3, "new_version": 0,
                   "unchanged": 0, "failed": 0, "deferred": 0},
    }],
    "totals": {"registered": 3, "new_version": 0, "unchanged": 0,
               "failed": 0, "deferred": 0},
}


class _EnvGuard(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.get(FLAG)

    def tearDown(self):
        if self._saved is None:
            os.environ.pop(FLAG, None)
        else:
            os.environ[FLAG] = self._saved


class SocialConnectionHtmlTests(_EnvGuard):

    def test_renders_payload_facts(self):
        html = views.social_connection_html(OVERVIEW)
        self.assertIn("YouTube: Bayo Creates", html)
        self.assertIn("UCtestchannel123", html)
        self.assertIn("active", html)
        self.assertIn("2026-10-19T11:00:00+00:00, 3 works", html)
        self.assertIn("batch_0123456789abcdef01234567", html)
        self.assertIn("3 registered, 0 new versions, 0 unchanged, "
                      "0 failed, 0 deferred", html)

    def test_provenance_sentence_exact(self):
        html = views.social_connection_html(OVERVIEW)
        self.assertIn("The account controls this content on the "
                      "platform.", html)

    def test_never_renders_verification(self):
        html = views.social_connection_html(OVERVIEW)
        self.assertNotIn("verif", html.lower())

    def test_empty_states(self):
        empty = {"connection": OVERVIEW["connection"],
                 "provenance": OVERVIEW["provenance"],
                 "last_scan": None, "scan_count": 0, "batches": [],
                 "totals": {"registered": 0, "new_version": 0,
                            "unchanged": 0, "failed": 0,
                            "deferred": 0}}
        html = views.social_connection_html(empty)
        self.assertIn("No scan yet", html)
        self.assertIn("No registrations yet from this connection.",
                      html)

    def test_renders_nothing_for_no_connection(self):
        self.assertEqual(views.social_connection_html(None), "")
        self.assertEqual(views.social_connection_html({}), "")
        self.assertEqual(
            views.social_connection_html({"connection": {}}), "")
        self.assertEqual(views.social_connections_html([]), "")
        self.assertEqual(views.social_connections_html(None), "")

    def test_escapes_payload_text(self):
        hostile = {"connection": {
            "connection_id": "conn_x", "platform": "youtube",
            "platform_account_id": "<b>UC</b>",
            "account_display_name": "<script>alert(1)</script>",
            "status": "active",
            "created_at": "2026-10-19T10:00:00+00:00"},
            "provenance": "p", "last_scan": None, "scan_count": 0,
            "batches": [], "totals": {}}
        html = views.social_connection_html(hostile)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<b>UC</b>", html)


class SocialFlagGatingTests(_EnvGuard):

    def test_flag_off_no_nav_entry(self):
        os.environ.pop(FLAG, None)
        self.assertFalse(views.social_enabled())
        html = views.page("Home", views.home_view(),
                          "https://api.example")
        self.assertNotIn('href="/social"', html)
        self.assertNotIn("npc-social", html)

    def test_flag_on_nav_entry_appears(self):
        os.environ[FLAG] = "1"
        self.assertTrue(views.social_enabled())
        html = views.page("Home", views.home_view(),
                          "https://api.example")
        self.assertIn('<a href="/social">Social</a>', html)

    def test_view_is_read_only(self):
        html = views.social_view("https://api.example")
        self.assertIn('id="npc-social"', html)
        self.assertIn('id="npc-social-form"', html)
        self.assertIn("/v1/social/connections/list",
                      views.SOCIAL_CONNECTIONS_JS)
        self.assertIn("/overview", views.SOCIAL_CONNECTIONS_JS)
        for write in ("/scan", "/register", "/disconnect",
                      "connect/start"):
            self.assertNotIn(write, views.SOCIAL_CONNECTIONS_JS)
            self.assertNotIn(write, html)


class SocialRouteTests(helpers.DashTestCase, _EnvGuard):
    """Dispatch-level gating. The suite's own handler is built by
    helpers with the flag unset; the flag-on handler is built here
    the same way test_failclosed builds one."""

    def _serve(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever,
                                  daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return server.server_address[1]

    def _get(self, port, path):
        conn = http.client.HTTPConnection("127.0.0.1", port,
                                          timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        status = resp.status
        conn.close()
        return status, data

    def test_social_404s_with_flag_off(self):
        os.environ.pop(FLAG, None)
        status, html = self.get("/social")
        self.assertEqual(status, 404)
        self.assertIn("Not found", html)
        self.assertNotIn('href="/social"', html)

    def test_social_serves_with_flag_on(self):
        os.environ[FLAG] = "1"
        handler = make_handler(type(self).api_url,
                               type(self).verifier_key)
        port = self._serve(handler)
        status, html = self._get(port, "/social")
        self.assertEqual(status, 200)
        self.assertIn("Social connections", html)
        self.assertIn('id="npc-social-form"', html)
        self.assertIn('<a href="/social">Social</a>', html)


if __name__ == "__main__":
    unittest.main()
