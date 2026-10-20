"""Request verification (cycle completion, 2026-10-15): the
dashboard half of workstream 3.

Pins: the Search result for a registration offers the ask when no
request exists and shows "Verification requested" with the date
once one does; the /verify page ships the widget script and wires
it into the registration result; the search page for an unknown ID
carries the request widget inside its live-lookup scripts; the copy
stays in the customer register (no em dashes, no absolutes about
verification itself).
"""
import http.client
import json

try:
    from tests.helpers import DashTestCase
except ImportError:  # pragma: no cover - direct invocation
    from helpers import DashTestCase


def _api(port, method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    payload = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=payload,
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = resp.read()
    status = resp.status
    conn.close()
    return status, json.loads(data) if data else {}


class RequestVerificationSearchTest(DashTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, rec = _api(cls.api_port, "POST", "/v1/register/content", {
            "title": "A dashboard-cycle story", "kind": "text",
            "locator": "sha256:" + "cd" * 32,
            "creator_name": "Dash Maker",
            "creator_email": "dash-maker@example.com"})
        assert status == 201, status
        cls.record_id = rec["record_id"]

    def test_search_result_offers_the_ask(self):
        status, body = self.get("/search?id=" + self.record_id)
        self.assertEqual(status, 200)
        self.assertIn("npc-request-verification", body)
        self.assertIn('data-record-id="%s"' % self.record_id, body)
        self.assertIn("Request verification", body)
        self.assertIn("The email you registered with", body)
        # the widget script ships with the rendered widget so the
        # form actually works on this page
        self.assertIn(":request-verification", body)
        self.assertNotIn("Verification</dt><dd>Requested", body)

    def test_search_result_shows_requested_state(self):
        status, req = _api(
            self.api_port, "POST",
            "/v1/records/%s:request-verification" % self.record_id,
            {"email": "dash-maker@example.com"})
        self.assertEqual(status, 201)
        status, body = self.get("/search?id=" + self.record_id)
        self.assertEqual(status, 200)
        self.assertIn("Verification</dt><dd>Requested %s"
                      % req["requested_at"], body)
        # once requested, the ask itself is gone
        self.assertNotIn("npc-request-verification", body)


class RequestVerificationPagesTest(DashTestCase):
    def test_verify_page_ships_widget_and_wires_result(self):
        status, body = self.get("/verify")
        self.assertEqual(status, 200)
        self.assertIn("npcRequestVerificationBox", body)
        self.assertIn(":request-verification", body)
        self.assertIn("That email does not match this registration.",
                      body)

    def test_unknown_search_carries_live_widget(self):
        status, body = self.get("/search?id=reg_not_here_yet")
        self.assertEqual(status, 200)
        # live lookup fetches the request state and can offer the ask
        self.assertIn("/verification-request", body)
        self.assertIn("npcRequestVerificationBox", body)
        self.assertIn("Verification requested", body)

    def test_widget_copy_register(self):
        # customer copy rules: no em dashes anywhere in the widget
        # markup or script, and asking never promises the mark
        from dashboard import views
        html = views.request_verification_html(
            "reg_example", "https://api.example.test")
        self.assertNotIn("—", html)
        self.assertNotIn("—", views.REQUEST_VERIFY_JS)
        self.assertIn("Verification is the next step", html)
        self.assertNotIn("guarantee", html.lower())


if __name__ == "__main__":
    import unittest
    unittest.main()
