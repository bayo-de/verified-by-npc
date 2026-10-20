"""Verify yours (verification-start): the registration forms page,
Search resolving API-issued IDs, and the degradation contract.

The forms themselves POST from the visitor's browser to the API base
baked into the page as data-api-base; these tests pin that wiring,
the honest copy around it, and the server-side Search resolution of
registration IDs through GET /v1/records/{id}. The browser-side
behavior against a live and a dead API is demonstrated in the build
report (headless Chromium), not faked here.
"""
import http.client
import json

try:
    from tests.helpers import DashTestCase
except ImportError:  # pragma: no cover - direct invocation
    from helpers import DashTestCase


def _api_post(port, path, body):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", path, body=json.dumps(body).encode(),
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = resp.read()
    status = resp.status
    conn.close()
    return status, json.loads(data)


class VerifyPageTest(DashTestCase):
    def test_verify_page_renders_both_forms(self):
        status, body = self.get("/verify")
        self.assertEqual(status, 200)
        self.assertIn("Start verification of your own work.", body)
        # the content registration form, field for field
        self.assertIn('id="npc-content-form"', body)
        for name in ("title", "kind", "locator", "creator_name",
                     "creator_email"):
            self.assertIn('name="%s"' % name, body)
        # the agent registration form, field for field
        self.assertIn('id="npc-agent-form"', body)
        for name in ("agent_name", "owner_name", "owner_email",
                     "homepage", "description"):
            self.assertIn('name="%s"' % name, body)
        # the forms aim at the dashboard's configured API base
        self.assertIn('data-api-base="%s"' % self.api_url, body)
        self.assertIn("/v1/register/content", body)
        self.assertIn("/v1/register/agent", body)
        # honest framing, stated before any submission happens
        self.assertIn("Registration is not verification", body)
        self.assertIn("registered, checks pending", body)
        self.assertIn("Registration is free", body)

    def test_content_form_offers_every_kind_the_api_accepts(self):
        # The API accepts image, text, audio, video, and other today;
        # the form must offer all five, with plain labels, so audio
        # and video registrations are not hidden behind "other".
        status, body = self.get("/verify")
        self.assertEqual(status, 200)
        for value, label in (("image", "Image"), ("text", "Text"),
                             ("audio", "Audio"), ("video", "Video"),
                             ("other", "Other")):
            self.assertIn('<option value="%s">%s</option>' % (value, label),
                          body)

    def test_verify_page_degradation_contract(self):
        status, body = self.get("/verify")
        self.assertEqual(status, 200)
        # The plain down-state ships in the page, hidden until the
        # script's health check fails: the exact words a visitor sees
        # when the verification service is not answering.
        self.assertIn("The verification service is not answering yet",
                      body)
        self.assertIn("Nothing you type is sent or saved", body)
        self.assertIn('href="/"', body)  # the waitlist path
        # The no-JavaScript fallback is equally plain.
        self.assertIn("Registration needs JavaScript", body)
        # Nothing on the page fakes an issued ID or a sent state.
        self.assertNotIn("reg_", body.split('id="npc-register-result"')[0])

    def test_verify_reachable_from_search_and_help(self):
        for path in ("/search", "/help"):
            status, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn('href="/verify"', body, path)


class LiveResolutionTest(DashTestCase):
    def _register_content(self):
        status, rec = _api_post(self.api_port, "/v1/register/content", {
            "title": "A dashboard-resolved registration",
            "kind": "text",
            "locator": "sha256:" + "cd" * 32,
            "creator_name": "Test Maker",
            "creator_email": "dash@example.com",
        })
        self.assertEqual(status, 201)
        return rec

    def test_search_resolves_registration_id(self):
        rec = self._register_content()
        status, body = self.get("/search?id=" + rec["record_id"])
        self.assertEqual(status, 200)
        self.assertIn("A dashboard-resolved registration", body)
        self.assertIn("Registered, checks pending", body)
        self.assertIn(rec["record_id"], body)
        self.assertIn("Registration is not verification", body)
        self.assertIn("Checks that ran", body)
        self.assertIn("Checks that have not run yet", body)
        # the registrant email is never rendered
        self.assertNotIn("dash@example.com", body)

    def test_search_resolves_agent_registration_id(self):
        status, rec = _api_post(self.api_port, "/v1/register/agent", {
            "agent_name": "Dashboard Agent",
            "owner_name": "Test Owner",
            "owner_email": "agent-dash@example.com",
            "description": "Resolves through Search.",
        })
        self.assertEqual(status, 201)
        status, body = self.get("/search?id=" + rec["record_id"])
        self.assertEqual(status, 200)
        self.assertIn("Dashboard Agent", body)
        self.assertIn("Test Owner", body)
        self.assertIn("Registered, checks pending", body)
        self.assertNotIn("agent-dash@example.com", body)

    def test_unknown_search_carries_the_live_lookup(self):
        # Search's primary path for API-issued IDs is the live lookup:
        # the Unknown answer ships the marker the browser script uses
        # to ask the API, so an ID the baked data does not know can
        # still resolve live. An ID the API also lacks stays Unknown.
        status, body = self.get("/search?id=reg_not_issued_yet")
        self.assertEqual(status, 200)
        self.assertIn("Unknown", body)
        self.assertIn('id="npc-live-lookup"', body)
        self.assertIn('data-id="reg_not_issued_yet"', body)
        self.assertIn('data-api-base="%s"' % self.api_url, body)
        self.assertIn("/v1/records/", body)

    def test_unknown_route_carries_the_live_lookup(self):
        status, body = self.get("/search/unknown?id=reg_anything")
        self.assertEqual(status, 200)
        self.assertIn("Unknown.", body)
        self.assertIn('id="npc-live-lookup"', body)
        self.assertIn('data-id="reg_anything"', body)

    def test_unknown_search_invites_registration(self):
        # The Unknown answer stays honest (no record, not a verdict)
        # and invites the owner to put the work or agent on record
        # (Bayo, 2026-10-15: the record books grow by registration).
        status, body = self.get("/search?id=reg_not_issued_yet")
        self.assertEqual(status, 200)
        self.assertIn("That means unknown, not false.", body)
        self.assertIn("If this work or this agent is yours", body)
        self.assertIn('<a href="/verify">put it on record</a>', body)
        self.assertIn("Registration is free", body)

    def test_unknown_route_invites_registration(self):
        status, body = self.get("/search/unknown?id=reg_anything")
        self.assertEqual(status, 200)
        self.assertIn("We have no record of this ID.", body)
        self.assertIn("If this work or this agent is yours", body)
        self.assertIn('<a href="/verify">put it on record</a>', body)
