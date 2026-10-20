"""The 2026-10-16 public restage drop (Bayo: "Yes do all the
above" on the registration-flow audit).

Pins the audit fixes 2-6 as they ship in ONE dashboard drop,
restaged on the live tree:

- the /verify success script carries the "Keep this record" block
  (copyable NPC ID, copyable record link, downloadable record);
- the Search record card, server-rendered and live-lookup alike,
  shows the proof: signature, signing key, content kind, and the
  checks that ran and have not run yet;
- the Unknown answer carries the neutral "Looking up this ID…"
  interim state, so a real record is never declared unknown
  before its lookup answers;
- the public footer no longer calls every record a sample;
- the API tab is in the nav and baked as a page;
- and the Biblo chat widget is NOT in this drop: the restage
  export builds with include_chat=False, so no page carries a
  chat button, panel, script, or button art, while the default
  build (local preview, test suite) keeps the widget.
"""
import http.client
import json
import os
import sys
import tempfile
import unittest

try:
    from tests.helpers import DashTestCase
except ImportError:  # pragma: no cover - direct invocation
    from helpers import DashTestCase

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BASE))      # the `dashboard` package itself

from dashboard import export_static, fixtures  # noqa: E402

BUILD_DATE = "2026-10-16"


def _api_post(port, path, body):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", path, body=json.dumps(body).encode(),
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = resp.read()
    status = resp.status
    conn.close()
    return status, json.loads(data)


class KeepThisRecordTest(DashTestCase):
    """Gap 2: the success screen gives the customer something to keep."""

    def test_verify_page_ships_the_keep_block(self):
        status, body = self.get("/verify")
        self.assertEqual(status, 200)
        self.assertIn("Keep this record", body)
        self.assertIn("npc-keep-record", body)
        self.assertIn("npc-copy-id", body)
        self.assertIn("npc-copy-link", body)
        self.assertIn("npc-download-record", body)
        # the link and the download are built from the record the
        # API just issued, in the visitor's browser
        self.assertIn('"/search?id="', body)
        self.assertIn("JSON.stringify(rec", body)
        self.assertIn('".json"', body)


class RecordCardProofTest(DashTestCase):
    """Gap 3: the record card renders the proof the API signed."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, rec = _api_post(cls.api_port, "/v1/register/content", {
            "title": "Proof on the card", "kind": "text",
            "locator": "sha256:" + "ef" * 32,
            "creator_name": "Card Maker",
            "creator_email": "card-maker@example.com"})
        assert status == 201, status
        cls.rec = rec

    def test_server_card_shows_signature_and_key(self):
        status, body = self.get("/search?id=" + self.rec["record_id"])
        self.assertEqual(status, 200)
        self.assertIn("<dt>Signature</dt>", body)
        self.assertIn(self.rec["signature"], body)
        self.assertIn("Signed with key", body)
        self.assertIn(self.rec["key_id"], body)
        self.assertIn("<dt>Kind</dt><dd>text</dd>", body)
        self.assertIn("Checks that ran", body)
        self.assertIn("Checks that have not run yet", body)

    def test_live_lookup_script_renders_the_same_proof(self):
        # The live-lookup card is the one a real customer sees for
        # an API-issued ID; its script must build the same proof.
        status, body = self.get("/search/unknown?id=" + self.rec["record_id"])
        self.assertEqual(status, 200)
        self.assertIn('row("Signature", rec.signature, true)', body)
        self.assertIn('row("Signed with key", rec.key_id, true)', body)
        self.assertIn("rec.content_kind", body)
        self.assertIn("rec.checks_run", body)
        self.assertIn("rec.checks_not_run", body)


class LookupInterimStateTest(DashTestCase):
    """Gap 4: no ID is declared unknown while its lookup runs."""

    def test_unknown_page_carries_the_pending_state(self):
        status, body = self.get("/search/unknown?id=reg_pending_check")
        self.assertEqual(status, 200)
        self.assertIn('id="npc-unknown-head"', body)
        self.assertIn('id="npc-lookup-pending" hidden', body)
        self.assertIn("Looking up this ID", body)
        # the script swaps verdict and pending in both directions
        self.assertIn("function showPending()", body)
        self.assertIn("function showUnknown()", body)
        # the honest verdict is still in the page for the miss and
        # for visitors without JavaScript
        self.assertIn("We have no record of this ID.", body)
        self.assertIn('id="npc-unknown-notice"', body)


class RestageExportTest(unittest.TestCase):
    """The restage artifact: cycle fixes in, chat widget out."""

    @classmethod
    def setUpClass(cls):
        DashTestCase.setUpClass()
        cls.tmp = tempfile.mkdtemp(prefix="verify_restage_")
        cls.written = export_static.build(
            cls.tmp, build_date=BUILD_DATE, case=DashTestCase,
            include_chat=False)
        cls.tmp_chat = tempfile.mkdtemp(prefix="verify_default_")
        cls.written_chat = export_static.build(
            cls.tmp_chat, build_date=BUILD_DATE, case=DashTestCase)

    @classmethod
    def tearDownClass(cls):
        DashTestCase.tearDownClass()

    def _read(self, rel, chat=False):
        root = self.tmp_chat if chat else self.tmp
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            return f.read()

    def test_no_chat_affordance_anywhere(self):
        for rel in self.written:
            if not rel.endswith(".html"):
                continue
            html = self._read(rel)
            self.assertNotIn('id="npc-chat-btn"', html, rel)
            # (the shared CSS still names the widget's classes;
            # what must not ship is the markup and the script)
            self.assertNotIn('class="npc-chat-panel', html, rel)
            self.assertNotIn("npc-chat-float", html, rel)
            self.assertNotIn("/v1/chat", html, rel)
            self.assertNotIn("biblo-chat-icon", html, rel)
            self.assertNotIn("Ask Biblo", html, rel)
        # and the button art does not ship either
        for rel in export_static.ASSET_FILES:
            self.assertNotIn(rel, self.written)
            self.assertFalse(
                os.path.exists(os.path.join(self.tmp, rel)), rel)

    def test_default_build_keeps_the_widget(self):
        # The gate is a build choice, not a removal: the default
        # export still carries the widget and its art.
        home = self._read("index.html", chat=True)
        self.assertIn('id="npc-chat-btn"', home)
        for rel in export_static.ASSET_FILES:
            self.assertIn(rel, self.written_chat)

    def test_footer_no_longer_calls_every_record_a_sample(self):
        for rel in ("index.html", "records/index.html",
                    "search/index.html", "verify/index.html",
                    "help/index.html"):
            html = self._read(rel)
            self.assertIn(export_static.SNAPSHOT_FOOTER_LEFT, html, rel)
            self.assertIn(
                export_static.SNAPSHOT_FOOTER_RIGHT % BUILD_DATE,
                html, rel)
            self.assertNotIn("Every record shown is a sample", html, rel)
            self.assertNotIn("Sample records.", html, rel)

    def test_api_tab_baked_and_in_nav(self):
        self.assertIn("api/index.html", self.written)
        api = self._read("api/index.html")
        self.assertIn("The signed record, from your own code.", api)
        for rel in ("index.html", "search/unknown/index.html",
                    "verify/index.html", "help/index.html"):
            html = self._read(rel)
            self.assertIn(
                '<a href="/plugins">Plugins</a><a href="/api">API</a>'
                '<a href="/verify">Verify yours</a>', html, rel)

    def test_customer_fixes_baked(self):
        verify = self._read("verify/index.html")
        self.assertIn("Keep this record", verify)
        self.assertIn("npc-copy-id", verify)
        self.assertIn("npc-copy-link", verify)
        self.assertIn("npc-download-record", verify)
        # request verification rides the drop (audit fix 1)
        self.assertIn(":request-verification", verify)
        self.assertIn("npcRequestVerificationBox", verify)
        unknown = self._read("search/unknown/index.html")
        self.assertIn('id="npc-lookup-pending" hidden', unknown)
        self.assertIn("Looking up this ID", unknown)
        self.assertIn('row("Signature", rec.signature, true)', unknown)
        # the mobile header fix ships in the shared CSS
        self.assertIn("@media(max-width:640px){nav{display:flex",
                      self._read("index.html"))

    def test_live_pages_all_present(self):
        # Nothing the live site serves today is missing from the
        # restage; the API page is the one addition.
        for rel in ("index.html", "records/index.html",
                    "search/index.html", "search/keys/index.html",
                    "search/unknown/index.html", "plugins/index.html",
                    "privacy/index.html", "help/index.html",
                    "verify/index.html", "archive/index.html",
                    "404.html", "_redirects", "_headers"):
            self.assertIn(rel, self.written)
        for cred_id in fixtures.PREVIEW_CREDENTIALS:
            self.assertIn("search/%s/index.html" % cred_id, self.written)
        for tag in fixtures.PREVIEW_PRODUCTS:
            self.assertIn("search/%s/index.html" % tag, self.written)
        for tag in fixtures.ARCHIVE_PRODUCTS:
            self.assertIn("search/%s/index.html" % tag, self.written)


if __name__ == "__main__":
    unittest.main()
