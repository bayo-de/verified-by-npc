"""Tests for the Netlify static export (dashboard/export_static.py).

- The artifact renders the same content as the local app (modulo the
  documented public-site footer deltas).
- Fixture lookup URLs have baked detail pages matching the local app.
- The artifact contains zero secrets: no API keys, no private key
  material, no loopback URLs, no local filesystem paths.
- The generated _redirects carries the query rewrites the lookup URLs
  depend on, every one of them forced and covering both path forms.
- No em-dashes anywhere in the public artifact (Bayo's standing rule).
"""
import http.client
import os
import re
import sys
import tempfile
import unittest
import urllib.parse

from tests.helpers import DashTestCase  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BASE))      # the `dashboard` package itself

from dashboard import export_static, fixtures  # noqa: E402

BUILD_DATE = "2026-10-06"

EXPECTED_PAGES = [
    "index.html",
    "records/index.html",
    "search/index.html",
    "search/keys/index.html",
    "search/unknown/index.html",
    "plugins/index.html",
    "api/index.html",
    "privacy/index.html",
    "help/index.html",
    "verify/index.html",
    "404.html",
] + ["search/%s/index.html" % c for c in fixtures.PREVIEW_CREDENTIALS] \
  + ["search/%s/index.html" % t for t in fixtures.PREVIEW_PRODUCTS] \
  + ["archive/index.html"] \
  + ["search/%s/index.html" % t for t in fixtures.ARCHIVE_PRODUCTS]

LOCAL_ROUTES = {
    "index.html": "/",
    "records/index.html": "/records",
    "search/index.html": "/search",
    "search/keys/index.html": "/search/keys",
    "search/unknown/index.html": "/search/unknown",
    "plugins/index.html": "/plugins",
    "api/index.html": "/api",
    "privacy/index.html": "/privacy",
    "help/index.html": "/help",
    "verify/index.html": "/verify",
    "404.html": "/__definitely_missing__",
    "archive/index.html": "/archive",
}
for c in fixtures.PREVIEW_CREDENTIALS:
    LOCAL_ROUTES["search/%s/index.html" % c] = (
        "/search?id=" + urllib.parse.quote(c, safe=""))
for t in fixtures.PREVIEW_PRODUCTS:
    LOCAL_ROUTES["search/%s/index.html" % t] = (
        "/search?id=" + urllib.parse.quote(t, safe=""))
for t in fixtures.ARCHIVE_PRODUCTS:
    LOCAL_ROUTES["search/%s/index.html" % t] = (
        "/search?id=" + urllib.parse.quote(t, safe=""))

ARCHIVE_PAGES = ["archive/index.html"] + [
    "search/%s/index.html" % t for t in fixtures.ARCHIVE_PRODUCTS]

PRIVACY_PAGES = ["privacy/index.html"]

# Patterns that must never appear in the public artifact.
FORBIDDEN = [
    r"npc_test_",                 # plaintext test API keys (bearer tokens)
    r"-----BEGIN[^-]*KEY-----",   # PEM private key blocks
    r"Bearer\s+[A-Za-z0-9_\-.]",  # authorization header values
    r"127\.0\.0\.1",              # loopback URLs
    r"\blocalhost\b",
    r"::1",
    r"/tmp/",                     # local build paths
    r"/home/",
    r"\.seed\b",                  # private key file suffix
    r"token_hex",
    r"PRIVATE KEY",
    r"\bsk_test\b",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bxoxb-",
]


def _local_get(case, route):
    conn = http.client.HTTPConnection("127.0.0.1", case.dash_port, timeout=30)
    conn.request("GET", route)
    resp = conn.getresponse()
    status, data = resp.status, resp.read().decode("utf-8")
    conn.close()
    return status, data


class StaticExportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        DashTestCase.setUpClass()
        keys_doc = DashTestCase.api_app.keys.publish()
        cls.key_ids = []
        current = (keys_doc.get("api_signing") or {}).get("current")
        if current:
            cls.key_ids.append(current["key_id"])
        for entry in (keys_doc.get("api_signing") or {}).get("history", []):
            cls.key_ids.append(entry["key_id"])
        for entry in keys_doc.get("issuers", []):
            cls.key_ids.append(entry["key_id"])
        for key_id in cls.key_ids:
            rel = "search/%s/index.html" % key_id
            if rel not in EXPECTED_PAGES:
                EXPECTED_PAGES.append(rel)
                LOCAL_ROUTES[rel] = (
                    "/search?id=" + urllib.parse.quote(key_id, safe=""))
        cls.tmp = tempfile.mkdtemp(prefix="verify_dist_")
        cls.written = export_static.build(cls.tmp, build_date=BUILD_DATE,
                                          case=DashTestCase)

    @classmethod
    def tearDownClass(cls):
        DashTestCase.tearDownClass()

    def _read(self, rel):
        with open(os.path.join(self.tmp, rel), encoding="utf-8") as f:
            return f.read()

    # -- completeness ---------------------------------------------------
    def test_all_expected_pages_written(self):
        self.assertEqual(sorted(self.written),
                         sorted(EXPECTED_PAGES + ["_redirects", "_headers"]
                                + export_static.ASSET_FILES))

    def test_headers_file_carries_the_security_headers(self):
        # The live site deploys from this bundle (Netlify Drop), where
        # netlify.toml [[headers]] rules never apply; the generated
        # _headers file is the only thing standing between the pages
        # and a headerless response (live defect found 2026-10-15:
        # verify.npclabs.xyz served no CSP / nosniff / frame headers).
        headers = self._read("_headers")
        self.assertIn("/*", headers)
        for name, value in export_static.SECURITY_HEADERS:
            self.assertIn("%s: %s" % (name, value), headers)
        # and the values must stay in step with netlify.toml
        with open(os.path.join(os.path.dirname(BASE), "netlify.toml"),
                  encoding="utf-8") as f:
            toml = f.read()
        for name, value in export_static.SECURITY_HEADERS:
            self.assertIn('%s = "%s"' % (name, value), toml)

    # -- equivalence with the local app ---------------------------------
    def test_pages_match_local_app(self):
        for rel in EXPECTED_PAGES:
            route = LOCAL_ROUTES[rel]
            status, local = _local_get(DashTestCase, route)
            expected_status = 404 if rel == "404.html" else 200
            self.assertEqual(status, expected_status, route)
            # The build fetches through the same stack; the only public
            # deltas are the documented footer/label transforms.
            self.assertIn("http://127.0.0.1", local, route)
            if rel in ARCHIVE_PAGES:
                want = export_static._publicize_archive(
                    local, DashTestCase.api_url, BUILD_DATE)
            elif rel in PRIVACY_PAGES:
                want = export_static._publicize_privacy(
                    local, DashTestCase.api_url, BUILD_DATE)
            else:
                want = export_static._publicize(local, DashTestCase.api_url,
                                                BUILD_DATE)
            self.assertEqual(self._read(rel), want,
                             "dist page differs from local app: %s" % rel)

    def test_public_deltas_applied(self):
        home = self._read("index.html")
        self.assertIn("main.wrap{padding:72px 24px 64px}", home)
        self.assertIn(
            ".top-in{display:flex;align-items:baseline;"
            "justify-content:space-between;flex-wrap:wrap;"
            "padding-top:18px;padding-bottom:18px;gap:12px}", home)
        self.assertIn(export_static.SNAPSHOT_FOOTER_LEFT, home)
        self.assertIn(export_static.SNAPSHOT_FOOTER_RIGHT % BUILD_DATE, home)
        self.assertNotIn("Reading from http://127.0.0.1", home)
        records = self._read("records/index.html")
        self.assertNotIn("Check a claim", records)
        self.assertNotIn("claim_text", records)
        self.assertNotIn("Live claim checking runs against the verification "
                         "API.", records)
        self.assertIn('<a href="/archive">Browse the archive</a>', records)
        # The public API base appears only as the chat widget's
        # data-api-base attribute (the widget rides every page since
        # the Biblo chat change, 2026-10-15); never loose in content.
        home = self._read("index.html")
        self.assertEqual(
            home.count("https://api.npclabs.xyz"),
            home.count('data-api-base="https://api.npclabs.xyz"'))

    def test_fixture_content_rendered_not_emptied(self):
        # The export must carry real fixture content, not hollow shells.
        records = self._read("records/index.html")
        self.assertIn("The test widget passes drop testing", records)
        cred = self._read("search/cred_test_001/index.html")
        self.assertIn("cred_test_001", cred)
        prod = self._read("search/tag_test_authentic/index.html")
        self.assertIn("tag_test_authentic", prod)
        keys = self._read("search/keys/index.html")
        self.assertIn("npc-api_signing-", keys)
        key_detail = self._read(
            "search/%s/index.html" % self.key_ids[0])
        self.assertIn("Public key found", key_detail)
        unknown = self._read("search/unknown/index.html")
        self.assertIn("Unknown.", unknown)
        self.assertNotIn("Nothing here.", unknown)

    def test_registration_push_rendered(self):
        # The registration push (Bayo, 2026-10-15) is baked in: the
        # home steps section and the Unknown answer's invitation.
        home = self._read("index.html")
        self.assertIn("Put your own work on record.", home)
        self.assertIn(
            "Get a signed record with its own NPC ID, on the spot.", home)
        self.assertIn(
            "Registration is free, and it takes about a minute.", home)
        unknown = self._read("search/unknown/index.html")
        self.assertIn("If this work or this agent is yours", unknown)
        self.assertIn('<a href="/verify">put it on record</a>', unknown)

    def test_api_page_rendered(self):
        # The developer tab (Bayo, 2026-10-15) is baked in: the API
        # page renders with its live examples, and every page's nav
        # carries API next to Plugins.
        api = self._read("api/index.html")
        self.assertIn("The signed record, from your own code.", api)
        self.assertIn("reg_6789fb4ca0f5363853a23dc0", api)
        self.assertIn("https://api.npclabs.xyz/v1/mcp", api)
        self.assertIn("npc-verify-mcp", api)
        main = api.split("<main", 1)[1].split("</main>", 1)[0]
        self.assertNotIn("request-verification", main)
        self.assertNotIn("/v1/chat", main)
        for rel in ("index.html", "plugins/index.html",
                    "api/index.html", "help/index.html"):
            html = self._read(rel)
            self.assertIn(
                '<a href="/plugins">Plugins</a><a href="/api">API</a>'
                '<a href="/verify">Verify yours</a>', html, rel)

    # -- secrets ----------------------------------------------------------
    def test_zero_secrets_in_artifact(self):
        for rel in EXPECTED_PAGES:
            html = self._read(rel)
            for pat in FORBIDDEN:
                self.assertIsNone(re.search(pat, html, re.IGNORECASE),
                                  "forbidden pattern %r in %s" % (pat, rel))

    def test_keys_page_has_no_private_material(self):
        keys = self._read("search/keys/index.html")
        # No private KEY material. (The bare word "private" now also
        # appears in visitor copy: the chat widget's notice, on every
        # page since 2026-10-15, says "do not share private details".)
        self.assertNotIn("private key", keys.lower())
        self.assertNotIn("-----begin", keys.lower())
        self.assertNotIn("seed phrase", keys.lower())

    # -- public-copy rules -------------------------------------------------
    def test_no_em_dashes(self):
        for rel in EXPECTED_PAGES:
            self.assertNotIn("\u2014", self._read(rel), rel)

    def test_no_fundraising_or_profit_claims(self):
        blob = "".join(self._read(r) for r in EXPECTED_PAGES).lower()
        for phrase in ("raised", "profitable", "profitability", "funding round",
                       "seed round", "$18m", "18m raise"):
            self.assertNotIn(phrase, blob)

    # -- netlify wiring ----------------------------------------------------
    def test_search_redirects_cover_lookups_and_unknown(self):
        with open(os.path.join(os.path.dirname(BASE), "netlify.toml"),
                  encoding="utf-8") as f:
            toml = f.read()
        self.assertIn('publish = "dashboard/dist"', toml)
        self.assertNotIn('to = "/credentials/:id/"', toml)
        self.assertNotIn('to = "/products/:tag/"', toml)
        redirects = self._read("_redirects")
        lines = [line for line in redirects.splitlines()
                 if line and not line.startswith("#")]
        for subject_id in (fixtures.PREVIEW_CREDENTIALS
                           + fixtures.PREVIEW_PRODUCTS
                           + fixtures.ARCHIVE_PRODUCTS + self.key_ids):
            self.assertIn("/search id=%s /search/%s/ 200!"
                          % (subject_id, subject_id), lines)
            self.assertIn("/search/ id=%s /search/%s/ 200!"
                          % (subject_id, subject_id), lines)
            self.assertTrue(
                os.path.isfile(os.path.join(
                    self.tmp, "search", subject_id, "index.html")),
                subject_id)
        self.assertEqual(lines[-2:],
                         ["/search id=:id /search/unknown/ 200!",
                          "/search/ id=:id /search/unknown/ 200!"])

    def test_search_redirects_are_forced_and_cover_both_path_forms(self):
        # Regression guard for the 2026-10-14 live defect: the export
        # shipped unforced "/search ... 200" rules, and on Netlify they
        # never fired. Netlify shadows an unforced rule when a static
        # file exists at the from-path (search/index.html sits at
        # /search), and its slash normalization moves /search to
        # /search/, so the rule must be forced (200!) and must exist
        # for both path forms. NOTE: a local static test cannot
        # replicate Netlify's rule precedence; this test only pins the
        # shape of the generated file. The real gate is the live check
        # after deploy: GET /search?id=<known ID> must serve the baked
        # record page, and an unknown ID must serve the Unknown page.
        redirects = self._read("_redirects")
        header = [line for line in redirects.splitlines()
                  if line.startswith("#")]
        self.assertTrue(any("forced" in line for line in header),
                        "header must state the rules are forced")
        lines = [line for line in redirects.splitlines()
                 if line and not line.startswith("#")]
        self.assertTrue(lines, "no redirect rules generated")
        for line in lines:
            self.assertTrue(line.endswith(" 200!"),
                            "rule is not forced: %s" % line)
            self.assertTrue(
                line.startswith("/search id=")
                or line.startswith("/search/ id="),
                "rule keys an unexpected path form: %s" % line)
        known_ids = (fixtures.PREVIEW_CREDENTIALS
                     + fixtures.PREVIEW_PRODUCTS
                     + fixtures.ARCHIVE_PRODUCTS + self.key_ids)
        # Exact rules: one per ID per path form, nothing more, and the
        # two fallback forms close the file in that order.
        self.assertEqual(len(lines), 2 * len(known_ids) + 2)
        unslashed = [line for line in lines
                     if line.startswith("/search id=")]
        slashed = [line for line in lines
                   if line.startswith("/search/ id=")]
        self.assertEqual(len(unslashed), len(known_ids) + 1)
        self.assertEqual(len(slashed), len(known_ids) + 1)
        for subject_id in known_ids:
            self.assertIn("/search id=%s /search/%s/ 200!"
                          % (subject_id, subject_id), unslashed)
            self.assertIn("/search/ id=%s /search/%s/ 200!"
                          % (subject_id, subject_id), slashed)

    # -- privacy page -------------------------------------------------------
    def test_privacy_page_carries_the_policy_not_fixture_labels(self):
        # /privacy is the NPC Verify privacy policy (the page the Chrome
        # Web Store listing points at). It must carry the policy text
        # and its own truthful footer, not the fixture labels.
        privacy = self._read("privacy/index.html")
        self.assertIn("NPC Verify Privacy Policy", privacy)
        self.assertIn("Last updated: %s" % BUILD_DATE, privacy)
        self.assertIn("SHA-256 hash", privacy)
        self.assertIn("hello@npclabs.xyz", privacy)
        self.assertIn(export_static.PRIVACY_FOOTER_LEFT, privacy)
        self.assertIn(export_static.PRIVACY_FOOTER_RIGHT % BUILD_DATE,
                      privacy)
        self.assertNotIn(export_static.SNAPSHOT_FOOTER_LEFT, privacy)
        # and every other page links to it from the footer
        self.assertIn('href="/privacy"', self._read("index.html"))

    # -- help page ---------------------------------------------------------
    def test_help_page_carries_real_guidance(self):
        # /help is the how-it-works + FAQ page (Bayo, 2026-10-14). It
        # carries real guidance in the preview idiom: the snapshot
        # footer, the FAQ, and no trace of the removed video block.
        help_html = self._read("help/index.html")
        self.assertIn("How it works", help_html)
        self.assertIn("What if something has no record?", help_html)
        self.assertIn("Public keys live in Search", help_html)
        self.assertIn("Can I verify or register my own digital "
                      "resources or agents?", help_html)
        self.assertIn('href="/verify"', help_html)
        self.assertIn("Registration is not verification", help_html)
        self.assertIn("The extension is coming soon.", help_html)
        # The API base appears only as chat data-api-base attributes
        # (the inline Ask Biblo panel plus the floating widget).
        self.assertEqual(
            help_html.count("https://api.npclabs.xyz"),
            help_html.count('data-api-base="https://api.npclabs.xyz"'))
        self.assertIn(export_static.SNAPSHOT_FOOTER_LEFT, help_html)
        self.assertNotIn("VIDEO_ID_PENDING", help_html)
        self.assertNotIn("demo-poster", help_html)
        self.assertNotIn("See it work", help_html)

    # -- archive set ------------------------------------------------------
    def test_archive_pages_carry_real_records_not_fixture_labels(self):
        # The archive set is real on-chain history. Its pages must render
        # the records and must not claim to be test fixtures.
        archive = self._read("archive/index.html")
        self.assertIn("Company history, on chain.", archive)
        self.assertIn(export_static.ARCHIVE_FOOTER_LEFT, archive)
        self.assertNotIn(export_static.SNAPSHOT_FOOTER_LEFT, archive)
        self.assertIn("0xe8AFB7C355B68A2A9C616E7877D0ef3352c59D5a", archive)
        for tag in fixtures.ARCHIVE_PRODUCTS:
            self.assertIn(tag, archive)
            detail = self._read("search/%s/index.html" % tag)
            self.assertIn(tag, detail)
            self.assertIn(export_static.ARCHIVE_FOOTER_LEFT, detail)
            self.assertNotIn(export_static.SNAPSHOT_FOOTER_LEFT, detail)
            # Every archive record renders its mint evidence from the
            # signed record's provenance timeline. The relic records
            # phrase it "Minted on ..."; the Zora records carry their
            # counts (or, for Mysteria Luna, the honest zero) in the
            # minted entry itself, so assert the entry, not one prose
            # style.
            self.assertIn('<span class="ev">minted</span>', detail)
        # Demo surfaces stay fixture-only: no archive tag leaks into the
        # preview browse lists or the records table.
        self.assertNotIn("tag_archive_", self._read("search/index.html"))
        self.assertNotIn("tag_archive_", self._read("records/index.html"))


if __name__ == "__main__":
    unittest.main()
