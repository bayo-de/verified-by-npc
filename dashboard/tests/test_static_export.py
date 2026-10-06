"""Tests for the Netlify static export (dashboard/export_static.py).

- The artifact renders the same content as the local app (modulo the
  documented public-site footer deltas).
- Fixture lookup URLs have baked detail pages matching the local app.
- The artifact contains zero secrets: no API keys, no private key
  material, no loopback URLs, no local filesystem paths.
- netlify.toml carries the query redirects the lookup URLs depend on.
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
    "credentials/index.html",
    "products/index.html",
    "keys/index.html",
    "plugins/index.html",
    "404.html",
] + ["credentials/%s/index.html" % c for c in fixtures.PREVIEW_CREDENTIALS] \
  + ["products/%s/index.html" % t for t in fixtures.PREVIEW_PRODUCTS]

LOCAL_ROUTES = {
    "index.html": "/",
    "records/index.html": "/records",
    "credentials/index.html": "/credentials",
    "products/index.html": "/products",
    "keys/index.html": "/keys",
    "plugins/index.html": "/plugins",
    "404.html": "/__definitely_missing__",
}
for c in fixtures.PREVIEW_CREDENTIALS:
    LOCAL_ROUTES["credentials/%s/index.html" % c] = (
        "/credentials?id=" + urllib.parse.quote(c, safe=""))
for t in fixtures.PREVIEW_PRODUCTS:
    LOCAL_ROUTES["products/%s/index.html" % t] = (
        "/products?tag=" + urllib.parse.quote(t, safe=""))

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
        self.assertEqual(sorted(self.written), sorted(EXPECTED_PAGES))

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
            want = export_static._publicize(local, DashTestCase.api_url,
                                            BUILD_DATE)
            self.assertEqual(self._read(rel), want,
                             "dist page differs from local app: %s" % rel)

    def test_public_deltas_applied(self):
        home = self._read("index.html")
        self.assertIn(export_static.SNAPSHOT_FOOTER_LEFT, home)
        self.assertIn(export_static.SNAPSHOT_FOOTER_RIGHT % BUILD_DATE, home)
        self.assertNotIn("Reading from http://127.0.0.1", home)
        records = self._read("records/index.html")
        self.assertIn("Live claim checking runs against the verification "
                      "API.", records)

    def test_fixture_content_rendered_not_emptied(self):
        # The export must carry real fixture content, not hollow shells.
        records = self._read("records/index.html")
        self.assertIn("The test widget passes drop testing", records)
        cred = self._read("credentials/cred_test_001/index.html")
        self.assertIn("cred_test_001", cred)
        prod = self._read("products/tag_test_authentic/index.html")
        self.assertIn("tag_test_authentic", prod)
        keys = self._read("keys/index.html")
        self.assertIn("npc-api_signing-", keys)

    # -- secrets ----------------------------------------------------------
    def test_zero_secrets_in_artifact(self):
        for rel in EXPECTED_PAGES:
            html = self._read(rel)
            for pat in FORBIDDEN:
                self.assertIsNone(re.search(pat, html, re.IGNORECASE),
                                  "forbidden pattern %r in %s" % (pat, rel))

    def test_keys_page_has_no_private_material(self):
        keys = self._read("keys/index.html")
        self.assertNotIn("private", keys.lower())

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
    def test_netlify_toml_redirects_cover_lookups(self):
        with open(os.path.join(os.path.dirname(BASE), "netlify.toml"),
                  encoding="utf-8") as f:
            toml = f.read()
        self.assertIn('query = {id = ":id"}', toml)
        self.assertIn('query = {tag = ":tag"}', toml)
        self.assertIn('to = "/credentials/:id/"', toml)
        self.assertIn('to = "/products/:tag/"', toml)
        self.assertIn('publish = "dashboard/dist"', toml)
        for c in fixtures.PREVIEW_CREDENTIALS:
            self.assertTrue(
                os.path.isfile(os.path.join(
                    self.tmp, "credentials", c, "index.html")), c)
        for t in fixtures.PREVIEW_PRODUCTS:
            self.assertTrue(
                os.path.isfile(os.path.join(
                    self.tmp, "products", t, "index.html")), t)


if __name__ == "__main__":
    unittest.main()
