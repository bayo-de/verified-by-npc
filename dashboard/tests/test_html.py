"""HTML sanity: crawl every internal link; no broken links, no placeholders,
no em-dashes, no typos-by-construction markers."""
import re

try:
    from tests.helpers import DashTestCase
except ImportError:  # pragma: no cover - direct invocation
    from helpers import DashTestCase

HREF = re.compile(r'href="(/[^"]*)"')

PAGES = [
    "/",
    "/records",
    "/search",
    "/search?id=cred_test_001",
    "/search?id=cred_test_002",
    "/search?id=tag_test_authentic",
    "/search?id=tag_test_counterfeit",
    "/search?id=tag_archive_seeker_hat_1",
    "/search/keys",
    "/search/unknown",
    "/archive",
    "/plugins",
    "/api",
    "/privacy",
    "/help",
    "/verify",
]


class HtmlSanityTest(DashTestCase):
    def test_no_broken_internal_links(self):
        seen = set()
        queue = list(PAGES)
        while queue:
            path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            status, body = self.get(path)
            self.assertEqual(status, 200, "broken internal link: %s" % path)
            for href in HREF.findall(body):
                if href not in seen and href not in queue:
                    queue.append(href)
        # every main page was reachable through the crawl
        for page in ("/", "/records", "/search", "/search/keys",
                     "/search/unknown", "/archive", "/plugins", "/api",
                     "/help", "/verify"):
            self.assertIn(page, seen)

    def test_no_placeholder_text(self):
        for path in PAGES:
            status, body = self.get(path)
            self.assertEqual(status, 200)
            # check visible text only: strip tags so HTML attributes like
            # placeholder="..." do not count as placeholder copy
            text = re.sub(r"<[^>]+>", " ", body).lower()
            markers = ["lorem ipsum", "todo", "fixme"]
            # "coming soon" is a placeholder marker everywhere except
            # /help, where it is the directed status line for the NPC
            # Verify extension (Bayo, 2026-10-14), surrounded by real
            # content asserted in test_routes.test_help_page, and
            # /plugins, where it is the directed status line for the
            # Chrome extension (Bayo, 2026-10-15: "Coming soon", never
            # a hard date).
            if path not in ("/help", "/plugins"):
                markers.append("coming soon")
            for marker in markers:
                self.assertNotIn(marker, text,
                                 "%r found on %s" % (marker, path))

    def test_no_em_dashes(self):
        for path in PAGES:
            status, body = self.get(path)
            self.assertEqual(status, 200)
            self.assertNotIn("\u2014", body,
                             "em-dash found on %s" % path)
            self.assertNotIn("&mdash;", body,
                             "em-dash entity found on %s" % path)

    def test_every_page_has_nav_and_footer(self):
        for path in PAGES:
            status, body = self.get(path)
            self.assertEqual(status, 200)
            for link in ("/records", "/search", "/plugins", "/api",
                         "/verify", "/help"):
                self.assertIn('href="%s"' % link, body, path)
            nav = body.split("<nav>", 1)[1].split("</nav>", 1)[0]
            self.assertIn(
                '<a href="/records">Records</a><a href="/search">Search</a>'
                '<a href="/plugins">Plugins</a><a href="/api">API</a>'
                '<a href="/verify">Verify yours</a>'
                '<a href="/help">How it works</a>', nav, path)
            for old in ("/archive", "/credentials", "/products", "/keys"):
                self.assertNotIn('href="%s">' % old, nav, path)
            self.assertIn("Internal preview. Local only.", body, path)

    def test_no_badge_artwork(self):
        # The public mark is counsel-gated: no checkmark/badge glyphs ship.
        for path in PAGES:
            status, body = self.get(path)
            self.assertEqual(status, 200)
            for glyph in ("\u2713", "\u2714", "\u2611", "\u2705"):
                self.assertNotIn(glyph, body,
                                 "badge glyph found on %s" % path)
