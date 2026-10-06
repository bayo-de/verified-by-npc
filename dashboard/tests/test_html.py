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
    "/credentials",
    "/credentials?id=cred_test_001",
    "/credentials?id=cred_test_002",
    "/products",
    "/products?tag=tag_test_authentic",
    "/products?tag=tag_test_counterfeit",
    "/keys",
    "/plugins",
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
        # every nav page was reachable through the crawl
        for page in ("/", "/records", "/credentials", "/products", "/keys",
                     "/plugins"):
            self.assertIn(page, seen)

    def test_no_placeholder_text(self):
        for path in PAGES:
            status, body = self.get(path)
            self.assertEqual(status, 200)
            # check visible text only: strip tags so HTML attributes like
            # placeholder="..." do not count as placeholder copy
            text = re.sub(r"<[^>]+>", " ", body).lower()
            for marker in ("lorem ipsum", "todo", "fixme", "coming soon"):
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
            for link in ("/records", "/credentials", "/products", "/keys",
                         "/plugins"):
                self.assertIn('href="%s"' % link, body, path)
            self.assertIn("Internal preview. Local only.", body, path)

    def test_no_badge_artwork(self):
        # The public mark is counsel-gated: no checkmark/badge glyphs ship.
        for path in PAGES:
            status, body = self.get(path)
            self.assertEqual(status, 200)
            for glyph in ("\u2713", "\u2714", "\u2611", "\u2705"):
                self.assertNotIn(glyph, body,
                                 "badge glyph found on %s" % path)
