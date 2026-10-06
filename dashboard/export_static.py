"""Build the Netlify static export of the Verified by NPC dashboard.

Boots the seeded API v1 and the dashboard on ephemeral loopback ports and
fetches every public route through the full stack, so every rendered row is
backed by a live, signature-verified API response, exactly as the local
app renders it.

server.py's loopback-only bind is never touched: both servers bind
127.0.0.1 on ephemeral ports, exactly as tests/helpers.py does. The public
artifact is plain HTML; nothing listens on a public port, no API is
reachable from it, and no secrets are baked in.

Public-site deltas (documented, minimal, covered by test_static_export):
- the footer "Reading from http://127.0.0.1:PORT" becomes a static
  snapshot label (no loopback URLs in the artifact);
- the footer "Internal preview. Local only." becomes "Internal preview.
  Test fixtures only." so it reads true on a public host;
- the records page claim form gets a one-line note: live claim checking
  runs against the verification API, and the static preview shows the
  fixture records (POST has no backend on a static host).

Lookup URLs keep their local shape: the baked detail pages for fixture
IDs are served through Netlify query redirects (see ../../netlify.toml),
so /credentials?id=cred_test_001 and /products?tag=tag_test_authentic
keep working. Anything else falls through to the dashboard 404.

Usage:
    python3 dashboard/export_static.py [out_dir]
Default out dir: dashboard/dist/
"""
import datetime
import http.client
import os
import re
import sys
import urllib.parse

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)                       # dashboard package contents
sys.path.insert(0, os.path.dirname(BASE))      # the `dashboard` package itself
sys.path.insert(0, os.path.normpath(os.path.join(BASE, "tests")))

from tests.helpers import DashTestCase  # noqa: E402
from dashboard import fixtures  # noqa: E402

SNAPSHOT_FOOTER_RIGHT = "Static snapshot of local test fixtures, built %s"
SNAPSHOT_FOOTER_LEFT = "Internal preview. Test fixtures only."
LOCAL_FOOTER_LEFT = "Internal preview. Local only."
RECORDS_NOTE = ("<p class=\"examples\">Live claim checking runs against the "
                "verification API. This static preview shows the fixture "
                "records above.</p>")
RECORDS_ANCHOR = "<p class=\"examples\">Records shown are internal test fixtures.</p>"


def _get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request("GET", path)
    resp = conn.getresponse()
    status, data = resp.status, resp.read().decode("utf-8")
    conn.close()
    return status, data


def _publicize(html, api_url, build_date):
    """Apply the documented public-site deltas to one rendered page."""
    html = html.replace(
        "<span>%s</span>" % LOCAL_FOOTER_LEFT,
        "<span>%s</span>" % SNAPSHOT_FOOTER_LEFT)
    html = re.sub(
        r"Reading from http://127\.0\.0\.1:\d+",
        SNAPSHOT_FOOTER_RIGHT % build_date, html)
    html = html.replace(RECORDS_ANCHOR, RECORDS_NOTE + RECORDS_ANCHOR)
    return html


def build(out_dir, build_date=None, case=None):
    """Render the static export into out_dir. Returns the written rel paths.

    case: an already-booted DashTestCase (servers stay up; the caller owns
    teardown). When None, servers are booted and torn down here.
    """
    build_date = build_date or datetime.date.today().isoformat()
    owned = case is None
    if owned:
        DashTestCase.setUpClass()
        case = DashTestCase
    try:
        api_url = case.api_url
        port = case.dash_port
        pages = [
            ("/", "index.html"),
            ("/records", "records/index.html"),
            ("/credentials", "credentials/index.html"),
            ("/products", "products/index.html"),
            ("/keys", "keys/index.html"),
            ("/plugins", "plugins/index.html"),
        ]
        for cred_id in fixtures.PREVIEW_CREDENTIALS:
            q = "/credentials?id=" + urllib.parse.quote(cred_id, safe="")
            pages.append((q, "credentials/%s/index.html" % cred_id))
        for tag in fixtures.PREVIEW_PRODUCTS:
            q = "/products?tag=" + urllib.parse.quote(tag, safe="")
            pages.append((q, "products/%s/index.html" % tag))

        written = []
        for route, rel in pages:
            status, html = _get(port, route)
            if status != 200:
                raise RuntimeError("GET %s returned %s" % (route, status))
            html = _publicize(html, api_url, build_date)
            dest = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as f:
                f.write(html)
            written.append(rel)

        status, html = _get(port, "/__definitely_missing__")
        if status != 404:
            raise RuntimeError("expected 404 for missing route, got %s"
                               % status)
        html = _publicize(html, api_url, build_date)
        dest = os.path.join(out_dir, "404.html")
        with open(dest, "w", encoding="utf-8") as f:
            f.write(html)
        written.append("404.html")
        return written
    finally:
        if owned:
            DashTestCase.tearDownClass()


def main(argv):
    out_dir = (os.path.abspath(argv[1]) if len(argv) > 1
               else os.path.join(BASE, "dist"))
    written = build(out_dir)
    print("wrote %d pages to %s" % (len(written), out_dir))
    for rel in written:
        print("  " + rel)


if __name__ == "__main__":
    main(sys.argv)
