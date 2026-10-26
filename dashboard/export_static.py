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
- the footer "Reading from http://127.0.0.1:PORT" becomes an
  "Updated <build date>" label (no loopback URLs in the artifact);
- the footer "Internal preview. Local only." becomes "Signed
  records, open to anyone to check." (Changed 2026-10-16: the site
  carries real registrations alongside the labeled fixture samples,
  so a blanket "every record shown is a sample" label would sit
  untrue under a real customer's record. Sample records are
  labeled on the record and its page, where the label belongs.)
- every footer carries a Privacy link to /privacy (added 2026-10-13
  with the privacy page itself; the link is the only change to the
  pre-existing pages' bytes);
- the privacy page footer names the page for what it is ("NPC Verify
  privacy policy.") instead of the fixture label, and its policy date
  is the build date;
- Search is the one lookup surface. The baked detail pages for every
  credential, product, archive, and public key ID in the build live
  under /search/<id>/, and the generated dist/_redirects file rewrites
  /search?id=<known ID> to its baked page. Any other ID rewrites to
  /search/unknown/ with status 200, so an unmatched lookup lands on the
  honest Unknown answer instead of a raw 404. Every rule is forced
  (200!) and emitted for both the /search and /search/ path forms:
  Netlify shadows an unforced rule when a static file exists at the
  from-path (search/index.html sits at /search), and its slash
  normalization moves /search to /search/, so an unforced, unslashed
  rule never fires on the live host (defect found 2026-10-14);
- the Verify yours page (/verify) and the live Search lookup carry
  the dashboard's configured API base in data-api-base attributes.
  Locally that is the loopback API; in the export it is rewritten to
  the public API base (views.PUBLIC_API_BASE), because the forms and
  the lookup run in the visitor's browser against the live API.
  Search's primary resolution for API-issued IDs is that live lookup
  (GET /v1/records/{id}); the baked pages and the _redirects rules
  cover the fixture IDs only.
- every page carries the Biblo chat widget (floating button plus
  panel; /help also carries the inline Ask Biblo section) unless
  the build passes include_chat=False (the --no-chat flag), which
  is how the public restage of 2026-10-16 ships: chat activates
  only after Bayo places the API key and the grounding eval
  passes, so that build has no chat affordance and ships no chat
  button art. The widget's data-api-base is rewritten like the
  other browser surfaces. Its button art ships as static files
  under /assets/ (copied from dashboard/assets/), and the CSP
  gained img-src 'self' in both places it lives (this file's
  SECURITY_HEADERS and netlify.toml) so the button image may load;
  the chat itself talks to the API origin connect-src already
  allows.

Usage:
    python3 dashboard/export_static.py [--no-chat] [out_dir]
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
from dashboard import fixtures, views  # noqa: E402

SNAPSHOT_FOOTER_RIGHT = "Updated %s"
SNAPSHOT_FOOTER_LEFT = "Signed records, open to anyone to check."
ARCHIVE_FOOTER_LEFT = "Public archive. Real on-chain records."
LOCAL_FOOTER_LEFT = "Internal preview. Local only."
PRIVACY_FOOTER_LEFT = "NPC Verify privacy policy."
PRIVACY_FOOTER_RIGHT = "Updated %s"
_PRIVACY_LINK = ' <a href="/privacy">Privacy</a>'
# Security headers for every page of the static export. Mirrors the
# [[headers]] block in netlify.toml; the _headers file generated from
# this list is the copy that applies to Drop-bundle deploys.
SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy",
     "default-src 'none'; style-src 'unsafe-inline'; "
     "script-src 'unsafe-inline'; img-src 'self'; "
     "connect-src https://api.npclabs.xyz; "
     "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
]

# Static assets shipped with the export (the Biblo chat button art).
# Copied from dashboard/assets/ into dist/assets/ at build time.
# Skipped when the build passes include_chat=False: no chat
# affordance ships, so its button art does not ship either.
ASSET_FILES = [
    "assets/biblo-chat-icon-56.png",
    "assets/biblo-chat-icon-112.png",
    "assets/biblo-chat-icon.webp",
]

LOCAL_FOOTER_SPAN = "<span>%s%s</span>" % (LOCAL_FOOTER_LEFT, _PRIVACY_LINK)
SNAPSHOT_FOOTER_SPAN = "<span>%s%s</span>" % (SNAPSHOT_FOOTER_LEFT,
                                             _PRIVACY_LINK)
ARCHIVE_FOOTER_SPAN = "<span>%s%s</span>" % (ARCHIVE_FOOTER_LEFT,
                                            _PRIVACY_LINK)
def _get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request("GET", path)
    resp = conn.getresponse()
    status, data = resp.status, resp.read().decode("utf-8")
    conn.close()
    return status, data


def _search_key_ids(port):
    """Read the public key IDs from the rendered Search key list."""
    status, html = _get(port, "/search/keys")
    if status != 200:
        raise RuntimeError("GET /search/keys returned %s" % status)
    return list(dict.fromkeys(re.findall(
        r"<strong>(npc-[A-Za-z0-9_-]+)</strong>", html)))


def _publicize(html, api_url, build_date):
    """Apply the documented public-site deltas to one rendered page."""
    html = html.replace(LOCAL_FOOTER_SPAN, SNAPSHOT_FOOTER_SPAN)
    html = re.sub(
        r"Reading from http://127\.0\.0\.1:\d+",
        SNAPSHOT_FOOTER_RIGHT % build_date, html)
    # The browser-side surfaces (Verify yours forms, live Search
    # lookup) are configured with the dashboard's API URL; on the
    # public host that base is the public API, never the loopback one.
    html = html.replace(api_url, views.PUBLIC_API_BASE)
    return html


def _publicize_archive(html, api_url, build_date):
    """Publicize an archive page: real records, so the fixture footer and
    the snapshot label would be untrue. The footer names the set for what
    it is, and the right-hand label says the records are on-chain mints."""
    html = _publicize(html, api_url, build_date)
    html = html.replace(SNAPSHOT_FOOTER_SPAN, ARCHIVE_FOOTER_SPAN)
    html = html.replace(
        SNAPSHOT_FOOTER_RIGHT % build_date,
        "On-chain records. Updated %s" % build_date)
    return html


def _publicize_privacy(html, api_url, build_date):
    """Publicize the privacy page: it is the NPC Verify policy, not a
    fixture preview, so its footer names it for what it is, and the
    policy's "Last updated" date is the build date."""
    html = _publicize(html, api_url, build_date)
    html = html.replace(
        SNAPSHOT_FOOTER_SPAN, "<span>%s</span>" % PRIVACY_FOOTER_LEFT)
    html = html.replace(
        SNAPSHOT_FOOTER_RIGHT % build_date,
        PRIVACY_FOOTER_RIGHT % build_date)
    html = re.sub(r"Last updated: \d{4}-\d{2}-\d{2}",
                  "Last updated: %s" % build_date, html)
    return html


def build(out_dir, build_date=None, case=None, include_chat=True):
    """Render the static export into out_dir. Returns the written rel paths.

    case: an already-booted DashTestCase (servers stay up; the caller owns
    teardown). When None, servers are booted and torn down here.

    include_chat: when False, the export carries no Biblo chat
    affordance (views.CHAT_WIDGET_ENABLED is off for the duration
    of the build and restored afterwards) and the chat button art
    is not copied. The 2026-10-16 public restage builds this way.
    """
    build_date = build_date or datetime.date.today().isoformat()
    owned = case is None
    if owned:
        DashTestCase.setUpClass()
        case = DashTestCase
    prev_chat = views.CHAT_WIDGET_ENABLED
    views.CHAT_WIDGET_ENABLED = bool(include_chat)
    try:
        api_url = case.api_url
        port = case.dash_port
        pages = [
            ("/", "index.html"),
            ("/records", "records/index.html"),
            ("/search", "search/index.html"),
            ("/search/keys", "search/keys/index.html"),
            ("/search/unknown", "search/unknown/index.html"),
            ("/plugins", "plugins/index.html"),
            ("/api", "api/index.html"),
            ("/privacy", "privacy/index.html"),
            ("/help", "help/index.html"),
            ("/verify", "verify/index.html"),
        ]
        for cred_id in fixtures.PREVIEW_CREDENTIALS:
            q = "/search?id=" + urllib.parse.quote(cred_id, safe="")
            pages.append((q, "search/%s/index.html" % cred_id))
        for tag in fixtures.PREVIEW_PRODUCTS:
            q = "/search?id=" + urllib.parse.quote(tag, safe="")
            pages.append((q, "search/%s/index.html" % tag))
        # Archive set: real historical mints, publicized with the archive
        # footer so no page carrying a real record claims to be fixtures.
        archive_pages = [("/archive", "archive/index.html")]
        for tag in fixtures.ARCHIVE_PRODUCTS:
            q = "/search?id=" + urllib.parse.quote(tag, safe="")
            archive_pages.append((q, "search/%s/index.html" % tag))

        written = []
        for route, rel in pages:
            status, html = _get(port, route)
            if status != 200:
                raise RuntimeError("GET %s returned %s" % (route, status))
            if route == "/privacy":
                html = _publicize_privacy(html, api_url, build_date)
            else:
                html = _publicize(html, api_url, build_date)
            dest = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as f:
                f.write(html)
            written.append(rel)
        for route, rel in archive_pages:
            status, html = _get(port, route)
            if status != 200:
                raise RuntimeError("GET %s returned %s" % (route, status))
            html = _publicize_archive(html, api_url, build_date)
            dest = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as f:
                f.write(html)
            written.append(rel)

        key_ids = _search_key_ids(port)
        redirect_rules = []
        known_ids = (fixtures.PREVIEW_CREDENTIALS
                     + fixtures.PREVIEW_PRODUCTS
                     + fixtures.ARCHIVE_PRODUCTS + key_ids)
        for subject_id in known_ids:
            # Every rule is FORCED (200!) and emitted for both path
            # forms: Netlify shadows an unforced rule when a static
            # file exists at the from-path (search/index.html sits at
            # /search), and its slash normalization moves /search to
            # /search/, so an unforced /search-only rule never fires.
            redirect_rules.append("/search id=%s /search/%s/ 200!" % (
                subject_id, subject_id))
            redirect_rules.append("/search/ id=%s /search/%s/ 200!" % (
                subject_id, subject_id))
            if subject_id in key_ids:
                route = "/search?id=" + urllib.parse.quote(
                    subject_id, safe="")
                status, html = _get(port, route)
                if status != 200:
                    raise RuntimeError("GET %s returned %s" % (route, status))
                html = _publicize(html, api_url, build_date)
                rel = "search/%s/index.html" % subject_id
                dest = os.path.join(out_dir, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "w", encoding="utf-8") as f:
                    f.write(html)
                written.append(rel)
        redirect_rules.append("/search id=:id /search/unknown/ 200!")
        redirect_rules.append("/search/ id=:id /search/unknown/ 200!")
        redirects_dest = os.path.join(out_dir, "_redirects")
        with open(redirects_dest, "w", encoding="utf-8") as f:
            f.write("# Generated by dashboard/export_static.py. Exact Search "
                    "IDs land on their baked pages; every other ID lands "
                    "on the Unknown answer. Rules are forced (200!) "
                    "because Netlify shadows unforced rules when a static "
                    "file exists at the from-path, and both the /search "
                    "and /search/ path forms are listed because Netlify "
                    "normalizes the unslashed path to the slashed one.\n")
            f.write("\n".join(redirect_rules) + "\n")
        written.append("_redirects")

        headers_dest = os.path.join(out_dir, "_headers")
        with open(headers_dest, "w", encoding="utf-8") as f:
            f.write("# Generated by dashboard/export_static.py. The live "
                    "site is deployed from this bundle (Netlify Drop), "
                    "where netlify.toml [[headers]] rules do not apply; "
                    "this file is what actually carries the security "
                    "headers. Keep the values in step with netlify.toml.\n")
            f.write("/*\n")
            for name, value in SECURITY_HEADERS:
                f.write("  %s: %s\n" % (name, value))
        written.append("_headers")

        import shutil
        for rel in (ASSET_FILES if include_chat else []):
            src = os.path.join(BASE, rel)
            dest = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(src, dest)
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
        views.CHAT_WIDGET_ENABLED = prev_chat
        if owned:
            DashTestCase.tearDownClass()


def main(argv):
    include_chat = "--no-chat" not in argv
    positional = [a for a in argv[1:] if not a.startswith("--")]
    out_dir = (os.path.abspath(positional[0]) if positional
               else os.path.join(BASE, "dist"))
    written = build(out_dir, include_chat=include_chat)
    print("wrote %d pages to %s" % (len(written), out_dir))
    for rel in written:
        print("  " + rel)


if __name__ == "__main__":
    main(sys.argv)
