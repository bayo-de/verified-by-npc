#!/usr/bin/env python3
"""Smoke test for the Verified by NPC dashboard.

Boots the real API v1 server and the dashboard on ephemeral localhost
ports (127.0.0.1 only), seeds the fictional fixtures, and verifies that
every page renders with real, signature-verified data.

Usage:
    python3 smoke_test.py        (run from the dashboard/ directory)
"""
import http.client
import os
import sys
import tempfile
import threading
import urllib.parse
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))  # the `dashboard` package itself
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "api")))

from npc_verify.server import create_app, Handler as ApiHandler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from dashboard.server import make_handler  # noqa: E402

FAILURES = []


def check(name, cond, detail=""):
    print("%s - %s" % ("PASS" if cond else "FAIL", name))
    if not cond:
        FAILURES.append(name + (" (%s)" % detail if detail else ""))


def get(port, path, method="GET", fields=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = None
    headers = {}
    if fields is not None:
        body = urllib.parse.urlencode(fields).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8")
    status = resp.status
    conn.close()
    return status, data


def main():
    tmp = tempfile.mkdtemp(prefix="dash_smoke_")
    api_app = create_app(os.path.join(tmp, "t.db"),
                         os.path.join(tmp, "keys"))
    seeded = seed_all(api_app.store, api_app.keys)

    ApiHandler.app = api_app
    api_server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
    threading.Thread(target=api_server.serve_forever, daemon=True).start()
    api_port = api_server.server_address[1]

    dash_handler = make_handler("http://127.0.0.1:%d" % api_port,
                                seeded["verifier_key"])
    dash_server = ThreadingHTTPServer(("127.0.0.1", 0), dash_handler)
    threading.Thread(target=dash_server.serve_forever, daemon=True).start()
    dash_port = dash_server.server_address[1]
    dash_url = "http://127.0.0.1:%d" % dash_port
    print("dashboard: %s" % dash_url)
    print("api:       http://127.0.0.1:%d" % api_port)
    print()

    check("dashboard binds loopback only",
          dash_server.server_address[0] == "127.0.0.1",
          str(dash_server.server_address))
    check("api binds loopback only",
          api_server.server_address[0] == "127.0.0.1")

    s, b = get(dash_port, "/")
    check("home renders (200)", s == 200)
    check("home has the why", "Know what is real before you act on it." in b)
    check("home links plugins page", 'href="/plugins"' in b)

    s, b = get(dash_port, "/records")
    check("records renders (200)", s == 200)
    check("records shows claim attestations",
          "The test widget passes drop testing" in b
          and "Test Farms honey is single-origin" in b)
    check("records shows agent attestations",
          "agent_test_scout" in b and "agent_test_herald" in b)
    check("records shows sanitized findings",
          "Mechanical drop test, 1.2m, 50 cycles." in b)

    s, b = get(dash_port, "/records", method="POST",
               fields={"claim_text": "The test widget passes drop testing"})
    check("claim check matches (200)", s == 200 and "Matched a record" in b)

    s, b = get(dash_port, "/credentials?id=cred_test_001")
    check("credential detail (200)", s == 200)
    check("credential shows fixture data",
          "Test Artisan Certificate" in b and "Valid" in b)

    s, b = get(dash_port, "/credentials?id=cred_test_003")
    check("expired credential renders", s == 200 and "Expired" in b)

    s, b = get(dash_port, "/products?tag=tag_test_authentic")
    check("product lookup (200)", s == 200)
    check("product shows authentic + provenance",
          "Authentic" in b and "manufactured" in b)

    s, b = get(dash_port, "/keys")
    check("keys page (200)", s == 200)
    check("keys page publishes signing key", "npc-api_signing" in b)

    s, b = get(dash_port, "/plugins")
    check("plugins page (200)", s == 200 and "MCP" in b)

    s, b = get(dash_port, "/credentials?id=cred_nope")
    check("unknown credential fail-closed",
          s == 200 and "Unknown" in b
          and "Test Artisan Certificate" not in b)

    s, b = get(dash_port, "/nope")
    check("404 page", s == 404)

    # every rendered byte above came from signature-verified API responses:
    # the dashboard client refuses to render unverified data (see tests/).
    print()
    if FAILURES:
        print("SMOKE FAILED: %d check(s)" % len(FAILURES))
        for f in FAILURES:
            print("  -", f)
        api_server.shutdown()
        dash_server.shutdown()
        sys.exit(1)
    print("SMOKE OK: all checks passed against %s" % dash_url)
    api_server.shutdown()
    dash_server.shutdown()


if __name__ == "__main__":
    main()
