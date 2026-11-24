"""Render real dashboard pages to HTML files for the Node/jsdom
page tests (wallet_claim_page.test.js, chat_widget.test.js).

Usage: python3 render_fixtures.py <out_dir>

Writes home.html (a plain page carrying the chat widget),
verify.html (the Verify yours page), unknown.html (the live
Search lookup page for an API-issued ID), and record.html (the
server-rendered Search result for a freshly registered record,
fetched through the booted dashboard exactly as a browser gets
it). The record page needs the test stack, so this boots
DashTestCase once and tears it down.
"""
import http.client
import json as _json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.dirname(BASE))
sys.path.insert(0, os.path.join(BASE, "tests"))

from dashboard import views  # noqa: E402


def main(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    api = "https://api.example"

    def write(name, html):
        with open(os.path.join(out_dir, name), "w",
                  encoding="utf-8") as fh:
            fh.write(html)

    write("home.html", views.page("Home", views.home_view(), api))
    write("verify.html",
          views.page("Verify yours", views.verify_view(api), api))
    write("unknown.html", views.page(
        "Search", views.search_unknown_view("reg_fixture", api), api))

    from tests.helpers import DashTestCase
    DashTestCase.setUpClass()
    try:
        conn = http.client.HTTPConnection(
            "127.0.0.1", DashTestCase.api_port, timeout=10)
        conn.request("POST", "/v1/register/content",
                     body=_json.dumps({
                         "title": "Fixture claim record",
                         "kind": "text",
                         "locator": "sha256:" + "ab" * 32,
                         "creator_name": "Fixture Maker",
                         "creator_email": "claim@example.com"}).encode(),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        reg = _json.loads(resp.read())
        conn.close()
        assert resp.status == 201, resp.status
        case = DashTestCase("run")
        status, body = case.get("/search?id=" + reg["record_id"])
        assert status == 200, status
        write("record.html", body)
        with open(os.path.join(out_dir, "record_id.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write(reg["record_id"])
    finally:
        DashTestCase.tearDownClass()


if __name__ == "__main__":
    main(sys.argv[1])
