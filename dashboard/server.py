"""HTTP server for the Verified by NPC dashboard.

Standard library only (http.server). Binds 127.0.0.1 only; run() refuses
any non-loopback host. The dashboard is a thin, read-first client over the
NPC Verification API v1: every API response is signature-verified before
it is rendered, and anything unverifiable renders "unknown" or
"unavailable". No data is ever invented.

Routes:
  GET  /                  home: the why, links to plugin pages
  GET  /records           verification records (attestations)
  POST /records           check a claim against attested records
  GET  /credentials[?id=] credential lookup + detail
  GET  /products[?tag=]   product authenticity lookup + detail
  GET  /keys              published public keys
  GET  /plugins           the plugin surfaces and their gates
"""
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import views
from .client import ApiError, UnknownSubject, VerifiedClient
from . import fixtures

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
MAX_FORM = 64 * 1024  # 64 KiB


def _records_rows(client):
    """Build attestation rows from live, signature-verified API responses.

    Each row comes from a real API response; failures degrade to
    unknown/unavailable rows, never invented data.
    """
    rows = []
    for text in fixtures.PREVIEW_CLAIMS:
        try:
            res = client.verify_claim(claim_text=text)
            a = res["attestation"]
            rows.append({
                "label": text,
                "subject_id": a["id"],
                "verdict": a["verdict"],
                "scope": a.get("scope"),
                "tested_at": a.get("tested_at"),
                "findings": a.get("findings_summary"),
            })
        except UnknownSubject:
            rows.append({"label": text, "subject_id": "not on record",
                         "verdict": "unknown", "scope": None,
                         "tested_at": "not on record",
                         "findings": "No attested record for this claim."})
        except ApiError:
            rows.append({"label": text, "subject_id": "could not confirm",
                         "verdict": "unknown", "scope": None,
                         "tested_at": "could not confirm",
                         "findings": "The record could not be confirmed."})
    for agent_id in fixtures.PREVIEW_AGENTS:
        try:
            r = client.get_agent_attestation(agent_id)
            anchor = r.get("onchain_anchor") or {}
            findings = r.get("notes") or ""
            if anchor.get("status") == "not_anchored":
                findings = (findings + " Anchor recorded locally; "
                            "no chain write yet.").strip()
            rows.append({
                "label": "agent " + agent_id,
                "subject_id": r.get("attestation_id"),
                "verdict": r.get("verdict"),
                "scope": r.get("scope"),
                "tested_at": r.get("valid_from"),
                "findings": findings,
            })
        except UnknownSubject:
            rows.append({"label": "agent " + agent_id,
                         "subject_id": "not on record",
                         "verdict": "unknown", "scope": None,
                         "tested_at": "not on record",
                         "findings": "No attested record for this agent."})
        except ApiError:
            rows.append({"label": "agent " + agent_id,
                         "subject_id": "could not confirm",
                         "verdict": "unknown", "scope": None,
                         "tested_at": "could not confirm",
                         "findings": "The record could not be confirmed."})
    return rows


class _Req:
    def __init__(self, method, path, query, form):
        self.method = method
        self.path = path
        self.query = query  # dict of first values
        self.form = form    # dict of first values (POST forms)


class _App:
    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.client = VerifiedClient(base_url=api_url, api_key=api_key)
        self.routes = []
        self._register()

    # -- routing ------------------------------------------------------
    def route(self, method, pattern):
        def deco(fn):
            self.routes.append((method, re.compile(pattern), fn))
            return fn
        return deco

    def _register(self):
        app = self

        @app.route("GET", r"^/$")
        def home(req):
            return views.home_view()

        @app.route("GET", r"^/plugins$")
        def plugins(req):
            return views.plugins_view()

        @app.route("GET", r"^/records$")
        def records(req):
            rows = _records_rows(app.client)
            return views.records_view(rows)

        @app.route("POST", r"^/records$")
        def records_check(req):
            rows = _records_rows(app.client)
            text = (req.form.get("claim_text") or "").strip()
            if not text:
                return views.records_view(rows, claim_error="unknown")
            try:
                res = app.client.verify_claim(claim_text=text)
                res = dict(res)
                res["claim_text"] = text
                return views.records_view(rows, claim_result=res)
            except UnknownSubject:
                return views.records_view(rows, claim_error="unknown")
            except ApiError:
                return views.records_view(rows, claim_error="unavailable")

        @app.route("GET", r"^/credentials$")
        def credentials(req):
            cred_id = (req.query.get("id") or "").strip()
            if not cred_id:
                return views.credentials_view(
                    examples=fixtures.PREVIEW_CREDENTIALS)
            try:
                cred = app.client.get_credential(cred_id)
                return views.credentials_view(
                    cred, state="ok",
                    examples=fixtures.PREVIEW_CREDENTIALS)
            except UnknownSubject:
                return views.credentials_view(
                    {"id": cred_id}, state="unknown",
                    examples=fixtures.PREVIEW_CREDENTIALS)
            except ApiError:
                return views.credentials_view(
                    {"id": cred_id}, state="unavailable",
                    examples=fixtures.PREVIEW_CREDENTIALS)

        @app.route("GET", r"^/products$")
        def products(req):
            tag = (req.query.get("tag") or "").strip()
            if not tag:
                return views.products_view(
                    examples=fixtures.PREVIEW_PRODUCTS)
            try:
                product = app.client.get_product(tag)
                return views.products_view(
                    product, state="ok",
                    examples=fixtures.PREVIEW_PRODUCTS)
            except UnknownSubject:
                return views.products_view(
                    {"tag_id": tag}, state="unknown",
                    examples=fixtures.PREVIEW_PRODUCTS)
            except ApiError:
                return views.products_view(
                    {"tag_id": tag}, state="unavailable",
                    examples=fixtures.PREVIEW_PRODUCTS)

        @app.route("GET", r"^/keys$")
        def keys(req):
            try:
                doc = app.client.keys()
            except ApiError:
                return views.unavailable_notice()
            return views.keys_view(doc)

    # -- dispatch -------------------------------------------------------
    def dispatch(self, req):
        for route_method, pattern, fn in self.routes:
            if route_method != req.method:
                continue
            if pattern.match(req.path):
                try:
                    body_html = fn(req)
                except Exception:
                    body_html = views.unavailable_notice(
                        "Something went wrong rendering this page.")
                return 200, views.page(_title_for(req.path), body_html,
                                       self.api_url)
        return 404, views.page("Not found", views.not_found_view(),
                               self.api_url)


def _title_for(path):
    return {
        "/": "Home",
        "/records": "Records",
        "/credentials": "Credentials",
        "/products": "Products",
        "/keys": "Keys",
        "/plugins": "Plugins",
    }.get(path, "Not found")


def make_handler(api_url, api_key):
    """Build a request-handler class bound to one API target."""
    app = _App(api_url, api_key)

    class Handler(BaseHTTPRequestHandler):
        def _handle(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw_body = self.rfile.read(length) if length else b""
            form = {}
            if self.command == "POST" and raw_body:
                if len(raw_body) > MAX_FORM:
                    self.send_response(413)
                    self.end_headers()
                    return
                ctype = self.headers.get("Content-Type", "")
                if "application/x-www-form-urlencoded" in ctype:
                    form = {k: v[0] for k, v in urllib.parse.parse_qs(
                        raw_body.decode("utf-8", "replace")).items()}
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path or "/"
            query = {k: v[0] for k, v in
                     urllib.parse.parse_qs(parsed.query).items()}
            req = _Req(self.command, path, query, form)
            code, html = app.dispatch(req)
            payload = html.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _handle
        do_POST = _handle

        def log_message(self, fmt, *args):  # quiet by default
            pass

    return Handler


def run(api_url, api_key, host="127.0.0.1", port=8790):
    """Start the dashboard. Binds loopback only; refuses anything else."""
    if host not in LOOPBACK_HOSTS:
        raise ValueError("refusing to bind non-loopback host %r; "
                         "the dashboard is local-only" % (host,))
    handler = make_handler(api_url, api_key)
    server = ThreadingHTTPServer((host, port), handler)
    return server
