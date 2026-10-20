"""HTTP server for the Verified by NPC dashboard.

Standard library only (http.server). Binds 127.0.0.1 only; run() refuses
any non-loopback host. The dashboard is a thin, read-first client over the
NPC Verification API v1: every API response is signature-verified before
it is rendered, and anything unverifiable renders "unknown" or
"unavailable". No data is ever invented.

Routes:
  GET  /                  home: the why and the four main surfaces
  GET  /records           verification records (attestations)
  GET  /search[?id=]      one lookup for credential, product, archive,
                          and public key IDs; API-issued registration
                          IDs resolve through GET /v1/records/{id}
  GET  /search/keys       the full public key list, inside Search
  GET  /search/unknown    the honest unknown answer for an unmatched ID
  GET  /verify            Verify yours: the content and agent
                          registration forms (they POST from the
                          visitor's browser to the verification API;
                          this server never proxies a submission)
  GET  /archive           archive of NPC Labs' real historical on-chain
                          mints (company history; reached from Records)
  GET  /plugins           the plugin surfaces and their honest status
  GET  /api               the developer API: endpoints, live examples,
                          and the published signing keys (static text)
  GET  /privacy           the NPC Verify privacy policy (static text)
  GET  /help              how it works + FAQ (static text)
"""
import datetime
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


def _archive_rows(client):
    """Build archive rows from live, signature-verified API responses.

    The archive set is fixtures.ARCHIVE_PRODUCTS (real historical mints,
    not test fixtures). Display facts (chain, standard, collection, token)
    come from fixtures.ARCHIVE_META; the item name, status, and mint date
    come from the verified API product record itself. A record the API
    cannot confirm degrades to an unknown row, never invented data.
    """
    rows = []
    for tag in fixtures.ARCHIVE_PRODUCTS:
        meta = fixtures.ARCHIVE_META[tag]
        row = {"tag_id": tag, "chain": meta["chain"],
               "standard": meta["standard"],
               "collection": meta["collection"],
               "token_id": meta["token_id"],
               "name": "could not confirm", "status": "unknown",
               "minted_at": "could not confirm"}
        try:
            product = client.get_product(tag)
            minted = None
            for ev in product.get("provenance") or []:
                if ev.get("event") == "minted":
                    minted = (ev.get("at") or "")[:10]
            row.update({
                "name": product.get("name") or row["name"],
                "status": product.get("status") or "unknown",
                "minted_at": minted or row["minted_at"],
            })
        except (UnknownSubject, ApiError):
            pass
        rows.append(row)
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

        def key_entries():
            try:
                doc = app.client.keys()
            except ApiError:
                return None, []
            return doc, views.key_entries(doc)

        def search_page(query="", result_html="", live_lookup_id=None):
            doc, _entries = key_entries()
            return views.search_view(
                query=query, result_html=result_html,
                credential_examples=fixtures.PREVIEW_CREDENTIALS,
                product_examples=fixtures.PREVIEW_PRODUCTS,
                keys_doc=doc, live_lookup_id=live_lookup_id,
                api_base=app.api_url)

        def search_result(query):
            try:
                cred = app.client.get_credential(query)
                return search_page(query, views.credential_result(cred))
            except UnknownSubject:
                pass
            except ApiError:
                return search_page(query, views.unavailable_notice())
            try:
                product = app.client.get_product(query)
                return search_page(query, views.product_result(product))
            except UnknownSubject:
                pass
            except ApiError:
                return search_page(query, views.unavailable_notice())
            doc, entries = key_entries()
            if doc is None:
                return search_page(query, views.unavailable_notice())
            for entry, label in entries:
                if entry.get("key_id") == query:
                    result = (
                        '<div class="notice"><h3>Public key found</h3>'
                        '<p>This key ID is published in Search. The full '
                        'public key is below and in the '
                        '<a href="/search/keys#%s">public key list</a>.'
                        '</p></div>%s' % (
                            views.esc(query),
                            views.key_card(entry, label)))
                    return views.search_view(
                        query=query, result_html=result,
                        credential_examples=fixtures.PREVIEW_CREDENTIALS,
                        product_examples=fixtures.PREVIEW_PRODUCTS,
                        keys_doc=doc, api_base=app.api_url)
            # API-issued IDs (registrations above all) resolve through
            # the one records endpoint, signature-verified like every
            # API answer this dashboard renders.
            try:
                rec = app.client.get_record(query)
                state = None
                if str(rec.get("record_type") or "").startswith(
                        "npc.registry."):
                    try:
                        state = app.client.get_verification_request(
                            query)
                    except (UnknownSubject, ApiError):
                        state = None
                rendered = views.record_result(
                    rec, verification_request=state,
                    api_base=app.api_url)
                if rendered and "npc-request-verification" in rendered:
                    rendered += ("<script>%s</script>"
                                 % views.REQUEST_VERIFY_JS)
                if rendered:
                    return views.search_view(
                        query=query, result_html=rendered,
                        credential_examples=fixtures.PREVIEW_CREDENTIALS,
                        product_examples=fixtures.PREVIEW_PRODUCTS,
                        keys_doc=doc, api_base=app.api_url)
            except UnknownSubject:
                pass
            except ApiError:
                return search_page(query, views.unavailable_notice())
            return search_page(
                query,
                views.unknown_notice("this ID",
                                     notice_id="npc-unknown-notice"),
                live_lookup_id=query)

        @app.route("GET", r"^/$")
        def home(req):
            return views.home_view()

        @app.route("GET", r"^/plugins$")
        def plugins(req):
            return views.plugins_view()

        @app.route("GET", r"^/api$")
        def api(req):
            return views.api_view()

        @app.route("GET", r"^/records$")
        def records(req):
            rows = _records_rows(app.client)
            return views.records_view(rows)

        @app.route("GET", r"^/search$")
        def search(req):
            if (req.query.get("view") or "").strip() == "keys":
                return search_keys(req)
            query = (req.query.get("id") or req.query.get("tag")
                     or req.query.get("key") or "").strip()
            if not query:
                return search_page()
            return search_result(query)

        @app.route("GET", r"^/search/keys$")
        def search_keys(req):
            query = (req.query.get("id") or "").strip()
            doc, _entries = key_entries()
            return views.search_keys_view(doc, query=query)

        @app.route("GET", r"^/search/unknown$")
        def search_unknown(req):
            query = (req.query.get("id") or "").strip()
            return views.search_unknown_view(query, api_base=app.api_url)

        @app.route("GET", r"^/verify$")
        def verify(req):
            return views.verify_view(api_base=app.api_url)

        @app.route("GET", r"^/archive$")
        def archive(req):
            return views.archive_view(_archive_rows(app.client))

        @app.route("GET", r"^/privacy$")
        def privacy(req):
            return views.privacy_view(
                datetime.date.today().isoformat())

        @app.route("GET", r"^/help$")
        def help_page(req):
            return views.help_view(api_base=app.api_url)

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
    if path.startswith("/search"):
        return "Search"
    return {
        "/": "Home",
        "/records": "Records",
        "/archive": "Archive",
        "/plugins": "Plugins",
        "/api": "API",
        "/privacy": "Privacy",
        "/help": "How it works",
        "/verify": "Verify yours",
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
