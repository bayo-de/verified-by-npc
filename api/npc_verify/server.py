"""HTTP server for the NPC Verification API v1.

Standard library only (http.server). Every JSON response body is
canonicalized (NPC-JCS-v1) and Ed25519-signed; the signature travels in
X-NPC-Signature (base64) with X-NPC-Key-ID. GET /v1/keys publishes the
public keys so responses verify offline.

Endpoints:
  GET  /v1/health                        (no auth)
  GET  /v1/keys                          (no auth)
  GET  /v1/credentials/{id}              (verifier+)
  POST /v1/claims/verify                  (verifier+)
  GET  /v1/products/{tag_id}             (verifier+)
  GET  /v1/agents/{agent_id}/attestation  (verifier+)
  POST /v1/attestations                   (issuer only)

Fail-closed: unknown subjects -> 404 {"verdict": "unknown"}.
"""
import base64
import hashlib
import json
import re
import secrets
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import errors
from .auth import Auth, RateLimiter, hash_key
from .canonical import (canonicalize, claim_hash_for_text,
                        normalize_claim_text)
from .keys import KeyRegistry
from .models import Attestation, utcnow_iso
from .seed import ANCHOR_CHAIN
from .store import Store

# Trust-layer memory (DESIGN v1 section 5). The memory library owns record
# validation, chain checks, scoping, and verification status; the endpoints
# below are a thin authenticated transport over it.
from npc_memory.identity import key_id_for_public_key
from npc_memory.records import (public_dict as memory_public_dict,
                                record_hash as memory_record_hash,
                                signing_core as memory_signing_core,
                                validate_shape as validate_memory_shape)
from npc_memory.scope import (STREAM_KINDS, Scope, agent_may_write,
                              fleet_write_allowed, key_may_read,
                              key_may_write, stream_key as memory_stream_key,
                              valid_scope_id)
from npc_memory.scrub import (SecretRefusedError, scrub_check, scrub_tag,
                              scrub_text)
from npc_memory.store import MemoryStore, MemoryStoreError
from npc_memory.verify import StreamVerifier
from npc_verify import ed25519 as _ed25519

API_VERSION = "1.0.0"
MAX_BODY = 1024 * 1024  # 1 MiB
CHAIN_STATUS = {"network": "none", "anchoring": "disabled",
                "mode": "local-first",
                "note": "Phase 1 records anchor hashes locally; "
                        "no chain writes until the mainnet gate clears."}


class Request:
    def __init__(self, method, path, headers, body):
        self.method = method
        self.path = path
        self.headers = headers  # lowercased keys
        self.body = body  # parsed JSON dict, or None
        self.key = None  # set by auth wrapper


def _key_scope(key_row) -> Scope:
    """Build the authorization scope from an API key row."""
    return Scope(company_id=key_row.get("company_id"),
                 team_id=key_row.get("team_id"),
                 agent_id=key_row.get("agent_id"))


def _parse_stream_key(stream_key: str):
    """Split 'kind[:company[:team[:agent]]' into dims. None when malformed."""
    if not isinstance(stream_key, str):
        return None
    parts = stream_key.split(":")
    kind = parts[0]
    if kind not in STREAM_KINDS:
        return None
    dims = parts[1:]
    if kind == "fleet" and len(dims) != 0:
        return None
    if kind == "company" and len(dims) != 1:
        return None
    if kind == "team" and len(dims) != 2:
        return None
    if kind == "agent" and len(dims) != 3:
        return None
    if any(not valid_scope_id(d) for d in dims):
        return None
    dims += [None] * (3 - len(dims))
    return (kind, dims[0], dims[1], dims[2])


class App:
    def __init__(self, db_path: str, keys_dir: str):
        self.store = Store(db_path)
        self.keys = KeyRegistry(self.store, keys_dir)
        self.auth = Auth(self.store)
        self.limiter = RateLimiter()
        self.keys.ensure_bootstrap()
        # Trust-layer memory shares the API's connection and lock.
        self.memory = MemoryStore(self.store.db, self.store.db_lock)
        self.memverify = StreamVerifier(self.memory)
        self.routes = []
        self._register()

    # -- routing ----------------------------------------------------------
    def route(self, method, pattern):
        def deco(fn):
            self.routes.append((method, re.compile(pattern), fn))
            return fn
        return deco

    def _register(self):
        app = self

        @app.route("GET", r"^/v1/health$")
        def health(req):
            return 200, {
                "status": "ok",
                "version": API_VERSION,
                "key_id": app.keys.active_key_id("api_signing"),
                "chain": CHAIN_STATUS,
                "time": utcnow_iso(),
            }

        @app.route("GET", r"^/v1/keys$")
        def get_keys(req):
            return 200, app.keys.publish()

        @app.route("GET", r"^/v1/credentials/(?P<id>[^/]{1,128})$")
        @app.require_role("verifier")
        def get_credential(req, id):
            row = app.store.get_credential(id)
            if row is None:
                return errors.unknown()
            return 200, {
                "id": row["id"],
                "status": row["status"],
                "title": row["title"],
                "issuer": row["issuer"],
                "holder_name": (row["holder_name"]
                                if row["holder_public"] else None),
                "issued_at": row["issued_at"],
                "expires_at": row["expires_at"],
                "assessed_skills": json.loads(row["skills_json"]),
                "signature": row["signature_b64"],
                "key_id": row["key_id"],
                "verification_url": row["verification_url"],
            }

        @app.route("POST", r"^/v1/claims/verify$")
        @app.require_role("verifier")
        def verify_claim(req):
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            text = req.body.get("claim_text")
            given_hash = req.body.get("claim_hash")
            if text is not None and not isinstance(text, str):
                return errors.bad_request("claim_text must be a string")
            if given_hash is not None and not isinstance(given_hash, str):
                return errors.bad_request("claim_hash must be a string")
            if text:
                claim_hash = claim_hash_for_text(text)
            elif given_hash:
                claim_hash = given_hash.strip().lower()
                if not re.fullmatch(r"[0-9a-f]{64}", claim_hash):
                    return errors.bad_request(
                        "claim_hash must be 64 hex chars")
            else:
                return errors.bad_request(
                    "provide claim_text or claim_hash")
            rows = app.store.attestations_by_claim_hash(claim_hash)
            if not rows:
                status, body = errors.unknown()
                body = dict(body)
                body["matched"] = False
                return status, body
            r = rows[0]
            return 200, {
                "matched": True,
                "claim_hash": claim_hash,
                "attestation": {
                    "id": r["id"],
                    "verdict": r["verdict"],
                    "scope": json.loads(r["scope_json"]),
                    "tested_at": r["tested_at"],
                    "expires_at": r["expires_at"],
                    "findings_summary": r["findings_summary"],
                    "signature": r["signature_b64"],
                    "key_id": r["key_id"],
                    "onchain_anchor": {
                        "chain": r["anchor_chain"],
                        "tx": r["anchor_tx"],
                        "hash": r["anchor_hash"],
                        "status": r["anchor_status"],
                    },
                },
            }

        @app.route("GET", r"^/v1/products/(?P<tag_id>[^/]{1,128})$")
        @app.require_role("verifier")
        def get_product(req, tag_id):
            row = app.store.get_product(tag_id)
            if row is None:
                return errors.unknown()
            status = row["status"]
            verdict = ("verified" if status == "authentic"
                       else "not_verified" if status == "counterfeit"
                       else "unknown")
            return 200, {
                "tag_id": row["tag_id"],
                "status": status,
                "verdict": verdict,
                "name": row["name"],
                "creator": row["creator"],
                "description": row["description"],
                "provenance": json.loads(row["provenance_json"]),
                "attestation_id": row["attestation_id"],
            }

        @app.route("GET", r"^/v1/agents/(?P<agent_id>[^/]{1,128})/attestation$")
        @app.require_role("verifier")
        def get_agent_attestation(req, agent_id):
            row = app.store.get_agent(agent_id)
            if row is None:
                return errors.unknown()
            att = app.store.get_attestation(row["attestation_id"])
            anchor = None
            if att is not None:
                anchor = {"chain": att["anchor_chain"], "tx": att["anchor_tx"],
                          "hash": att["anchor_hash"],
                          "status": att["anchor_status"]}
            return 200, {
                "agent_id": row["agent_id"],
                "verdict": row["verdict"],
                "scope": json.loads(row["scope_json"]),
                "valid_from": row["valid_from"],
                "valid_until": row["valid_until"],
                "attestation_id": row["attestation_id"],
                "onchain_anchor": anchor,
                "notes": row["notes"],
            }

        @app.route("POST", r"^/v1/attestations$")
        @app.require_role("issuer")
        def create_attestation(req):
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            body = req.body
            att = Attestation(
                id="att_" + secrets.token_hex(12),
                subject_type=body.get("subject_type", ""),
                subject_id=body.get("subject_id", ""),
                verdict=body.get("verdict", ""),
                scope=body.get("scope", {}),
                tested_at=body.get("tested_at", ""),
                expires_at=body.get("expires_at"),
                findings_summary=body.get("findings_summary", ""),
                claim_hash=body.get("claim_hash"),
            )
            problems = att.validate()
            if problems:
                return errors.unprocessable("; ".join(problems))
            if att.claim_hash is not None:
                if (not isinstance(att.claim_hash, str)
                        or not re.fullmatch(r"[0-9a-f]{64}",
                                             att.claim_hash.strip().lower())):
                    return errors.unprocessable(
                        "claim_hash must be 64 hex chars or omitted")
                att.claim_hash = att.claim_hash.strip().lower()
            # NPC signs the canonical attestation core with the issuer key.
            core = {
                "id": att.id,
                "subject_type": att.subject_type,
                "subject_id": att.subject_id,
                "verdict": att.verdict,
                "scope": att.scope,
                "tested_at": att.tested_at,
                "findings_summary": att.findings_summary,
            }
            key_id, sig = app.keys.sign("issuer", canonicalize(core))
            att.signature_b64 = base64.b64encode(sig).decode()
            att.key_id = key_id
            # Anchor hash recorded locally; NO chain write in Phase 1.
            att.anchor_hash = hashlib.sha256(
                canonicalize(core)).hexdigest()
            att.anchor_chain = ANCHOR_CHAIN
            att.anchor_status = "not_anchored"
            app.store.add_attestation(att)
            return 201, {
                "id": att.id,
                "signature": att.signature_b64,
                "key_id": att.key_id,
                "onchain_anchor": {
                    "chain": att.anchor_chain,
                    "tx": None,
                    "hash": att.anchor_hash,
                    "status": att.anchor_status,
                },
                "created_at": att.created_at,
            }

        # -- trust-layer memory (DESIGN v1 section 5) --------------------
        # Authenticated, agent-scoped endpoints under /v1/memory/.
        # Every write is a signed MemoryRecord: the API checks shape,
        # write-boundary secrets, API-key scope, the writer's registered
        # agent scope, the Ed25519 signature, and the stream chain before
        # appending. Every read returns verification status with the record.

        @app.route("POST", r"^/v1/memory/agents$")
        @app.require_role("issuer")
        def memory_register_agent(req):
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            body = req.body
            agent_id = body.get("agent_id")
            company_id = body.get("company_id")
            team_id = body.get("team_id")
            pub_b64 = body.get("public_key_b64")
            if not valid_scope_id(agent_id or ""):
                return errors.bad_request(
                    "agent_id must match [A-Za-z0-9_-] (max 64)")
            for name, val in (("company_id", company_id),
                              ("team_id", team_id)):
                if val is not None and not valid_scope_id(val):
                    return errors.bad_request(
                        f"{name} must match [A-Za-z0-9_-] (max 64) or be null")
            if team_id is not None and company_id is None:
                return errors.bad_request("team_id requires company_id")
            try:
                pub = base64.b64decode(pub_b64 or "", validate=True)
            except Exception:
                return errors.bad_request(
                    "public_key_b64 must be valid base64")
            if len(pub) != 32:
                return errors.bad_request(
                    "public_key_b64 must decode to 32 bytes")
            # The API key's scope must cover the agent's scope, and
            # agent-scoped keys cannot register agents.
            kscope = _key_scope(req.key)
            if kscope.agent_id is not None:
                return errors.forbidden(
                    "agent-scoped keys cannot register agents")
            for dim, val in (("company_id", company_id),
                             ("team_id", team_id)):
                kv = getattr(kscope, dim)
                if kv is not None and kv != val:
                    return errors.forbidden(
                        "API key scope does not cover this agent")
            key_id = key_id_for_public_key(pub)
            existing = app.memory.get_agent(agent_id)
            if existing is not None:
                if existing["public_key_b64"] == pub_b64:
                    return 200, {"agent_id": agent_id,
                                 "status": "already_registered",
                                 "key_id": key_id}
                return errors.conflict(
                    "agent_id is registered with a different key")
            try:
                app.memory.register_agent(agent_id, company_id, team_id,
                                          pub_b64, key_id, utcnow_iso(),
                                          req.key["name"])
            except MemoryStoreError as exc:
                return errors.conflict(str(exc))
            return 201, {"agent_id": agent_id, "company_id": company_id,
                         "team_id": team_id, "key_id": key_id,
                         "status": "registered"}

        @app.route("POST", r"^/v1/memory/records$")
        @app.require_role("verifier")
        def memory_append(req):
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            rec = req.body
            problems = validate_memory_shape(rec)
            if problems:
                return errors.unprocessable("; ".join(problems))
            try:
                scrub_check(rec["content"])
                scrub_check(rec["provenance"])
                scrub_text(rec["content"]["text"])
                for t in rec["content"].get("tags", []):
                    scrub_tag(t)
            except SecretRefusedError as exc:
                return errors.unprocessable(str(exc))
            kind = rec["stream_kind"]
            dims = (rec.get("company_id"), rec.get("team_id"),
                    rec.get("stream_agent_id"))
            kscope = _key_scope(req.key)
            if not key_may_write(kscope, kind, *dims):
                return errors.forbidden(
                    "API key scope does not cover this stream")
            if kind == "fleet" and not fleet_write_allowed(req.key["role"]):
                return errors.forbidden(
                    "fleet stream writes need an issuer key")
            agent = app.memory.get_agent(rec["agent_id"])
            if agent is None:
                return errors.unprocessable("writer agent is not registered")
            if agent["key_id"] != rec["key_id"]:
                return errors.unprocessable(
                    "record key_id does not match the registered agent key")
            ascope = Scope(company_id=agent["company_id"],
                           team_id=agent["team_id"],
                           agent_id=agent["agent_id"])
            if not agent_may_write(ascope, kind, *dims):
                return errors.forbidden(
                    "writer agent scope does not cover this stream")
            try:
                pub = base64.b64decode(agent["public_key_b64"])
                sig = base64.b64decode(rec["signature_b64"])
            except Exception:
                return errors.unprocessable("bad signature encoding")
            if not _ed25519.verify(pub,
                                   canonicalize(memory_signing_core(rec)),
                                   sig):
                return errors.unprocessable("record signature is invalid")
            if memory_record_hash(rec) != rec.get("record_hash"):
                return errors.unprocessable("record_hash does not match "
                                            "the record content")
            if rec["type"] in ("memory.supersede", "memory.retract"):
                target_id = rec["content"]["target_id"]
                sk = rec["stream_key"]
                target = app.memory.get(target_id)
                if target is None or target["stream_key"] != sk:
                    return errors.conflict(
                        "supersede/retract target not found in this stream")
                if app.memory.live_retract(target_id, sk) is not None:
                    return errors.conflict("target is already retracted")
                if rec["type"] == "memory.supersede":
                    if target["type"] == "memory.retract":
                        return errors.conflict(
                            "a retraction cannot be superseded")
                    if app.memory.live_supersede(target_id, sk) is not None:
                        return errors.conflict("target is already superseded")
                elif target["type"] == "memory.retract":
                    return errors.conflict(
                        "a retraction cannot be retracted; assert a new "
                        "memory instead")
            try:
                app.memory.append(rec)
            except MemoryStoreError as exc:
                return errors.conflict(str(exc))
            app.memverify._chain_cache.pop(rec["stream_key"], None)
            return 201, {"id": rec["id"], "seq": rec["seq"],
                         "stream_key": rec["stream_key"],
                         "standing": "live"}

        @app.route("GET", r"^/v1/memory/records/(?P<id>mem_[^/]{1,128})$")
        @app.require_role("verifier")
        def memory_get(req, id):
            row = app.memory.get(id)
            if row is None:
                return errors.not_found()
            rec = MemoryStore._inflate(row)
            kscope = _key_scope(req.key)
            if not key_may_read(kscope, rec["stream_kind"],
                                rec["company_id"], rec["team_id"],
                                rec["stream_agent_id"]):
                # Same shape as unknown: never confirm what exists elsewhere.
                return errors.not_found()
            status = app.memverify.status_for(rec)
            return 200, {"record": memory_public_dict(rec),
                         "verification": status}

        @app.route("POST", r"^/v1/memory/recall$")
        @app.require_role("verifier")
        def memory_recall(req):
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            body = req.body
            kscope = _key_scope(req.key)
            stream_keys = []
            if body.get("stream_key"):
                parsed = _parse_stream_key(body["stream_key"])
                if parsed is None:
                    return errors.bad_request("stream_key is malformed")
                kind, cid, tid, said = parsed
                if not key_may_read(kscope, kind, cid, tid, said):
                    return errors.forbidden(
                        "API key scope does not cover this stream")
                stream_keys = [body["stream_key"]]
            elif body.get("stream_kind"):
                kind = body["stream_kind"]
                if kind not in STREAM_KINDS:
                    return errors.bad_request(
                        f"stream_kind must be one of {STREAM_KINDS}")
                cid, tid, said = (body.get("company_id"),
                                  body.get("team_id"),
                                  body.get("agent_id"))
                try:
                    sk = memory_stream_key(kind, cid, tid, said)
                except ValueError as exc:
                    return errors.bad_request(str(exc))
                if not key_may_read(kscope, kind, cid, tid, said):
                    return errors.forbidden(
                        "API key scope does not cover this stream")
                stream_keys = [sk]
            else:
                for s in app.memory.distinct_streams():
                    if key_may_read(kscope, s["stream_kind"],
                                    s["company_id"], s["team_id"],
                                    s["stream_agent_id"]):
                        stream_keys.append(s["stream_key"])
            tags = body.get("tags") or []
            if not isinstance(tags, list) or any(
                    not isinstance(t, str) for t in tags):
                return errors.bad_request("tags must be a list of strings")
            q = body.get("q")
            if q is not None and not isinstance(q, str):
                return errors.bad_request("q must be a string")
            limit = body.get("limit", 50)
            if not isinstance(limit, int) or isinstance(limit, bool):
                return errors.bad_request("limit must be an integer")
            rows = app.memory.query(
                stream_keys=stream_keys or ["__none__"], tags=tags,
                keyword=q, since=body.get("since"), until=body.get("until"),
                limit=limit)
            items = app.memverify.status_many(rows)
            if body.get("live_only"):
                items = [(r, s) for r, s in items
                         if s["standing"] == "live"]
            return 200, {
                "records": [{"record": memory_public_dict(r),
                             "verification": s} for r, s in items],
                "count": len(items),
            }

    # -- auth + rate limit decorator ---------------------------------------
    def require_role(self, role):
        def deco(fn):
            def wrapper(req, **kw):
                key = self.auth.authenticate(req.headers)
                if key is None:
                    return errors.unauthorized()
                ok, retry_after = self._check_limit(key)
                if not ok:
                    return errors.rate_limited(retry_after)
                if not Auth.allows(key, role):
                    return errors.forbidden()
                req.key = key
                return fn(req, **kw)
            return wrapper
        return deco

    def _check_limit(self, key_row):
        key_hash = key_row["key_hash"]
        self.limiter.set_limit(key_hash, key_row["per_minute"])
        return self.limiter.allowed(key_hash)

    # -- dispatch ------------------------------------------------------------
    def dispatch(self, method, raw_path, headers, body_bytes):
        path = urlparse(raw_path).path
        body = None
        if body_bytes:
            if len(body_bytes) > MAX_BODY:
                return self._finalize(*errors.bad_request("body too large"))
            try:
                body = json.loads(body_bytes.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return self._finalize(
                    *errors.bad_request("invalid JSON body"))
        for route_method, pattern, fn in self.routes:
            if route_method != method:
                continue
            m = pattern.match(path)
            if m:
                req = Request(method, path, headers, body)
                try:
                    status, resp_body = fn(req, **m.groupdict())
                except Exception:  # never leak internals
                    return self._finalize(
                        *errors.bad_request("request could not be processed"))
                return self._finalize(status, resp_body)
        return self._finalize(*errors.not_found())

    def _finalize(self, status, body):
        """Canonicalize + sign every response body."""
        code = status.value if hasattr(status, "value") else int(status)
        canonical = canonicalize(body)
        key_id, sig = self.keys.sign("api_signing", canonical)
        headers = {
            "Content-Type": "application/json",
            "X-NPC-Signature": base64.b64encode(sig).decode(),
            "X-NPC-Key-ID": key_id,
            "Content-Length": str(len(canonical)),
        }
        return code, headers, canonical


class Handler(BaseHTTPRequestHandler):
    app: App = None  # set by run()

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        headers = {k.lower(): v for k, v in self.headers.items()}
        code, out_headers, payload = self.app.dispatch(
            self.command, self.path, headers, body)
        self.send_response(code)
        for k, v in out_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle

    def log_message(self, fmt, *args):  # quiet by default
        pass


def create_app(db_path: str, keys_dir: str) -> App:
    return App(db_path, keys_dir)


def run(db_path: str, keys_dir: str, host="127.0.0.1", port=8787):
    app = create_app(db_path, keys_dir)
    Handler.app = app
    server = ThreadingHTTPServer((host, port), Handler)
    return server, app
