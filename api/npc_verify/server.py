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
  POST /v1/images/ai-check                (verifier+; Sightengine-backed,
                                           signed like every response)
  POST /v1/pact/grants                    (issuer only; mints the signed
                                           consent record at issuance)
  POST /v1/pact/grants/{id}/receipts      (issuer only; appends a receipt
                                           to the hash-chained audit log)
  GET  /v1/pact/grants/{id}/audit         (verifier+; entries + live
                                           chain verification)
  POST /v1/pact/grants/{id}:revoke        (issuer only; signed append-only
                                           revocation record)
  GET  /v1/pact/grants/{id}/status        (verifier+; signed status record)
  POST /v1/register/content               (PUBLIC; registers a piece of
                                           content and starts verification:
                                           a signed registration record,
                                           status "registered, checks
                                           pending"; intake checks run on
                                           what was provided)
  POST /v1/register/agent                 (PUBLIC; issues the signed agent
                                           registration claim per the Agent
                                           Registry spec: free, named owner,
                                           registration not verification)
  GET  /v1/records/{id}                   (PUBLIC; the signed record for
                                           any API-issued ID: registrations,
                                           credentials, products, agents,
                                           attestations, PACT consents;
                                           social batch receipts too,
                                           while NPC_SOCIAL_PROFILES=1)
  POST /v1/records/{id}/identity-links/siwe/challenge
  POST /v1/records/{id}/identity-links/siwe/verify
  POST /v1/records/{id}/identity-links/{github|google}/start
  GET  /v1/link/{github|google}/callback
  POST /v1/records/{id}/identity-links/coinbase/refresh
  GET  /v1/records/{id}/identity-panel     (PUBLIC; the "Identity the
                                           owner has linked" panel
                                           data at current observed
                                           state. All six linking
                                           routes are gated by
                                           NPC_IDENTITY_SIGNALS=1)
  POST /v1/social/{youtube|instagram|tiktok}/connect/start
  GET  /v1/social/{youtube|instagram|tiktok}/callback
  POST /v1/social/connections/list
  POST /v1/social/connections/{id}/scan
  POST /v1/social/connections/{id}/register
  POST /v1/social/connections/{id}/disconnect
  POST /v1/social/connections/{id}/overview
  POST /v1/social/x/register
  POST /v1/social/spotify/register        (the social profiles
                                           content-registration
                                           lane: owners connect a
                                           profile and register
                                           the content on it as
                                           signed records. All
                                           routes gated by
                                           NPC_SOCIAL_PROFILES=1)
  POST /v1/chat                           (PUBLIC; Biblo site chat:
                                           grounded answers over the
                                           public corpus; UNSIGNED,
                                           chat is never a record)
  POST /v1/chat/feedback                  (PUBLIC; thumbs feedback on a
                                           chat turn; UNSIGNED,
                                           best-effort, never an error)

Fail-closed: unknown subjects -> 404 {"verdict": "unknown"}.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import errors
from .auth import Auth, RateLimiter, hash_key
from .canonical import (canonicalize, claim_hash_for_text,
                        normalize_claim_text)
from .detector import (DetectorError, DetectorNotConfigured,
                       detector_from_env)
from .keys import KeyRegistry
from .models import Attestation, utcnow_iso
from . import chat as chat_module
from . import credits as credits_module
from . import anchor as anchor_module
from . import linking as linking_module
from . import mailer as mailer_module
from . import accounts as accounts_module
from . import signin_page as signin_page_module
from . import social as social_module
from . import kya as kya_module
from . import pact
from . import registry
from .seed import ANCHOR_CHAIN
from .store import Store, make_store  # noqa: F401  (Store re-exported)
from .store import registration_email_hash as _email_hash_of

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
# Raw image cap for /v1/images/ai-check: base64 inflates by 4/3, so
# 750 KB of image keeps the JSON body under MAX_BODY.
MAX_IMAGE_BYTES = 750 * 1000
MAX_IMAGE_URL = 2048
CHAIN_STATUS = {"network": "none", "anchoring": "disabled",
                "mode": "local-first",
                "note": "Phase 1 records anchor hashes locally; "
                        "no chain writes until the mainnet gate clears."}


class Request:
    def __init__(self, method, path, headers, body, query=None,
                 raw_body=b""):
        self.method = method
        self.path = path
        self.headers = headers  # lowercased keys
        self.body = body  # parsed JSON dict, or None
        # The exact request bytes, before JSON parsing. The Stripe
        # webhook verifies its signature over these bytes; nothing
        # else reads them.
        self.raw_body = raw_body
        self.query = query or {}  # first value per query parameter
        self.key = None  # set by auth wrapper
        # TCP peer (or gateway-reported source IP), injected by the
        # transport, never taken from a client-supplied header. Used
        # only for the public registration submission caps.
        self.client_ip = headers.get("x-npc-peer", "")


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


def _credential_body(row):
    return {
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


def _product_body(row):
    status = row["status"]
    verdict = ("verified" if status == "authentic"
               else "not_verified" if status == "counterfeit"
               else "unknown")
    return {
        "tag_id": row["tag_id"],
        "status": status,
        "verdict": verdict,
        "name": row["name"],
        "creator": row["creator"],
        "description": row["description"],
        "provenance": json.loads(row["provenance_json"]),
        "attestation_id": row["attestation_id"],
    }


def _agent_body(store, row):
    att = store.get_attestation(row["attestation_id"])
    anchor = None
    if att is not None:
        anchor = {"chain": att["anchor_chain"], "tx": att["anchor_tx"],
                  "hash": att["anchor_hash"],
                  "status": att["anchor_status"]}
    body = {
        "agent_id": row["agent_id"],
        "verdict": row["verdict"],
        "scope": json.loads(row["scope_json"]),
        "valid_from": row["valid_from"],
        "valid_until": row["valid_until"],
        "attestation_id": row["attestation_id"],
        "onchain_anchor": anchor,
        "notes": row["notes"],
    }
    if kya_module.kya_enabled():
        # KYA block (npc_verify.kya). The principal is resolved
        # from the recorded chain: the agent registration that
        # names this agent_id and its accountable owner; when no
        # registration names the agent, the chain is not recorded
        # and the principal stays null. The reputation is the
        # agent's rating, computed here from its whole attestation
        # history (this module's store-backed reads are where a
        # history is visible). The revoked flag is read from the
        # linked attestation when one exists; without one it stays
        # out of the block.
        body["kya"] = kya_module.kya_for_scope(
            scope=body["scope"], valid_from=row["valid_from"],
            valid_until=row["valid_until"],
            revoked=(bool(att["revoked"]) if att is not None
                     else None),
            verdict=row["verdict"],
            principal=kya_module.principal_from_registration(
                store.registration_for_agent(row["agent_id"])),
            rating=kya_module.compute_agent_rating(
                store.attestations_for_subject(
                    "agent", row["agent_id"]),
                as_of=utcnow_iso()))
    return body


def _attestation_body(store, row):
    body = {
        "id": row["id"],
        "subject_type": row["subject_type"],
        "subject_id": row["subject_id"],
        "verdict": row["verdict"],
        "scope": json.loads(row["scope_json"]),
        "tested_at": row["tested_at"],
        "expires_at": row["expires_at"],
        "findings_summary": row["findings_summary"],
        "signature": row["signature_b64"],
        "key_id": row["key_id"],
        "onchain_anchor": {
            "chain": row["anchor_chain"],
            "tx": row["anchor_tx"],
            "hash": row["anchor_hash"],
            "status": row["anchor_status"],
        },
        "revoked": bool(row["revoked"]),
        "created_at": row["created_at"],
    }
    if row["subject_type"] == "agent" and kya_module.kya_enabled():
        # Agent subjects resolve like _agent_body: the principal
        # from the registration that names this agent (null when
        # the chain is not recorded), and the reputation as the
        # rating computed from the subject's attestation history.
        body["kya"] = kya_module.kya_for_scope(
            scope=body["scope"], expires_at=row["expires_at"],
            revoked=bool(row["revoked"]), verdict=row["verdict"],
            principal=kya_module.principal_from_registration(
                store.registration_for_agent(row["subject_id"])),
            rating=kya_module.compute_agent_rating(
                store.attestations_for_subject(
                    row["subject_type"], row["subject_id"]),
                as_of=utcnow_iso()))
    return body


def _registration_claim_body(claim_hash, rec):
    """POST /v1/claims/verify answer when a registration matches.

    A registration is not an attestation: it carries no verdict and
    no verification mark, and the record itself says "registered,
    checks pending". The body keeps that standing in its shape:
    match_type and the registration object carry the record's own
    fields. The attestation-shaped summary exists because clients
    are built against the attestation contract: the extension reads
    attestation.verdict first and defaults a MISSING verdict to
    "verified", so the honest standing is spelled out in that field,
    never omitted. Its signature and key_id are the registration
    record's own, so the full record resolves at GET
    /v1/records/{id} and verifies offline exactly as issued.
    """
    locator = rec.get("locator") or ""
    by_address = isinstance(locator, str) and (
        locator.startswith("https://")
        or locator.startswith("http://")) and hashlib.sha256(
            locator.strip().encode("utf-8")).hexdigest() == claim_hash
    standing = rec.get("status_label") or "registered, checks pending"
    return {
        "matched": True,
        "claim_hash": claim_hash,
        "match_type": "registration",
        "registration": {
            "id": rec.get("record_id"),
            "record_type": rec.get("record_type"),
            "status": rec.get("status"),
            "status_label": standing,
            "title": rec.get("title"),
            "creator_name": rec.get("creator_name"),
            "content_kind": rec.get("content_kind"),
            "locator": rec.get("locator"),
            "registered_at": rec.get("registered_at"),
            "matched_by": "locator_address" if by_address
                          else "content_bytes",
            "signature": rec.get("signature"),
            "key_id": rec.get("key_id"),
        },
        "attestation": {
            "id": rec.get("record_id"),
            "verdict": standing,
            "creator_name": rec.get("creator_name"),
            "title": rec.get("title"),
            "scope": {},
            "tested_at": None,
            "created_at": rec.get("registered_at"),
            "expires_at": None,
            "findings_summary": (
                "Registered, checks pending. Registration is not "
                "verification, and no verification mark has been "
                "issued for this record."),
            "signature": rec.get("signature"),
            "key_id": rec.get("key_id"),
            "onchain_anchor": {
                "chain": None,
                "tx": None,
                "hash": None,
                "status": "not_anchored",
            },
        },
    }


class UnsignedBody:
    """Marker wrapper: a response body that must NOT be signed.

    Chat is never a record (biblo-chat spec section 3), so chat
    responses travel without X-NPC-Signature / X-NPC-Key-ID. The
    finalize step unwraps the marker and emits the plain body with
    the usual transport headers only."""

    def __init__(self, body):
        self.body = body


class HtmlBody:
    """Marker wrapper: an HTML page response, served unsigned.

    The account sign-in page is not a record either, and it cannot
    be canonicalized or signed like a JSON body. The finalize step
    emits it as text/html with the no-store and nosniff transport
    headers and no signature pair."""

    def __init__(self, html):
        self.html = html


class App:
    def __init__(self, db_path: str, keys_dir: str, detector=None,
                 fetcher=None, chat_provider=None, chat_config=None,
                 mailer=None, link_http=None, coinbase_reader=None,
                 payments=None, anchor_chain=None):
        self.store = make_store(db_path)
        self.keys = KeyRegistry(self.store, keys_dir)
        self.auth = Auth(self.store)
        self.limiter = RateLimiter()
        # AI-generation detection (Sightengine), credentials from the
        # server environment only. Tests inject a fake detector here.
        self.detector = detector if detector is not None \
            else detector_from_env()
        # Biblo site chat (biblo-chat spec). The provider comes from
        # the environment (NPC_CHAT_LLM_API_KEY) when not injected;
        # with no key the service rests instead of failing. Tests and
        # evals inject a provider here.
        self.chat = chat_module.ChatService(
            self.store,
            provider=chat_provider if chat_provider is not None
            else chat_module.provider_from_env(),
            config=chat_config)
        # Intake fetcher for public registration (one bounded fetch of
        # a submitted URL). Tests inject a fake here.
        self.fetcher = fetcher if fetcher is not None \
            else registry.fetch_url_bytes
        # Registrant email follow-up (npc_verify.mailer). Built from
        # the environment (NPC_MAIL_ENABLED=1) when not injected;
        # with follow-up off the mailer rests and sends nothing.
        # Every send fails soft: mail never breaks a request.
        self.mailer = mailer if mailer is not None \
            else mailer_module.mailer_from_env()
        # Paid check credits (npc_verify.credits). The payments
        # client comes from the environment (NPC_STRIPE_*) when not
        # injected; with any piece missing the purchase rail rests
        # and its routes answer honestly. Pack configuration is read
        # once here, from NPC_CREDITS_PACKS_JSON.
        self.payments = payments if payments is not None \
            else credits_module.payments_from_env()
        self.credit_packs, self.credit_packs_is_default = \
            credits_module.packs_from_env()
        # Onchain anchoring (npc_verify.anchor). Configuration comes
        # from the environment (NPC_ANCHOR_*), the chain client is
        # built against the configured RPC URL, and tests inject a
        # fake chain here. With the lane off (the default) the engine
        # rests and record payloads are byte-identical to before. A
        # malformed anchoring key in an enabled lane raises here, at
        # build time, rather than resting silently (config_from_env).
        self.anchor_config = anchor_module.config_from_env()
        self.anchor_chain = anchor_chain if anchor_chain is not None \
            else anchor_module.chain_from_env()
        # Federated identity linking (phase 1). Every external call
        # the linking service makes (OAuth exchanges, the Coinbase
        # EAS read) goes through this one injectable HTTP callable,
        # so tests never touch the network. The Coinbase reader is
        # built on the same callable unless one is injected whole.
        self.link_http = link_http if link_http is not None \
            else linking_module.default_http
        self.coinbase_reader = coinbase_reader \
            if coinbase_reader is not None \
            else linking_module.CoinbaseReader(self.link_http)
        # Unified accounts (Gate G1, npc_verify.accounts). One
        # account per person across every surface: passkeys first,
        # email links as the anchor and fallback, revocable device
        # sessions, and the desktop browser handoff. Configuration
        # comes from the environment (NPC_AUTH_*); the mailer is the
        # app's own, so with mail resting the link flow rests too
        # (locally the stub mailer carries it end to end).
        self.accounts = accounts_module.AccountService(
            self.store, self.mailer,
            accounts_module.config_from_env())
        self.keys.ensure_bootstrap()
        # Trust-layer memory shares the API store's connection and
        # lock on the SQLite backend. The DynamoDB backend has no
        # sqlite connection, so memory keeps its own sqlite file next
        # to db_path (per-environment, exactly as it behaved when the
        # whole store lived under /tmp).
        mem_conn = self.store.db
        if mem_conn is None:
            mem_path = os.path.join(
                os.path.dirname(os.path.abspath(db_path)),
                "npc_memory.sqlite3")
            mem_conn = sqlite3.connect(mem_path, check_same_thread=False)
        self.memory = MemoryStore(mem_conn, self.store.db_lock)
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
            return 200, _credential_body(row)

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
                # No attestation attests to this hash. A public
                # registration may still name it: registrations are
                # indexed by the hash of their locator address and
                # by the content hash recorded at intake, which is
                # the lookup the browser extension performs for an
                # image on a page. A registration match is presented
                # as a registration (its own standing, "registered,
                # checks pending"), never as a verification.
                records = app.store.registrations_by_claim_hash(
                    claim_hash)
                if records:
                    return 200, _registration_claim_body(
                        claim_hash, records[0])
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

        @app.route("POST", r"^/v1/images/ai-check$")
        @app.require_role("verifier")
        def ai_check_image(req):
            """AI-generation check for one image, via Sightengine.

            The extension sends the image itself (base64) or its URL;
            the API holds the Sightengine credentials, so no client
            ever sees them. The detector's probability is returned as
            an integer percent: the signed envelope (NPC-JCS-v1) is
            defined over strings, booleans, integers and nulls, and a
            float would not canonicalize identically on every client.
            When detection is off or the service fails, the answer is
            an honest 503. A score is never fabricated.
            """
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            image_url = req.body.get("image_url")
            image_b64 = req.body.get("image_base64")
            if (image_url is None) == (image_b64 is None):
                return errors.bad_request(
                    "provide exactly one of image_url or image_base64")
            image_bytes = None
            if image_b64 is not None:
                if not isinstance(image_b64, str):
                    return errors.bad_request(
                        "image_base64 must be a string")
                try:
                    image_bytes = base64.b64decode(image_b64,
                                                   validate=True)
                except Exception:
                    return errors.bad_request(
                        "image_base64 must be valid base64")
                if not image_bytes:
                    return errors.bad_request(
                        "image_base64 decodes to no image bytes")
                if len(image_bytes) > MAX_IMAGE_BYTES:
                    return errors.bad_request(
                        "image is too large for this check")
            else:
                if not isinstance(image_url, str) \
                        or len(image_url) > MAX_IMAGE_URL \
                        or not (image_url.startswith("https://")
                                or image_url.startswith("http://")):
                    return errors.bad_request(
                        "image_url must be an http(s) URL")
            detector = app.detector
            if detector is None or not detector.configured:
                return errors.detector_unavailable(
                    "AI generation detection is not configured on "
                    "this API")
            try:
                prob = detector.check_ai(image_bytes=image_bytes,
                                         image_url=image_url)
            except DetectorNotConfigured:
                return errors.detector_unavailable(
                    "AI generation detection is not configured on "
                    "this API")
            except DetectorError:
                return errors.detector_unavailable(
                    "the detection service could not complete the "
                    "check")
            percent = int(prob * 100 + 0.5)
            percent = max(0, min(100, percent))
            return 200, {
                "check": "ai_generation",
                "provider": detector.provider,
                "model": detector.model,
                "ai_generated_percent": percent,
                "image_sha256": (hashlib.sha256(image_bytes).hexdigest()
                                 if image_bytes is not None else None),
                "source": "bytes" if image_bytes is not None else "url",
                "checked_at": utcnow_iso(),
            }

        # -- paid check credits (npc_verify.credits) --------------------
        # Public by design: the redeem code is the credential, the
        # way a gift card is, so no API key gates these routes. A
        # per-IP rate limit bounds code guessing, and a code carries
        # 100 bits of entropy. Free checks stay local to the
        # extension; these routes are only about paid credits.

        def _credits_limited(req):
            key = "credits-ip:" + (req.client_ip or "unknown")
            app.limiter.set_limit(key, 120)
            return app.limiter.allowed(key)

        def _credit_body(row):
            # The balance is the ledger truth: the code row's own
            # counters plus whatever its live Pass grants still
            # hold. ai_balance is the part of that balance an AI
            # generation check may spend: the Pass grants' AI
            # sub-allowances plus any bonus balance plus the code
            # row's own pack counters (AI draws spend the
            # sub-allowances first, then bonus grants, then the
            # pack counters).
            # registry_unlimited is the Pass's other half: while
            # the subscription is active, standard registry checks
            # are covered by the Pass and draw no pool at all, so
            # the finite balance below is what stands if the
            # subscription ends.
            grant_balance = row.get("grant_balance", 0)
            return {
                "pack_id": row["pack_id"],
                "status": row["status"],
                "credits_total": row["credits_total"],
                "credits_used": row["credits_used"],
                "grant_balance": grant_balance,
                "ai_balance": row.get("ai_balance", 0),
                "balance": row["credits_total"] - row["credits_used"]
                    + grant_balance,
                "subscription_status": row.get("subscription_status"),
                "registry_unlimited":
                    row.get("subscription_status") == "active",
            }

        def _code_from_body(req):
            """(code_hash, None) or (None, error tuple)."""
            if not isinstance(req.body, dict):
                return None, errors.bad_request(
                    "JSON object body required")
            code = req.body.get("code")
            if not isinstance(code, str) \
                    or not credits_module.valid_code_shape(code):
                return None, errors.bad_request(
                    "a valid NPC checks code is required")
            return credits_module.code_hash(code), None

        @app.route("GET", r"^/v1/credits/packs$")
        def credit_packs(req):
            return 200, {
                "packs": [credits_module.public_pack(p)
                          for p in app.credit_packs],
                "packs_source": "default"
                    if app.credit_packs_is_default else "environment",
                "checkout_available": bool(
                    getattr(app.payments, "configured", False)),
            }

        @app.route("POST", r"^/v1/credits/checkout$")
        def credit_checkout(req):
            ok, retry_after = _credits_limited(req)
            if not ok:
                return errors.rate_limited(retry_after)
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            pack = credits_module.find_pack(
                app.credit_packs, req.body.get("pack_id"))
            if pack is None:
                return errors.bad_request("unknown pack_id")
            # Both kinds are on sale (Bayo, 2026-10-28): "pack" is a
            # one-time grant, "access" is the Verifier Pass, whose
            # checkout the payments layer runs as a subscription.
            email = req.body.get("email")
            if email is not None:
                if not isinstance(email, str) or "@" not in email \
                        or len(email) > 254:
                    return errors.bad_request("email must be an address")
                email = email.strip() or None
            # An optional referral code rides the purchase (only
            # its hash is stored): when the payment completes, the
            # webhook attributes the new code to the referral
            # code's owner and lands both referral bonuses.
            referral_hash = None
            referral_code = req.body.get("referral_code")
            if referral_code is not None:
                if not isinstance(referral_code, str) \
                        or not credits_module.valid_code_shape(
                            referral_code):
                    return errors.bad_request(
                        "referral_code must be a valid NPC code")
                referral_hash = credits_module.code_hash(
                    referral_code)
            if not getattr(app.payments, "configured", False):
                return errors.unavailable(
                    "payments_not_configured",
                    "payments are not configured on this API")
            # Fail closed on the catalog wiring (Bayo, 2026-10-29):
            # an offer with no Stripe catalog price cannot check
            # out, and no session or purchase row is created for
            # it. There is no inline-price fallback.
            if not pack.get("stripe_price_id"):
                return errors.unavailable(
                    "checkout_not_configured",
                    "this offer is not configured for checkout")
            try:
                session = app.payments.create_checkout_session(
                    pack, email=email)
            except credits_module.PaymentsError:
                return errors.unavailable(
                    "payments_unavailable",
                    "the payment provider could not start checkout")
            app.store.create_credit_purchase(
                session["id"], pack["id"], email, utcnow_iso(),
                referral_hash=referral_hash)
            return 201, {"session_id": session["id"],
                         "checkout_url": session["url"],
                         "pack_id": pack["id"]}

        @app.route("POST", r"^/v1/credits/stripe-webhook$")
        def credit_stripe_webhook(req):
            if not getattr(app.payments, "configured", False):
                return errors.unavailable(
                    "payments_not_configured",
                    "payments are not configured on this API")
            try:
                event = app.payments.verify_webhook(
                    req.raw_body, req.headers.get("stripe-signature"))
            except credits_module.WebhookSignatureError:
                return errors.bad_request("invalid webhook signature")
            except credits_module.PaymentsError:
                return errors.unavailable(
                    "payments_not_configured",
                    "payments are not configured on this API")
            etype = event.get("type")
            obj = (event.get("data") or {}).get("object") or {}
            session_id = obj.get("id")
            if etype == "checkout.session.completed" \
                    and isinstance(session_id, str):
                purchase = app.store.get_credit_purchase(session_id)
                if purchase is not None \
                        and purchase["status"] != "paid":
                    pack = credits_module.find_pack(
                        app.credit_packs, purchase["pack_id"])
                    # The charge ran on a Stripe catalog price.
                    # When the event names the price it charged
                    # (expanded line items), that price is the
                    # ground truth of the money: it must resolve
                    # (pack_by_price_id) to the pack the purchase
                    # recorded. An unknown price, or one resolving
                    # to a different pack, refuses the mint: the
                    # handler still answers 200 below, so Stripe
                    # stops retrying a charge we cannot account
                    # for, and no code is granted against it. When
                    # the purchase's own pack has left the
                    # configuration, a resolving price names what
                    # was sold; failing that, the session metadata
                    # (metadata[pack_id], set at checkout) does.
                    refused = False
                    price_id = credits_module.session_price_id(obj)
                    if price_id is not None:
                        priced = credits_module.pack_by_price_id(
                            app.credit_packs, price_id)
                        if priced is None or (
                                pack is not None
                                and priced["id"] != pack["id"]):
                            refused = True
                        elif pack is None:
                            pack = priced
                    if pack is None and not refused:
                        meta = obj.get("metadata")
                        if isinstance(meta, dict):
                            pack = credits_module.find_pack(
                                app.credit_packs,
                                meta.get("pack_id"))
                    if pack is not None and not refused:
                        email = purchase["buyer_email"]
                        details = obj.get("customer_details") or {}
                        if isinstance(details.get("email"), str) \
                                and details["email"]:
                            email = details["email"]
                        elif isinstance(obj.get("customer_email"),
                                        str) and obj["customer_email"]:
                            email = obj["customer_email"]
                        code = credits_module.generate_code()
                        now = utcnow_iso()
                        if pack.get("kind") == "access" and isinstance(
                                obj.get("subscription"), str):
                            # The Verifier Pass: open the
                            # subscription and land the first
                            # month's grant. The grant is keyed by
                            # the session's invoice when Stripe
                            # names one, so a replay can never
                            # double-grant (activation itself is
                            # also idempotent in the store).
                            subscription_id = obj.get("subscription")
                            invoice_id = obj.get("invoice")
                            grant_id = invoice_id \
                                if isinstance(invoice_id, str) \
                                and invoice_id else \
                                "first:" + session_id
                            row = app.store.activate_pass_subscription(
                                session_id,
                                credits_module.code_hash(code), code,
                                pack, email,
                                subscription_id
                                if isinstance(subscription_id, str)
                                else None,
                                obj.get("customer")
                                if isinstance(obj.get("customer"), str)
                                else None,
                                grant_id, now,
                                credits_module.grant_expiry(now))
                            if row is not None:
                                mailer_module.send_verifier_pass(
                                    app.mailer, email, code, pack)
                        else:
                            row = app.store.complete_credit_purchase(
                                session_id,
                                credits_module.code_hash(code), code,
                                pack, email, now)
                            if row is not None:
                                mailer_module.send_credit_code(
                                    app.mailer, email, code, pack)
                        if row is not None:
                            # Every minted code, pack or Pass,
                            # carries a personal referral code
                            # (hash-only; its plaintext rests until
                            # the one-time referral lookup delivery).
                            own_referral = credits_module \
                                .generate_code()
                            app.store.ensure_referral_code(
                                row["code_hash"],
                                credits_module.code_hash(own_referral),
                                own_referral, now)
                            # A purchase carried in with a referral
                            # code attributes here, at the buyer's
                            # first paid purchase: the referral row
                            # the store writes makes both bonuses
                            # land exactly once, so a replayed
                            # webhook grants nothing twice.
                            if purchase.get("referral_hash"):
                                app.store.attribute_referral(
                                    row["code_hash"],
                                    purchase["referral_hash"],
                                    "referee:" + row["code_hash"],
                                    "referrer:" + row["code_hash"],
                                    now,
                                    credits_module.grant_expiry(now),
                                    credits_module
                                    .REFEREE_BONUS_CHECKS,
                                    credits_module
                                    .REFERRER_BONUS_CHECKS,
                                    credits_module
                                    .REFERRAL_MONTHLY_CAP_CHECKS,
                                    referrer_link_bonus=
                                    credits_module
                                    .REFERRER_LINK_BONUS_CHECKS,
                                    referrer_link_grant_id=
                                    "referrer-link:"
                                    + row["code_hash"])
            elif etype == "invoice.paid":
                # A Pass renewal was paid. The invoice id keys the
                # grant, so a replayed delivery grants exactly
                # once; a canceled subscription grants nothing.
                # The renewal resolves through the catalog too
                # (Bayo, 2026-10-29): when the invoice names its
                # price (the 2022-08-01 shape assumed here carries
                # it at lines.data[].price.id, with the
                # subscription at the top level), the price must
                # resolve to the very pack this subscription was
                # opened under; an unknown or foreign price grants
                # nothing. An invoice naming no price keeps the
                # recorded subscription as its authority.
                subscription_id = obj.get("subscription")
                invoice_id = obj.get("id")
                if isinstance(subscription_id, str) \
                        and isinstance(invoice_id, str):
                    grant = True
                    price_id = credits_module.invoice_price_id(obj)
                    if price_id is not None:
                        priced = credits_module.pack_by_price_id(
                            app.credit_packs, price_id)
                        sub = app.store.get_subscription(
                            subscription_id)
                        grant = priced is not None \
                            and sub is not None \
                            and priced["id"] == sub["pack_id"]
                    if grant:
                        now = utcnow_iso()
                        app.store.grant_subscription_allowance(
                            subscription_id, invoice_id, now,
                            credits_module.grant_expiry(now))
            elif etype == "customer.subscription.deleted":
                # Cancellation stops future grants. Checks already
                # granted stay spendable until their expiry.
                if isinstance(session_id, str):
                    app.store.cancel_subscription(
                        session_id, utcnow_iso())
            elif etype == "checkout.session.expired" \
                    and isinstance(session_id, str):
                app.store.expire_credit_purchase(
                    session_id, utcnow_iso())
            return 200, {"received": True}

        @app.route("GET", r"^/v1/credits/checkout-status$")
        def credit_checkout_status(req):
            session_id = req.query.get("session_id")
            if not session_id:
                return errors.bad_request("session_id is required")
            purchase = app.store.get_credit_purchase(session_id)
            if purchase is None:
                return 404, {"error": "session_not_found"}
            body = {"status": purchase["status"],
                    "pack_id": purchase["pack_id"]}
            if purchase["status"] == "paid":
                pack = credits_module.find_pack(
                    app.credit_packs, purchase["pack_id"])
                if pack is not None:
                    body["checks"] = pack["checks"]
                code, _purchase = app.store.take_credit_code_delivery(
                    session_id)
                body["delivered_with_this_response"] = code is not None
                if code is not None:
                    body["code"] = code
            return 200, body

        @app.route("POST", r"^/v1/credits/redeem$")
        def credit_redeem(req):
            ok, retry_after = _credits_limited(req)
            if not ok:
                return errors.rate_limited(retry_after)
            code_hash, err = _code_from_body(req)
            if err:
                return err
            row = app.store.redeem_credit_code(
                code_hash, utcnow_iso())
            if row is None:
                return 404, {"error": "code_not_found"}
            if row["status"] == "revoked":
                return 403, {"error": "code_revoked"}
            return 200, _credit_body(row)

        @app.route("POST", r"^/v1/credits/balance$")
        def credit_balance(req):
            ok, retry_after = _credits_limited(req)
            if not ok:
                return errors.rate_limited(retry_after)
            code_hash, err = _code_from_body(req)
            if err:
                return err
            row = app.store.get_credit_code(code_hash, utcnow_iso())
            if row is None:
                return 404, {"error": "code_not_found"}
            if row["status"] == "revoked":
                return 403, {"error": "code_revoked"}
            return 200, _credit_body(row)

        @app.route("POST", r"^/v1/credits/referral/lookup$")
        def credit_referral_lookup(req):
            """Read a code's own referral code and referral record.

            The referral plaintext is delivered exactly once, the
            way the redeem code is: later lookups report the record
            (counts, this month's bonus, whether this code was
            itself referred) without the code. A code minted before
            referrals existed gets its referral code here, on
            demand."""
            ok, retry_after = _credits_limited(req)
            if not ok:
                return errors.rate_limited(retry_after)
            code_hash, err = _code_from_body(req)
            if err:
                return err
            now = utcnow_iso()
            row = app.store.get_credit_code(code_hash, now)
            if row is None:
                return 404, {"error": "code_not_found"}
            if row["status"] == "revoked":
                return 403, {"error": "code_revoked"}
            if app.store.get_referral_code_for(code_hash) is None:
                own_referral = credits_module.generate_code()
                app.store.ensure_referral_code(
                    code_hash,
                    credits_module.code_hash(own_referral),
                    own_referral, now)
            plain, _rec = app.store.take_referral_code_delivery(
                code_hash)
            stats = app.store.referral_stats(code_hash, now)
            return 200, {
                "referral_code": plain,
                "referral_code_included": plain is not None,
                "referred_count": stats["referred_count"],
                "referral_bonus_this_month":
                    stats["referral_bonus_this_month"],
                "referred_by": stats["referred_by"],
            }

        @app.route("POST", r"^/v1/credits/referral/link$")
        def credit_referral_link(req):
            """Attribute the presented code to a referral code's
            owner and land the bonuses (the store's
            attribute_referral is the exactly-once record).

            A code exists only because a paid purchase minted it,
            so linking attributes that first purchase: both sides
            are rewarded at the link itself (the referee +10, the
            referrer +10), and the referrer earns +100 more for
            that first purchase, the referrer's grants trimmed
            together at the monthly cap. Linking again, or linking
            one's own code (or a code bought under the same email),
            grants nothing."""
            ok, retry_after = _credits_limited(req)
            if not ok:
                return errors.rate_limited(retry_after)
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            code_hash, err = _code_from_body(req)
            if err:
                return err
            referral_code = req.body.get("referral_code")
            if not isinstance(referral_code, str) \
                    or not credits_module.valid_code_shape(
                        referral_code):
                return errors.bad_request(
                    "a valid referral_code is required")
            now = utcnow_iso()
            result = app.store.attribute_referral(
                code_hash, credits_module.code_hash(referral_code),
                "referee:" + code_hash, "referrer:" + code_hash,
                now, credits_module.grant_expiry(now),
                credits_module.REFEREE_BONUS_CHECKS,
                credits_module.REFERRER_BONUS_CHECKS,
                credits_module.REFERRAL_MONTHLY_CAP_CHECKS,
                referrer_link_bonus=
                credits_module.REFERRER_LINK_BONUS_CHECKS,
                referrer_link_grant_id="referrer-link:" + code_hash)
            outcome = result["outcome"]
            if outcome == "not_found":
                return 404, {"error": "code_not_found"}
            if outcome == "revoked":
                return 403, {"error": "code_revoked"}
            if outcome == "referral_not_found":
                return 404, {"error": "referral_not_found"}
            if outcome == "self_referral":
                return 200, {"outcome": "self_referral",
                             "granted": False}
            body = _credit_body(
                app.store.get_credit_code(code_hash, now))
            body["outcome"] = outcome
            body["granted"] = outcome == "linked"
            if outcome == "linked":
                body["referee_bonus_checks"] = \
                    result["referee_bonus"]
                body["referrer_bonus_checks"] = \
                    result["referrer_bonus"]
                body["referrer_link_bonus_checks"] = \
                    result["referrer_link_bonus"]
            return 200, body

        @app.route("POST", r"^/v1/credits/consume$")
        def credit_consume(req):
            """Charge one credit for one new image.

            The extension calls this only after a signature-verified
            registry answer about an image it has not charged before,
            so a failed or unreachable check never reaches this route
            and never consumes. A repeat call for the same image is
            the ledger's duplicate: answered, never charged twice.
            While the code's Verifier Pass subscription is active a
            standard charge is covered by the Pass (unlimited
            registry checks) and draws no pool; a per-code hourly
            backstop answers 429 rate_limited when a code's charged
            consumes inside the trailing hour pass the
            anti-scripting limit, an engineering guard rather than
            a usage cap.
            """
            ok, retry_after = _credits_limited(req)
            if not ok:
                return errors.rate_limited(retry_after)
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            code_hash, err = _code_from_body(req)
            if err:
                return err
            identity = req.body.get("image_identity")
            if not isinstance(identity, str) \
                    or not 1 <= len(identity) <= 160:
                return errors.bad_request(
                    "image_identity is required")
            claim_hash = req.body.get("claim_hash")
            if claim_hash is not None:
                if not isinstance(claim_hash, str) or not re.fullmatch(
                        r"[0-9a-f]{64}", claim_hash.strip().lower()):
                    return errors.bad_request(
                        "claim_hash must be 64 hex chars")
                claim_hash = claim_hash.strip().lower()
            # kind: "standard" (a registry check, the default) or
            # "ai" (an AI generation check, funded by a Verifier
            # Pass grant's AI sub-allowance first, by bonus grants
            # after it, and by the code's pack counters last).
            kind = req.body.get("kind", "standard")
            if kind not in credits_module.CHECK_KINDS:
                return errors.bad_request(
                    "kind must be \"standard\" or \"ai\"")
            result = app.store.consume_credit(
                code_hash, identity, claim_hash,
                "chg_" + uuid.uuid4().hex, utcnow_iso(), kind=kind,
                hourly_limit=credits_module.CONSUME_HOURLY_LIMIT)
            outcome = result["outcome"]
            row = result["code"]
            if outcome == "not_found":
                return 404, {"error": "code_not_found"}
            if outcome == "revoked":
                return 403, {"error": "code_revoked"}
            body = _credit_body(row)
            body["charged"] = outcome == "charged"
            body["duplicate"] = outcome == "duplicate"
            body["kind"] = kind
            if outcome == "rate_limited":
                body["error"] = "rate_limited"
                return 429, body
            if outcome in ("no_credits", "no_ai_credits"):
                body["error"] = outcome
                return 402, body
            return 200, body

        @app.route("GET", r"^/v1/products/(?P<tag_id>[^/]{1,128})$")
        @app.require_role("verifier")
        def get_product(req, tag_id):
            row = app.store.get_product(tag_id)
            if row is None:
                return errors.unknown()
            return 200, _product_body(row)

        @app.route("GET", r"^/v1/agents/(?P<agent_id>[^/]{1,128})/attestation$")
        @app.require_role("verifier")
        def get_agent_attestation(req, agent_id):
            row = app.store.get_agent(agent_id)
            if row is None:
                return errors.unknown()
            return 200, _agent_body(app.store, row)

        def _mint_attestation(req):
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

        @app.route("POST", r"^/v1/attestations$")
        @app.require_role("issuer")
        def create_attestation(req):
            return app._idempotent(req, "POST /v1/attestations",
                                   lambda: _mint_attestation(req))

        # -- public registration layer (verification-start) --------------
        # POST /v1/register/* is how a member of the public starts
        # verification of their own work, creations, and agents. These
        # endpoints are deliberately unauthenticated: registration is
        # free and open. The abuse minimums are the required email, the
        # per-email and per-IP caps counted in the store layer, and the
        # server-wide body cap. Registration is NOT verification: the
        # minted records say "registered, checks pending", list the
        # checks that ran at intake and those that have not, and carry
        # no verdict and no verification mark. Shapes, intake checks,
        # and signing live in npc_verify.registry.
        #
        # Content registration runs two cap lanes (Bayo, 2026-11-01;
        # the tier table and resolver live in npc_verify.registry):
        # the OPERATOR lane — a request carrying a valid issuer-role
        # API key is NPC's own submission and skips the public caps
        # entirely — and the PUBLIC lane, tiered per email with an
        # IP abuse floor. Agent registration keeps the flat caps.

        def _register_content_impl(req):
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            problems = registry.validate_content_input(req.body)
            if problems:
                return errors.unprocessable("; ".join(problems))
            email = req.body["creator_email"].strip().lower()
            # Operator lane: the API key is the credential, never
            # the unauthenticated creator_email. An absent or
            # invalid key is not an error on this public endpoint;
            # it simply stays on the public lane.
            key = app.auth.authenticate(req.headers)
            if key is None or not Auth.allows(key, "issuer"):
                tier = registry.registration_tier_for_email(
                    app.store, email)
                capped = registry.content_cap_status(
                    app.store, email, req.client_ip, utcnow_iso(),
                    tier)
                if capped is not None:
                    return errors.rate_limited(
                        capped["retry_after_seconds"])
            checks_run, checks_not_run = registry.run_content_intake(
                app.detector, app.fetcher, req.body["kind"],
                req.body["locator"],
                source=registry.normalize_source(
                    req.body.get("source")))
            rec = registry.mint_content_registration(
                app.store, app.keys, req.body, checks_run, checks_not_run,
                email, req.client_ip)
            # Lifecycle email (fails soft inside the mailer): the
            # registrant gets their record ID and its public link.
            mailer_module.send_registration_confirmation(
                app.mailer, rec, email)
            return 201, rec

        @app.route("POST", r"^/v1/register/content$")
        def register_content(req):
            return app._idempotent(
                req, "POST /v1/register/content",
                lambda: _register_content_impl(req))

        def _register_agent_impl(req):
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            problems = registry.validate_agent_input(req.body)
            if problems:
                return errors.unprocessable("; ".join(problems))
            email = req.body["owner_email"].strip().lower()
            hit = registry.cap_exceeded(app.store, email, req.client_ip,
                                        utcnow_iso())
            if hit:
                return errors.rate_limited(3600)
            rec = registry.mint_agent_registration(
                app.store, app.keys, req.body, email, req.client_ip)
            mailer_module.send_registration_confirmation(
                app.mailer, rec, email)
            return 201, rec

        @app.route("POST", r"^/v1/register/agent$")
        def register_agent(req):
            return app._idempotent(
                req, "POST /v1/register/agent",
                lambda: _register_agent_impl(req))

        @app.route("GET", r"^/v1/records/(?P<id>[^/]{1,128})$")
        def get_record(req, id):
            """The signed record for any API-issued ID (PUBLIC).

            Registrations return the signed record minted at issuance.
            Existing record types return exactly the body their own
            endpoint returns, so Search has one resolution path for
            every NPC ID. While the social profiles lane is enabled,
            its signed batch receipts (npc.social.registration_batch)
            resolve here too, as the stored signed record; with the
            lane off a receipt ID answers exactly as it did before
            the lane existed. Unknown IDs fail closed.
            """
            rec = app.store.get_registration(id)
            if rec is not None:
                # The onchain anchor section is read-time metadata,
                # like the KYA block on agent records: the stored
                # signed record is never edited. With the anchor
                # lane off and no anchor data on record, the section
                # is absent and the answer is byte-identical to
                # before the lane existed.
                section = anchor_module.anchor_section(
                    app.store, id, app.anchor_config.enabled,
                    cfg=app.anchor_config)
                if section is not None:
                    body = dict(rec)
                    body["anchor"] = section
                    return 200, body
                return 200, rec
            row = app.store.get_credential(id)
            if row is not None:
                return 200, _credential_body(row)
            row = app.store.get_product(id)
            if row is not None:
                return 200, _product_body(row)
            row = app.store.get_agent(id)
            if row is not None:
                return 200, _agent_body(app.store, row)
            row = app.store.get_attestation(id)
            if row is not None:
                return 200, _attestation_body(app.store, row)
            consent = app.store.get_pact_consent(id) \
                or app.store.get_pact_consent_by_record_id(id)
            if consent is not None:
                return 200, consent
            if social_module.social_enabled():
                batch = app.store.get_social_batch(id)
                if batch is not None:
                    return 200, batch
            return errors.unknown()

        # -- onchain anchoring (internal trigger) -------------------------
        # The anchor engine (npc_verify.anchor) batches unanchored
        # registrations and writes their Merkle root to Base. It runs
        # when an issuer calls the run endpoint; the scheduled caller
        # is whatever cron the operator points at it (the deploy
        # runbook names the fleet scheduler). One pass per call:
        # finalize an open batch or prepare and submit the next. The
        # summary answers honestly in every state, including disabled
        # and unfunded, so a scheduled caller can log the truth.
        @app.route("POST", r"^/v1/internal/anchor/run$")
        @app.require_role("issuer")
        def anchor_run(req):
            return 200, anchor_module.run_anchor_pass(
                app.store, app.anchor_chain, app.anchor_config,
                utcnow_iso())

        @app.route("GET", r"^/v1/internal/anchor/status$")
        @app.require_role("issuer")
        def anchor_status(req):
            return 200, anchor_module.anchor_status(
                app.store, app.anchor_chain, app.anchor_config)

        # The signer half of the flow: a prepared batch waits for
        # the signer wallet's signature (Bayo signs the commitment
        # statement in MetaMask). The signature is recorded only
        # when it recovers to the currently authorized signer; the
        # next run pass then submits the batch from the owner
        # wallet. The summary states answer honestly.
        @app.route("POST", r"^/v1/internal/anchor/sign$")
        @app.require_role("issuer")
        def anchor_sign(req):
            if not isinstance(req.body, dict):
                return 400, {
                    "error": "invalid_signature",
                    "detail": "The body must carry batch_id and "
                              "signature."}
            out = anchor_module.record_batch_signature(
                app.store, app.anchor_config,
                str(req.body.get("batch_id") or ""),
                str(req.body.get("signature") or ""))
            if out["status"] == "signed":
                return 200, out
            if out["status"] == "unknown_batch":
                return 404, dict(out, error="unknown_batch")
            return 400, dict(out, error=out["status"])

        # Signer rotation: the OWNER wallet (the fresh server
        # wallet, the sole rotation authority) rotates the signer
        # by signing a rotation notice. The endpoint builds the
        # notice and signs it with the owner key server-side; the
        # recorded notice is the inspectable event, also served
        # publicly at GET /v1/anchor/authority. A compromised
        # signer cannot rotate itself: that takes the owner key,
        # which never leaves the Lambda environment.
        @app.route("POST", r"^/v1/internal/anchor/rotate-signer$")
        @app.require_role("issuer")
        def anchor_rotate_signer(req):
            cfg = app.anchor_config
            if cfg.private_key is None:
                return 409, {
                    "error": "owner_not_configured",
                    "detail": "No owner key is configured on this "
                              "deployment, so no rotation can be "
                              "signed. Nothing was recorded."}
            if not isinstance(req.body, dict):
                return 400, {
                    "error": "invalid_rotation",
                    "detail": "The body must carry "
                              "to_signer_address."}
            from .ethkeys import is_valid_address, \
                to_checksum_address
            to_signer = req.body.get("to_signer_address")
            if not isinstance(to_signer, str) \
                    or not is_valid_address(to_signer):
                return 400, {
                    "error": "invalid_rotation",
                    "detail": "to_signer_address is not a valid "
                              "Ethereum address. Nothing was "
                              "recorded."}
            current = anchor_module.authorized_signer(
                app.store, cfg)
            if to_checksum_address(to_signer) == current:
                return 400, {
                    "error": "invalid_rotation",
                    "detail": "That address is already the "
                              "authorized signer. Nothing was "
                              "recorded."}
            notice = anchor_module.build_signer_rotation(
                cfg.private_key, current,
                to_checksum_address(to_signer), utcnow_iso(),
                note=req.body.get("note"))
            if not anchor_module.verify_signer_rotation(
                    notice, cfg.address):
                # The builder and the verifier disagreeing is a
                # code fault, never a recorded rotation.
                return 500, {
                    "error": "rotation_self_check_failed",
                    "detail": "The rotation notice did not verify "
                              "against the owner wallet. Nothing "
                              "was recorded."}
            notice_id = anchor_module.rotation_notice_id(notice)
            app.store.add_anchor_rotation(
                notice_id, notice, utcnow_iso())
            return 200, {
                "status": "recorded",
                "notice_id": notice_id,
                "notice": notice,
                "authorized_signer": notice["to_signer"],
                "detail": "The signer rotation is recorded and "
                          "owner-signed. Batches signed by the "
                          "previous signer stay provable against "
                          "the rotation history."}

        # The public authority statement: who submits (the owner
        # wallet), who signs (the authorized signer), and the
        # complete owner-signed rotation history. Public because
        # the authority claim must be inspectable by the same
        # people who check anchor proofs. With the lane off there
        # is no authority to state, and the answer fails closed
        # like any unknown resource.
        @app.route("GET", r"^/v1/anchor/authority$")
        def anchor_authority(req):
            if not app.anchor_config.enabled:
                return errors.unknown()
            return 200, anchor_module.authority_block(
                app.store, app.anchor_config)

        # -- Request verification (cycle completion, 2026-10-15) ---------
        # Step two of the self-serve cycle: the registrant asks NPC
        # to verify their own record. Registration records are
        # immutable, so the request is its own signed record in a
        # queryable store partition (NPC's step-two work queue),
        # never an edit to the record. A wrong email and an unknown
        # ID get the identical signed "unknown" answer, so the
        # endpoint leaks nothing about which IDs exist beyond what
        # the public record endpoint already shows. Attempts are
        # counted before the match, so probing is capped exactly
        # like registering.
        @app.route("POST",
                   r"^/v1/records/(?P<id>[^/:]{1,128})"
                   r":request-verification$")
        def request_verification(req, id):
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            problems = registry.validate_verification_request_input(
                req.body)
            if problems:
                return errors.unprocessable("; ".join(problems))
            email = req.body["email"].strip().lower()
            now = utcnow_iso()
            hit = registry.verification_request_cap_exceeded(
                app.store, email, req.client_ip, now)
            if hit:
                return errors.rate_limited(3600)
            matched = registry.verification_request_email_matches(
                app.store, id, email)
            app.store.record_verification_request_attempt(
                id, email, req.client_ip, matched, now)
            if not matched:
                return errors.unknown()
            subject = app.store.get_registration(id)
            rec, created = registry.mint_verification_request(
                app.store, app.keys, subject, email, req.client_ip)
            if created:
                # Lifecycle email (fails soft): only on a NEW
                # request, so repeats never spam the registrant.
                mailer_module.send_verification_request_received(
                    app.mailer, subject, rec, email)
            return (201 if created else 200), rec

        @app.route("GET",
                   r"^/v1/records/(?P<id>[^/]{1,128})"
                   r"/verification-request$")
        def get_verification_request(req, id):
            """Public read of a registration's request state, so the
            record view can show "Verification requested". Unknown
            and non-registration IDs fail closed, same answer."""
            if app.store.get_registration(id) is None:
                return errors.unknown()
            request = app.store.get_verification_request(id)
            return 200, {
                "record_id": id,
                "verification_requested": request is not None,
                "requested_at": request["requested_at"]
                if request else None,
                "request": request,
            }

        # -- Federated identity linking (phase 1, 2026-10-19) ------------
        # The linking service behind the registry's identity_signals
        # block (design: integrations/federated-identity-signals-
        # DESIGN-2026-10-19.md). Every route here is gated by the
        # same NPC_IDENTITY_SIGNALS=1 flag: with the flag off the
        # service answers a clear 503 rather than signing claims it
        # cannot stand behind. Owner-driven POSTs prove record
        # ownership exactly like request-verification (the
        # registration email, compared by hash, attempts counted
        # before the match under the same caps), and a wrong email
        # and an unknown ID get the identical signed "unknown"
        # answer. A completed link is its own signed record; the
        # registration is never edited and no status changes.

        def _identity_gate(req, id):
            """Returns (error, subject, email): on success error is
            None and subject is the registration record."""
            if not linking_module.linking_enabled():
                return errors.unavailable(
                    "identity_linking_not_enabled",
                    "identity linking is not enabled on this "
                    "deployment"), None, None
            if not isinstance(req.body, dict):
                return errors.bad_request(
                    "JSON object body required"), None, None
            problems = registry.validate_verification_request_input(
                req.body)
            if problems:
                return errors.unprocessable(
                    "; ".join(problems)), None, None
            email = req.body["email"].strip().lower()
            now = utcnow_iso()
            hit = linking_module.link_cap_exceeded(
                app.store, email, req.client_ip, now)
            if hit:
                return errors.rate_limited(3600), None, None
            matched = linking_module.email_matches_record(
                app.store, id, email)
            app.store.record_identity_link_attempt(
                id, email, req.client_ip, matched, now)
            if not matched:
                return errors.unknown(), None, None
            return None, app.store.get_registration(id), email

        def _link_not_configured(provider):
            return errors.unavailable(
                "identity_linking_not_configured",
                "the %s link is not configured on this deployment"
                % provider)

        def _siwe_challenge_impl(req, id):
            err, subject, email = _identity_gate(req, id)
            if err is not None:
                return err
            wallet = req.body.get("wallet_address")
            if not linking_module.valid_wallet(wallet):
                return errors.unprocessable(
                    "wallet_address must be a valid Ethereum "
                    "address")
            out = linking_module.start_siwe_challenge(
                app.store, subject, email, wallet, utcnow_iso())
            return 201, {"record_id": id, "challenge": out}

        @app.route("POST",
                   r"^/v1/records/(?P<id>[^/]{1,128})"
                   r"/identity-links/siwe/challenge$")
        def siwe_challenge(req, id):
            return app._idempotent(
                req, "POST /v1/records/%s/identity-links/siwe/"
                "challenge" % id,
                lambda: _siwe_challenge_impl(req, id))

        def _siwe_verify_impl(req, id):
            err, subject, _email = _identity_gate(req, id)
            if err is not None:
                return err
            challenge_id = req.body.get("challenge_id")
            message = req.body.get("message")
            signature = req.body.get("signature")
            if not isinstance(challenge_id, str) \
                    or not isinstance(message, str) \
                    or not isinstance(signature, str):
                return errors.bad_request(
                    "challenge_id, message, and signature are "
                    "required strings")
            rec, problems = linking_module.complete_siwe(
                app.store, app.keys, subject, challenge_id, message,
                signature, utcnow_iso())
            if problems:
                return errors.unprocessable("; ".join(problems))
            return 201, {"record_id": id, "link": rec,
                         "signal": rec["signal"]}

        @app.route("POST",
                   r"^/v1/records/(?P<id>[^/]{1,128})"
                   r"/identity-links/siwe/verify$")
        def siwe_verify(req, id):
            return app._idempotent(
                req, "POST /v1/records/%s/identity-links/siwe/"
                "verify" % id,
                lambda: _siwe_verify_impl(req, id))

        def _oauth_start_impl(req, id, provider):
            err, subject, email = _identity_gate(req, id)
            if err is not None:
                return err
            out, problems = linking_module.start_oauth(
                app.store, provider, subject, email, utcnow_iso())
            if problems:
                return _link_not_configured(provider)
            return 201, dict({"record_id": id}, **out)

        @app.route("POST",
                   r"^/v1/records/(?P<id>[^/]{1,128})"
                   r"/identity-links/(?P<provider>github|google)"
                   r"/start$")
        def oauth_start(req, id, provider):
            return app._idempotent(
                req, "POST /v1/records/%s/identity-links/%s/start"
                % (id, provider),
                lambda: _oauth_start_impl(req, id, provider))

        @app.route("GET",
                   r"^/v1/link/(?P<provider>github|google)"
                   r"/callback$")
        def oauth_callback(req, provider):
            """The browser landing for an OAuth link. The state is
            consumed before the token exchange, so a callback can
            never be replayed, whatever its outcome."""
            if not linking_module.linking_enabled():
                return errors.unavailable(
                    "identity_linking_not_enabled",
                    "identity linking is not enabled on this "
                    "deployment")
            code = req.query.get("code")
            state = req.query.get("state")
            if not code or not state:
                return errors.bad_request(
                    "code and state query parameters are required")
            rec, problems = linking_module.complete_oauth(
                app.store, app.keys, provider, code, state,
                app.link_http, utcnow_iso())
            if problems:
                if problems == ["not_configured"]:
                    return _link_not_configured(provider)
                return errors.unprocessable("; ".join(problems))
            return 200, {
                "linked": True,
                "record_id": rec["subject_record_id"],
                "link_record_id": rec["record_id"],
                "provider": provider,
                "signal": rec["signal"],
            }

        def _coinbase_refresh_impl(req, id):
            err, subject, _email = _identity_gate(req, id)
            if err is not None:
                return err
            summary = linking_module.refresh_coinbase(
                app.store, app.keys, subject, app.coinbase_reader,
                utcnow_iso())
            return 200, {"record_id": id, "observations": summary}

        @app.route("POST",
                   r"^/v1/records/(?P<id>[^/]{1,128})"
                   r"/identity-links/coinbase/refresh$")
        def coinbase_refresh(req, id):
            return app._idempotent(
                req, "POST /v1/records/%s/identity-links/coinbase/"
                "refresh" % id,
                lambda: _coinbase_refresh_impl(req, id))

        @app.route("GET",
                   r"^/v1/records/(?P<id>[^/]{1,128})"
                   r"/identity-panel$")
        def identity_panel(req, id):
            """The "Identity the owner has linked" panel data for a
            registration: the drafted labels and boundary line, the
            signals grouped by assurance class at their current
            observed state, and the links that no longer count.
            Unknown IDs fail closed, same answer as everywhere."""
            if not linking_module.linking_enabled():
                return errors.unavailable(
                    "identity_linking_not_enabled",
                    "identity linking is not enabled on this "
                    "deployment")
            subject = app.store.get_registration(id)
            if subject is None:
                return errors.unknown()
            return 200, linking_module.build_identity_panel(
                app.store, subject, utcnow_iso())

        # -- Social profiles lane (build pass 1, 2026-10-19) ------------
        # Owners connect a social profile (read-only OAuth) and
        # register the content on it as signed records, plus the
        # connection-less X permalink and Spotify catalog lanes.
        # Every route is gated by NPC_SOCIAL_PROFILES=1; with the
        # flag off the lane answers a clean 503 and nothing about
        # the rest of the API changes. The connect callback carries
        # no owner proof in the browser redirect, so its handler
        # result rides a signed JSON response, the same deviation
        # as the Phase 1 linking callbacks. Owner-driven POSTs
        # prove ownership by matching the connection's stored
        # email hash, behind attempts counted before the match
        # under the registry caps: a wrong email and an unknown
        # connection are the same signed 404.
        def _social_flag_gate():
            if not social_module.social_enabled():
                return errors.unavailable(
                    "social_profiles_not_enabled",
                    "social profile registration is not enabled "
                    "on this deployment")
            return None

        def _social_not_configured(platform):
            return errors.unavailable(
                "social_profiles_not_configured",
                "the %s lane is not configured on this deployment"
                % platform)

        def _social_email_problems(body):
            if not isinstance(body, dict):
                return ["request body must be a JSON object"]
            return registry.validate_verification_request_input(
                {"email": body.get("email")})

        def _social_creator_name(body):
            name = body.get("creator_name")
            if not isinstance(name, str) or not name.strip() \
                    or len(name.strip()) > 128:
                return None
            return name.strip()

        def _social_connection_gate(req, id):
            """(error, connection_row, email): the flag gate, the
            body and caps gates, then the ownership match. The
            attempt is recorded before the match, and a mismatch is
            the storefront unknown."""
            gate = _social_flag_gate()
            if gate is not None:
                return gate, None, None
            body = req.body if isinstance(req.body, dict) else {}
            problems = _social_email_problems(body)
            if problems:
                return errors.unprocessable(problems), None, None
            email = body["email"].strip().lower()
            now = utcnow_iso()
            capped = social_module.social_cap_exceeded(
                app.store, email, req.client_ip, now)
            if capped:
                return errors.cap(capped), None, None
            conn = app.store.get_social_connection(id)
            matched = conn is not None \
                and conn.get("status") == "active" \
                and conn.get("email_hash") == \
                _email_hash_of(email)
            app.store.record_social_attempt(
                id, email, req.client_ip, matched, now)
            if not matched:
                return errors.unknown(), None, None
            return None, conn, email

        @app.route("POST",
                   r"^/v1/social/(?P<platform>youtube|instagram"
                   r"|tiktok)/connect/start$")
        def social_connect_start(req, platform):
            def _impl():
                gate = _social_flag_gate()
                if gate is not None:
                    return gate
                body = req.body if isinstance(req.body, dict) \
                    else {}
                problems = _social_email_problems(body)
                if problems:
                    return errors.unprocessable(problems)
                email = body["email"].strip().lower()
                now = utcnow_iso()
                capped = social_module.social_cap_exceeded(
                    app.store, email, req.client_ip, now)
                if capped:
                    return errors.cap(capped)
                app.store.record_social_attempt(
                    "connect:" + platform, email, req.client_ip,
                    True, now)
                out, problems = social_module.start_connect(
                    app.store, platform, email, now)
                if problems == ["not_configured"]:
                    return _social_not_configured(platform)
                if problems:
                    return errors.unprocessable(problems)
                return 201, out
            return app._idempotent(
                req, "POST /v1/social/%s/connect/start" % platform,
                _impl)

        @app.route("GET",
                   r"^/v1/social/(?P<platform>youtube|instagram"
                   r"|tiktok)/callback$")
        def social_callback(req, platform):
            params = req.query or {}
            code = params.get("code", "")
            state = params.get("state", "")
            if not code or not state:
                return errors.unprocessable(
                    ["the platform did not return a code and "
                     "state"])
            conn, problems = social_module.complete_connect(
                app.store, platform, code, state, app.link_http,
                utcnow_iso())
            if problems:
                return errors.unprocessable(problems)
            return 201, {"connection": conn}

        @app.route("POST", r"^/v1/social/connections/list$")
        def social_connections_list(req):
            def _impl():
                gate = _social_flag_gate()
                if gate is not None:
                    return gate
                body = req.body if isinstance(req.body, dict) \
                    else {}
                problems = _social_email_problems(body)
                if problems:
                    return errors.unprocessable(problems)
                email = body["email"].strip().lower()
                now = utcnow_iso()
                capped = social_module.social_cap_exceeded(
                    app.store, email, req.client_ip, now)
                if capped:
                    return errors.cap(capped)
                email_hash = _email_hash_of(email)
                app.store.record_social_attempt(
                    "connections", email, req.client_ip, True, now)
                rows = app.store.list_social_connections(email_hash)
                return 200, {"connections": [
                    social_module.connection_public(r) for r in rows]}
            return app._idempotent(
                req, "POST /v1/social/connections/list", _impl)

        @app.route("POST",
                   r"^/v1/social/connections/(?P<id>[^/]{1,128})"
                   r"/scan$")
        def social_connection_scan(req, id):
            def _impl():
                error, conn, _email = _social_connection_gate(
                    req, id)
                if error is not None:
                    return error
                summary, problems = social_module.scan_connection(
                    app.store, conn, app.link_http, utcnow_iso())
                if problems:
                    return errors.unavailable(
                        "social_platform_read_failed", problems[0])
                return 201, summary
            return app._idempotent(
                req, "POST /v1/social/connections/%s/scan" % id,
                _impl)

        @app.route("POST",
                   r"^/v1/social/connections/(?P<id>[^/]{1,128})"
                   r"/register$")
        def social_connection_register(req, id):
            def _impl():
                error, conn, email = _social_connection_gate(req, id)
                if error is not None:
                    return error
                body = req.body if isinstance(req.body, dict) \
                    else {}
                creator_name = _social_creator_name(body)
                if creator_name is None:
                    return errors.unprocessable(
                        ["creator_name is required (string, max "
                         "128 chars)"])
                scan_id = body.get("scan_id")
                if not isinstance(scan_id, str) or not scan_id:
                    return errors.unprocessable(
                        ["scan_id is required"])
                selected = body.get("external_ids")
                if selected is not None:
                    if not isinstance(selected, list) or any(
                            not isinstance(v, str)
                            for v in selected):
                        return errors.unprocessable(
                            ["external_ids must be a list of "
                             "strings"])
                batch, summary, problems = \
                    social_module.register_scan(
                        app.store, app.keys, conn, scan_id, email,
                        creator_name, req.client_ip, selected,
                        utcnow_iso())
                if problems == ["unknown_scan"]:
                    return errors.unknown()
                if problems:
                    return errors.unprocessable(problems)
                return 201, {"batch": batch, "summary": summary}
            return app._idempotent(
                req, "POST /v1/social/connections/%s/register" % id,
                _impl)

        @app.route("POST",
                   r"^/v1/social/connections/(?P<id>[^/]{1,128})"
                   r"/disconnect$")
        def social_connection_disconnect(req, id):
            def _impl():
                error, conn, _email = _social_connection_gate(
                    req, id)
                if error is not None:
                    return error
                return 200, social_module.disconnect(
                    app.store, conn, app.link_http, utcnow_iso())
            return app._idempotent(
                req, "POST /v1/social/connections/%s/disconnect" % id,
                _impl)

        @app.route("POST",
                   r"^/v1/social/connections/(?P<id>[^/]{1,128})"
                   r"/overview$")
        def social_connection_overview(req, id):
            """The read side of the lane for one connection: its
            public view, last scan, and registration outcomes,
            behind the same ownership gate as scan and register.
            Read-only: it never reads a platform and never mints."""
            def _impl():
                error, conn, _email = _social_connection_gate(
                    req, id)
                if error is not None:
                    return error
                return 200, social_module.build_connection_overview(
                    app.store, conn)
            return app._idempotent(
                req, "POST /v1/social/connections/%s/overview" % id,
                _impl)

        def _social_manual_gate(req, target):
            """(error, email, creator_name) for the two lanes with
            no connection (X permalinks, Spotify references). The
            caller's email is the registrations' owner key, the
            same trust level as the public registration form,
            counted under the lane caps."""
            gate = _social_flag_gate()
            if gate is not None:
                return gate, None, None
            body = req.body if isinstance(req.body, dict) else {}
            problems = _social_email_problems(body)
            if problems:
                return errors.unprocessable(problems), None, None
            creator_name = _social_creator_name(body)
            if creator_name is None:
                return errors.unprocessable(
                    ["creator_name is required (string, max 128 "
                     "chars)"]), None, None
            email = body["email"].strip().lower()
            now = utcnow_iso()
            capped = social_module.social_cap_exceeded(
                app.store, email, req.client_ip, now)
            if capped:
                return errors.cap(capped), None, None
            app.store.record_social_attempt(
                target, email, req.client_ip, True, now)
            return None, email, creator_name

        @app.route("POST", r"^/v1/social/x/register$")
        def social_x_register(req):
            def _impl():
                error, email, creator_name = _social_manual_gate(
                    req, "x")
                if error is not None:
                    return error
                body = req.body if isinstance(req.body, dict) \
                    else {}
                permalinks = body.get("permalinks")
                if not isinstance(permalinks, list) \
                        or not permalinks:
                    return errors.unprocessable(
                        ["permalinks is required (a non-empty "
                         "list)"])
                batch, summary = \
                    social_module.register_x_permalinks(
                        app.store, app.keys, email, creator_name,
                        req.client_ip, permalinks, utcnow_iso())
                return 201, {"batch": batch, "summary": summary}
            return app._idempotent(
                req, "POST /v1/social/x/register", _impl)

        @app.route("POST", r"^/v1/social/spotify/register$")
        def social_spotify_register(req):
            def _impl():
                error, email, creator_name = _social_manual_gate(
                    req, "spotify")
                if error is not None:
                    return error
                body = req.body if isinstance(req.body, dict) \
                    else {}
                references = body.get("references")
                if not isinstance(references, list) \
                        or not references:
                    return errors.unprocessable(
                        ["references is required (a non-empty "
                         "list)"])
                batch, summary, problems = \
                    social_module.register_spotify_references(
                        app.store, app.keys, email, creator_name,
                        req.client_ip, references, app.link_http,
                        utcnow_iso())
                if problems == ["not_configured"]:
                    return _social_not_configured("spotify")
                if problems:
                    return errors.unprocessable(problems)
                return 201, {"batch": batch, "summary": summary}
            return app._idempotent(
                req, "POST /v1/social/spotify/register", _impl)

        # -- Biblo site chat (biblo-chat-SPEC-2026-10-15.md) --------------
        # Public, no API key, and UNSIGNED: chat is never a record, so
        # its responses carry no signature headers. The flow lives in
        # npc_verify.chat (grounded generation over the public corpus,
        # spend governor, per-IP and per-thread caps). Both POSTs ride
        # the Idempotency-Key wrapper like the other public POSTs; the
        # stored body is re-wrapped as unsigned on replay.
        @app.route("POST", r"^/v1/chat$")
        def chat_turn(req):
            status, body = app._idempotent(
                req, "POST /v1/chat",
                lambda: app.chat.post_chat(req.body,
                                           req.client_ip))
            return status, UnsignedBody(body)

        @app.route("POST", r"^/v1/chat/feedback$")
        def chat_feedback(req):
            status, body = app._idempotent(
                req, "POST /v1/chat/feedback",
                lambda: app.chat.post_feedback(req.body))
            return status, UnsignedBody(body)

        # -- PACT record layer (flywheel #73) ----------------------------
        # NPC's extension records for PACT delegated grants: the consent
        # record PACT never defines, the hash-chained audit log fed by
        # section 5.6 receipts, and the revocation + signed status read
        # that give section 5.5's check something to read. NPC is its
        # own first Provider here: these endpoints are the surface that
        # mints, appends, revokes, and reads. Shapes and verification
        # live in npc_verify.pact; the format profile is
        # trust-tab/pact-record-layer-PROFILE-DRAFT.md (internal draft).

        @app.route("POST", r"^/v1/pact/grants$")
        @app.require_role("issuer")
        def pact_create_grant(req):
            """Grant issuance: mint the signed Consent Record.

            The record preserves scopes_requested vs scopes_granted
            exactly as approved at the consent ceremony, so what the
            user withheld stays visible in a portable signed artifact.
            """
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            problems = pact.validate_consent_input(req.body)
            if problems:
                return errors.unprocessable("; ".join(problems))
            rec = pact.mint_consent_record(app.store, app.keys, req.body)
            if rec is None:
                return errors.conflict(
                    "a consent record already exists for this grant_id")
            return 201, rec

        @app.route("POST",
                   r"^/v1/pact/grants/(?P<grant_id>[^/]{1,128})/receipts$")
        @app.require_role("issuer")
        def pact_append_receipt(req, grant_id):
            """Append one Provider receipt to the grant's audit log."""
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            claims = req.body.get("receipt")
            if not isinstance(claims, dict):
                return errors.bad_request(
                    "body must carry the receipt claims object as "
                    "'receipt'")
            if app.store.get_pact_consent(grant_id) is None:
                return errors.unknown()
            claimed = claims.get("grantId")
            if claimed is not None and claimed != grant_id:
                return errors.unprocessable(
                    "receipt grantId does not match the path grant_id")
            entry = pact.append_receipt(app.store, app.keys, grant_id,
                                        claims, ts=req.body.get("ts"))
            if entry is None:
                return errors.conflict(
                    "audit log append conflicted; retry the append")
            return 201, entry

        @app.route("GET", r"^/v1/pact/grants/(?P<grant_id>[^/]{1,128})/audit$")
        @app.require_role("verifier")
        def pact_get_audit(req, grant_id):
            """The grant's audit trail, with live chain verification."""
            if app.store.get_pact_consent(grant_id) is None:
                return errors.unknown()
            entries = app.store.pact_audit_entries(grant_id)
            ok, detail = pact.verify_audit_chain(app.keys, entries)
            return 200, {
                "grant_id": grant_id,
                "entries": entries,
                "chain": {"valid": ok, "detail": detail,
                          "entries": len(entries)},
            }

        @app.route("POST",
                   r"^/v1/pact/grants/(?P<grant_id>[^/]{1,128}):revoke$")
        @app.require_role("issuer")
        def pact_revoke_grant(req, grant_id):
            """Revoke a grant: a new signed record, never an edit."""
            if not isinstance(req.body, dict):
                return errors.bad_request("JSON object body required")
            revoked_by = req.body.get("revoked_by")
            reason = req.body.get("reason")
            if not isinstance(revoked_by, str) or not revoked_by \
                    or len(revoked_by) > 128:
                return errors.bad_request(
                    "revoked_by is required (string, max 128 chars)")
            if not isinstance(reason, str) or not reason \
                    or len(reason) > 1000:
                return errors.bad_request(
                    "reason is required (string, max 1000 chars)")
            if app.store.get_pact_consent(grant_id) is None:
                return errors.unknown()
            rec = pact.revoke_grant(app.store, app.keys, grant_id,
                                    revoked_by, reason)
            if rec is None:
                return errors.conflict("grant is already revoked")
            return 201, rec

        @app.route("GET",
                   r"^/v1/pact/grants/(?P<grant_id>[^/]{1,128})/status$")
        @app.require_role("verifier")
        def pact_get_status(req, grant_id):
            """Signed status read: active / revoked / expired.

            The body IS the signed npc.pact.grant_status record, so a
            receipt-holder can verify it offline against /v1/keys,
            independent of this response's envelope signature.
            """
            rec = pact.grant_status_record(app.store, app.keys, grant_id)
            if rec is None:
                return errors.unknown()
            return 200, rec

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

        # -- unified accounts (Gate G1, npc_verify.accounts) -----------
        # One account per person, rooted at an email address:
        # passkeys first, one-time email links as the anchor and
        # fallback, recovery codes from the first enrollment,
        # revocable device sessions on every surface, and the
        # desktop app's browser handoff. These routes authenticate
        # with the account session token, never with an API key:
        # the two credential families stay separate by design, and
        # a session token presented to a key route (or the reverse)
        # simply does not authenticate.

        def _bearer(req):
            header = req.headers.get("authorization") or ""
            if header.lower().startswith("bearer "):
                return header[7:].strip()
            return ""

        def _account_ctx(req):
            token = _bearer(req)
            if not token:
                return None
            return app.accounts.authenticate(token)

        def _auth_limited(req, bucket, per_minute):
            key = "auth-%s:%s" % (bucket, req.client_ip or "unknown")
            app.limiter.set_limit(key, per_minute)
            return app.limiter.allowed(key)

        def _account_call(fn):
            try:
                return 200, fn()
            except accounts_module.AccountError as exc:
                return exc.status, exc.body

        @app.route("GET", r"^/auth/sign-in$")
        def auth_sign_in_page(req):
            return 200, HtmlBody(signin_page_module.render_signin_page())

        @app.route("POST", r"^/v1/auth/email/request$")
        def auth_email_request(req):
            if not _auth_limited(req, "email", 20):
                return errors.rate_limited(60)
            body = req.body or {}
            return _account_call(lambda: app.accounts.request_email_link(
                body.get("email"), handoff_id=body.get("handoff_id")))

        @app.route("POST", r"^/v1/auth/email/redeem$")
        def auth_email_redeem(req):
            if not _auth_limited(req, "email-redeem", 30):
                return errors.rate_limited(60)
            body = req.body or {}
            return _account_call(lambda: app.accounts.redeem_email_link(
                body.get("token"), surface=body.get("surface") or "web",
                device_label=body.get("device_label") or ""))

        @app.route("POST", r"^/v1/auth/passkeys/register/begin$")
        def auth_passkey_register_begin(req):
            ctx = _account_ctx(req)
            if ctx is None:
                return errors.unauthorized()
            account, _session = ctx
            return _account_call(
                lambda: app.accounts.begin_passkey_registration(account))

        @app.route("POST", r"^/v1/auth/passkeys/register/finish$")
        def auth_passkey_register_finish(req):
            ctx = _account_ctx(req)
            if ctx is None:
                return errors.unauthorized()
            account, _session = ctx
            body = dict(req.body or {})
            challenge_id = body.pop("challenge_id", "")
            return _account_call(
                lambda: app.accounts.finish_passkey_registration(
                    account, challenge_id, body))

        @app.route("POST", r"^/v1/auth/passkeys/authenticate/begin$")
        def auth_passkey_auth_begin(req):
            if not _auth_limited(req, "passkey-begin", 60):
                return errors.rate_limited(60)
            body = req.body or {}
            return _account_call(
                lambda: app.accounts.begin_passkey_authentication(
                    email=body.get("email") or None))

        @app.route("POST", r"^/v1/auth/passkeys/authenticate/finish$")
        def auth_passkey_auth_finish(req):
            if not _auth_limited(req, "passkey-finish", 60):
                return errors.rate_limited(60)
            body = dict(req.body or {})
            challenge_id = body.pop("challenge_id", "")
            surface = body.pop("surface", None) or "web"
            device_label = body.pop("device_label", None) or ""
            handoff_id = body.pop("handoff_id", None)
            return _account_call(
                lambda: app.accounts.finish_passkey_authentication(
                    challenge_id, body, surface=surface,
                    device_label=device_label, handoff_id=handoff_id))

        @app.route("POST", r"^/v1/auth/recovery/redeem$")
        def auth_recovery_redeem(req):
            if not _auth_limited(req, "recovery", 10):
                return errors.rate_limited(60)
            body = req.body or {}
            return _account_call(
                lambda: app.accounts.redeem_recovery_code(
                    body.get("email"), body.get("code"),
                    surface=body.get("surface") or "web",
                    device_label=body.get("device_label") or ""))

        @app.route("GET", r"^/v1/auth/me$")
        def auth_me(req):
            ctx = _account_ctx(req)
            if ctx is None:
                return errors.unauthorized()
            account, session = ctx
            return 200, {
                "account": app.accounts._account_body(account),
                "session": app.accounts._session_body(
                    session, current=True),
            }

        @app.route("GET", r"^/v1/auth/sessions$")
        def auth_sessions(req):
            ctx = _account_ctx(req)
            if ctx is None:
                return errors.unauthorized()
            account, session = ctx
            return 200, app.accounts.list_sessions(
                account, current_session_id=session["session_id"])

        @app.route("POST", r"^/v1/auth/sessions/revoke$")
        def auth_sessions_revoke(req):
            ctx = _account_ctx(req)
            if ctx is None:
                return errors.unauthorized()
            account, session = ctx
            body = req.body or {}
            return _account_call(
                lambda: app.accounts.revoke_session(
                    account, body.get("session_id") or "",
                    current_session_id=session["session_id"]))

        @app.route("POST", r"^/v1/auth/sign-out$")
        def auth_sign_out(req):
            ctx = _account_ctx(req)
            if ctx is None:
                return errors.unauthorized()
            account, session = ctx
            return _account_call(
                lambda: app.accounts.revoke_session(
                    account, session["session_id"],
                    current_session_id=session["session_id"]))

        @app.route("POST", r"^/v1/auth/handoff$")
        def auth_handoff_create(req):
            if not _auth_limited(req, "handoff", 30):
                return errors.rate_limited(60)
            body = req.body or {}
            return _account_call(lambda: app.accounts.create_handoff(
                device_label=body.get("device_label") or ""))

        @app.route("POST", r"^/v1/auth/handoff/poll$")
        def auth_handoff_poll(req):
            body = req.body or {}
            return _account_call(lambda: app.accounts.poll_handoff(
                body.get("handoff_id"), body.get("secret")))

        @app.route("POST", r"^/v1/auth/handoff/exchange$")
        def auth_handoff_exchange(req):
            body = req.body or {}
            return _account_call(lambda: app.accounts.exchange_handoff(
                body.get("handoff_id"), body.get("secret")))

    # -- idempotency (audit D4) ---------------------------------------------
    def _idempotent(self, req, route, produce):
        """Honor an optional Idempotency-Key header on a minting POST.

        No header: produce() runs exactly as before. With a header,
        the first successful (2xx) response is stored in the store
        layer under (key, route); a repeat call with the same key and
        the same body replays that stored response instead of minting
        a duplicate, and the same key with a DIFFERENT body is a 409.
        Only 2xx responses are stored, so a key first used on a
        request that failed validation is not burned. The body hash
        covers the parsed JSON body (key order-insensitive), so a
        faithful retry matches even if the client re-serializes.
        """
        key = req.headers.get("idempotency-key")
        if key is None:
            return produce()
        if not isinstance(key, str) or not key.strip() \
                or len(key) > 255:
            return errors.bad_request(
                "Idempotency-Key must be a non-empty string of at "
                "most 255 characters")
        body_hash = hashlib.sha256(json.dumps(
            req.body, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        existing = self.store.get_idempotency(key, route)
        if existing is not None:
            if existing["body_hash"] != body_hash:
                return errors.conflict(
                    "Idempotency-Key was already used with a "
                    "different request body")
            return existing["status"], existing["response"]
        status, body = produce()
        code = status.value if hasattr(status, "value") else int(status)
        if 200 <= code < 300 and not self.store.put_idempotency(
                key, route, body_hash, code, body, utcnow_iso()):
            # A concurrent mint with the same key stored first:
            # answer with the stored response, never a duplicate.
            existing = self.store.get_idempotency(key, route)
            if existing is not None:
                if existing["body_hash"] != body_hash:
                    return errors.conflict(
                        "Idempotency-Key was already used with a "
                        "different request body")
                return existing["status"], existing["response"]
        return status, body

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
        parsed_url = urlparse(raw_path)
        path = parsed_url.path
        query = {k: values[0] for k, values in
                 parse_qs(parsed_url.query).items()}
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
                req = Request(method, path, headers, body,
                              query=query, raw_body=body_bytes)
                try:
                    status, resp_body = fn(req, **m.groupdict())
                except Exception:  # never leak internals
                    return self._finalize(
                        *errors.bad_request("request could not be processed"))
                return self._finalize(status, resp_body)
        return self._finalize(*errors.not_found())

    def _finalize(self, status, body):
        """Canonicalize + sign every response body.

        The one exception is chat (an UnsignedBody): chat responses
        are never signed, because chat is never a record. They carry
        the same transport headers, minus the signature pair."""
        code = status.value if hasattr(status, "value") else int(status)
        if isinstance(body, HtmlBody):
            payload = body.html.encode("utf-8")
            headers = {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": str(len(payload)),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            }
            return code, headers, payload
        if isinstance(body, UnsignedBody):
            payload = canonicalize(body.body)
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            }
            return code, headers, payload
        canonical = canonicalize(body)
        key_id, sig = self.keys.sign("api_signing", canonical)
        headers = {
            "Content-Type": "application/json",
            "X-NPC-Signature": base64.b64encode(sig).decode(),
            "X-NPC-Key-ID": key_id,
            "Content-Length": str(len(canonical)),
            # Records carry personal-adjacent data (registration emails
            # are never returned, but verdicts and records are not
            # cacheable answers): never store, never MIME-sniff.
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        }
        return code, headers, canonical


class Handler(BaseHTTPRequestHandler):
    app: App = None  # set by run()

    # Browser clients (the NPC Verify Chrome extension above all) call
    # this API cross-origin. Reads are either public (/v1/health,
    # /v1/keys) or gated by Bearer keys, and no cookies are used, so a
    # wildcard origin cannot leak credentials. The signature headers
    # are exposed so a client can verify the response signature, which
    # is the whole point of signing it.
    CORS_HEADERS = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods":
            "GET, POST, PUT, DELETE, PATCH, OPTIONS",
        "Access-Control-Allow-Headers":
            "Authorization, Content-Type, Idempotency-Key",
        "Access-Control-Expose-Headers": "X-NPC-Signature, X-NPC-Key-ID",
    }

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in self.CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        headers = {k.lower(): v for k, v in self.headers.items()}
        # The TCP peer, set after the client's own headers are read so
        # a client-supplied value can never spoof it. Used only for
        # the public registration submission caps.
        headers["x-npc-peer"] = self.client_address[0]
        code, out_headers, payload = self.app.dispatch(
            self.command, self.path, headers, body)
        self.send_response(code)
        for k, v in self.CORS_HEADERS.items():
            self.send_header(k, v)
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


def create_app(db_path: str, keys_dir: str, detector=None,
               fetcher=None, chat_provider=None, chat_config=None,
               mailer=None, link_http=None,
               coinbase_reader=None, payments=None,
               anchor_chain=None) -> App:
    return App(db_path, keys_dir, detector=detector, fetcher=fetcher,
               chat_provider=chat_provider, chat_config=chat_config,
               mailer=mailer, link_http=link_http,
               coinbase_reader=coinbase_reader, payments=payments,
               anchor_chain=anchor_chain)


def run(db_path: str, keys_dir: str, host="127.0.0.1", port=8787):
    app = create_app(db_path, keys_dir)
    Handler.app = app
    server = ThreadingHTTPServer((host, port), Handler)
    return server, app
