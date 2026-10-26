"""Federated identity linking service (phase 1).

Design: integrations/federated-identity-signals-DESIGN-2026-10-19.md.
The prototype in npc_verify.registry validates and signs
`identity_signals` a registration carries. This module is the
linking service that stands behind those claims: it runs the actual
link with the provider, and only then attaches the signal.

A link is its own signed record (npc.identity.signal_link) in its
own store partition, minted through the same normalize-and-derive
machinery the registry uses, so an attached signal has exactly the
shape a registration-carried signal has, assurance class derived
server-side included. The registration record itself is never
edited, and a signal changes no status: the record stays
"registered, checks pending" and the verification decision stays
NPC's own.

Phase 1 links:

- SIWE wallet control (EIP-4361): the server issues a nonce
  challenge; the owner signs the sign-in message with the wallet;
  the signature must recover to the challenged wallet, with the
  domain, nonce, chain, and expiry all matching, fail closed on any
  mismatch.
- GitHub and Google account linking through NPC's own OAuth apps:
  authorization URL, callback, token exchange, identity fetch,
  attach. Credentials come from the environment only. With no
  credentials configured the flow refuses with a clear
  not-configured error; it never fakes a link.
- Coinbase Verifications: public EAS attestations on Base, read for
  a wallet the owner has already proven control of. Each re-read is
  stored as an observation; the panel reads the latest observation,
  so a revoked or expired attestation stops producing its signal.

Ownership of the target record is proven the same way the
request-verification step proves it: the registration email,
compared by hash, with attempts counted before the match under the
same caps. OAuth tokens and provider emails are never written into
any record: a signal's subject reference is the provider's opaque
id (a GitHub numeric id, a Google sub, a wallet address).

Everything here is gated by NPC_IDENTITY_SIGNALS=1, the same flag
as the registry block: a deployment without the linking service
refuses to sign claims it cannot stand behind.
"""
import json
import os
import re
import secrets
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from . import ethkeys, pact, registry
from .models import is_iso8601, utcnow_iso
from .store import registration_email_hash

LINK_RECORD_TYPE = "npc.identity.signal_link"
CHALLENGE_TTL = timedelta(minutes=10)
OAUTH_PROVIDERS = ("github", "google")

# -- panel copy (the design's drafted tier language) -------------------------
# Plain customer words, no absolutes, no em dashes. Drafted in the
# design note for Bayo's approval; the panel ships the data with
# these labels so a front end never invents its own.
PANEL_HEADING = "Identity the owner has linked"
PANEL_INTRO = ("These checks were run by the services named. NPC "
               "recorded what each service confirmed about the "
               "owner of this record.")
PANEL_BOUNDARY = ("Linked checks show what the services named "
                  "confirmed about the owner. They are not an "
                  "identity check by NPC, and they do not change "
                  "what this record's status says.")
PANEL_NOT_CURRENT_NOTE = ("A link below is no longer confirmed. "
                          "NPC re-checks the service named, and a "
                          "link stops counting when the service no "
                          "longer stands behind it.")
CLASS_HEADINGS = {
    "account_control": "Accounts the owner controls",
    "aggregated_personhood": "A combined score from several checks",
    "unique_human": "Proof of one unique human",
    "kyc_backed_account": "Accounts backed by an identity check",
    "document_check": "Identity documents checked",
}
# Rough guidance order from the design, weakest to strongest for
# most purposes; the beholder's own policy does the deciding.
CLASS_ORDER = ("account_control", "aggregated_personhood",
               "unique_human", "kyc_backed_account", "document_check")
SIGNAL_LABELS = {
    ("world_id", "proof_of_human"):
        "World ID: the owner proved they are one unique person. "
        "This proof does not include a name.",
    ("world_id", "passport"):
        "World ID: a passport chip was read for the owner of this "
        "record.",
    ("world_id", "selfie_check"):
        "World ID: a live selfie check confirmed a real person was "
        "present.",
    ("world_id", "identity_check"):
        "World ID: details from an identity document were checked, "
        "such as age or nationality.",
    ("google", "account"):
        "Google: the owner controls a Google account, and Google "
        "has confirmed that account's email address.",
    ("github", "account"):
        "GitHub: the owner controls a GitHub account.",
    ("x", "account"):
        "X: the owner controls an X account.",
    ("coinbase", "verified_account"):
        "Coinbase: this wallet belongs to a Coinbase customer "
        "whose identity Coinbase has checked.",
    ("coinbase", "verified_country"):
        "Coinbase: this wallet belongs to a Coinbase customer, and "
        "Coinbase recorded a country of residence for the account.",
    ("gitcoin_passport", "score"):
        "Gitcoin Passport: several checks were combined into one "
        "score for this wallet.",
    ("stripe_identity", "document_check"):
        "Stripe Identity: an identity document for the owner was "
        "checked and passed.",
    ("persona", "document_check"):
        "Persona: an identity document for the owner was checked "
        "and passed.",
    ("siwe", "wallet_control"):
        "Ethereum wallet: the owner proved they control this "
        "wallet by signing in with it.",
}
NOT_CURRENT_REASONS = {
    "revoked": "The service withdrew this confirmation.",
    "expired": "This confirmation has expired.",
    "not_seen_at_last_check":
        "The service no longer shows this confirmation.",
}


def linking_enabled():
    """The same flag as the registry identity_signals block."""
    return os.environ.get(registry.IDENTITY_SIGNALS_ENV) == "1"


# -- configuration (environment only) -----------------------------------------
def public_base_url():
    base = os.environ.get("NPC_PUBLIC_BASE_URL") \
        or "https://api.npclabs.xyz"
    return base.rstrip("/")


def link_domain():
    return urllib.parse.urlsplit(public_base_url()).netloc


def siwe_chain_id():
    try:
        return int(os.environ.get("NPC_SIWE_CHAIN_ID") or "1")
    except ValueError:
        return 1


def oauth_config(provider):
    """(client_id, client_secret) for a provider, or None when the
    deployment has not configured NPC's OAuth app for it."""
    env = {"github": ("NPC_GITHUB_CLIENT_ID",
                      "NPC_GITHUB_CLIENT_SECRET"),
           "google": ("NPC_GOOGLE_CLIENT_ID",
                      "NPC_GOOGLE_CLIENT_SECRET")}[provider]
    client_id = os.environ.get(env[0])
    client_secret = os.environ.get(env[1])
    if not client_id or not client_secret:
        return None
    return client_id, client_secret


def oauth_redirect_uri(provider):
    return "%s/v1/link/%s/callback" % (public_base_url(), provider)


# -- small HTTP helper (injectable; tests never touch the network) ------------
def default_http(method, url, headers=None, form=None, json_body=None,
                 timeout=10):
    """One bounded HTTP call. Returns (status, parsed_json_or_None,
    raw_text)."""
    data = None
    hdrs = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        hdrs.setdefault("Content-Type",
                        "application/x-www-form-urlencoded")
    elif json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace") \
            if exc.fp is not None else ""
        status = exc.code
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = None
    return status, parsed, text


# -- ownership + caps (mirroring the request-verification pattern) ------------
def link_cap_exceeded(store, email, client_ip, now_iso):
    """Link attempts share the registration ceilings: same per-email
    and per-IP caps over the same rolling window, counted over
    attempts (matched and not)."""
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    since = (now - registry.CAP_WINDOW).isoformat(timespec="seconds")
    if store.count_identity_link_attempts_since(
            "email", email, since) >= registry.EMAIL_DAILY_CAP:
        return "email"
    if client_ip and store.count_identity_link_attempts_since(
            "ip", client_ip, since) >= registry.IP_DAILY_CAP:
        return "ip"
    return None


def email_matches_record(store, record_id, email):
    """True when the presented email is the one the record was
    registered with, compared by hash, exactly as the
    request-verification step compares it."""
    return registry.verification_request_email_matches(
        store, record_id, email)


# -- link record minting ---------------------------------------------------------
_LINK_DETAILS = {
    ("siwe", "wallet_control"):
        "The owner proved control of this wallet by signing a "
        "sign-in message with it. NPC confirmed the signature at "
        "link time. This shows control of the wallet's key, and "
        "nothing about a person.",
    ("github", "account"):
        "The owner signed in with this GitHub account through "
        "GitHub's own sign-in, and GitHub confirmed the account. "
        "NPC recorded the account's numeric id only.",
    ("google", "account"):
        "The owner signed in with this Google account through "
        "Google's own sign-in, and Google confirmed the account. "
        "NPC recorded the account's opaque id only.",
    ("coinbase", "verified_account"):
        "Coinbase's public attestation for this wallet was read "
        "from Base. It says the wallet belongs to a Coinbase "
        "customer whose identity Coinbase has checked. NPC re-reads "
        "the attestation; if Coinbase withdraws it or it expires, "
        "the link stops counting.",
    ("coinbase", "verified_country"):
        "Coinbase's public attestation for this wallet was read "
        "from Base. It records a country of residence for the "
        "account. NPC re-reads the attestation; if Coinbase "
        "withdraws it or it expires, the link stops counting.",
}


def mint_link_record(store, keys, subject, provider, signal,
                     subject_ref, linked_at, observed_at=None,
                     evidence_ref=None):
    """Sign and store one identity-link record. The signal entry
    rides through the registry's normalize step, so its shape and
    derived assurance class are exactly what a registration-carried
    signal gets. Returns the record, or None when a link with the
    same identity already exists (the caller reads the existing
    one)."""
    raw = {"provider": provider, "signal": signal,
           "subject_ref": subject_ref, "linked_at": linked_at}
    if observed_at:
        raw["observed_at"] = observed_at
    if evidence_ref:
        raw["evidence_ref"] = evidence_ref
    normalized = registry.normalize_identity_signals([raw])
    if not normalized:
        raise ValueError("signal could not be normalized: %r" % (raw,))
    entry = normalized[0]
    core = {
        "record_type": LINK_RECORD_TYPE,
        "record_id": "link_" + secrets.token_hex(12),
        "subject_record_id": subject["record_id"],
        "subject_kind": subject.get("kind"),
        "status": "linked",
        "status_label": "Identity check linked",
        "linked_at": linked_at,
        "signal": entry,
        "detail": _LINK_DETAILS.get(
            (provider, signal),
            "The owner linked an outside identity check. The link "
            "was confirmed with the service named at link time."),
    }
    rec = pact.sign_record(keys, core)
    if not store.add_identity_link(rec):
        existing = find_link(store, subject["record_id"], provider,
                             signal, subject_ref)
        return existing
    return rec


def find_link(store, subject_record_id, provider, signal, subject_ref):
    """The existing link record for one exact signal identity, or
    None. Wallet subjects compare case-insensitively."""
    for rec in store.list_identity_links(subject_record_id):
        entry = rec.get("signal") or {}
        if entry.get("provider") != provider \
                or entry.get("signal") != signal:
            continue
        have = entry.get("subject_ref") or ""
        if provider in ("siwe", "coinbase"):
            if have.lower() == subject_ref.lower():
                return rec
        elif have == subject_ref:
            return rec
    return None


# -- SIWE (EIP-4361) -------------------------------------------------------------
SIWE_STATEMENT = (
    "Link this wallet to your Verified by NPC record. Signing "
    "proves you control this wallet. It does not move funds or "
    "approve any transaction.")
_WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def valid_wallet(address):
    return isinstance(address, str) \
        and bool(_WALLET_RE.match(address)) \
        and ethkeys.is_valid_address(address)


def build_siwe_message(domain, address, uri, chain_id, nonce,
                       issued_at, expires_at):
    lines = [
        "%s wants you to sign in with your Ethereum account:"
        % domain,
        ethkeys.to_checksum_address(address),
        "",
        SIWE_STATEMENT,
        "",
        "URI: %s" % uri,
        "Version: 1",
        "Chain ID: %d" % chain_id,
        "Nonce: %s" % nonce,
        "Issued At: %s" % issued_at,
        "Expiration Time: %s" % expires_at,
    ]
    return "\n".join(lines)


_SIWE_FIELD_KEYS = ("URI", "Version", "Chain ID", "Nonce",
                    "Issued At", "Expiration Time", "Not Before",
                    "Request ID")


def parse_siwe_message(message):
    """Parse a canonical EIP-4361 message. Returns a field dict, or
    None when the layout is not the canonical one (fail closed)."""
    if not isinstance(message, str) or "\r" in message:
        return None
    lines = message.split("\n")
    if len(lines) < 10:
        return None
    head = lines[0]
    suffix = " wants you to sign in with your Ethereum account:"
    if not head.endswith(suffix):
        return None
    domain = head[:-len(suffix)]
    address = lines[1]
    if not _WALLET_RE.match(address):
        return None
    if lines[2] != "":
        return None
    idx = 3
    statement = None
    if lines[idx] and not lines[idx].startswith("URI: "):
        statement = lines[idx]
        idx += 1
    if idx >= len(lines) or lines[idx] != "":
        return None
    idx += 1
    fields = {}
    for line in lines[idx:]:
        if ": " not in line:
            return None
        key, value = line.split(": ", 1)
        if key not in _SIWE_FIELD_KEYS or key in fields:
            return None
        fields[key] = value
    for required in ("URI", "Version", "Chain ID", "Nonce",
                     "Issued At"):
        if required not in fields:
            return None
    return {"domain": domain, "address": address,
            "statement": statement, "fields": fields}


def _iso_after(a, b):
    """True when ISO instant a is later than instant b."""
    return datetime.fromisoformat(a.replace("Z", "+00:00")) \
        > datetime.fromisoformat(b.replace("Z", "+00:00"))


def verify_siwe(message, signature_hex, expected, now_iso):
    """Verify a SIWE signature against the challenge it answers.

    `expected` carries the server-issued domain, nonce, wallet, and
    chain id. Every field is checked; any mismatch fails closed.
    Returns (problems, recovered_address_or_None).
    """
    problems = []
    parsed = parse_siwe_message(message)
    if parsed is None:
        return ["the sign-in message is not in the expected format"], \
            None
    fields = parsed["fields"]
    if parsed["domain"] != expected["domain"]:
        problems.append("the sign-in message names a different "
                        "domain than this service issued")
    if parsed["address"].lower() != expected["wallet"].lower():
        problems.append("the sign-in message names a different "
                        "wallet than the one challenged")
    if fields["URI"] != expected["uri"]:
        problems.append("the sign-in message names a different URI")
    if fields["Version"] != "1":
        problems.append("the sign-in message version is not 1")
    if fields["Chain ID"] != str(expected["chain_id"]):
        problems.append("the sign-in message names a different "
                        "chain than the one challenged")
    if fields["Nonce"] != expected["nonce"]:
        problems.append("the sign-in message does not carry the "
                        "nonce this service issued")
    if not is_iso8601(fields["Issued At"]):
        problems.append("the sign-in message Issued At is not a "
                        "timestamp")
    elif _iso_after(fields["Issued At"],
                    (datetime.fromisoformat(
                        now_iso.replace("Z", "+00:00"))
                     + timedelta(minutes=5)).isoformat()):
        problems.append("the sign-in message was issued in the "
                        "future")
    expires = fields.get("Expiration Time")
    if not expires or not is_iso8601(expires):
        problems.append("the sign-in message carries no valid "
                        "expiration time")
    elif not _iso_after(expires, now_iso):
        problems.append("the sign-in message has expired")
    not_before = fields.get("Not Before")
    if not_before and is_iso8601(not_before) \
            and _iso_after(not_before, now_iso):
        problems.append("the sign-in message is not valid yet")
    if problems:
        return problems, None
    if not isinstance(signature_hex, str):
        return ["the signature is missing"], None
    hex_part = signature_hex[2:] if signature_hex.startswith("0x") \
        else signature_hex
    try:
        signature = bytes.fromhex(hex_part)
    except ValueError:
        return ["the signature is not valid hex"], None
    recovered = ethkeys.verify_personal_signature(
        message.encode("utf-8"), signature)
    if recovered is None:
        return ["the signature could not be verified"], None
    if recovered.lower() != expected["wallet"].lower():
        return ["the signature was made by a different wallet"], \
            None
    return [], recovered


def start_siwe_challenge(store, subject, email, wallet, now_iso):
    """Issue a SIWE challenge for one wallet on one record. The
    nonce lives server-side only until the owner signs."""
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    expires = (now + CHALLENGE_TTL).isoformat(timespec="seconds")
    nonce = secrets.token_hex(8)
    challenge_id = "lchg_" + secrets.token_hex(12)
    domain = link_domain()
    message = build_siwe_message(
        domain, wallet, public_base_url(), siwe_chain_id(), nonce,
        now.isoformat(timespec="seconds"), expires)
    store.add_identity_link_challenge({
        "challenge_id": challenge_id, "kind": "siwe",
        "provider": "siwe",
        "subject_record_id": subject["record_id"],
        "email_hash": registration_email_hash(email),
        "secret": nonce, "wallet": wallet,
        "created_at": now_iso, "expires_at": expires,
    })
    return {"challenge_id": challenge_id, "message": message,
            "nonce": nonce, "domain": domain,
            "chain_id": siwe_chain_id(), "expires_at": expires,
            "wallet": ethkeys.to_checksum_address(wallet)}


def complete_siwe(store, keys, subject, challenge_id, message,
                  signature, now_iso):
    """Finish a SIWE challenge. Returns (link_record, problems):
    exactly one of the two is meaningful."""
    row = store.get_identity_link_challenge(challenge_id)
    if row is None or row["kind"] != "siwe" \
            or row["subject_record_id"] != subject["record_id"]:
        return None, ["this sign-in challenge is not open"]
    if row["consumed_at"]:
        return None, ["this sign-in challenge was already used"]
    if not _iso_after(row["expires_at"], now_iso):
        return None, ["this sign-in challenge has expired"]
    problems, _recovered = verify_siwe(message, signature, {
        "domain": link_domain(), "nonce": row["secret"],
        "wallet": row["wallet"], "chain_id": siwe_chain_id(),
        "uri": public_base_url(),
    }, now_iso)
    if problems:
        return None, problems
    if not store.consume_identity_link_challenge(challenge_id,
                                                 now_iso):
        return None, ["this sign-in challenge was already used"]
    rec = mint_link_record(
        store, keys, subject, "siwe", "wallet_control",
        row["wallet"], now_iso, observed_at=now_iso)
    return rec, []


# -- OAuth (GitHub, Google) -------------------------------------------------------
_OAUTH_AUTHORIZE = {
    "github": "https://github.com/login/oauth/authorize",
    "google": "https://accounts.google.com/o/oauth2/v2/auth",
}
_OAUTH_TOKEN = {
    "github": "https://github.com/login/oauth/access_token",
    "google": "https://oauth2.googleapis.com/token",
}
# The minimum scopes that carry the identity fact the design names.
# GitHub: the public profile (numeric id) from GET /user. Google:
# the OpenID subject, plus email so Google reports email_verified;
# the address itself is never recorded.
OAUTH_SCOPES = {"github": "read:user", "google": "openid email"}


def start_oauth(store, provider, subject, email, now_iso):
    """Begin an OAuth link. Returns (start_dict, problems): the
    start dict carries the authorization URL for the owner's
    browser. With no app configured, problems says so plainly."""
    config = oauth_config(provider)
    if config is None:
        return None, ["not_configured"]
    client_id, _secret = config
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    expires = (now + CHALLENGE_TTL).isoformat(timespec="seconds")
    state = secrets.token_urlsafe(24)
    store.add_identity_link_challenge({
        "challenge_id": "lchg_" + secrets.token_hex(12),
        "kind": "oauth", "provider": provider,
        "subject_record_id": subject["record_id"],
        "email_hash": registration_email_hash(email),
        "secret": state, "wallet": "",
        "created_at": now_iso, "expires_at": expires,
    })
    params = {"client_id": client_id,
              "redirect_uri": oauth_redirect_uri(provider),
              "state": state, "scope": OAUTH_SCOPES[provider]}
    if provider == "google":
        params["response_type"] = "code"
        params["access_type"] = "online"
    url = _OAUTH_AUTHORIZE[provider] + "?" \
        + urllib.parse.urlencode(params)
    return {"provider": provider, "authorization_url": url,
            "state": state, "expires_at": expires,
            "redirect_uri": oauth_redirect_uri(provider)}, []


def _oauth_fetch_subject(provider, code, http, now_iso):
    """Exchange the code and read the provider's identity fact.

    Returns (subject_ref, problems). For GitHub the subject is the
    account's numeric id. For Google it is the OpenID `sub`, taken
    from Google's own token check, never from an unverified decode.
    The provider email is read only where the design names it
    (Google's email_verified) and is never returned or stored.
    """
    config = oauth_config(provider)
    if config is None:
        return None, ["not_configured"]
    client_id, client_secret = config
    status, token, _text = http(
        "POST", _OAUTH_TOKEN[provider],
        headers={"Accept": "application/json"},
        form={"client_id": client_id, "client_secret": client_secret,
              "code": code,
              "redirect_uri": oauth_redirect_uri(provider),
              **({"grant_type": "authorization_code"}
                 if provider == "google" else {})})
    if status != 200 or not isinstance(token, dict) \
            or not token.get("access_token"):
        return None, ["the provider did not complete the sign-in"]
    if provider == "github":
        status, user, _text = http(
            "GET", "https://api.github.com/user",
            headers={"Authorization": "Bearer "
                     + token["access_token"],
                     "Accept": "application/vnd.github+json"})
        if status != 200 or not isinstance(user, dict) \
                or not isinstance(user.get("id"), int):
            return None, ["GitHub did not return the account"]
        return str(user["id"]), []
    # google: validate the ID token with Google's token check.
    id_token = token.get("id_token")
    if not id_token:
        return None, ["Google did not return an identity token"]
    status, info, _text = http(
        "GET", "https://oauth2.googleapis.com/tokeninfo?id_token="
        + urllib.parse.quote(id_token, safe=""))
    if status != 200 or not isinstance(info, dict):
        return None, ["Google could not confirm the identity token"]
    if info.get("aud") != client_id:
        return None, ["the identity token was issued for a "
                      "different app"]
    if info.get("iss") not in ("accounts.google.com",
                               "https://accounts.google.com"):
        return None, ["the identity token has an unexpected issuer"]
    try:
        exp = int(info.get("exp") or 0)
    except (TypeError, ValueError):
        exp = 0
    now_epoch = int(datetime.fromisoformat(
        now_iso.replace("Z", "+00:00")).timestamp())
    if exp <= now_epoch:
        return None, ["the identity token has expired"]
    if not info.get("sub"):
        return None, ["Google did not return an account id"]
    return str(info["sub"]), []


def complete_oauth(store, keys, provider, code, state, http,
                   now_iso):
    """Finish an OAuth callback. Returns (link_record, problems).
    The state is consumed before the exchange, so a callback can
    never be replayed, whatever its outcome."""
    rows = [r for r in _pending_oauth(store, provider, state)]
    if not rows:
        return None, ["this sign-in link is not open"]
    row = rows[0]
    if not _iso_after(row["expires_at"], now_iso):
        return None, ["this sign-in link has expired"]
    if not store.consume_identity_link_challenge(
            row["challenge_id"], now_iso):
        return None, ["this sign-in link was already used"]
    subject = store.get_registration(row["subject_record_id"])
    if subject is None:
        return None, ["the record for this sign-in no longer "
                      "exists"]
    subject_ref, problems = _oauth_fetch_subject(provider, code,
                                                 http, now_iso)
    if problems:
        return None, problems
    rec = mint_link_record(
        store, keys, subject, provider, "account", subject_ref,
        now_iso, observed_at=now_iso)
    return rec, []


def _pending_oauth(store, provider, state):
    """Find the pending OAuth challenge for a state value, via the
    store's by-secret lookup. Challenge volume is small and
    short-lived by construction."""
    if not isinstance(state, str) or not state:
        return []
    row = store.find_identity_link_challenge("oauth", provider,
                                             state)
    return [row] if row else []


# -- Coinbase Verifications (EAS on Base) ---------------------------------------
EAS_GRAPHQL_DEFAULT = "https://base.easscan.org/graphql"
# Coinbase's published verified-account schema on Base. The schema
# is resolver-gated to Coinbase's own attester, so a schema plus
# recipient read is a Coinbase read. Both values stay
# environment-overridable, and the pre-flip review confirms them
# against Coinbase's published schemas before the flag turns on.
COINBASE_VERIFIED_ACCOUNT_SCHEMA_DEFAULT = \
    "0xf8b05c79f090979bf4a6e36f5400a8ec90d9c291372badb573fbd716b1" \
    "e840e0"
_COINBASE_SIGNALS = (("verified_account", "_account_schema"),
                     ("verified_country", "_country_schema"))


def _unix_to_iso(value):
    try:
        ts = int(value)
    except (TypeError, ValueError):
        return ""
    if ts <= 0:
        return ""
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(
        timespec="seconds")


class CoinbaseReader:
    """Reads Coinbase's public EAS attestations on Base through the
    EAS indexer. Injectable HTTP, like every external call here."""

    def __init__(self, http, graphql_url=None,
                 account_schema=None, country_schema=None):
        self.http = http
        self.graphql_url = graphql_url or os.environ.get(
            "NPC_COINBASE_EAS_URL") or EAS_GRAPHQL_DEFAULT
        self._account_schema = account_schema or os.environ.get(
            "NPC_COINBASE_VERIFIED_ACCOUNT_SCHEMA") \
            or COINBASE_VERIFIED_ACCOUNT_SCHEMA_DEFAULT
        self._country_schema = country_schema or os.environ.get(
            "NPC_COINBASE_VERIFIED_COUNTRY_SCHEMA") or None
        # Optional: with a trusted attester configured, reads from
        # any other issuer are ignored. Coinbase's schemas are
        # resolver-gated, but the filter protects the pre-flip
        # review window where the schema UIDs are being confirmed.
        attester = os.environ.get("NPC_COINBASE_ATTESTER") or ""
        self._attester = attester.lower() or None

    def schemas(self):
        out = []
        for signal, attr in _COINBASE_SIGNALS:
            schema = getattr(self, attr)
            if schema:
                out.append((signal, schema))
        return out

    def attestations_for(self, wallet):
        """Every Coinbase attestation the indexer shows for this
        wallet under the configured schemas, newest first per
        schema, normalized. Revoked and expired entries are
        returned too: the caller decides currency, and a revoked
        latest entry is exactly what stops a signal."""
        found = []
        for signal, schema in self.schemas():
            query = (
                "query($recipient: String!, $schemaId: String!) {"
                " attestations(where: { recipient: { equals: "
                "$recipient }, schemaId: { equals: $schemaId } },"
                " orderBy: { time: desc }, take: 25) {"
                " id attester recipient time expirationTime"
                " revocationTime revoked data schemaId } }")
            status, payload, _text = self.http(
                "POST", self.graphql_url,
                json_body={"query": query,
                           "variables": {
                               "recipient": wallet,
                               "schemaId": schema}})
            if status != 200 or not isinstance(payload, dict):
                continue
            items = ((payload.get("data") or {})
                     .get("attestations")) or []
            for item in items:
                if not isinstance(item, dict):
                    continue
                if self._attester \
                        and (item.get("attester") or "").lower() \
                        != self._attester:
                    continue
                found.append({
                    "signal": signal,
                    "uid": item.get("id") or "",
                    "attester": item.get("attester") or "",
                    "recipient": item.get("recipient") or wallet,
                    "time": item.get("time"),
                    "expiration_time": item.get(
                        "expirationTime"),
                    "revoked": bool(item.get("revoked"))
                    or bool(item.get("revocationTime")),
                    "data": item.get("data") or "",
                })
        return found


def _attestation_state(att, now_iso):
    """The currency of one attestation at a moment: valid, revoked,
    expired, or (by the caller) absent. Expiry is evaluated against
    the moment, here and again when the panel is built."""
    if att is None:
        return "not_seen"
    if att.get("revoked"):
        return "revoked"
    expires = _unix_to_iso(att.get("expiration_time"))
    if expires and not _iso_after(expires, now_iso):
        return "expired"
    if att["signal"] == "verified_account":
        # The schema carries one bool: verified. A malformed payload
        # never produces a signal.
        data = att.get("data") or ""
        try:
            raw = bytes.fromhex(data[2:] if data.startswith("0x")
                                else data)
        except ValueError:
            return "not_seen"
        if len(raw) < 32 or raw[-1] != 1:
            return "not_seen"
    return "valid"


def _record_wallets(store, subject):
    """Wallets the owner has proven control of for this record: the
    SIWE links, plus any SIWE signal the registration itself
    carries. Coinbase pairs only with a proven wallet (design)."""
    wallets = []
    seen = set()

    def add(value):
        if isinstance(value, str) and _WALLET_RE.match(value) \
                and value.lower() not in seen:
            seen.add(value.lower())
            wallets.append(value)

    for entry in subject.get("identity_signals") or []:
        if entry.get("provider") == "siwe":
            add(entry.get("subject_ref"))
    for rec in store.list_identity_links(subject["record_id"]):
        entry = rec.get("signal") or {}
        if entry.get("provider") == "siwe":
            add(entry.get("subject_ref"))
    return wallets


def refresh_coinbase(store, keys, subject, reader, now_iso):
    """Re-read Coinbase attestations for the record's proven
    wallets, store the observations, and mint a link record for any
    signal newly valid. Returns the observation summary."""
    summary = []
    for wallet in _record_wallets(store, subject):
        attestations = reader.attestations_for(wallet)
        for signal, _schema in reader.schemas():
            candidates = [a for a in attestations
                          if a["signal"] == signal]
            latest = candidates[0] if candidates else None
            state = _attestation_state(latest, now_iso)
            store.add_identity_observation({
                "subject_record_id": subject["record_id"],
                "wallet": wallet, "provider": "coinbase",
                "signal": signal,
                "attestation_uid": latest["uid"] if latest else "",
                "state": state,
                "attested_at": _unix_to_iso(latest["time"])
                if latest else "",
                "expires_at": _unix_to_iso(
                    latest["expiration_time"]) if latest else "",
                "observed_at": now_iso,
            })
            linked = None
            if state == "valid":
                # One link record per signal identity: a refresh
                # that finds the attestation still valid records
                # the observation, it does not mint a duplicate.
                linked = find_link(store, subject["record_id"],
                                   "coinbase", signal, wallet)
                if linked is None:
                    linked = mint_link_record(
                        store, keys, subject, "coinbase", signal,
                        wallet, now_iso, observed_at=now_iso,
                        evidence_ref=latest["uid"])
            summary.append({
                "wallet": wallet, "signal": signal,
                "state": state,
                "attestation_uid": latest["uid"] if latest
                else None,
                "link_record_id": linked["record_id"]
                if linked else None,
            })
    return summary


# -- the record panel --------------------------------------------------------------
def _signal_state(entry, observations, now_iso):
    """The current observed state of one signal entry.

    Coinbase signals are observed state: the latest observation
    decides, and an attestation whose stored expiry has since
    passed drops at read time even between refreshes. Other
    providers' links were confirmed at link time and stand as
    recorded."""
    if entry.get("provider") != "coinbase":
        return "current", ""
    key = ((entry.get("subject_ref") or "").lower(), "coinbase",
           entry.get("signal"))
    obs = observations.get(key)
    if obs is None:
        return "recorded", ""
    if obs["state"] == "valid":
        expires = obs.get("expires_at") or ""
        if expires and not _iso_after(expires, now_iso):
            return "expired", NOT_CURRENT_REASONS["expired"]
        return "current", ""
    if obs["state"] == "revoked":
        return "revoked", NOT_CURRENT_REASONS["revoked"]
    if obs["state"] == "expired":
        return "expired", NOT_CURRENT_REASONS["expired"]
    return "not_seen_at_last_check", \
        NOT_CURRENT_REASONS["not_seen_at_last_check"]


def build_identity_panel(store, subject, now_iso):
    """Everything the "Identity the owner has linked" panel needs:
    the drafted heading, intro, and boundary line, the signals
    grouped by assurance class at their current observed state, and
    the links that no longer count, with the reason in customer
    words. Pure read: no mutation, no network."""
    entries = []
    seen = set()

    def add(entry, origin):
        key = (entry.get("provider"), entry.get("signal"),
               (entry.get("subject_ref") or "").lower()
               if entry.get("provider") in ("siwe", "coinbase")
               else entry.get("subject_ref"))
        if key in seen:
            return
        seen.add(key)
        entries.append((entry, origin))

    for rec in store.list_identity_links(subject["record_id"]):
        if isinstance(rec.get("signal"), dict):
            add(rec["signal"], "link")
    for entry in subject.get("identity_signals") or []:
        add(entry, "record")
    observations = store.latest_identity_observations(
        subject["record_id"])
    groups = {}
    not_current = []
    for entry, _origin in entries:
        state, reason = _signal_state(entry, observations, now_iso)
        item = {
            "provider": entry["provider"],
            "signal": entry["signal"],
            "assurance_class": entry["assurance_class"],
            "label": SIGNAL_LABELS.get(
                (entry["provider"], entry["signal"]), ""),
            "subject_ref": entry["subject_ref"],
            "linked_at": entry.get("linked_at"),
            "observed_at": entry.get("observed_at"),
            "state": state,
        }
        if entry.get("evidence_ref"):
            item["evidence_ref"] = entry["evidence_ref"]
        if state in ("current", "recorded"):
            groups.setdefault(entry["assurance_class"],
                              []).append(item)
        else:
            item["reason"] = reason
            not_current.append(item)
    panel_groups = []
    for cls in CLASS_ORDER:
        if cls in groups:
            signals = sorted(
                groups[cls],
                key=lambda s: (s["provider"], s["signal"],
                               s["subject_ref"]))
            panel_groups.append({
                "assurance_class": cls,
                "heading": CLASS_HEADINGS[cls],
                "signals": signals,
            })
    return {
        "record_id": subject["record_id"],
        "record_status": subject.get("status"),
        "record_status_label": subject.get("status_label"),
        "panel": {
            "heading": PANEL_HEADING,
            "intro": PANEL_INTRO,
            "boundary": PANEL_BOUNDARY,
            "groups": panel_groups,
            "not_current": not_current,
            "not_current_note": PANEL_NOT_CURRENT_NOTE
            if not_current else None,
            "signals_current": sum(len(g["signals"])
                                   for g in panel_groups),
            "signals_not_current": len(not_current),
        },
    }
