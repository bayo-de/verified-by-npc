"""The unified NPC account (Gate G1, design decided 2026-10-24 in
unified-login-and-crypto-payments-2026-10-24.md).

One account per person, rooted at an email address, shared by every
NPC surface (the main site, verify.npclabs.xyz, and the desktop
app):

- Passkeys (WebAuthn) are the primary sign-in method on all
  surfaces; ceremony verification lives in npc_verify.webauthn.
- Email is the identity anchor and the fallback: a one-time email
  sign-in link covers devices where no passkey is available yet,
  and enrolling a passkey is offered right after.
- Recovery is entailed at enrollment, not improvised: the first
  passkey enrollment issues one-time recovery codes (shown once,
  stored only as hashes), a second passkey is encouraged, and
  signing in by email link on an account that already holds
  passkeys is written to the account's event log, which is the
  audit trail support-assisted recovery must leave behind (it
  requires proof of control of the account email, and the email
  link is exactly that proof).
- Sessions follow the account. Each sign-in creates a revocable
  device session for one surface; every surface can list the
  account's sessions and revoke any of them.
- The desktop app signs in through a browser handoff: the app
  creates a handoff, the user signs in in their browser, and the
  app exchanges a one-time code for its own device session. The
  app never sees the passkey ceremony.
- API keys stay separate (npc_verify.auth): they are generated and
  revoked under the account's authority but never depend on a
  passkey, a session, or a wallet. A session token is not an API
  key and is never accepted as one, and vice versa.

Secrets at rest are hashes only (session tokens, email-link tokens,
handoff secrets and exchange codes, recovery codes), compared in
constant time where a guess could be retried. Plaintext secrets
are returned exactly once, at creation.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from . import mailer as mailer_module
from . import webauthn
from .auth import hash_key
from .c2pa import _cbor_decode, _cbor_encode

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")

SESSION_TOKEN_PREFIX = "npc_sess_"
EMAIL_TOKEN_PREFIX = "npc_link_"
HANDOFF_SECRET_PREFIX = "npc_hoff_"
RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
RECOVERY_CODE_COUNT = 10

DEFAULT_RP_ID = "npclabs.xyz"
DEFAULT_RP_NAME = "NPC"
DEFAULT_ORIGINS = ("https://verify.npclabs.xyz", "https://npclabs.xyz")


class AccountError(Exception):
    """A domain failure with its public error shape attached, in
    the (status, body) form npc_verify.errors produces."""

    def __init__(self, status, body):
        super().__init__(body.get("detail") or body.get("error"))
        self.status = status
        self.body = body


def _bad(detail):
    return AccountError(400, {"error": "bad_request", "detail": detail})


def _unauthorized():
    return AccountError(401, {"error": "unauthorized"})


def _conflict(detail):
    return AccountError(409, {"error": "conflict", "detail": detail})


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc)


def _new_id(prefix):
    return prefix + secrets.token_hex(8)


def normalize_email(email):
    if not isinstance(email, str):
        raise _bad("an email address is required")
    cleaned = email.strip().lower()
    if not EMAIL_RE.match(cleaned):
        raise _bad("that email address does not look complete")
    return cleaned


def config_from_env(env=None):
    """Account configuration from the environment, detector-style.

    NPC_AUTH_RP_ID / NPC_AUTH_RP_NAME name the WebAuthn relying
    party; NPC_AUTH_ORIGINS is the comma separated allowlist of
    web origins ceremonies may come from; NPC_AUTH_SITE_BASE is
    where sign-in links land (default: the mailer's site base, so
    local runs can point both at a loopback server and production
    never sets either).
    """
    env = os.environ if env is None else env

    def _get(name, default=""):
        return (env.get(name) or "").strip() or default

    origins = tuple(o.strip() for o in
                    _get("NPC_AUTH_ORIGINS").split(",") if o.strip()) \
        or DEFAULT_ORIGINS
    try:
        session_days = int(_get("NPC_AUTH_SESSION_TTL_DAYS", "30"))
    except ValueError:
        session_days = 30
    return {
        "rp_id": _get("NPC_AUTH_RP_ID", DEFAULT_RP_ID),
        "rp_name": _get("NPC_AUTH_RP_NAME", DEFAULT_RP_NAME),
        "origins": origins,
        "site_base": _get("NPC_AUTH_SITE_BASE") or mailer_module._site_base(env),
        "session_ttl": timedelta(days=max(1, session_days)),
        "email_ttl": timedelta(minutes=15),
        "challenge_ttl": timedelta(minutes=5),
        "handoff_ttl": timedelta(minutes=10),
    }


class AccountService:
    def __init__(self, store, mailer, config=None):
        self.store = store
        self.mailer = mailer
        self.config = config or config_from_env()

    # -- internals -----------------------------------------------------

    def _event(self, account_id, kind, detail=None):
        self.store.add_account_event({
            "event_id": _new_id("evt_"),
            "account_id": account_id,
            "kind": kind,
            "detail": json.dumps(detail or {}),
            "created_at": _iso(_now()),
        })

    def _account_body(self, row):
        return {"account_id": row["account_id"], "email": row["email"],
                "created_at": row["created_at"]}

    def _session_body(self, row, current=False):
        return {
            "session_id": row["session_id"],
            "surface": row["surface"],
            "device_label": row["device_label"],
            "created_at": row["created_at"],
            "last_seen_at": row["last_seen_at"],
            "expires_at": row["expires_at"],
            "current": bool(current),
        }

    def _create_session(self, account_id, surface, device_label):
        token = SESSION_TOKEN_PREFIX + secrets.token_urlsafe(32)
        moment = _now()
        row = {
            "session_id": _new_id("sess_"),
            "account_id": account_id,
            "token_hash": hash_key(token),
            "surface": (surface or "web")[:32],
            "device_label": (device_label or "")[:120],
            "created_at": _iso(moment),
            "last_seen_at": _iso(moment),
            "expires_at": _iso(moment + self.config["session_ttl"]),
            "revoked_at": "",
        }
        self.store.add_account_session(row)
        self._event(account_id, "session_created",
                    {"surface": row["surface"],
                     "session_id": row["session_id"]})
        return row, token

    def _get_or_create_account(self, email):
        row = self.store.get_account_by_email(email)
        if row:
            return row, False
        row = {
            "account_id": _new_id("acct_"),
            "email": email,
            "email_hash": hashlib.sha256(email.encode()).hexdigest(),
            "created_at": _iso(_now()),
            "updated_at": _iso(_now()),
        }
        if not self.store.add_account(row):
            return self.store.get_account_by_email(email), False
        self._event(row["account_id"], "account_created", {})
        return row, True

    def _complete_handoff(self, handoff_id, account_id):
        """Mark a pending handoff ready for the desktop app to
        exchange. Called by every successful browser sign-in that
        carries the handoff. Silently does nothing when the handoff
        is unknown, expired, or already settled: the sign-in itself
        must never fail because a handoff went stale."""
        if not handoff_id:
            return
        row = self.store.get_account_handoff(handoff_id)
        if not row or row.get("status") != "pending":
            return
        if _parse(row["expires_at"]) <= _now():
            return
        self.store.complete_account_handoff(
            handoff_id, account_id, _iso(_now()))

    # -- email sign-in links -------------------------------------------

    def request_email_link(self, email, handoff_id=None):
        """Create (if needed) the account for `email` and send it a
        one-time sign-in link. The response never reveals whether
        the account already existed. A fresh request retires every
        earlier unused link for the account."""
        email = normalize_email(email)
        account, _created = self._get_or_create_account(email)
        self.store.invalidate_email_tokens(
            account["account_id"], _iso(_now()))
        token = EMAIL_TOKEN_PREFIX + secrets.token_urlsafe(32)
        moment = _now()
        bound_handoff = ""
        if handoff_id:
            handoff = self.store.get_account_handoff(handoff_id)
            if handoff and handoff.get("status") == "pending" \
                    and _parse(handoff["expires_at"]) > moment:
                bound_handoff = handoff_id
        self.store.add_email_token({
            "token_hash": hash_key(token),
            "account_id": account["account_id"],
            "handoff_id": bound_handoff,
            "created_at": _iso(moment),
            "expires_at": _iso(moment + self.config["email_ttl"]),
            "consumed_at": "",
        })
        link = "%s/auth/sign-in?token=%s" % (
            self.config["site_base"].rstrip("/"), token)
        if bound_handoff:
            link += "&handoff=" + bound_handoff
        sent = mailer_module.send_sign_in_link(
            self.mailer, email, link,
            int(self.config["email_ttl"].total_seconds() // 60))
        self._event(account["account_id"], "email_link_requested",
                    {"delivered": bool(sent)})
        return {"ok": True, "email": email}

    def redeem_email_link(self, token, surface="web", device_label=""):
        """Trade a one-time email link token for a device session.
        This is also the support-assisted recovery path: control of
        the account email is the proof, and the redemption is
        written to the account's event log either way."""
        if not isinstance(token, str) or not token:
            raise _bad("a sign-in token is required")
        row = self.store.get_email_token(hash_key(token))
        if not row or row.get("consumed_at"):
            raise _bad("that sign-in link has already been used")
        if _parse(row["expires_at"]) <= _now():
            raise _bad("that sign-in link has expired; request a new one")
        if not self.store.consume_email_token(row["token_hash"],
                                              _iso(_now())):
            raise _bad("that sign-in link has already been used")
        account = self.store.get_account(row["account_id"])
        had_passkeys = bool(
            self.store.list_account_credentials(account["account_id"]))
        session, plaintext = self._create_session(
            account["account_id"], surface, device_label)
        self._event(account["account_id"],
                    "email_signin_with_passkeys_on_file"
                    if had_passkeys else "email_signin",
                    {"session_id": session["session_id"]})
        if row.get("handoff_id"):
            self._complete_handoff(row["handoff_id"],
                                   account["account_id"])
        return {
            "account": self._account_body(account),
            "session_token": plaintext,
            "session": self._session_body(session, current=True),
            "passkey_enrollment_recommended": not had_passkeys,
        }

    # -- passkey ceremonies ----------------------------------------------

    def _new_challenge(self, account_id, kind):
        challenge = secrets.token_bytes(32)
        challenge_id = _new_id("chal_")
        moment = _now()
        self.store.add_account_challenge({
            "challenge_id": challenge_id,
            "account_id": account_id or "",
            "kind": kind,
            "challenge": webauthn.b64url_encode(challenge),
            "created_at": _iso(moment),
            "expires_at": _iso(moment + self.config["challenge_ttl"]),
            "consumed_at": "",
        })
        return challenge_id, challenge

    def _take_challenge(self, challenge_id, kind):
        row = self.store.get_account_challenge(challenge_id or "")
        if not row or row.get("kind") != kind or row.get("consumed_at"):
            raise _bad("that sign-in ceremony has expired; start again")
        if _parse(row["expires_at"]) <= _now():
            raise _bad("that sign-in ceremony has expired; start again")
        if not self.store.consume_account_challenge(
                row["challenge_id"], _iso(_now())):
            raise _bad("that sign-in ceremony has expired; start again")
        return row

    def begin_passkey_registration(self, account):
        """Registration options for a signed-in account adding a
        passkey (its first, or an encouraged second)."""
        existing = self.store.list_account_credentials(
            account["account_id"])
        challenge_id, challenge = self._new_challenge(
            account["account_id"], "webauthn_create")
        options = {
            "rp": {"id": self.config["rp_id"],
                   "name": self.config["rp_name"]},
            "user": {
                "id": webauthn.b64url_encode(
                    account["account_id"].encode("utf-8")),
                "name": account["email"],
                "displayName": account["email"],
            },
            "challenge": webauthn.b64url_encode(challenge),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7},
                                 {"type": "public-key", "alg": -8},
                                 {"type": "public-key", "alg": -257}],
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": "preferred",
            },
            "attestation": "none",
            "excludeCredentials": [
                {"type": "public-key", "id": c["credential_id"]}
                for c in existing],
        }
        return {"challenge_id": challenge_id, "publicKey": options,
                "existing_passkeys": len(existing)}

    def finish_passkey_registration(self, account, challenge_id,
                                    response):
        row = self._take_challenge(challenge_id, "webauthn_create")
        if row.get("account_id") != account["account_id"]:
            raise _bad("that sign-in ceremony belongs to another account")
        try:
            credential = webauthn.verify_registration(
                self.config["rp_id"], self.config["origins"],
                webauthn.b64url_decode(row["challenge"]), response)
        except webauthn.WebAuthnError as exc:
            raise _bad("the passkey could not be registered: %s" % exc)
        credential_id = webauthn.b64url_encode(
            credential["credential_id"])
        if self.store.get_account_credential(credential_id):
            raise _conflict("that passkey is already registered")
        first = not self.store.list_account_credentials(
            account["account_id"])
        self.store.add_account_credential({
            "credential_id": credential_id,
            "account_id": account["account_id"],
            "public_key_cose": webauthn.b64url_encode(
                _cbor_encode(credential["cose_key"])),
            "alg": credential["alg"],
            "sign_count": credential["sign_count"],
            "aaguid": credential["aaguid"],
            "transports": "",
            "label": "",
            "created_at": _iso(_now()),
            "last_used_at": "",
        })
        self._event(account["account_id"], "passkey_added",
                    {"credential_id": credential_id})
        result = {"credential_id": credential_id,
                  "passkeys_on_file": len(self.store
                                          .list_account_credentials(
                                              account["account_id"]))}
        if first:
            result["recovery_codes"] = self._issue_recovery_codes(
                account["account_id"])
            result["recovery_codes_shown_once"] = True
        return result

    def _issue_recovery_codes(self, account_id):
        codes = []
        rows = []
        for _ in range(RECOVERY_CODE_COUNT):
            raw = "".join(secrets.choice(RECOVERY_ALPHABET)
                          for _ in range(12))
            pretty = "%s-%s-%s" % (raw[:4], raw[4:8], raw[8:])
            codes.append(pretty)
            rows.append({
                "account_id": account_id,
                "code_hash": hash_key(raw),
                "created_at": _iso(_now()),
                "consumed_at": "",
            })
        self.store.add_recovery_codes(rows)
        self._event(account_id, "recovery_codes_issued",
                    {"count": len(rows)})
        return codes

    def begin_passkey_authentication(self, email=None):
        """Authentication options. With an email, the account's own
        passkeys are offered; without one, the ceremony is
        discoverable (the authenticator names the account)."""
        account = None
        allow = []
        if email:
            account = self.store.get_account_by_email(
                normalize_email(email))
            if account:
                allow = [{"type": "public-key", "id": c["credential_id"]}
                         for c in self.store.list_account_credentials(
                             account["account_id"])]
        challenge_id, challenge = self._new_challenge(
            account["account_id"] if account else "", "webauthn_get")
        return {
            "challenge_id": challenge_id,
            "publicKey": {
                "challenge": webauthn.b64url_encode(challenge),
                "rpId": self.config["rp_id"],
                "userVerification": "preferred",
                "allowCredentials": allow,
            },
        }

    def finish_passkey_authentication(self, challenge_id, response,
                                      surface="web", device_label="",
                                      handoff_id=None):
        row = self._take_challenge(challenge_id, "webauthn_get")
        if not isinstance(response, dict) or not response.get("id"):
            raise _bad("the sign-in response is incomplete")
        credential = self.store.get_account_credential(response["id"])
        if not credential:
            raise _bad("that passkey is not registered with NPC")
        if row.get("account_id") \
                and row["account_id"] != credential["account_id"]:
            raise _bad("that passkey belongs to another account")
        try:
            cose_key, _used = _cbor_decode(
                webauthn.b64url_decode(credential["public_key_cose"]))
            new_count = webauthn.verify_authentication(
                self.config["rp_id"], self.config["origins"],
                webauthn.b64url_decode(row["challenge"]), response,
                cose_key, credential.get("sign_count") or 0)
        except webauthn.WebAuthnError as exc:
            raise _bad("the passkey sign-in could not be verified: %s"
                       % exc)
        self.store.update_credential_use(
            credential["credential_id"], new_count, _iso(_now()))
        account = self.store.get_account(credential["account_id"])
        session, plaintext = self._create_session(
            account["account_id"], surface, device_label)
        self._event(account["account_id"], "passkey_signin",
                    {"session_id": session["session_id"],
                     "credential_id": credential["credential_id"]})
        if handoff_id:
            self._complete_handoff(handoff_id, account["account_id"])
        return {
            "account": self._account_body(account),
            "session_token": plaintext,
            "session": self._session_body(session, current=True),
        }

    # -- recovery codes ----------------------------------------------------

    def redeem_recovery_code(self, email, code, surface="web",
                             device_label=""):
        """Trade one recovery code for a session. The failure shape
        is identical for an unknown email and a wrong code, so the
        endpoint cannot be used to learn which emails hold
        accounts."""
        failure = _bad(
            "that email and recovery code do not match our records")
        try:
            cleaned_email = normalize_email(email)
        except AccountError:
            raise failure
        if not isinstance(code, str):
            raise failure
        normalized = re.sub(r"[^A-Za-z0-9]", "", code).upper()
        account = self.store.get_account_by_email(cleaned_email)
        if not account or not normalized:
            raise failure
        found = self.store.find_recovery_code(
            account["account_id"], hash_key(normalized))
        if not found or found.get("consumed_at"):
            raise failure
        if not self.store.consume_recovery_code(
                account["account_id"], found["code_hash"], _iso(_now())):
            raise failure
        session, plaintext = self._create_session(
            account["account_id"], surface, device_label)
        self._event(account["account_id"], "recovery_code_used",
                    {"session_id": session["session_id"]})
        _total, unused = self.store.count_recovery_codes(
            account["account_id"])
        return {
            "account": self._account_body(account),
            "session_token": plaintext,
            "session": self._session_body(session, current=True),
            "passkey_enrollment_recommended": True,
            "recovery_codes_remaining": unused,
        }

    # -- sessions ------------------------------------------------------------

    def authenticate(self, token):
        """Resolve a session token to (account, session), or None.
        Expired and revoked sessions resolve to None, exactly like
        an unknown token."""
        if not isinstance(token, str) \
                or not token.startswith(SESSION_TOKEN_PREFIX):
            return None
        row = self.store.find_account_session_by_token(hash_key(token))
        if not row or row.get("revoked_at"):
            return None
        moment = _now()
        if _parse(row["expires_at"]) <= moment:
            return None
        if moment - _parse(row["last_seen_at"]) > timedelta(minutes=5):
            self.store.touch_account_session(row["session_id"],
                                             _iso(moment))
            row = dict(row, last_seen_at=_iso(moment))
        account = self.store.get_account(row["account_id"])
        if account is None:
            return None
        return account, row

    def list_sessions(self, account, current_session_id=None):
        rows = self.store.list_account_sessions(account["account_id"])
        live = [r for r in rows if not r.get("revoked_at")
                and _parse(r["expires_at"]) > _now()]
        live.sort(key=lambda r: r["created_at"], reverse=True)
        return {"sessions": [
            self._session_body(r, current=(
                r["session_id"] == current_session_id)) for r in live]}

    def revoke_session(self, account, session_id, current_session_id=None):
        row = None
        for candidate in self.store.list_account_sessions(
                account["account_id"]):
            if candidate["session_id"] == session_id:
                row = candidate
                break
        if row is None:
            raise AccountError(404, {"error": "not_found",
                                     "detail": "no such session"})
        if not row.get("revoked_at"):
            self.store.revoke_account_session(session_id, _iso(_now()))
            self._event(account["account_id"], "session_revoked",
                        {"session_id": session_id})
        return {"ok": True,
                "revoked_current": session_id == current_session_id}

    # -- desktop handoff -----------------------------------------------------

    def create_handoff(self, device_label=""):
        handoff_id = _new_id("hoff_")
        secret = HANDOFF_SECRET_PREFIX + secrets.token_urlsafe(24)
        moment = _now()
        self.store.add_account_handoff({
            "handoff_id": handoff_id,
            "secret_hash": hash_key(secret),
            "device_label": (device_label or "")[:120],
            "status": "pending",
            "account_id": "",
            "created_at": _iso(moment),
            "expires_at": _iso(moment + self.config["handoff_ttl"]),
            "completed_at": "",
            "consumed_at": "",
        })
        return {
            "handoff_id": handoff_id,
            "secret": secret,
            "authorize_url": "%s/auth/sign-in?handoff=%s" % (
                self.config["site_base"].rstrip("/"), handoff_id),
            "expires_at": _iso(moment + self.config["handoff_ttl"]),
        }

    def _checked_handoff(self, handoff_id, secret):
        row = self.store.get_account_handoff(handoff_id or "")
        if not row or not isinstance(secret, str) or not hmac.compare_digest(
                row.get("secret_hash", ""), hash_key(secret)):
            raise _bad("that handoff is not recognized")
        return row

    def poll_handoff(self, handoff_id, secret):
        row = self._checked_handoff(handoff_id, secret)
        status = row["status"]
        if status == "pending" and _parse(row["expires_at"]) <= _now():
            status = "expired"
        return {"status": status, "expires_at": row["expires_at"]}

    def exchange_handoff(self, handoff_id, secret):
        """Trade a completed handoff for the desktop app's own
        device session, exactly once: the handoff's secret (which
        never leaves the app) is the exchange credential, and the
        handoff is consumed as the session is minted."""
        row = self._checked_handoff(handoff_id, secret)
        if row["status"] == "consumed":
            raise _bad("that handoff has already been exchanged")
        if row["status"] != "ready":
            raise _bad("that handoff has not been signed in yet")
        if _parse(row["expires_at"]) <= _now():
            raise _bad("that handoff has expired; start again")
        if not self.store.consume_account_handoff(handoff_id,
                                                  _iso(_now())):
            raise _bad("that handoff has already been exchanged")
        account = self.store.get_account(row["account_id"])
        session, plaintext = self._create_session(
            account["account_id"], "desktop",
            row.get("device_label") or "")
        self._event(account["account_id"], "handoff_exchanged",
                    {"session_id": session["session_id"]})
        return {
            "account": self._account_body(account),
            "session_token": plaintext,
            "session": self._session_body(session, current=True),
        }
