"""PACT record layer (flywheel #73): NPC's extension records for the
Personal Agent Consent & Trust Protocol's delegated-grant flow.

PACT 1.0 defines the consent ceremony (section 5.3), the grant token
(section 5.4), a revocation *check* with no mechanism (section 5.5 step
2), and signed per-call receipts (section 5.6), but no consent-record
format, no audit-log format, and no revocation endpoint. This module is
the record layer that fills those three gaps, built entirely from
machinery this codebase already runs: NPC-JCS-v1 canonicalization,
Ed25519 signing with key_id (issuer purpose), and the append-only
store. The shapes are ported unchanged from the proven scratch
demonstration (flywheel sandbox/pact-test/extension_demo.py, 9/9
checks); see trust-tab/pact-record-layer-PROFILE-DRAFT.md for the
format profile.

Records produced here:

- Consent Record (npc.pact.consent_record), minted at grant issuance.
  Preserves scopes_requested vs scopes_granted exactly as approved:
  what the user withheld stays visible in the signed record.
- Grant Audit Log entries. Every Provider receipt (section 5.6 claims)
  is appended as a signed, hash-chained entry; the chain gives the
  completeness property PACT lacks: a missing entry, a never-issued
  receipt, or a rewritten receipt breaks verification at the exact
  sequence number.
- Revocation records (npc.pact.revocation), append-only: revoking is
  writing a new signed record, never editing the consent.
- Grant status records (npc.pact.grant_status), signed at read time,
  carrying the consent record_id so anyone holding a receipt can check
  the grant behind it. Status is one of active / revoked / expired.

Honesty rule: a record here is a signed NPC record. It is labelled
exactly that, never as a PACT-native artifact; PACT itself defines
none of these formats.
"""
import base64
import secrets
from datetime import datetime, timezone

from .canonical import canonicalize, canonical_sha256_hex
from .models import is_iso8601, utcnow_iso

GENESIS_HASH = "0" * 64

CONSENT_RECORD_TYPE = "npc.pact.consent_record"
REVOCATION_RECORD_TYPE = "npc.pact.revocation"
STATUS_RECORD_TYPE = "npc.pact.grant_status"

# The signing purpose for record-layer artifacts. Responses are signed
# with "api_signing" by the server envelope; the records themselves are
# issuer-signed so they stay verifiable as portable artifacts.
SIGNING_PURPOSE = "issuer"


# -- signing ----------------------------------------------------------------
def sign_record(keys, core: dict) -> dict:
    """Sign a record core with the active issuer key.

    The signature covers the canonical bytes of the record including
    key_id and excluding the signature field itself: the library's
    signing convention, identical to the scratch demonstration.
    """
    rec = dict(core)
    rec["key_id"] = keys.active_key_id(SIGNING_PURPOSE)
    if not rec["key_id"]:
        raise RuntimeError(f"no active key for purpose '{SIGNING_PURPOSE}'")
    _, sig = keys.sign(SIGNING_PURPOSE, canonicalize(rec))
    rec["signature"] = base64.b64encode(sig).decode()
    return rec


def verify_record(keys, rec: dict) -> bool:
    """Verify a signed record against the published key registry."""
    if not isinstance(rec, dict):
        return False
    key_id = rec.get("key_id")
    sig_b64 = rec.get("signature")
    if not key_id or not sig_b64:
        return False
    body = {k: v for k, v in rec.items() if k != "signature"}
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False
    return keys.verify(key_id, canonicalize(body), sig)


# -- consent records ----------------------------------------------------------
def validate_consent_input(fields: dict) -> list:
    """Shape checks for a grant-issuance request. Returns problems."""
    problems = []
    for name in ("pa_iss", "pa_sub", "brand_id", "user_id_at_brand"):
        v = fields.get(name)
        if not isinstance(v, str) or not v or len(v) > 256:
            problems.append(f"{name} is required (string, max 256 chars)")
    grant_id = fields.get("grant_id")
    if grant_id is not None and (not isinstance(grant_id, str)
                                 or not grant_id or len(grant_id) > 128):
        problems.append("grant_id must be a string (max 128 chars)")
    for name in ("scopes_requested", "scopes_granted"):
        v = fields.get(name)
        if not isinstance(v, list) or any(
                not isinstance(s, str) or not s or len(s) > 128
                for s in v):
            problems.append(f"{name} must be a list of scope strings")
    req = fields.get("scopes_requested")
    granted = fields.get("scopes_granted")
    if isinstance(req, list) and isinstance(granted, list):
        if not set(granted) <= set(req):
            problems.append(
                "scopes_granted must be a subset of scopes_requested: "
                "the ceremony can only grant what was requested")
    for name in ("shown_at", "granted_at", "expires_at"):
        v = fields.get(name)
        if v is not None and not is_iso8601(v):
            problems.append(f"{name} must be ISO-8601")
    return problems


def mint_consent_record(store, keys, fields: dict):
    """Mint and store the signed Consent Record for a new grant.

    Assumes fields passed validate_consent_input. Returns the record,
    or None when a consent already exists for the grant_id.
    """
    now = utcnow_iso()
    core = {
        "record_type": CONSENT_RECORD_TYPE,
        "record_id": "cr_" + secrets.token_hex(12),
        "grant_id": fields.get("grant_id") or "grant_" + secrets.token_hex(12),
        "pa_iss": fields["pa_iss"],
        "pa_sub": fields["pa_sub"],
        "brand_id": fields["brand_id"],
        "user_id_at_brand": fields["user_id_at_brand"],
        "scopes_requested": list(fields["scopes_requested"]),
        "scopes_granted": list(fields["scopes_granted"]),
        "shown_at": fields.get("shown_at") or now,
        "granted_at": fields.get("granted_at") or now,
        "expires_at": fields.get("expires_at"),
    }
    rec = sign_record(keys, core)
    if not store.add_pact_consent(rec):
        return None
    return rec


def verify_consent_record(keys, rec: dict) -> bool:
    return (isinstance(rec, dict)
            and rec.get("record_type") == CONSENT_RECORD_TYPE
            and verify_record(keys, rec))


# -- grant audit log ---------------------------------------------------------
def entry_hash_of(entry: dict) -> str:
    """Chain hash of one audit entry.

    Defined ONCE and used at both write and verify time (the scratch
    run's one bug was assembling this input two ways). The hash covers
    the signed entry, excluding the stored receipt claims (bound via
    receipt_claims_hash) and the hash field itself.
    """
    body = {k: v for k, v in entry.items()
            if k not in ("receipt_claims", "entry_hash")}
    return canonical_sha256_hex(body)


def append_receipt(store, keys, grant_id: str, receipt_claims: dict,
                   ts: str = None):
    """Append one Provider receipt to the grant's audit log.

    receipt_claims are the section 5.6 claims exactly as the Provider
    issued them ({grantId, user, pa, brand, scopesUsed, actions, ts});
    they are stored with the entry so the entry is independently
    checkable. Returns the signed entry, or None on a sequence clash.
    """
    last = store.last_pact_audit_entry(grant_id)
    prev = last["entry_hash"] if last else GENESIS_HASH
    seq = (last["seq"] + 1) if last else 1
    entry = {
        "record_type": "npc.pact.audit_entry",
        "seq": seq,
        "grant_id": grant_id,
        "receipt_claims_hash": canonical_sha256_hex(receipt_claims),
        "prev_entry_hash": prev,
        "ts": ts or receipt_claims.get("ts") or utcnow_iso(),
        "receipt_claims": receipt_claims,
    }
    entry = sign_record(keys, entry)
    entry["entry_hash"] = entry_hash_of(entry)
    if not store.add_pact_audit_entry(entry):
        return None
    return entry


def verify_audit_chain(keys, entries) -> tuple:
    """Verify a grant's full audit chain. Returns (ok, detail).

    Checks, per entry and in order: the prev_entry_hash link, the
    receipt-claims hash against the stored claims, the entry hash, and
    the entry signature. The first failure names its exact seq, which
    is what makes a rewritten or missing receipt detectable.
    """
    prev = GENESIS_HASH
    expect_seq = 1
    for e in entries:
        if e.get("seq") != expect_seq:
            return False, (f"seq {expect_seq}: entry missing or "
                           f"out of order (found seq {e.get('seq')})")
        if e["prev_entry_hash"] != prev:
            return False, f"seq {e['seq']}: prev_entry_hash link broken"
        if canonical_sha256_hex(e["receipt_claims"]) \
                != e["receipt_claims_hash"]:
            return False, (f"seq {e['seq']}: receipt claims do not match "
                           f"logged hash")
        if entry_hash_of(e) != e["entry_hash"]:
            return False, f"seq {e['seq']}: entry hash mismatch"
        body = {k: v for k, v in e.items() if k != "entry_hash"}
        if not verify_record(keys, body):
            return False, f"seq {e['seq']}: entry signature invalid"
        prev = e["entry_hash"]
        expect_seq += 1
    return True, "chain intact"


# -- revocation + status -------------------------------------------------------
def revoke_grant(store, keys, grant_id: str, revoked_by: str,
                 reason: str, revoked_at: str = None):
    """Write the signed revocation record for a grant (append-only).

    Returns the record, or None when the grant is already revoked.
    """
    core = {
        "record_type": REVOCATION_RECORD_TYPE,
        "record_id": "rv_" + secrets.token_hex(12),
        "grant_id": grant_id,
        "revoked_at": revoked_at or utcnow_iso(),
        "revoked_by": revoked_by,
        "reason": reason,
    }
    rec = sign_record(keys, core)
    if not store.add_pact_revocation(rec):
        return None
    return rec


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def grant_status_record(store, keys, grant_id: str, at: str = None):
    """Build the signed status record for a grant at a moment in time.

    Status is revoked when a revocation record exists, else expired
    when the consent's expires_at has passed, else active. The record
    carries the consent record_id (and, when revoked, the revocation
    record_id) so a receipt-holder can trace the whole grant history.
    Returns None when no consent exists for the grant.
    """
    consent = store.get_pact_consent(grant_id)
    if consent is None:
        return None
    checked_at = at or utcnow_iso()
    revocation = store.get_pact_revocation(grant_id)
    core = {
        "record_type": STATUS_RECORD_TYPE,
        "grant_id": grant_id,
        "consent_record_id": consent["record_id"],
        "status": "active",
        "checked_at": checked_at,
    }
    if revocation is not None:
        core["status"] = "revoked"
        core["revoked_at"] = revocation["revoked_at"]
        core["revocation_record_id"] = revocation["record_id"]
    elif consent.get("expires_at") and \
            _parse_iso(checked_at) > _parse_iso(consent["expires_at"]):
        core["status"] = "expired"
    return sign_record(keys, core)


def verify_status_record(keys, rec: dict) -> bool:
    return (isinstance(rec, dict)
            and rec.get("record_type") == STATUS_RECORD_TYPE
            and verify_record(keys, rec))


def gate_allows(keys, status_rec: dict) -> bool:
    """The section 5.5 step-2 gate, reading the extension status.

    Fails closed: anything but a signature-verified status of exactly
    "active" denies.
    """
    return verify_status_record(keys, status_rec) \
        and status_rec.get("status") == "active"
