"""MemoryRecord: a signed claim on the evidence spine.

Shape (per DESIGN v1 section 5):

  MemoryRecord {
    id, seq (per-stream, contiguous), ts,
    stream_kind, company_id, team_id, stream_agent_id,
    agent_id (writer), writer_company_id, writer_team_id,
    type: memory.assert | memory.supersede | memory.retract,
    content: { text, tags[], confidence, [target_id, reason] },
    provenance: { derived_from[], source, [url, captured_at, hash], trust },
    prev_hash, signature_b64, key_id
  }

Append-only: corrections are memory.supersede pointing at the old record's
id; withdrawals are memory.retract. The signature covers the canonical
signing core; the chain links record_hash(prev) == prev_hash.
"""
import base64
import binascii
import re
from dataclasses import dataclass, field

from npc_verify.models import utcnow_iso, is_iso8601

from .scope import (MEMORY_TYPES, STREAM_KINDS, valid_record_id,
                    valid_scope_id, valid_tag, stream_key)

GENESIS_PREV = "0" * 64
MAX_TEXT = 4000
MAX_TAGS = 16
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^ak_[0-9a-f]{16}$")


def new_record_id() -> str:
    import secrets
    return "mem_" + secrets.token_hex(12)


def signing_core(rec: dict) -> dict:
    """Canonical dict covered by the writer's signature."""
    return {
        "id": rec["id"],
        "seq": rec["seq"],
        "stream": rec["stream_key"],
        "ts": rec["ts"],
        "agent_id": rec["agent_id"],
        "writer_scope": {
            "company_id": rec.get("writer_company_id"),
            "team_id": rec.get("writer_team_id"),
        },
        "type": rec["type"],
        "content": rec["content"],
        "provenance": rec["provenance"],
        "prev_hash": rec["prev_hash"],
    }


def record_hash(rec: dict) -> str:
    """SHA-256 hex of the canonical signing core (chain link)."""
    from npc_verify.canonical import canonicalize
    import hashlib
    return hashlib.sha256(canonicalize(signing_core(rec))).hexdigest()


def validate_shape(rec: dict) -> list:
    """Fail-closed shape validation. Returns a list of problems (empty ok)."""
    problems = []
    if not isinstance(rec, dict):
        return ["record must be a JSON object"]

    if not valid_record_id(rec.get("id")):
        problems.append("id must look like mem_<8-64 base chars>")
    seq = rec.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        problems.append("seq must be a non-negative integer")
    if not isinstance(rec.get("ts"), str) or not is_iso8601(rec["ts"]):
        problems.append("ts must be ISO-8601")

    kind = rec.get("stream_kind")
    if kind not in STREAM_KINDS:
        problems.append(f"stream_kind must be one of {STREAM_KINDS}")
    else:
        cid, tid, said = (rec.get("company_id"), rec.get("team_id"),
                          rec.get("stream_agent_id"))
        try:
            expect = stream_key(kind, cid, tid, said)
        except ValueError as exc:
            problems.append(f"stream dimensions invalid: {exc}")
            expect = None
        if expect is not None and rec.get("stream_key") != expect:
            problems.append("stream_key does not match stream dimensions")

    writer = rec.get("agent_id")
    if not valid_scope_id(writer or ""):
        problems.append("agent_id (writer) must match [A-Za-z0-9_-]")
    if kind == "agent" and said != writer:
        problems.append("agent streams accept writes only from their agent")
    for name in ("writer_company_id", "writer_team_id"):
        v = rec.get(name)
        if v is not None and not valid_scope_id(v):
            problems.append(f"{name} must match [A-Za-z0-9_-] or be null")

    rtype = rec.get("type")
    if rtype not in MEMORY_TYPES:
        problems.append(f"type must be one of {MEMORY_TYPES}")

    content = rec.get("content")
    if not isinstance(content, dict):
        problems.append("content must be an object")
    else:
        text = content.get("text")
        if not isinstance(text, str) or not text.strip():
            problems.append("content.text is required")
        elif len(text) > MAX_TEXT:
            problems.append(f"content.text exceeds {MAX_TEXT} chars")
        tags = content.get("tags", [])
        if not isinstance(tags, list) or len(tags) > MAX_TAGS:
            problems.append(f"content.tags must be a list (max {MAX_TAGS})")
        else:
            for t in tags:
                if not valid_tag(t):
                    problems.append(
                        "content.tags must be lowercase slugs "
                        "[a-z0-9_-] (max 48)")
                    break
        conf = content.get("confidence", 1.0)
        if not isinstance(conf, (int, float)) or isinstance(conf, bool) \
                or not 0.0 <= conf <= 1.0:
            problems.append("content.confidence must be a number in [0, 1]")
        target = content.get("target_id")
        if rtype in ("memory.supersede", "memory.retract"):
            if not valid_record_id(target or ""):
                problems.append(
                    "supersede/retract content.target_id must be a mem_ id")
        elif target is not None:
            problems.append("content.target_id only on supersede/retract")
        reason = content.get("reason")
        if reason is not None and (not isinstance(reason, str)
                                   or len(reason) > 500):
            problems.append("content.reason must be a string (max 500)")

    prov = rec.get("provenance")
    if not isinstance(prov, dict):
        problems.append("provenance must be an object")
    else:
        df = prov.get("derived_from", [])
        if not isinstance(df, list) or len(df) > 32:
            problems.append("provenance.derived_from must be a list (max 32)")
        else:
            for d in df:
                if not isinstance(d, str) or len(d) > 128 or not d.strip():
                    problems.append("provenance.derived_from entries must be "
                                    "non-empty strings (max 128)")
                    break
        source = prov.get("source")
        if source not in ("session", "memory", "external"):
            problems.append(
                "provenance.source must be session, memory, or external")
        trust = prov.get("trust", "trusted")
        if source == "external":
            if trust != "untrusted":
                problems.append(
                    "external provenance must be labeled untrusted")
            url = prov.get("url")
            if not isinstance(url, str) or not url.startswith(
                    ("http://", "https://")) or len(url) > 500:
                problems.append("external provenance needs an http(s) url")
            if not isinstance(prov.get("captured_at"), str) or not is_iso8601(
                    prov.get("captured_at")):
                problems.append(
                    "external provenance needs captured_at (ISO-8601)")
            if not isinstance(prov.get("hash"), str) or not HASH_RE.match(
                    prov.get("hash") or ""):
                problems.append(
                    "external provenance needs hash (64 hex chars)")
        elif trust not in ("trusted", "untrusted"):
            problems.append("provenance.trust must be trusted or untrusted")

    ph = rec.get("prev_hash")
    if not isinstance(ph, str) or not HASH_RE.match(ph):
        problems.append("prev_hash must be 64 hex chars")
    sig = rec.get("signature_b64")
    try:
        raw = base64.b64decode(sig or "", validate=True)
        if len(raw) != 64:
            problems.append("signature_b64 must decode to 64 bytes")
    except (binascii.Error, ValueError, TypeError):
        problems.append("signature_b64 must be valid base64")
    if not isinstance(rec.get("key_id"), str) or not KEY_ID_RE.match(
            rec.get("key_id") or ""):
        problems.append("key_id must look like ak_<16 hex>")
    return problems


def public_dict(rec: dict) -> dict:
    """Response-safe dict. Records carry no secrets (write boundary)."""
    return {
        "id": rec["id"],
        "seq": rec["seq"],
        "ts": rec["ts"],
        "stream_kind": rec["stream_kind"],
        "stream_key": rec["stream_key"],
        "company_id": rec.get("company_id"),
        "team_id": rec.get("team_id"),
        "stream_agent_id": rec.get("stream_agent_id"),
        "agent_id": rec["agent_id"],
        "writer_scope": {
            "company_id": rec.get("writer_company_id"),
            "team_id": rec.get("writer_team_id"),
        },
        "type": rec["type"],
        "content": rec["content"],
        "provenance": rec["provenance"],
        "prev_hash": rec["prev_hash"],
        "record_hash": rec.get("record_hash"),
        "signature": rec["signature_b64"],
        "key_id": rec["key_id"],
    }
