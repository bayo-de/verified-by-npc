"""Canonical JSON for response signing (NPC-JCS-v1).

Deterministic serialization used as the signature input for every API
response body. Definition:

- UTF-8 encoding
- Object keys sorted lexicographically (Unicode code point order)
- No insignificant whitespace
- Numbers serialized as JSON numbers (int/float as produced by json.dumps)
- No NaN / Infinity (rejected)

Verifiers MUST reproduce exactly this serialization before checking the
X-NPC-Signature header. A reference verifier is provided in docs/API.md.
"""
import json
import math


def canonicalize(obj) -> bytes:
    """Serialize obj to canonical bytes. Raises ValueError on non-finite floats."""
    _reject_nonfinite(obj)
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)
    return text.encode("utf-8")


def _reject_nonfinite(obj):
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("non-finite float cannot be canonicalized")
    elif isinstance(obj, dict):
        for v in obj.values():
            _reject_nonfinite(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_nonfinite(v)


def canonical_sha256_hex(obj) -> str:
    """SHA-256 hex digest of the canonical bytes (used for claim hashes)."""
    import hashlib
    return hashlib.sha256(canonicalize(obj)).hexdigest()


def normalize_claim_text(text: str) -> str:
    """Normalize claim text before hashing: strip, collapse whitespace, lowercase."""
    return " ".join(text.strip().split()).lower()


def claim_hash_for_text(text: str) -> str:
    """SHA-256 hex of the normalized claim text."""
    import hashlib
    return hashlib.sha256(normalize_claim_text(text).encode("utf-8")).hexdigest()
