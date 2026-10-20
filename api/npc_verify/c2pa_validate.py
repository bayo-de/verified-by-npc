"""C2PA cryptographic validation (stdlib only).

Runs the manifest checks the structural parser (c2pa.py) does not:

1. COSE signature: the signature box's COSE_Sign1 is verified
   against the signing certificate carried in its x5chain header,
   over the claim bytes exactly as stored in the file.
2. Assertion integrity: every assertion the claim lists with a hash
   (created + gathered) is re-hashed from the bytes stored in the
   manifest; all must match.
3. Asset binding: the data-hash assertion (c2pa.hash.data) is
   recomputed over the asset with the claim's own exclusion ranges
   removed, per the C2PA spec.
4. Certificate chain: adjacent certificates in the presented chain
   are signature-checked, and the signing certificate's validity
   window is read. NO trust-list verdict is rendered: with no trust
   list configured, the signer is reported exactly as presented in
   the certificate, unrated. This module answers "does the
   cryptography check out and who does the certificate name", never
   "should you trust them".

Validated means all of 1-3 pass. Anything this implementation
cannot evaluate (an unknown COSE algorithm, a BMFF Merkle binding,
a certificate chain signature algorithm outside its set) keeps the
result honestly unvalidated with the specific reason, so plumbing
can land per-case without a record ever claiming a check ran that
did not.

Runs in the Lambda runtime: pure Python, no native dependencies.
Never raises.
"""
import hashlib

from . import c2pa as _c2pa
from . import cose as _cose
from . import der as _der

_HASH_ALGS = ("sha256", "sha384", "sha512")


def _label_from_url(url):
    if not isinstance(url, str):
        return None
    tail = url.rsplit("/", 1)[-1]
    return tail or None


def _hash_bytes(alg, data):
    try:
        return hashlib.new(alg, data).digest()
    except Exception:
        return None


def _leaf_hash_candidates(manifest, label):
    """The byte forms a claim assertion hash may cover for a label:
    each matching leaf's enclosing-box content span (description box
    + content box: the form real signers hash, verified against the
    reference SDK's output), then its bare content bytes."""
    out = []
    for e in manifest["leaves"]:
        if e["label"] == label:
            out.append(e.get("box_bytes") or e["bytes"])
            out.append(e["bytes"])
    return out


def _signature_leaves(manifest, claim):
    """Candidate signature boxes for a claim, best first: the leaf
    the claim's own signature URI names, then any signature leaf."""
    label = _label_from_url((claim or {}).get("signature"))
    out = []
    if label:
        out.extend(e for e in manifest["leaves"]
                   if e["label"] == label)
    out.extend(e for e in manifest["leaves"]
               if e["label"] == "c2pa.signature" and e not in out)
    return out


def _assertion_integrity(manifest, claim):
    """(ok, checked, reason): every assertion the claim lists with a
    hash must re-hash to that value from the stored bytes."""
    claim = claim or {}
    alg = str(claim.get("alg") or "sha256").lower()
    if alg not in _HASH_ALGS:
        return None, 0, "unsupported claim hash algorithm: %s" % alg
    entries = []
    for field in ("created_assertions", "gathered_assertions",
                  "assertions"):
        listed = claim.get(field)
        if isinstance(listed, list):
            entries.extend(listed)
    checked = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        want = entry.get("hash")
        if not isinstance(url, str) or not isinstance(want, bytes):
            continue
        if not url.startswith("self#jumbf"):
            continue  # remote / ingredient assertions: not embedded
        label = _label_from_url(url)
        candidates = _leaf_hash_candidates(manifest, label)
        if not candidates:
            return False, checked, \
                "assertion %s is listed in the claim but missing" % label
        if not any(_hash_bytes(alg, c) == want for c in candidates):
            return False, checked, \
                "assertion %s does not match the hash in the claim" % label
        checked += 1
    if checked == 0:
        return None, 0, "the claim lists no assertion hashes to check"
    return True, checked, None


def _asset_binding(asset, manifest):
    """(state, detail): the data-hash assertion, recomputed.

    state is "verified", "failed", or "not_run" (with detail saying
    why it could not run)."""
    hash_leaf = None
    for e in manifest["leaves"]:
        if e["label"] in ("c2pa.hash.data",) and \
                isinstance(e["data"], dict):
            hash_leaf = e
            break
    if hash_leaf is None:
        for e in manifest["leaves"]:
            if isinstance(e["label"], str) and \
                    e["label"].startswith("c2pa.hash.bmff"):
                return "not_run", (
                    "BMFF Merkle asset binding is not evaluated by "
                    "this verifier yet")
        return "not_run", "the manifest carries no data hash assertion"
    spec = hash_leaf["data"]
    want = spec.get("hash")
    alg = str(spec.get("alg") or "sha256").lower()
    if not isinstance(want, bytes) or alg not in _HASH_ALGS:
        return "not_run", "the data hash assertion is not readable"
    if spec.get("merkle") or spec.get("hashes"):
        return "not_run", ("BMFF Merkle asset binding is not evaluated "
                           "by this verifier yet")
    exclusions = spec.get("exclusions")
    ranges = []
    if isinstance(exclusions, list):
        for ex in exclusions:
            if isinstance(ex, dict) and \
                    isinstance(ex.get("start"), int) and \
                    isinstance(ex.get("length"), int):
                ranges.append((ex["start"], ex["length"]))
    ranges.sort()
    try:
        h = hashlib.new(alg)
        pos = 0
        for start, length in ranges:
            if start < pos or start > len(asset) or length < 0:
                return "not_run", "the data hash exclusions are malformed"
            h.update(asset[pos:start])
            pos = max(pos, start + length)
        h.update(asset[pos:])
    except Exception:
        return "not_run", "the data hash could not be recomputed"
    if h.digest() == want:
        return "verified", "the asset matches the hash in the claim"
    return "failed", "the asset does not match the hash in the claim"


def _chain_facts(chain_der):
    """Parse the presented chain; check each adjacent link's
    signature. Returns (certs, chain_state, chain_reason)."""
    certs = []
    for der_bytes in chain_der:
        facts = _der.parse_certificate(der_bytes)
        if facts is None:
            return certs, "unreadable", \
                "a certificate in the chain could not be parsed"
        certs.append(facts)
    if not certs:
        return certs, "absent", "the signature carries no certificate"
    for i in range(len(certs) - 1):
        subject, issuer = certs[i], certs[i + 1]
        if not _cose.verify_cert_signature(issuer, subject):
            return certs, "unverifiable", (
                "the chain link above %s could not be verified with "
                "this verifier" % (subject["subject"] or "the signer"))
    return certs, "verified", None


def _validate_claim(data, manifest, claim, claim_raw):
    """Validate one claim from a manifest store. Returns the result
    dict validate_credentials documents; never raises."""
    result = {
        "status": "not_validated",
        "signature": {"state": "not_run", "algorithm": None},
        "assertions": {"state": "not_run", "checked": 0},
        "asset_binding": {"state": "not_run", "detail": None},
        "signer": None,
        "detail": None,
    }
    sig_leaf = None
    cose_sign1 = None
    for candidate in _signature_leaves(manifest, claim):
        try:
            decoded, _used = _c2pa._cbor_decode(candidate["bytes"])
        except _c2pa._CborError:
            continue
        if isinstance(decoded, list) and len(decoded) == 4:
            sig_leaf = candidate
            cose_sign1 = decoded
            break
    if cose_sign1 is None:
        result["detail"] = ("the manifest carries no readable "
                            "signature box, so there is no signature "
                            "to verify")
        return result
    protected, unprotected, _payload, signature = cose_sign1
    if not isinstance(protected, bytes) or \
            not isinstance(signature, bytes):
        result["detail"] = "the signature box could not be read"
        return result
    try:
        phdr, _u = _c2pa._cbor_decode(protected)
    except _c2pa._CborError:
        result["detail"] = "the signature header could not be read"
        return result
    if not isinstance(phdr, dict):
        result["detail"] = "the signature header could not be read"
        return result
    alg = _c2pa._map_get(phdr, 1)
    alg_name = _cose.COSE_ALG_NAMES.get(alg) \
        if isinstance(alg, int) else None
    result["signature"]["algorithm"] = alg_name
    # The certificate chain (x5chain) sits in the protected header in
    # current manifests and in the unprotected header in v1-era ones.
    chain = _c2pa._map_get(phdr, 33)
    if chain is None and isinstance(unprotected, dict):
        chain = _c2pa._map_get(unprotected, 33)
        if chain is None:
            chain = unprotected.get("x5chain")
    if isinstance(chain, bytes):
        chain = [chain]
    if not isinstance(chain, list) or not chain or \
            not all(isinstance(c, bytes) for c in chain):
        result["detail"] = ("the signature carries no readable "
                            "signing certificate")
        return result
    certs, chain_state, chain_reason = _chain_facts(chain)
    if not certs:
        result["detail"] = chain_reason or \
            "the signing certificate could not be read"
        return result
    leaf_cert = certs[0]
    result["signer"] = {
        "subject": leaf_cert["subject"],
        "issuer": leaf_cert["issuer"],
        "algorithm": alg_name,
        "not_before": leaf_cert["not_before"],
        "not_after": leaf_cert["not_after"],
        "chain": chain_state,
        "trust": "as_presented_not_rated",
    }
    if alg_name is None:
        result["detail"] = ("unsupported signature algorithm in "
                            "the manifest: %r" % (alg,))
        return result

    # 1. COSE signature over the stored claim bytes.
    tbs = _c2pa._cbor_encode(["Signature1", protected, b"", claim_raw])
    sig_ok, _name = _cose.verify_cose_signature(
        alg, leaf_cert, tbs, signature)
    result["signature"]["state"] = "valid" if sig_ok else "invalid"

    # 2. Assertion integrity against the claim's hashes.
    a_ok, a_checked, a_reason = _assertion_integrity(manifest, claim)
    result["assertions"]["checked"] = a_checked
    result["assertions"]["state"] = (
        "verified" if a_ok is True else
        "failed" if a_ok is False else "not_run")

    # 3. Asset binding.
    b_state, b_detail = _asset_binding(data, manifest)
    result["asset_binding"] = {"state": b_state, "detail": b_detail}

    if sig_ok and a_ok is True and b_state == "verified":
        result["status"] = "valid"
        result["detail"] = (
            "the manifest signature verifies, every assertion "
            "matches the claim, and the file matches its recorded "
            "hash")
    elif not sig_ok:
        result["status"] = "invalid"
        result["detail"] = ("the manifest signature does not "
                            "verify against its signing certificate")
    elif a_ok is False:
        result["status"] = "invalid"
        result["detail"] = a_reason or \
            "an assertion does not match the claim"
    elif b_state == "failed":
        result["status"] = "invalid"
        result["detail"] = b_detail
    else:
        reasons = [r for r in (a_reason if a_ok is None else None,
                               b_detail if b_state == "not_run"
                               else None) if r]
        result["detail"] = ("the signature verifies, but full "
                            "validation could not complete: "
                            + "; ".join(reasons)) if reasons else \
            "full validation could not complete"
    return result


def validate_credentials(data):
    """Cryptographically validate an asset's C2PA manifest.

    Returns None when no readable claim is present (the caller keeps
    the structural result, or the not_present result). Otherwise a
    dict:

      {status: "valid" | "invalid" | "not_validated",
       signature: {state, algorithm},
       assertions: {state, checked},
       asset_binding: {state, detail},
       signer: {subject, issuer, algorithm, not_before, not_after,
                chain, trust: "as_presented_not_rated"} | None,
       detail: a plain sentence about the outcome}

    "not_validated" means the manifest is present but this verifier
    could not evaluate some part of it; the reason is in detail. A
    store can hold several manifests (ingredients carry their own);
    every claim found is tried and the strongest outcome reported,
    a fully valid one first. Never raises.
    """
    try:
        manifest = _c2pa.extract_manifest(data)
        if manifest is None or not manifest["claims"]:
            return None
        results = []
        for entry in manifest["claims"]:
            results.append(_validate_claim(
                data, manifest, entry["claim"], entry["claim_raw"]))
        for wanted in ("valid",):
            for r in results:
                if r["status"] == wanted:
                    return r
        for r in results:
            if r["signature"]["state"] == "valid":
                return r
        return results[0]
    except Exception:
        return None
