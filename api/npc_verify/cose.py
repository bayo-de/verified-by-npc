"""COSE_Sign1 signature verification (stdlib only).

The COSE side of C2PA validation: verify a manifest signature
against the public key in the signer's certificate. Implemented in
pure Python so it runs anywhere the API runs, Lambda included:

- EdDSA (COSE alg -8): the in-repo RFC 8032 implementation
  (npc_verify.ed25519, already used for record signing).
- ES256/ES384/ES512 (-7/-35/-36): ECDSA over NIST P-256/P-384/P-521
  with the matching SHA-2 digest, below.
- PS256/PS384/PS512 (-37/-38/-39): RSASSA-PSS with MGF1, salt length
  recovered from the signature per RFC 8017 (COSE leaves the PSS
  salt length to the verifier; C2PA signers use the digest length,
  the Auto mode accepts what the signature itself proves).

Curves and PSS padding are small, well-specified arithmetic; each
verify returns a plain bool and never raises on hostile input.
"""
import hashlib

from . import ed25519

# -- NIST curves (SEC 2 parameters, hex) ------------------------------------
_CURVE_HEX = {
    "P-256": (
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        hashlib.sha256,
    ),
    "P-384": (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
        "FFFFFFFF0000000000000000FFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
        "FFFFFFFF0000000000000000FFFFFFFC",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
        "C656398D8A2ED19D2A85C8EDD3EC2AEF",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A3"
        "85502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
        "0A60B1CE1D7E819D7A431D7C90EA0E5F",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
        "581A0DB248B0A77AECEC196ACCC52973",
        hashlib.sha384,
    ),
    "P-521": (
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFF",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFC",
        "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF10"
        "9E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
        "3F00",
        "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3"
        "DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E"
        "5BD66",
        "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E"
        "662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD"
        "16650",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E9138"
        "6409",
        hashlib.sha512,
    ),
}


def _load_curves():
    out = {}
    for name, (p, a, b, gx, gy, n, hashfn) in _CURVE_HEX.items():
        vals = tuple(int(v, 16) if isinstance(v, str) else v
                     for v in (p, a, b, gx, gy, n))
        p_i, a_i, b_i, gx_i, gy_i, n_i = vals
        # Sanity, pinned by the API suite's real-signature fixtures:
        # the generator must sit on the curve and the order must be
        # the prime's bit length. A mistyped constant fails here, at
        # import, instead of silently mis-verifying signatures.
        if (gy_i * gy_i - (gx_i ** 3 + a_i * gx_i + b_i)) % p_i != 0:
            raise RuntimeError("curve constant error: %s" % name)
        if n_i.bit_length() != p_i.bit_length():
            raise RuntimeError("curve order error: %s" % name)
        out[name] = vals + (hashfn,)
    return out


_CURVES = _load_curves()


def _inv(a, m):
    return pow(a, -1, m)


def _curve_params(name):
    """(prime, a, b, gx, gy, order, hashfn, name) for a curve name."""
    p, a, b, gx, gy, n, hashfn = _CURVES[name]
    return (p, a, b, gx, gy, n, hashfn, name)


def _ec_add(params, pt, q):
    prime, a = params[0], params[1]
    if pt is None:
        return q
    if q is None:
        return pt
    x1, y1 = pt
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % prime == 0:
        return None
    if pt == q:
        lam = (3 * x1 * x1 + a) * _inv(2 * y1 % prime, prime) % prime
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % prime, prime) % prime
    x3 = (lam * lam - x1 - x2) % prime
    y3 = (lam * (x1 - x3) - y1) % prime
    return (x3, y3)


def _ec_mul(params, k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(params, result, addend)
        addend = _ec_add(params, addend, addend)
        k >>= 1
    return result


def ec_on_curve(name, x, y):
    p = _curve_params(name)
    prime, a, b = p[0], p[1], p[2]
    return (y * y - (x * x * x + a * x + b)) % prime == 0


def ecdsa_verify(curve_name, x, y, message, signature,
                 signature_format="raw", hashfn=None):
    """Verify an ECDSA signature. signature_format "raw" is the COSE
    form R||S; "der" is the X.509 SEQUENCE form. The digest defaults
    to the curve's COSE pairing; X.509 certificate signatures name
    their own digest (an ECDSA-with-SHA256 signature may sit on a
    P-384 key), so the certificate path passes it explicitly. False
    on any malformed input."""
    try:
        params = _curve_params(curve_name)
        prime, _a, _b, _gx, _gy, n, curve_hashfn, _nm = params
        if hashfn is None:
            hashfn = curve_hashfn
        if signature_format == "der":
            r, s = _ecdsa_der_split(signature)
            if r is None:
                return False
        else:
            size = (prime.bit_length() + 7) // 8
            if len(signature) != 2 * size:
                return False
            r = int.from_bytes(signature[:size], "big")
            s = int.from_bytes(signature[size:], "big")
        if not (1 <= r < n and 1 <= s < n):
            return False
        if not ec_on_curve(curve_name, x, y):
            return False
        digest = hashfn(message).digest()
        z = int.from_bytes(digest, "big")
        excess = len(digest) * 8 - n.bit_length()
        if excess > 0:
            z >>= excess
        w = _inv(s, n)
        u1 = (z * w) % n
        u2 = (r * w) % n
        point = _ec_add(params,
                        _ec_mul(params, u1, (params[3], params[4])),
                        _ec_mul(params, u2, (x, y)))
        if point is None:
            return False
        return point[0] % n == r
    except Exception:
        return False


def _ecdsa_der_split(sig):
    """Split an ASN.1 DER ECDSA-Sig-Value into (r, s); (None, None)
    when it does not parse."""
    try:
        if len(sig) < 8 or sig[0] != 0x30:
            return None, None
        idx = 2
        if sig[1] & 0x80:
            nlen = sig[1] & 0x7F
            idx = 2 + nlen
        values = []
        for _ in range(2):
            if sig[idx] != 0x02:
                return None, None
            ln = sig[idx + 1]
            hdr = 2
            if ln & 0x80:
                n = ln & 0x7F
                ln = int.from_bytes(sig[idx + 2:idx + 2 + n], "big")
                hdr = 2 + n
            values.append(int.from_bytes(
                sig[idx + hdr:idx + hdr + ln], "big"))
            idx += hdr + ln
        return values[0], values[1]
    except Exception:
        return None, None


# -- RSA ------------------------------------------------------------------
_HASH_INFO = {
    "sha256": (hashlib.sha256, bytes.fromhex(
        "3031300d060960864801650304020105000420")),
    "sha384": (hashlib.sha384, bytes.fromhex(
        "3041300d060960864801650304020205000430")),
    "sha512": (hashlib.sha512, bytes.fromhex(
        "3051300d060960864801650304020305000440")),
    "sha1": (hashlib.sha1, bytes.fromhex(
        "3021300906052b0e03021a05000414")),
}


def _mgf1(seed, length, hashfn):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashfn(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def rsa_pkcs1_v15_verify(n, e, message, signature, hash_name):
    """RSASSA-PKCS1-v1_5 verify (X.509 certificate signatures)."""
    try:
        hashfn, prefix = _HASH_INFO[hash_name]
        k = (n.bit_length() + 7) // 8
        if len(signature) != k:
            return False
        m = pow(int.from_bytes(signature, "big"), e, n)
        em = m.to_bytes(k, "big")
        t = prefix + hashfn(message).digest()
        expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        return em == expected
    except Exception:
        return False


def rsa_pss_verify(n, e, message, signature, hash_name):
    """RSASSA-PSS verify with the salt length recovered from the
    signature (RFC 8017 EMSA-PSS-VERIFY with sLen recovered)."""
    try:
        hashfn, _prefix = _HASH_INFO[hash_name]
        hlen = hashfn().digest_size
        k = (n.bit_length() + 7) // 8
        if len(signature) != k:
            return False
        s = int.from_bytes(signature, "big")
        if s >= n:
            return False
        em = pow(s, e, n).to_bytes(k, "big")
        if em[-1] != 0xBC:
            return False
        db_len = k - hlen - 1
        masked_db = em[:db_len]
        h = em[db_len:db_len + hlen]
        # The leftmost (8*emLen - modBits + 1) bits of maskedDB must be
        # zero; modBits is the modulus bit length minus one by the
        # RSA encoding convention (emBits = modBits - 1).
        mod_bits = n.bit_length()
        unused = 8 * k - (mod_bits - 1)
        if unused > 0 and (masked_db[0] >> (8 - unused)):
            return False
        top_bits = unused
        db = bytes(b ^ m for b, m in zip(
            masked_db, _mgf1(h, db_len, hashfn)))
        if top_bits:
            db = bytes([db[0] & (0xFF >> top_bits)]) + db[1:]
        # DB = PS (zeros) || 0x01 || salt
        i = 0
        while i < len(db) and db[i] == 0:
            i += 1
        if i >= len(db) or db[i] != 0x01:
            return False
        salt = db[i + 1:]
        m_hash = hashfn(message).digest()
        h2 = hashfn(b"\x00" * 8 + m_hash + salt).digest()
        return h2 == h
    except Exception:
        return False


# -- COSE dispatch ----------------------------------------------------------
COSE_ALG_NAMES = {
    -7: "ES256", -35: "ES384", -36: "ES512",
    -37: "PS256", -38: "PS384", -39: "PS512",
    -8: "EdDSA",
}
_ES_CURVES = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}
_PS_HASHES = {"PS256": "sha256", "PS384": "sha384", "PS512": "sha512"}


def verify_cose_signature(alg, cert_facts, tbs_bytes, signature):
    """Verify a COSE signature against a parsed certificate (see
    npc_verify.der.parse_certificate). Returns (ok, alg_name): ok is
    a plain bool; unknown algorithms return (False, name-or-None) and
    the caller reports them as unsupported rather than invalid."""
    alg_name = COSE_ALG_NAMES.get(alg)
    if alg_name is None or cert_facts is None:
        return False, alg_name
    key = cert_facts.get("public_key") or {}
    try:
        if alg_name == "EdDSA":
            if cert_facts.get("key_algorithm") != "ed25519":
                return False, alg_name
            raw = key.get("raw") or b""
            return bool(ed25519.verify(raw, tbs_bytes, signature)), \
                alg_name
        if alg_name in _ES_CURVES:
            if cert_facts.get("key_algorithm") != "ec" or \
                    cert_facts.get("ec_curve") != _ES_CURVES[alg_name]:
                return False, alg_name
            return ecdsa_verify(_ES_CURVES[alg_name], key["x"], key["y"],
                                tbs_bytes, signature), alg_name
        if alg_name in _PS_HASHES:
            if cert_facts.get("key_algorithm") != "rsa":
                return False, alg_name
            return rsa_pss_verify(key["n"], key["e"], tbs_bytes,
                                  signature, _PS_HASHES[alg_name]), \
                alg_name
    except Exception:
        return False, alg_name
    return False, alg_name


def verify_cert_signature(issuer_facts, subject_facts):
    """Verify a certificate's signature against its issuer's key
    (chain link check). Handles the signature algorithms common on
    C2PA chains; returns False for anything else."""
    if issuer_facts is None or subject_facts is None:
        return False
    try:
        from . import der as _der
        oid = subject_facts.get("signature_algorithm")
        tbs = subject_facts.get("tbs_der")
        sig = subject_facts.get("signature")
        key = issuer_facts.get("public_key") or {}
        ka = issuer_facts.get("key_algorithm")
        if oid in (_der.OID_SHA256_RSA, _der.OID_SHA384_RSA,
                   _der.OID_SHA512_RSA) and ka == "rsa":
            name = {_der.OID_SHA256_RSA: "sha256",
                    _der.OID_SHA384_RSA: "sha384",
                    _der.OID_SHA512_RSA: "sha512"}[oid]
            return rsa_pkcs1_v15_verify(key["n"], key["e"], tbs, sig,
                                         name)
        if oid in (_der.OID_ECDSA_SHA256, _der.OID_ECDSA_SHA384,
                   _der.OID_ECDSA_SHA512) and ka == "ec":
            import hashlib as _hl
            digest = {_der.OID_ECDSA_SHA256: _hl.sha256,
                      _der.OID_ECDSA_SHA384: _hl.sha384,
                      _der.OID_ECDSA_SHA512: _hl.sha512}[oid]
            curve = issuer_facts.get("ec_curve")
            return ecdsa_verify(curve, key["x"], key["y"], tbs, sig,
                                signature_format="der", hashfn=digest)
        if oid == "1.3.101.112" and ka == "ed25519":  # Ed25519 cert sig
            return bool(ed25519.verify(key.get("raw") or b"", tbs, sig))
        # RSASSA-PSS certificate signatures (params-carrying) and
        # anything else: not evaluated by this verifier.
        return False
    except Exception:
        return False
