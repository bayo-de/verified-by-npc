"""WebAuthn (passkey) ceremony verification for the unified NPC
account (Gate G1, design decided 2026-10-24).

This module verifies the two ceremonies server-side, with no third
party dependency: CBOR decoding reuses the package's minimal decoder
(npc_verify.c2pa), ECDSA/RSA verification reuses npc_verify.cose, and
Ed25519 verification reuses npc_verify.ed25519. It implements the
parts of the WebAuthn Level 2 verification procedures that a relying
party must not skip:

- the client data type, challenge, and origin are checked exactly;
- the authenticator data RP ID hash is checked against the
  configured relying party, and the user-present flag is required;
- registration accepts attestation formats "none" and "packed"
  (self-attestation, plus the x5c form verified against the leaf
  certificate's own key; no chain-of-trust validation is claimed,
  which matches how platform passkeys present: most arrive as
  "none", and a packed leaf proves the credential key's custody,
  not a vendor endorsement);
- authentication verifies the signature over
  authenticatorData || SHA-256(clientDataJSON) with the stored
  credential key (ES256, EdDSA, or RS256) and enforces the
  signature counter's monotonicity whenever either side is nonzero.

Everything fails closed: malformed input raises WebAuthnError and
nothing is ever treated as verified by default.
"""
import base64
import hashlib
import json

from . import cose
from . import der as der_module
from . import ed25519
from .c2pa import _cbor_decode, _CborError


class WebAuthnError(ValueError):
    pass


# -- base64url ---------------------------------------------------------------

def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text) -> bytes:
    if not isinstance(text, str):
        raise WebAuthnError("expected a base64url string")
    try:
        padded = text.strip() + "=" * (-len(text.strip()) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        raise WebAuthnError("invalid base64url")


# -- client data ---------------------------------------------------------------

def _parse_client_data(raw: bytes):
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise WebAuthnError("client data is not JSON")
    if not isinstance(data, dict):
        raise WebAuthnError("client data is not an object")
    return data


def _check_client_data(data, ceremony, expected_challenge: bytes,
                       origins):
    if data.get("type") != ceremony:
        raise WebAuthnError("wrong client data type")
    try:
        challenge = b64url_decode(data.get("challenge", ""))
    except WebAuthnError:
        raise WebAuthnError("client data challenge is malformed")
    if challenge != expected_challenge:
        raise WebAuthnError("challenge mismatch")
    if data.get("origin") not in origins:
        raise WebAuthnError("origin is not allowed for this service")


# -- authenticator data --------------------------------------------------------

class AuthenticatorData:
    def __init__(self, raw: bytes):
        if len(raw) < 37:
            raise WebAuthnError("authenticator data is truncated")
        self.raw = raw
        self.rp_id_hash = raw[:32]
        self.flags = raw[32]
        self.sign_count = int.from_bytes(raw[33:37], "big")
        self.user_present = bool(self.flags & 0x01)
        self.user_verified = bool(self.flags & 0x04)
        self.has_attested = bool(self.flags & 0x40)
        self.aaguid = None
        self.credential_id = None
        self.credential_cose = None
        if self.has_attested:
            pos = 37
            if len(raw) < pos + 18:
                raise WebAuthnError("attested credential data truncated")
            self.aaguid = raw[pos:pos + 16]
            pos += 16
            cred_len = int.from_bytes(raw[pos:pos + 2], "big")
            pos += 2
            if len(raw) < pos + cred_len:
                raise WebAuthnError("credential id is truncated")
            self.credential_id = raw[pos:pos + cred_len]
            pos += cred_len
            try:
                cose_key, _used = _cbor_decode(raw, pos)
            except _CborError:
                raise WebAuthnError("credential public key is not CBOR")
            self.credential_cose = normalize_cose_key(cose_key)


def _check_auth_data(auth, rp_id, require_attested):
    if auth.rp_id_hash != hashlib.sha256(rp_id.encode("utf-8")).digest():
        raise WebAuthnError("relying party hash mismatch")
    if not auth.user_present:
        raise WebAuthnError("user presence flag is not set")
    if require_attested and not auth.has_attested:
        raise WebAuthnError("no attested credential data present")


# -- COSE keys -----------------------------------------------------------------

_CURVES = {1: "P-256", 2: "P-384", 3: "P-521"}


def normalize_cose_key(cose_key):
    """The package CBOR decoder stringifies integer map keys, so a
    decoded COSE key arrives as {'1': .., '3': .., '-2': ..}. Put
    the integer labels back; non-numeric keys pass through."""
    if not isinstance(cose_key, dict):
        raise WebAuthnError("credential public key is not a map")
    out = {}
    for key, value in cose_key.items():
        if isinstance(key, str):
            try:
                key = int(key)
            except ValueError:
                pass
        out[key] = value
    return out


def cose_key_alg(cose_key) -> int:
    alg = normalize_cose_key(cose_key).get(3)
    if not isinstance(alg, int):
        raise WebAuthnError("credential key carries no algorithm")
    return alg


def _verify_with_cose_key(cose_key, message: bytes, signature: bytes):
    """Verify `signature` over `message` with a decoded COSE key.
    Supports ES256/384/512 (alg -7/-35/-36), EdDSA (-8), and RS256
    (-257). Returns True or False; malformed keys return False."""
    try:
        cose_key = normalize_cose_key(cose_key)
        kty = cose_key.get(1)
        alg = cose_key_alg(cose_key)
        if kty == 2:  # EC2
            curve = _CURVES.get(cose_key.get(-1))
            if curve is None:
                return False
            x = int.from_bytes(cose_key[-2], "big")
            y = int.from_bytes(cose_key[-3], "big")
            return cose.ecdsa_verify(curve, x, y, message, signature)
        if kty == 1:  # OKP
            if cose_key.get(-1) != 6 or alg != -8:  # Ed25519 only
                return False
            return ed25519.verify(cose_key[-2], message, signature)
        if kty == 3:  # RSA
            if alg != -257:
                return False
            n = int.from_bytes(cose_key[-1], "big")
            e = int.from_bytes(cose_key[-2], "big")
            return cose.rsa_pkcs1_v15_verify(n, e, message, signature,
                                             "sha256")
        return False
    except Exception:
        return False


def _verify_with_cert_key(facts, alg, message: bytes, signature: bytes):
    """Verify with the public key facts of an attestation leaf
    certificate (npc_verify.der.parse_certificate output)."""
    try:
        key = facts.get("public_key") or {}
        if "x" in key and "y" in key:  # EC
            curve = key.get("curve") or "P-256"
            hashfn = {-7: None, -35: hashlib.sha384,
                      -36: hashlib.sha512}.get(alg)
            return cose.ecdsa_verify(curve, key["x"], key["y"], message,
                                     signature, hashfn=hashfn)
        if "n" in key and "e" in key:  # RSA
            if alg != -257:
                return False
            return cose.rsa_pkcs1_v15_verify(key["n"], key["e"], message,
                                             signature, "sha256")
        if key.get("raw") and alg == -8:  # Ed25519 SPKI raw key
            return ed25519.verify(key["raw"][-32:], message, signature)
        return False
    except Exception:
        return False


# -- registration --------------------------------------------------------------

def verify_registration(rp_id, origins, expected_challenge: bytes,
                        response):
    """Verify a registration (create) ceremony response.

    `response` is the client's JSON: {id, response: {clientDataJSON,
    attestationObject}} with base64url values. Returns the credential
    to store: {credential_id (bytes), cose_key (dict), alg,
    sign_count, aaguid (hex)}. Raises WebAuthnError on any failure.
    """
    if not isinstance(response, dict) \
            or not isinstance(response.get("response"), dict):
        raise WebAuthnError("malformed registration response")
    inner = response["response"]
    client_data_raw = b64url_decode(inner.get("clientDataJSON", ""))
    client_data = _parse_client_data(client_data_raw)
    _check_client_data(client_data, "webauthn.create",
                       expected_challenge, origins)
    try:
        att_obj, _used = _cbor_decode(
            b64url_decode(inner.get("attestationObject", "")))
    except _CborError:
        raise WebAuthnError("attestation object is not CBOR")
    if not isinstance(att_obj, dict):
        raise WebAuthnError("attestation object is not a map")
    fmt = att_obj.get("fmt")
    att_stmt = att_obj.get("attStmt") or {}
    auth_raw = att_obj.get("authData")
    if not isinstance(auth_raw, (bytes, bytearray)):
        raise WebAuthnError("attestation carries no authenticator data")
    auth = AuthenticatorData(bytes(auth_raw))
    _check_auth_data(auth, rp_id, require_attested=True)
    cose_key = auth.credential_cose
    alg = cose_key_alg(cose_key)
    signed = bytes(auth_raw) + hashlib.sha256(client_data_raw).digest()
    if fmt == "none":
        if att_stmt:
            raise WebAuthnError("a 'none' attestation carries a statement")
    elif fmt == "packed":
        signature = att_stmt.get("sig")
        if not isinstance(signature, (bytes, bytearray)):
            raise WebAuthnError("packed attestation carries no signature")
        if att_stmt.get("alg") != alg:
            raise WebAuthnError("packed attestation algorithm mismatch")
        x5c = att_stmt.get("x5c")
        if x5c:
            try:
                facts = der_module.parse_certificate(bytes(x5c[0]))
            except Exception:
                raise WebAuthnError("attestation certificate unreadable")
            if not _verify_with_cert_key(facts, alg, signed,
                                         bytes(signature)):
                raise WebAuthnError("packed attestation does not verify")
        else:
            if not _verify_with_cose_key(cose_key, signed,
                                         bytes(signature)):
                raise WebAuthnError(
                    "packed self-attestation does not verify")
    else:
        raise WebAuthnError("unsupported attestation format: %r" % (fmt,))
    return {
        "credential_id": auth.credential_id,
        "cose_key": cose_key,
        "alg": alg,
        "sign_count": auth.sign_count,
        "aaguid": auth.aaguid.hex() if auth.aaguid else "",
    }


# -- authentication --------------------------------------------------------------

def verify_authentication(rp_id, origins, expected_challenge: bytes,
                          response, stored_cose_key, stored_sign_count):
    """Verify an authentication (get) ceremony response against the
    stored credential. Returns the new signature counter. Raises
    WebAuthnError on any failure, including a counter that does not
    advance when counters are in use (a cloned authenticator)."""
    if not isinstance(response, dict) \
            or not isinstance(response.get("response"), dict):
        raise WebAuthnError("malformed authentication response")
    inner = response["response"]
    client_data_raw = b64url_decode(inner.get("clientDataJSON", ""))
    client_data = _parse_client_data(client_data_raw)
    _check_client_data(client_data, "webauthn.get",
                       expected_challenge, origins)
    auth = AuthenticatorData(
        b64url_decode(inner.get("authenticatorData", "")))
    _check_auth_data(auth, rp_id, require_attested=False)
    signature = b64url_decode(inner.get("signature", ""))
    signed = bytes(auth.raw) + hashlib.sha256(client_data_raw).digest()
    if not _verify_with_cose_key(stored_cose_key, signed, signature):
        raise WebAuthnError("assertion signature does not verify")
    if (stored_sign_count or auth.sign_count) \
            and auth.sign_count <= (stored_sign_count or 0):
        raise WebAuthnError("signature counter did not advance")
    return auth.sign_count
