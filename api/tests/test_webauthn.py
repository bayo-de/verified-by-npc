"""Gate G1: npc_verify.webauthn ceremony verification, unit level.

Drives the verifier directly with the software authenticator from
tests.helpers: attestation formats, and the checks a relying party
must not skip (challenge, origin, relying party hash, user
presence, signature, counter monotonicity).
"""
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import webauthn  # noqa: E402
from npc_verify.c2pa import _cbor_decode  # noqa: E402
from tests.helpers import SoftAuthenticator  # noqa: E402

RP_ID = "localhost"
ORIGIN = "http://127.0.0.1"
CHALLENGE = bytes(range(32))


def _options():
    return {"challenge": webauthn.b64url_encode(CHALLENGE)}


class TestRegistration(unittest.TestCase):
    def test_none_attestation(self):
        auth = SoftAuthenticator(RP_ID, ORIGIN)
        result = webauthn.verify_registration(
            RP_ID, [ORIGIN], CHALLENGE, auth.create(_options()))
        self.assertEqual(result["credential_id"], auth.credential_id)
        self.assertEqual(result["alg"], -8)
        self.assertEqual(result["sign_count"], 0)

    def test_packed_self_attestation(self):
        auth = SoftAuthenticator(RP_ID, ORIGIN)
        result = webauthn.verify_registration(
            RP_ID, [ORIGIN], CHALLENGE,
            auth.create(_options(), fmt="packed"))
        self.assertEqual(result["credential_id"], auth.credential_id)

    def test_es256_none_attestation(self):
        auth = SoftAuthenticator(RP_ID, ORIGIN, alg=-7)
        result = webauthn.verify_registration(
            RP_ID, [ORIGIN], CHALLENGE, auth.create(_options()))
        self.assertEqual(result["alg"], -7)

    def test_challenge_mismatch_fails(self):
        auth = SoftAuthenticator(RP_ID, ORIGIN)
        payload = auth.create({"challenge": webauthn.b64url_encode(
            b"x" * 32)})
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                RP_ID, [ORIGIN], CHALLENGE, payload)

    def test_origin_not_allowlisted_fails(self):
        auth = SoftAuthenticator(RP_ID, "https://evil.example.com")
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                RP_ID, [ORIGIN], CHALLENGE, auth.create(_options()))

    def test_rp_mismatch_fails(self):
        auth = SoftAuthenticator("other.example.com", ORIGIN)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                RP_ID, [ORIGIN], CHALLENGE, auth.create(_options()))

    def test_unknown_format_fails_closed(self):
        auth = SoftAuthenticator(RP_ID, ORIGIN)
        payload = auth.create(_options())
        raw = webauthn.b64url_decode(
            payload["response"]["attestationObject"])
        obj, _used = _cbor_decode(raw)
        obj["fmt"] = "tpm"
        from npc_verify.c2pa import _cbor_encode
        payload["response"]["attestationObject"] = \
            webauthn.b64url_encode(_cbor_encode(obj))
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_registration(
                RP_ID, [ORIGIN], CHALLENGE, payload)


class TestAuthentication(unittest.TestCase):
    def _registered(self, alg=-8):
        auth = SoftAuthenticator(RP_ID, ORIGIN, alg=alg)
        result = webauthn.verify_registration(
            RP_ID, [ORIGIN], CHALLENGE, auth.create(_options()))
        return auth, result

    def test_roundtrip_and_counter(self):
        auth, result = self._registered()
        new_count = webauthn.verify_authentication(
            RP_ID, [ORIGIN], CHALLENGE, auth.get(_options()),
            result["cose_key"], result["sign_count"])
        self.assertEqual(new_count, 1)

    def test_counter_regression_fails(self):
        auth, result = self._registered()
        webauthn.verify_authentication(
            RP_ID, [ORIGIN], CHALLENGE, auth.get(_options()),
            result["cose_key"], 0)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_authentication(
                RP_ID, [ORIGIN], CHALLENGE,
                auth.get(_options(), count=1),
                result["cose_key"], 1)

    def test_tampered_signature_fails(self):
        auth, result = self._registered()
        payload = auth.get(_options())
        sig = bytearray(webauthn.b64url_decode(
            payload["response"]["signature"]))
        sig[0] ^= 0xFF
        payload["response"]["signature"] = webauthn.b64url_encode(
            bytes(sig))
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.verify_authentication(
                RP_ID, [ORIGIN], CHALLENGE, payload,
                result["cose_key"], 0)

    def test_es256_roundtrip(self):
        auth, result = self._registered(alg=-7)
        new_count = webauthn.verify_authentication(
            RP_ID, [ORIGIN], CHALLENGE, auth.get(_options()),
            result["cose_key"], result["sign_count"])
        self.assertEqual(new_count, 1)


if __name__ == "__main__":
    unittest.main()
