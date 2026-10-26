"""C2PA cryptographic validation (v5.5 workstream 1).

The fixtures in tests/fixtures/ are REAL manifests signed with the
official C2PA SDK (c2pa-python) by throwaway test chains built for
this suite (self-signed test CA issuing a leaf per algorithm); the
SDK's own Reader reports the same files Valid. The validator under
test is the shipped pure-Python one: if it ever disagrees with these
fixtures, the fixtures are right and the validator is wrong.

Tampered variants are byte flips of signed-es256.jpg in three
distinct places: the actions assertion (assertion integrity), the
COSE signature (signature), and the image scan data (asset binding).
"""
import os
import struct
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import c2pa, c2pa_validate  # noqa: E402

FIXTURES = os.path.join(BASE, "tests", "fixtures")


def _fixture(name):
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


class ValidFixturesTest(unittest.TestCase):
    def _assert_valid(self, name, algorithm):
        result = c2pa_validate.validate_credentials(_fixture(name))
        self.assertIsNotNone(result, name)
        self.assertEqual(result["status"], "valid", name)
        self.assertEqual(result["signature"]["state"], "valid", name)
        self.assertEqual(result["signature"]["algorithm"], algorithm,
                         name)
        self.assertEqual(result["assertions"]["state"], "verified",
                         name)
        self.assertGreaterEqual(result["assertions"]["checked"], 2,
                                name)
        self.assertEqual(result["asset_binding"]["state"], "verified",
                         name)
        signer = result["signer"]
        self.assertIsNotNone(signer, name)
        self.assertIn("NPC Test Signer", signer["subject"])
        self.assertIn("NPC Labs Test", signer["issuer"])
        self.assertEqual(signer["chain"], "verified", name)
        # The honesty rule: no trust verdict is invented, ever.
        self.assertEqual(signer["trust"], "as_presented_not_rated")

    def test_valid_es256_jpeg(self):
        self._assert_valid("signed-es256.jpg", "ES256")

    def test_valid_es384_jpeg(self):
        self._assert_valid("signed-es384.jpg", "ES384")

    def test_valid_es512_jpeg(self):
        self._assert_valid("signed-es512.jpg", "ES512")

    def test_valid_ed25519_jpeg(self):
        self._assert_valid("signed-ed25519.jpg", "EdDSA")

    def test_valid_ps256_jpeg(self):
        self._assert_valid("signed-ps256.jpg", "PS256")

    def test_valid_es256_png(self):
        self._assert_valid("signed-es256.png", "ES256")

    def test_signed_mp4_signature_and_assertions_verify(self):
        # BMFF (MP4) manifests: signature + assertion integrity run;
        # the Merkle asset binding is not evaluated by this verifier
        # yet, so the outcome is honestly not_validated, never valid.
        result = c2pa_validate.validate_credentials(
            _fixture("signed-es256.mp4"))
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "not_validated")
        self.assertEqual(result["signature"]["state"], "valid")
        self.assertEqual(result["assertions"]["state"], "verified")
        self.assertEqual(result["asset_binding"]["state"], "not_run")
        self.assertIn("Merkle", result["asset_binding"]["detail"])


class TamperFixturesTest(unittest.TestCase):
    def test_tampered_assertion_fails_assertion_integrity(self):
        result = c2pa_validate.validate_credentials(
            _fixture("tampered-assertion.jpg"))
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["signature"]["state"], "valid")
        self.assertEqual(result["assertions"]["state"], "failed")
        self.assertEqual(result["asset_binding"]["state"], "verified")

    def test_tampered_signature_fails_signature(self):
        result = c2pa_validate.validate_credentials(
            _fixture("tampered-signature.jpg"))
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["signature"]["state"], "invalid")
        self.assertEqual(result["assertions"]["state"], "verified")

    def test_tampered_asset_fails_binding(self):
        result = c2pa_validate.validate_credentials(
            _fixture("tampered-asset.jpg"))
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["signature"]["state"], "valid")
        self.assertEqual(result["asset_binding"]["state"], "failed")


class NoManifestTest(unittest.TestCase):
    def test_unsigned_image_returns_none(self):
        self.assertIsNone(
            c2pa_validate.validate_credentials(_fixture("plain.jpg")))
        self.assertIsNone(
            c2pa_validate.validate_credentials(_fixture("plain.png")))

    def test_garbage_returns_none(self):
        self.assertIsNone(c2pa_validate.validate_credentials(
            b"not an image at all"))
        self.assertIsNone(c2pa_validate.validate_credentials(b""))


def _cbor_text(s):
    b = s.encode("utf-8")
    if len(b) < 24:
        return bytes([0x60 + len(b)]) + b
    return bytes([0x78, len(b)]) + b


def _cbor_map(pairs):
    out = bytes([0xA0 + len(pairs)])
    for key, value_bytes in pairs:
        out += _cbor_text(key) + value_bytes
    return out


def _box(btype, payload):
    return struct.pack(">I", len(payload) + 8) + btype + payload


def _jumd(label):
    return _box(b"jumd", b"\x00" * 16 + b"\x00" + label.encode() + b"\x00")


def _jumb(children):
    return _box(b"jumb", b"".join(children))


def _manifest_without_signature():
    """The test_register.py hand-built shape: a claim, no signature
    box at all. Validation must run and report not_validated."""
    claim = _cbor_map([
        ("claim_generator", _cbor_text("TestGen 1.0")),
        ("instanceID", _cbor_text("xmp:iid:test-0001")),
    ])
    manifest = _jumb([
        _jumd("urn:c2pa:test-manifest"),
        _box(b"c2cl", claim),
    ])
    jumbf = _jumb([_jumd("c2pa"), manifest])
    payload = b"JUMB" + struct.pack(">H", 1) + jumbf
    app11 = b"\xff\xeb" + struct.pack(">H", len(payload) + 2) + payload
    return b"\xff\xd8" + app11 + b"\xff\xd9"


class BrokenManifestTest(unittest.TestCase):
    def test_claim_without_signature_box_is_not_validated(self):
        result = c2pa_validate.validate_credentials(
            _manifest_without_signature())
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "not_validated")
        self.assertEqual(result["signature"]["state"], "not_run")
        self.assertIn("no readable signature box", result["detail"])
        # The structural parse still reads the same file as present.
        creds = c2pa.parse_credentials(_manifest_without_signature())
        self.assertEqual(creds["status"],
                         "present_not_cryptographically_validated")
        self.assertEqual(creds["validated"], False)


if __name__ == "__main__":
    unittest.main()
