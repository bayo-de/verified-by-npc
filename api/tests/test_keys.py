"""Key registry: generation, rotation history, sign/verify, publishing."""
import os
import sys
import tempfile
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify.store import Store  # noqa: E402
from npc_verify.keys import KeyRegistry  # noqa: E402


class TestKeys(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_keys_test_")
        self.store = Store(os.path.join(self.tmp, "t.db"))
        self.reg = KeyRegistry(self.store, os.path.join(self.tmp, "keys"))

    def tearDown(self):
        self.store.close()

    def test_bootstrap_creates_both_purposes(self):
        created = self.reg.ensure_bootstrap()
        self.assertEqual(len(created), 2)
        self.assertIsNotNone(self.reg.active_key_id("api_signing"))
        self.assertIsNotNone(self.reg.active_key_id("issuer"))
        # idempotent
        self.assertEqual(self.reg.ensure_bootstrap(), [])

    def test_sign_verify_roundtrip(self):
        self.reg.ensure_bootstrap()
        key_id, sig = self.reg.sign("api_signing", b"hello")
        self.assertTrue(self.reg.verify(key_id, b"hello", sig))
        self.assertFalse(self.reg.verify(key_id, b"hellx", sig))

    def test_rotation_retires_old_key(self):
        self.reg.ensure_bootstrap()
        old_id = self.reg.active_key_id("api_signing")
        _, old_sig = self.reg.sign("api_signing", b"m")
        new = self.reg.rotate("api_signing")
        new_id = new["key_id"]
        self.assertNotEqual(old_id, new_id)
        self.assertEqual(self.reg.active_key_id("api_signing"), new_id)
        # old signatures still verify (retired, not deleted)
        self.assertTrue(self.reg.verify(old_id, b"m", old_sig))
        # new signatures verify under the new key
        _, sig2 = self.reg.sign("api_signing", b"m")
        self.assertTrue(self.reg.verify(new_id, b"m", sig2))

    def test_publish_shape(self):
        self.reg.ensure_bootstrap()
        self.reg.rotate("api_signing")
        pub = self.reg.publish()
        cur = pub["api_signing"]["current"]
        self.assertIsNotNone(cur)
        self.assertEqual(cur["algorithm"], "Ed25519")
        self.assertEqual(cur["status"], "active")
        self.assertEqual(len(pub["api_signing"]["history"]), 1)
        hist = pub["api_signing"]["history"][0]
        self.assertEqual(hist["status"], "retired")
        self.assertIsNotNone(hist["retired_at"])
        # no private material leaks
        blob = str(pub)
        self.assertNotIn("seed", blob.lower())

    def test_seed_file_permissions(self):
        self.reg.ensure_bootstrap()
        kid = self.reg.active_key_id("api_signing")
        mode = oct(os.stat(self.reg._priv_path(kid)).st_mode & 0o777)
        self.assertEqual(mode, "0o600")

    def test_unknown_key_fails_closed(self):
        self.reg.ensure_bootstrap()
        self.assertFalse(self.reg.verify("npc-nope-1", b"m", b"x" * 64))


if __name__ == "__main__":
    unittest.main()
