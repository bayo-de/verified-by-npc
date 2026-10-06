"""Ed25519 primitive: RFC 8032 vectors + tamper detection (vendored module)."""
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import ed25519  # noqa: E402


class TestEd25519(unittest.TestCase):
    def test_rfc8032_vectors(self):
        # Runs the vendored module's own self-test (TEST 1 + TEST 2 + roundtrip).
        ed25519.self_test()

    def test_tamper_detected(self):
        import secrets
        seed = secrets.token_bytes(32)
        pub = ed25519.publickey(seed)
        msg = b'{"verdict": "verified"}'
        sig = ed25519.sign(seed, msg)
        self.assertTrue(ed25519.verify(pub, msg, sig))
        self.assertFalse(ed25519.verify(pub, msg + b" ", sig))
        self.assertFalse(ed25519.verify(pub, b'{"verdict": "unknown"}', sig))

    def test_wrong_key_fails(self):
        import secrets
        s1, s2 = secrets.token_bytes(32), secrets.token_bytes(32)
        sig = ed25519.sign(s1, b"hello")
        self.assertFalse(ed25519.verify(ed25519.publickey(s2), b"hello", sig))

    def test_bad_inputs_fail_closed(self):
        self.assertFalse(ed25519.verify(b"short", b"m", b"x" * 64))
        self.assertFalse(ed25519.verify(b"y" * 32, b"m", b"short"))
        self.assertFalse(ed25519.verify(b"\x00" * 32, b"m", b"\x00" * 64))


if __name__ == "__main__":
    unittest.main()
