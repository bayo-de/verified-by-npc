"""Canonical JSON (NPC-JCS-v1): determinism, key order, edge cases."""
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify.canonical import (canonicalize, claim_hash_for_text,  # noqa: E402
                                  normalize_claim_text)


class TestCanonical(unittest.TestCase):
    def test_key_order_sorted(self):
        a = canonicalize({"z": 1, "a": {"d": 4, "b": 2}})
        b = canonicalize({"a": {"b": 2, "d": 4}, "z": 1})
        self.assertEqual(a, b)
        self.assertEqual(a, b'{"a":{"b":2,"d":4},"z":1}')

    def test_no_whitespace(self):
        out = canonicalize({"x": [1, 2], "y": "s"})
        self.assertNotIn(b" ", out)
        self.assertNotIn(b"\n", out)

    def test_utf8(self):
        out = canonicalize({"emoji": "\U0001F3C6"})
        self.assertEqual(out, '{"emoji":"\U0001F3C6"}'.encode("utf-8"))

    def test_nonfinite_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize({"x": float("nan")})
        with self.assertRaises(ValueError):
            canonicalize({"x": [float("inf")]})

    def test_claim_normalization(self):
        h1 = claim_hash_for_text("  The  Test\nWidget  ")
        h2 = claim_hash_for_text("the test widget")
        self.assertEqual(h1, h2)
        self.assertRegex(h1, r"^[0-9a-f]{64}$")
        self.assertEqual(normalize_claim_text("  A\tB "), "a b")


if __name__ == "__main__":
    unittest.main()
