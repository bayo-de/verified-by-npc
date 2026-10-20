"""Vendored signing primitives must never drift from the API originals.

The MCP package vendors byte-identical copies of the API's canonical
JSON and Ed25519 modules so a standalone PyPI install works with no
repo checkout. When the API tree is present (development layout), this
test asserts byte equality. In a standalone layout it skips.
"""
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_API_DIR = os.path.normpath(os.path.join(
    _HERE, "..", "..", "..", "api", "npc_verify"))
_VENDOR_DIR = os.path.normpath(os.path.join(
    _HERE, "..", "npc_verify_mcp", "_vendor"))


@unittest.skipUnless(os.path.isdir(_API_DIR),
                     "api tree not present (standalone layout)")
class TestVendorSync(unittest.TestCase):
    def test_canonical_byte_identical(self):
        self._assert_same("canonical.py")

    def test_ed25519_byte_identical(self):
        self._assert_same("ed25519.py")

    def _assert_same(self, name):
        with open(os.path.join(_API_DIR, name), "rb") as fh:
            original = fh.read()
        with open(os.path.join(_VENDOR_DIR, name), "rb") as fh:
            vendored = fh.read()
        self.assertEqual(original, vendored,
                         f"vendored {name} has drifted from the API "
                         f"original - re-copy api/npc_verify/{name}")


if __name__ == "__main__":
    unittest.main()
