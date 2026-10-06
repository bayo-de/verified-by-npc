"""AgentIdentity: keypair lifecycle and record signing."""
import base64
import os
import tempfile
import unittest

import mem_helpers  # noqa: F401  (sys.path bootstrap for npc_verify)
from npc_verify import ed25519
from npc_verify.canonical import canonicalize

from npc_memory.identity import (AgentIdentity, IdentityError,
                                 key_id_for_public_key)


class TestIdentity(unittest.TestCase):
    def test_generate_and_sign_roundtrip(self):
        ident = AgentIdentity.generate("test_agent")
        msg = canonicalize({"hello": "world"})
        sig = ident.sign(msg)
        self.assertTrue(ed25519.verify(ident.public_key, msg, sig))
        self.assertFalse(ed25519.verify(ident.public_key, msg + b"x", sig))

    def test_key_id_format(self):
        ident = AgentIdentity.generate("test_agent")
        self.assertRegex(ident.key_id, r"^ak_[0-9a-f]{16}$")
        self.assertEqual(key_id_for_public_key(ident.public_key),
                         ident.key_id)

    def test_save_load_roundtrip(self):
        tmp = tempfile.mkdtemp(prefix="mem_ident_")
        path = os.path.join(tmp, "agent.seed")
        ident = AgentIdentity.generate("test_agent")
        ident.save(path)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        loaded = AgentIdentity.load(path, "test_agent")
        self.assertEqual(loaded.public_key, ident.public_key)
        self.assertEqual(loaded.key_id, ident.key_id)

    def test_load_missing_file_fails(self):
        with self.assertRaises(IdentityError):
            AgentIdentity.load("/nonexistent/agent.seed", "x")

    def test_corrupt_seed_rejected(self):
        tmp = tempfile.mkdtemp(prefix="mem_ident_")
        path = os.path.join(tmp, "bad.seed")
        with open(path, "wb") as f:
            f.write(b"too short")
        with self.assertRaises(IdentityError):
            AgentIdentity.load(path, "x")

    def test_public_key_b64_decodes_to_32_bytes(self):
        ident = AgentIdentity.generate("test_agent")
        self.assertEqual(len(base64.b64decode(ident.public_key_b64)), 32)


if __name__ == "__main__":
    unittest.main()
