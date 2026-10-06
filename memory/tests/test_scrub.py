"""Write-boundary secret refusal."""
import unittest

from mem_helpers import MemoryTestCase, make_client
from npc_memory.scrub import (SecretRefusedError, scrub_check, scrub_tag,
                              scrub_text)


class TestScrubPrimitives(unittest.TestCase):
    def test_secret_keys_refused(self):
        for key in ("api_key", "password", "seed", "bearer_token",
                    "client_secret", "private_key"):
            with self.assertRaises(SecretRefusedError):
                scrub_check({"content": {"text": "x", key: "v"}})

    def test_benign_keys_pass(self):
        scrub_check({"content": {"text": "funding rates rose",
                                 "tags": ["defi"]}})

    def test_secret_shapes_in_text_refused(self):
        with self.assertRaises(SecretRefusedError):
            scrub_text("-----BEGIN EC PRIVATE KEY-----\nabc")
        with self.assertRaises(SecretRefusedError):
            scrub_text("key AKIAIOSFODNN7EXAMPLE here")
        with self.assertRaises(SecretRefusedError):
            scrub_text("token sk_live_abcdefghijklmnop here")
        with self.assertRaises(SecretRefusedError):
            scrub_text("npc_test_abcdefghijklmnop here")

    def test_plain_text_passes(self):
        scrub_text("funding rates spike before listings; tokenomics aside")

    def test_secret_tags_refused(self):
        with self.assertRaises(SecretRefusedError):
            scrub_tag("api_token")
        scrub_tag("defi")


class TestWriteBoundary(MemoryTestCase):
    def test_assert_with_secret_text_refused(self):
        with self.assertRaises(SecretRefusedError):
            self.client.assert_memory("deploy with sk_live_abcdefghijklmnop",
                                      tags=["ops"])

    def test_assert_with_secret_tag_refused(self):
        with self.assertRaises(SecretRefusedError):
            self.client.assert_memory("fine text", tags=["db_password"])

    def test_assert_with_secret_provenance_key_refused(self):
        with self.assertRaises(SecretRefusedError):
            self.client.assert_memory(
                "fine text",
                provenance={"source": "session", "api_key": "zzz"})

    def test_refused_write_leaves_no_record(self):
        before = len(self.store.query())
        with self.assertRaises(SecretRefusedError):
            self.client.assert_memory("AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(len(self.store.query()), before)

    def test_refused_write_keeps_seq_contiguous(self):
        r1 = self.client.assert_memory("first", tags=["t"])
        with self.assertRaises(SecretRefusedError):
            self.client.assert_memory("sk_live_abcdefghijklmnop")
        r2 = self.client.assert_memory("second", tags=["t"])
        self.assertEqual(r2["seq"], r1["seq"] + 1)


if __name__ == "__main__":
    unittest.main()
