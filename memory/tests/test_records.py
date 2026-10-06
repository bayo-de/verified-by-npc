"""MemoryRecord shape validation, signing core, and hashing."""
import unittest

from mem_helpers import MemoryTestCase
from npc_memory.records import (record_hash, signing_core, validate_shape)


class TestRecordShape(MemoryTestCase):
    def _good(self):
        rec = self.client._build("memory.assert", "some text", ["t1"], 0.9,
                                 {"source": "session"}, "agent")
        return rec

    def test_good_record_validates(self):
        self.assertEqual(validate_shape(self._good()), [])

    def test_bad_id(self):
        rec = self._good()
        rec["id"] = "nope"
        self.assertTrue(validate_shape(rec))

    def test_stream_key_must_match_dims(self):
        rec = self._good()
        rec["stream_key"] = "fleet"
        self.assertTrue(validate_shape(rec))

    def test_agent_stream_writer_must_match(self):
        rec = self._good()
        rec["agent_id"] = "someone_else"
        self.assertTrue(validate_shape(rec))

    def test_confidence_bounds(self):
        for bad in (-0.1, 1.5, "high", True):
            rec = self._good()
            rec["content"]["confidence"] = bad
            self.assertTrue(validate_shape(rec), bad)

    def test_tags_must_be_slugs(self):
        rec = self._good()
        rec["content"]["tags"] = ["Nope"]
        self.assertTrue(validate_shape(rec))

    def test_supersede_needs_target(self):
        rec = self.client._build("memory.supersede", "new text", [], 1.0,
                                 None, "agent", target_id="mem_abcdef12")
        self.assertEqual(validate_shape(rec), [])
        rec["content"].pop("target_id")
        self.assertTrue(validate_shape(rec))

    def test_assert_rejects_target_id(self):
        rec = self._good()
        rec["content"]["target_id"] = "mem_abcdef12"
        self.assertTrue(validate_shape(rec))

    def test_external_provenance_rules(self):
        prov = {"source": "external", "url": "https://example.com/x",
                "captured_at": "2026-10-06T00:00:00+00:00",
                "hash": "ab" * 32, "trust": "untrusted"}
        rec = self.client.assert_memory("ext", provenance=prov)
        self.assertTrue(rec["id"].startswith("mem_"))
        # trusted external is rejected
        bad = dict(prov, trust="trusted")
        with self.assertRaises(Exception):
            self.client.assert_memory("ext", provenance=bad)
        # missing url is rejected
        bad2 = dict(prov)
        del bad2["url"]
        with self.assertRaises(Exception):
            self.client.assert_memory("ext", provenance=bad2)

    def test_signing_core_is_stable(self):
        rec = self._good()
        core1 = signing_core(rec)
        rec["signature_b64"] = "tampered"
        rec["record_hash"] = "tampered"
        self.assertEqual(signing_core(rec), core1)

    def test_record_hash_changes_with_content(self):
        r1 = self._good()
        r2 = self.client._build("memory.assert", "different text", ["t1"],
                                0.9, {"source": "session"}, "agent")
        self.assertNotEqual(record_hash(r1), record_hash(r2))


if __name__ == "__main__":
    unittest.main()
