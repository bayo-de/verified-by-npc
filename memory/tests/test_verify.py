"""Verification status: signatures, chain integrity, standing."""
import base64
import json
import sqlite3
import unittest

from mem_helpers import MemoryTestCase, make_client
from npc_memory import Scope
from npc_memory.verify import StreamVerifier


class TestVerification(MemoryTestCase):
    def test_fresh_memory_is_live_and_valid(self):
        rec = self.client.assert_memory("note", tags=["t"])
        _, status = self.client.get(rec["id"])
        self.assertEqual(status["standing"], "live")
        self.assertEqual(status["signature"], "valid")
        self.assertTrue(status["chain_intact"])
        self.assertIsNone(status["superseded_by"])
        self.assertFalse(status["retracted"])

    def test_supersede_changes_standing(self):
        old = self.client.assert_memory("v1", tags=["t"])
        new = self.client.supersede(old["id"], "v2", tags=["t"])
        _, st_old = self.client.get(old["id"])
        _, st_new = self.client.get(new["id"])
        self.assertEqual(st_old["standing"], "superseded")
        self.assertEqual(st_old["superseded_by"], new["id"])
        self.assertEqual(st_new["standing"], "live")

    def test_retract_changes_standing(self):
        rec = self.client.assert_memory("oops", tags=["t"])
        self.client.retract(rec["id"], reason="wrong")
        _, status = self.client.get(rec["id"])
        self.assertEqual(status["standing"], "retracted")
        self.assertTrue(status["retracted"])

    def test_cannot_supersede_twice_or_retracted(self):
        rec = self.client.assert_memory("v1")
        self.client.supersede(rec["id"], "v2")
        with self.assertRaises(Exception):
            self.client.supersede(rec["id"], "v3")
        rec2 = self.client.assert_memory("gone")
        self.client.retract(rec2["id"])
        with self.assertRaises(Exception):
            self.client.supersede(rec2["id"], "nope")

    def test_retracting_supersede_revives_original(self):
        v1 = self.client.assert_memory("v1 belief", tags=["t"])
        v2 = self.client.supersede(v1["id"], "v2 belief", tags=["t"])
        _, st = self.client.get(v1["id"])
        self.assertEqual(st["standing"], "superseded")
        self.client.retract(v2["id"], reason="v2 was wrong")
        _, st_v1 = self.client.get(v1["id"])
        _, st_v2 = self.client.get(v2["id"])
        self.assertEqual(st_v1["standing"], "live")
        self.assertIsNone(st_v1["superseded_by"])
        self.assertEqual(st_v2["standing"], "retracted")

    def test_cannot_target_missing_record(self):
        with self.assertRaises(Exception):
            self.client.supersede("mem_" + "0" * 12, "nope")

    def test_tampered_content_breaks_chain(self):
        rec = self.client.assert_memory("honest", tags=["t"])
        self.client.assert_memory("later", tags=["t"])
        # Rewrite history directly in the DB: change text, keep the rest.
        conn = self.store.db
        row = conn.execute(
            "SELECT content_json FROM memory_records WHERE id=?",
            (rec["id"],)).fetchone()
        content = json.loads(row["content_json"])
        content["text"] = "dishonest"
        conn.execute("UPDATE memory_records SET content_json=? WHERE id=?",
                     (json.dumps(content), rec["id"]))
        conn.commit()
        verifier = StreamVerifier(self.store)
        _, status = self.client.get(rec["id"])
        # Recompute through a fresh verifier (cache was warm on client).
        status = verifier.status_for(
            dict(self.store._inflate(
                self.store.db.execute(
                    "SELECT * FROM memory_records WHERE id=?",
                    (rec["id"],)).fetchone())))
        self.assertFalse(status["chain_intact"])
        self.assertEqual(status["signature"], "invalid")

    def test_tampered_prev_hash_detected(self):
        r1 = self.client.assert_memory("one")
        r2 = self.client.assert_memory("two")
        conn = self.store.db
        conn.execute("UPDATE memory_records SET prev_hash=? WHERE id=?",
                     ("ff" * 32, r2["id"]))
        conn.commit()
        verifier = StreamVerifier(self.store)
        rec = self.store._inflate(
            self.store.db.execute("SELECT * FROM memory_records WHERE id=?",
                                  (r2["id"],)).fetchone())
        self.assertFalse(verifier.status_for(rec)["chain_intact"])
        # The earlier record is still intact.
        rec1 = self.store._inflate(
            self.store.db.execute("SELECT * FROM memory_records WHERE id=?",
                                  (r1["id"],)).fetchone())
        self.assertTrue(verifier.status_for(rec1)["chain_intact"])

    def test_unregistered_writer_is_unverifiable(self):
        other, _, _ = make_client(agent_id="ghost")
        # Ghost writes into its own store without registering.
        store2 = other.store
        from npc_memory.records import (GENESIS_PREV, new_record_id,
                                        record_hash, signing_core,
                                        validate_shape)
        from npc_memory.identity import AgentIdentity
        ident = AgentIdentity.generate("ghost2")
        rec = {"id": new_record_id(), "seq": 0,
               "ts": "2026-10-06T00:00:01+00:00", "stream_kind": "agent",
               "stream_key": "agent:test_co:test_team:ghost2",
               "company_id": "test_co", "team_id": "test_team",
               "stream_agent_id": "ghost2", "agent_id": "ghost2",
               "writer_company_id": "test_co", "writer_team_id": "test_team",
               "type": "memory.assert",
               "content": {"text": "unregistered", "tags": [],
                           "confidence": 1.0},
               "provenance": {"derived_from": [], "source": "session",
                              "trust": "trusted"},
               "prev_hash": GENESIS_PREV, "signature_b64": "",
               "key_id": ident.key_id}
        rec["signature_b64"] = ident.sign_record_core(signing_core(rec))
        rec["record_hash"] = record_hash(rec)
        self.assertEqual(validate_shape(rec), [])
        store2.append(rec)
        verifier = StreamVerifier(store2)
        inflated = store2._inflate(
            store2.db.execute("SELECT * FROM memory_records WHERE id=?",
                              (rec["id"],)).fetchone())
        self.assertEqual(verifier.status_for(inflated)["signature"],
                         "unverifiable")

    def test_verify_stream_report(self):
        self.client.assert_memory("one")
        self.client.assert_memory("two")
        report = self.client.verify_stream()
        self.assertEqual(report["records"], 2)
        self.assertTrue(report["chain_intact"])
        self.assertIsNone(report["broken_at_seq"])
        self.assertEqual(report["invalid_signatures"], [])


if __name__ == "__main__":
    unittest.main()
