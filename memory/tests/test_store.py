"""MemoryStore: append-only chains, forks, recall queries."""
import unittest

from mem_helpers import MemoryTestCase, make_client
from npc_memory import Scope
from npc_memory.store import MemoryStoreError


class TestAppend(MemoryTestCase):
    def test_seq_is_contiguous_per_stream(self):
        r1 = self.client.assert_memory("one")
        r2 = self.client.assert_memory("two")
        r3 = self.client.assert_memory("three", stream="team")
        self.assertEqual((r1["seq"], r2["seq"]), (0, 1))
        self.assertEqual(r3["seq"], 0)  # separate stream, separate seq

    def test_prev_hash_links(self):
        r1 = self.client.assert_memory("one")
        r2 = self.client.assert_memory("two")
        self.assertEqual(r2["prev_hash"], r1["record_hash"])
        self.assertEqual(r1["prev_hash"], "0" * 64)

    def test_replay_seq_rejected_as_fork(self):
        self.client.assert_memory("one")
        rec = self.client._build("memory.assert", "fork", [], 1.0, None,
                                 "agent")
        rec["seq"] = 0  # rewind
        with self.assertRaises(MemoryStoreError):
            self.store.append(rec)

    def test_duplicate_id_rejected(self):
        r1 = self.client.assert_memory("one")
        rec = self.client._build("memory.assert", "two", [], 1.0, None,
                                 "agent")
        rec["id"] = r1["id"]
        with self.assertRaises(MemoryStoreError):
            self.store.append(rec)

    def test_register_agent_idempotent_via_client(self):
        self.client.register_self()  # second call is a no-op
        self.client.register_self()

    def test_double_registration_rejected(self):
        with self.assertRaises(MemoryStoreError):
            self.store.register_agent("test_agent", "test_co", "test_team",
                                      "eA==", "ak_" + "0" * 16,
                                      "2026-10-06T00:00:00+00:00", "t")


class TestQuery(MemoryTestCase):
    def setUp(self):
        super().setUp()
        self.client.assert_memory("funding rates spike", tags=["defi"])
        self.client.assert_memory("SOL funding update", tags=["defi", "sol"])
        self.client.assert_memory("team standup notes", tags=["ops"],
                                  stream="team")

    def test_tag_recall_any_match(self):
        hits = self.client.recall(tags=["sol"])
        self.assertEqual(len(hits), 1)
        hits = self.client.recall(tags=["defi"])
        self.assertEqual(len(hits), 2)

    def test_keyword_recall(self):
        hits = self.client.recall(q="funding")
        self.assertEqual(len(hits), 2)
        hits = self.client.recall(q="FUNDING")  # case-insensitive
        self.assertEqual(len(hits), 2)
        hits = self.client.recall(q="nothing matches this")
        self.assertEqual(len(hits), 0)

    def test_recency_ordering(self):
        hits = self.client.recall()
        texts = [r["content"]["text"] for r, _ in hits]
        self.assertEqual(texts[0], "team standup notes")

    def test_since_until(self):
        # register_self() ticks the clock once; memories land at :02-:04.
        hits = self.client.recall(since="2026-10-06T00:00:03+00:00")
        self.assertEqual(len(hits), 2)
        hits = self.client.recall(until="2026-10-06T00:00:02+00:00")
        self.assertEqual(len(hits), 1)

    def test_limit(self):
        hits = self.client.recall(limit=1)
        self.assertEqual(len(hits), 1)

    def test_stream_narrowing(self):
        hits = self.client.recall(stream="team")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0]["stream_kind"], "team")

    def test_scope_isolation_between_companies(self):
        other, _, _ = make_client(agent_id="spy", company_id="other_co",
                                  team_id="other_team")
        # Separate in-memory DB: nothing leaks across stores.
        self.assertEqual(len(other.recall()), 0)


if __name__ == "__main__":
    unittest.main()
