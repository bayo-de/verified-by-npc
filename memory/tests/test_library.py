"""MemoryClient flows: the dogfood scenario.

Two agents (sentinel, trader) in company acme / team core share a team
stream and a company stream; a fleet agent writes fleet learnings; a
rival company's agent cannot read or write acme's streams.
"""
import unittest

from mem_helpers import Clock, make_client
from npc_memory import (AgentIdentity, MemoryClient, MemoryStore, Scope,
                        MemoryError)


def company_client(agent_id, company_id="acme", team_id="core"):
    store = MemoryStore.open(":memory:")
    ident = AgentIdentity.generate(agent_id)
    scope = Scope(company_id=company_id, team_id=team_id, agent_id=agent_id)
    client = MemoryClient(store, ident, scope, clock=Clock())
    client.register_self()
    return client


class TestDogfood(unittest.TestCase):
    def test_shared_store_team_and_company_streams(self):
        store = MemoryStore.open(":memory:")
        clock = Clock()

        def agent(name):
            ident = AgentIdentity.generate(name)
            c = MemoryClient(store, ident,
                             Scope(company_id="acme", team_id="core",
                                   agent_id=name), clock=clock)
            c.register_self()
            return c

        sentinel = agent("sentinel")
        trader = agent("trader")
        sentinel.assert_memory("Funding rates spike pre-listing",
                               tags=["regime"], stream="team")
        trader.assert_memory("Trimmed SOL into strength",
                             tags=["execution"], stream="team")
        sentinel.assert_memory("Q4 thesis: verify everything",
                               tags=["thesis"], stream="company")

        # Either agent recalls the whole team stream with verification.
        hits = trader.recall(stream="team")
        self.assertEqual(len(hits), 2)
        writers = {r["agent_id"] for r, _ in hits}
        self.assertEqual(writers, {"sentinel", "trader"})
        for _, st in hits:
            self.assertEqual(st["standing"], "live")
            self.assertEqual(st["signature"], "valid")
            self.assertTrue(st["chain_intact"])

        # Company stream is separate from the team stream.
        self.assertEqual(len(sentinel.recall(stream="company")), 1)

    def test_agent_cannot_read_other_company(self):
        store = MemoryStore.open(":memory:")
        clock = Clock()
        acme = MemoryClient(
            store, AgentIdentity.generate("a1"),
            Scope(company_id="acme", team_id="core", agent_id="a1"),
            clock=clock)
        acme.register_self()
        acme.assert_memory("acme secret sauce", tags=["alpha"])
        rival = MemoryClient(
            store, AgentIdentity.generate("r1"),
            Scope(company_id="rival", team_id="core", agent_id="r1"),
            clock=clock)
        rival.register_self()
        self.assertEqual(rival.recall(), [])
        self.assertIsNone(rival.get(
            acme.recall()[0][0]["id"]))

    def test_fleet_stream_with_attribution(self):
        store = MemoryStore.open(":memory:")
        clock = Clock()
        fleet_bot = MemoryClient(
            store, AgentIdentity.generate("fleet_scribe"),
            Scope(agent_id="fleet_scribe"), clock=clock)
        fleet_bot.register_self()
        rec = fleet_bot.assert_memory("Fleet learning: verify before trust",
                                      tags=["fleet"], stream="fleet")
        self.assertEqual(rec["stream_key"], "fleet")
        # A company agent reads the fleet stream but cannot write it.
        acme = MemoryClient(
            store, AgentIdentity.generate("a1"),
            Scope(company_id="acme", team_id="core", agent_id="a1"),
            clock=clock)
        acme.register_self()
        hits = acme.recall(stream="fleet")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0]["agent_id"], "fleet_scribe")
        # A company agent may contribute to the fleet stream; the write
        # carries writer attribution.
        contrib = acme.assert_memory("Acme lesson for the fleet",
                                     tags=["fleet"], stream="fleet")
        self.assertEqual(contrib["writer_scope"],
                         {"company_id": "acme", "team_id": "core"})

    def test_recall_across_own_streams(self):
        store = MemoryStore.open(":memory:")
        clock = Clock()
        c = MemoryClient(
            store, AgentIdentity.generate("a1"),
            Scope(company_id="acme", team_id="core", agent_id="a1"),
            clock=clock)
        c.register_self()
        c.assert_memory("personal note", tags=["me"])
        c.assert_memory("team note", tags=["we"], stream="team")
        c.assert_memory("fleet note", tags=["all"], stream="fleet")
        hits = c.recall()
        self.assertEqual(len(hits), 3)

    def test_get_unknown_returns_none(self):
        client = company_client("lonely")
        self.assertIsNone(client.get("mem_" + "f" * 12))

    def test_live_only_filter(self):
        client = company_client("editor")
        old = client.assert_memory("draft", tags=["doc"])
        client.supersede(old["id"], "final", tags=["doc"])
        self.assertEqual(len(client.recall()), 2)
        live = client.recall(live_only=True)
        self.assertEqual(len(live), 1)
        self.assertEqual(live[0][1]["standing"], "live")


if __name__ == "__main__":
    unittest.main()
