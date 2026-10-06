"""Tests for the /v1/memory/ endpoints (DESIGN v1 section 5).

Covers: agent registration, scoped API keys, signed appends, the
company-layer authz, recall with verification status, and fail-closed
behavior on tamper, forks, and secret-bearing writes.

All fixtures fictional.
"""
import json
import os
import sys
import unittest

from helpers import ApiTestCase  # noqa: E402

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_MEMORY_DIR = os.path.join(os.path.dirname(_TESTS_DIR), "..", "memory")
if _MEMORY_DIR not in sys.path:
    sys.path.insert(0, _MEMORY_DIR)

from npc_memory import AgentIdentity, Scope  # noqa: E402
from npc_memory.remote import RemoteMemoryClient, RemoteError  # noqa: E402


def make_remote(tc, agent_id, company_id="acme", team_id="core",
                key_role="verifier", key_scope=None):
    """A remote client with a fresh agent identity and a scoped API key."""
    ident = AgentIdentity.generate(agent_id)
    scope = Scope(company_id=company_id, team_id=team_id, agent_id=agent_id)
    ks = key_scope if key_scope is not None else {}
    api_key = tc.app.auth.create_key(
        f"testmem-{agent_id}", key_role,
        company_id=ks.get("company_id", company_id),
        team_id=ks.get("team_id", team_id),
        agent_id=ks.get("agent_id", agent_id))
    client = RemoteMemoryClient(f"http://127.0.0.1:{tc.port}", api_key,
                                ident, scope)
    return client, ident, api_key


def register_agent(tc, ident, company_id="acme", team_id="core"):
    """Register an agent identity via the suite's issuer key."""
    status, _, _ = tc.post(
        "/v1/memory/agents",
        {"agent_id": ident.agent_id, "company_id": company_id,
         "team_id": team_id, "public_key_b64": ident.public_key_b64},
        key=tc.issuer_key)
    assert status in (200, 201), f"registration failed: {status}"


class TestMemoryAgents(ApiTestCase):
    def test_register_agent(self):
        ident = AgentIdentity.generate("reg_agent")
        issuer = self.issuer_key
        status, headers, data = self.post(
            "/v1/memory/agents",
            {"agent_id": "reg_agent", "company_id": "acme",
             "team_id": "core", "public_key_b64": ident.public_key_b64},
            key=issuer)
        self.assertEqual(status, 201)
        body = self.check_signature(headers, data)
        self.assertEqual(body["key_id"], ident.key_id)
        self.assertEqual(body["status"], "registered")

    def test_client_register_agent_method(self):
        # RemoteMemoryClient.register_agent with an issuer key.
        ident = AgentIdentity.generate("client_reg")
        scope = Scope(company_id="acme", team_id="core",
                      agent_id="client_reg")
        issuer_key = self.app.auth.create_key(
            "testmem-clientreg", "issuer", company_id="acme", team_id="core")
        from npc_memory.remote import RemoteMemoryClient
        client = RemoteMemoryClient(f"http://127.0.0.1:{self.port}",
                                    issuer_key, ident, scope)
        doc = client.register_agent()
        self.assertEqual(doc["status"], "registered")
        self.assertEqual(doc["key_id"], ident.key_id)

    def test_register_idempotent_same_key(self):
        ident = AgentIdentity.generate("reg_agent2")
        payload = {"agent_id": "reg_agent2", "company_id": "acme",
                   "team_id": "core", "public_key_b64": ident.public_key_b64}
        s1, _, _ = self.post("/v1/memory/agents", payload,
                             key=self.issuer_key)
        s2, h2, d2 = self.post("/v1/memory/agents", payload,
                               key=self.issuer_key)
        self.assertEqual((s1, s2), (201, 200))
        self.assertEqual(self.check_signature(h2, d2)["status"],
                         "already_registered")

    def test_register_conflicting_key_rejected(self):
        ident = AgentIdentity.generate("reg_agent3")
        other = AgentIdentity.generate("reg_agent3")
        payload = {"agent_id": "reg_agent3", "company_id": "acme",
                   "team_id": "core", "public_key_b64": ident.public_key_b64}
        self.post("/v1/memory/agents", payload, key=self.issuer_key)
        payload["public_key_b64"] = other.public_key_b64
        status, _, _ = self.post("/v1/memory/agents", payload,
                                 key=self.issuer_key)
        self.assertEqual(status, 409)

    def test_register_needs_issuer(self):
        ident = AgentIdentity.generate("reg_agent4")
        status, _, _ = self.post(
            "/v1/memory/agents",
            {"agent_id": "reg_agent4", "company_id": "acme",
             "team_id": "core", "public_key_b64": ident.public_key_b64},
            key=self.verifier_key)
        self.assertEqual(status, 403)

    def test_register_rejects_bad_key_material(self):
        status, _, _ = self.post(
            "/v1/memory/agents",
            {"agent_id": "reg_agent5", "company_id": "acme",
             "team_id": "core", "public_key_b64": "!!!"},
            key=self.issuer_key)
        self.assertEqual(status, 400)

    def test_register_rejects_bad_agent_id(self):
        ident = AgentIdentity.generate("x")
        status, _, _ = self.post(
            "/v1/memory/agents",
            {"agent_id": "bad id!", "company_id": "acme",
             "team_id": "core", "public_key_b64": ident.public_key_b64},
            key=self.issuer_key)
        self.assertEqual(status, 400)

    def test_agent_scoped_key_cannot_register(self):
        scoped = self.app.auth.create_key("testmem-scoped", "issuer",
                                          company_id="acme", team_id="core",
                                          agent_id="someagent")
        ident = AgentIdentity.generate("reg_agent6")
        status, _, _ = self.post(
            "/v1/memory/agents",
            {"agent_id": "reg_agent6", "company_id": "acme",
             "team_id": "core", "public_key_b64": ident.public_key_b64},
            key=scoped)
        self.assertEqual(status, 403)


class TestMemoryRecords(ApiTestCase):
    def test_write_and_recall_roundtrip(self):
        client, ident, _ = make_remote(self, "api_sentinel")
        register_agent(self, ident)
        wrote = client.assert_memory("funding rates spike pre-listing",
                                     tags=["regime", "defi"])
        self.assertEqual(wrote["seq"], 0)
        self.assertEqual(wrote["standing"], "live")
        got, status = client.get(wrote["id"])
        self.assertEqual(got["id"], wrote["id"])
        self.assertEqual(status["standing"], "live")
        self.assertEqual(status["signature"], "valid")
        self.assertTrue(status["chain_intact"])
        hits = client.recall(tags=["defi"])
        self.assertEqual(len(hits), 1)

    def test_responses_are_signed(self):
        client, ident, _ = make_remote(self, "sig_agent")
        register_agent(self, ident)
        # Raw call so we can check the signature headers ourselves.
        rec = client._build("memory.assert", "signed check", ["t"], 1.0,
                            None, "agent")
        status, headers, data = self.post("/v1/memory/records", rec,
                                          key=client.api_key)
        self.assertEqual(status, 201)
        body = self.check_signature(headers, data)
        self.assertEqual(body["id"], rec["id"])

    def test_unregistered_writer_rejected(self):
        client, ident, _ = make_remote(self, "ghost_writer")
        # No register_agent() call.
        with self.assertRaises(RemoteError) as ctx:
            client.assert_memory("nobody knows me")
        self.assertIn("422", str(ctx.exception))

    def test_tampered_signature_rejected(self):
        client, ident, _ = make_remote(self, "tamper_agent")
        register_agent(self, ident)
        rec = client._build("memory.assert", "honest", ["t"], 1.0, None,
                            "agent")
        rec["content"]["text"] = "dishonest"
        with self.assertRaises(RemoteError) as ctx:
            client._post_record(rec)
        self.assertIn("422", str(ctx.exception))

    def test_seq_fork_rejected(self):
        client, ident, _ = make_remote(self, "fork_agent")
        register_agent(self, ident)
        client.assert_memory("first")
        rec = client._build("memory.assert", "replay", [], 1.0, None,
                            "agent")
        rec["seq"] = 0
        # Re-sign with the rewound seq so the failure is the fork, not sig.
        from npc_memory.records import (record_hash, signing_core,
                                        validate_shape)
        rec["signature_b64"] = client.identity.sign_record_core(
            signing_core(rec))
        rec["record_hash"] = record_hash(rec)
        self.assertEqual(validate_shape(rec), [])
        with self.assertRaises(RemoteError) as ctx:
            client._post_record(rec)
        self.assertIn("409", str(ctx.exception))

    def test_secret_write_refused(self):
        client, ident, _ = make_remote(self, "scrub_agent")
        register_agent(self, ident)
        with self.assertRaises(Exception):
            client.assert_memory("deploy with sk_live_abcdefghijklmnop")

    def test_supersede_and_retract_flow(self):
        client, ident, _ = make_remote(self, "rev_agent")
        register_agent(self, ident)
        old = client.assert_memory("v1 take", tags=["t"])
        new = client.supersede(old["id"], "v2 take", tags=["t"])
        _, st_old = client.get(old["id"])
        self.assertEqual(st_old["standing"], "superseded")
        self.assertEqual(st_old["superseded_by"], new["id"])
        client.retract(new["id"], reason="v2 was wrong")
        _, st_old2 = client.get(old["id"])
        _, st_new = client.get(new["id"])
        # Withdrawing the supersede revives the original belief.
        self.assertEqual(st_old2["standing"], "live")
        self.assertEqual(st_new["standing"], "retracted")
        # Retracting the original now works; both takes are withdrawn.
        # The two retraction records themselves remain live history.
        client.retract(old["id"], reason="dropping the take")
        live = client.recall(live_only=True)
        self.assertEqual(len(live), 2)
        self.assertTrue(all(r["type"] == "memory.retract" for r, _ in live))

    def test_supersede_missing_target_rejected(self):
        client, ident, _ = make_remote(self, "miss_agent")
        register_agent(self, ident)
        with self.assertRaises(RemoteError) as ctx:
            client.supersede("mem_" + "a" * 12, "nope")
        self.assertIn("409", str(ctx.exception))

    def test_unknown_record_is_404(self):
        client, ident, _ = make_remote(self, "404_agent")
        register_agent(self, ident)
        self.assertIsNone(client.get("mem_" + "f" * 12))

    def test_unauthenticated_rejected(self):
        status, _, _ = self.post("/v1/memory/records", {})
        self.assertEqual(status, 401)


class TestCompanyLayer(ApiTestCase):
    def _acme_writer(self, agent_id="acme_a1"):
        client, ident, _ = make_remote(self, agent_id)
        register_agent(self, ident)
        return client

    def test_company_isolation(self):
        acme = self._acme_writer()
        wrote = acme.assert_memory("acme alpha", tags=["alpha"])
        # A rival company's agent-scoped key cannot read it (404, not 403:
        # never confirm what exists elsewhere).
        rival, rival_ident, _ = make_remote(self, "rival_r1", company_id="rivalco",
                                  key_scope={"company_id": "rivalco",
                                             "team_id": "core",
                                             "agent_id": "rival_r1"})
        register_agent(self, rival_ident)
        self.assertIsNone(rival.get(wrote["id"]))
        self.assertEqual(rival.recall(), [])

    def test_agent_key_cannot_write_team_stream(self):
        client, ident, api_key = make_remote(self, "narrow_agent")
        register_agent(self, ident)
        rec = client._build("memory.assert", "team note", [], 1.0, None,
                            "team")
        status, _, _ = self.post("/v1/memory/records", rec, key=api_key)
        self.assertEqual(status, 403)

    def test_team_key_writes_team_stream(self):
        ident = AgentIdentity.generate("team_writer")
        scope = Scope(company_id="acme", team_id="core",
                      agent_id="team_writer")
        api_key = self.app.auth.create_key(
            "testmem-teamkey", "verifier", company_id="acme", team_id="core")
        client = RemoteMemoryClient(f"http://127.0.0.1:{self.port}", api_key,
                                    ident, scope)
        register_agent(self, ident)
        wrote = client.assert_memory("shared team learning", stream="team")
        self.assertEqual(wrote["stream_key"], "team:acme:core")

    def test_agent_key_cannot_reach_other_company(self):
        acme = self._acme_writer("acme_a2")
        wrote = acme.assert_memory("acme only", tags=["x"])
        other, other_ident, _ = make_remote(self, "other_o1", company_id="otherco",
                                  key_scope={"company_id": "otherco"})
        register_agent(self, other_ident)
        self.assertIsNone(other.get(wrote["id"]))

    def test_fleet_write_needs_issuer(self):
        client, ident, api_key = make_remote(self, "fleet_try")
        register_agent(self, ident)
        rec = client._build("memory.assert", "fleet learning", ["f"], 1.0,
                            None, "fleet")
        status, _, _ = self.post("/v1/memory/records", rec, key=api_key)
        self.assertEqual(status, 403)
        # Same agent, unscoped issuer key: allowed.
        issuer_key = self.app.auth.create_key("testmem-issuer", "issuer")
        status, headers, data = self.post("/v1/memory/records", rec,
                                          key=issuer_key)
        self.assertEqual(status, 201)
        body = self.check_signature(headers, data)
        self.assertEqual(body["stream_key"], "fleet")

    def test_company_stream_shared_with_attribution(self):
        # Company-stream writes need a company-scoped key (agent-scoped
        # keys only reach their own agent stream).
        def co_writer(agent_id):
            client, ident, _ = make_remote(
                self, agent_id,
                key_scope={"company_id": "acme", "team_id": None,
                           "agent_id": None})
            register_agent(self, ident)
            return client
        a1 = co_writer("acme_b1")
        a2 = co_writer("acme_b2")
        a1.assert_memory("company-wide learning", tags=["co"],
                        stream="company")
        hits = a2.recall(stream="company")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0]["agent_id"], "acme_b1")
        self.assertEqual(hits[0][1]["signature"], "valid")


class TestRecallFilters(ApiTestCase):
    _counter = 0

    def setUp(self):
        super().setUp()
        TestRecallFilters._counter += 1
        name = f"recall_agent_{TestRecallFilters._counter}"
        self.client, recall_ident, _ = make_remote(self, name)
        register_agent(self, recall_ident)
        self.client.assert_memory("funding rates spike", tags=["defi"])
        self.client.assert_memory("SOL funding update",
                                  tags=["defi", "sol"])
        self.wrote = self.client

    def test_recall_by_stream_key(self):
        hits = self.client.recall(stream="agent")
        self.assertEqual(len(hits), 2)

    def test_recall_keyword(self):
        hits = self.client.recall(q="funding")
        self.assertEqual(len(hits), 2)
        hits = self.client.recall(q="sol")
        self.assertEqual(len(hits), 1)

    def test_recall_malformed_stream_key(self):
        status, _, _ = self.post("/v1/memory/recall",
                                 {"stream_key": "bogus"},
                                 key=self.client.api_key)
        self.assertEqual(status, 400)

    def test_recall_out_of_scope_stream_forbidden(self):
        status, _, _ = self.post(
            "/v1/memory/recall",
            {"stream_key": "company:rivalco"},
            key=self.client.api_key)
        self.assertEqual(status, 403)

    def test_recall_limit_validated(self):
        status, _, _ = self.post("/v1/memory/recall", {"limit": "many"},
                                 key=self.client.api_key)
        self.assertEqual(status, 400)


class TestTamperEvident(ApiTestCase):
    def test_chain_break_visible_on_recall(self):
        client, ident, _ = make_remote(self, "chain_agent")
        register_agent(self, ident)
        r1 = client.assert_memory("honest one", tags=["t"])
        client.assert_memory("honest two", tags=["t"])
        # Rewrite history behind the API's back.
        conn = self.app.memory.db
        row = conn.execute(
            "SELECT content_json FROM memory_records WHERE id=?",
            (r1["id"],)).fetchone()
        content = json.loads(row["content_json"])
        content["text"] = "rewritten"
        conn.execute("UPDATE memory_records SET content_json=? WHERE id=?",
                     (json.dumps(content), r1["id"]))
        conn.commit()
        _, status = client.get(r1["id"])
        self.assertFalse(status["chain_intact"])
        self.assertEqual(status["signature"], "invalid")


if __name__ == "__main__":
    unittest.main()
