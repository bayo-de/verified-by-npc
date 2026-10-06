"""Company-layer scoping: stream keys and authorization rules."""
import unittest

from npc_memory.scope import (Scope, agent_may_write, fleet_write_allowed,
                              key_may_read, key_may_write, stream_key,
                              valid_record_id, valid_scope_id, valid_tag)


class TestStreamKeys(unittest.TestCase):
    def test_all_kinds(self):
        self.assertEqual(stream_key("fleet"), "fleet")
        self.assertEqual(stream_key("company", "acme"), "company:acme")
        self.assertEqual(stream_key("team", "acme", "core"),
                         "team:acme:core")
        self.assertEqual(stream_key("agent", "acme", "core", "sentinel"),
                         "agent:acme:core:sentinel")

    def test_bad_dimensions_rejected(self):
        with self.assertRaises(ValueError):
            stream_key("fleet", "acme")
        with self.assertRaises(ValueError):
            stream_key("company", "acme", "core")
        with self.assertRaises(ValueError):
            stream_key("agent", "acme", "core", None)
        with self.assertRaises(ValueError):
            stream_key("agent", "ac me", "core", "sentinel")
        with self.assertRaises(ValueError):
            stream_key("nope")

    def test_id_charset(self):
        self.assertTrue(valid_scope_id("acme-1_2"))
        self.assertFalse(valid_scope_id("ac me"))
        self.assertFalse(valid_scope_id(""))
        self.assertFalse(valid_scope_id("x" * 65))
        self.assertTrue(valid_record_id("mem_abcdef12"))
        self.assertFalse(valid_record_id("evt_abcdef12"))
        self.assertTrue(valid_tag("funding-rates"))
        self.assertFalse(valid_tag("Funding"))

    def test_scope_hierarchy_validated(self):
        self.assertEqual(Scope(team_id="t").validate(), [
            "team_id requires company_id"])
        # A fleet-level agent (agent_id only) is valid.
        self.assertEqual(Scope(agent_id="a").validate(), [])
        self.assertEqual(Scope().validate(), [])


class TestKeyAuthz(unittest.TestCase):
    def test_agent_key_reads_own_branch(self):
        key = Scope("acme", "core", "sentinel")
        self.assertTrue(key_may_read(key, "agent", "acme", "core",
                                     "sentinel"))
        self.assertTrue(key_may_read(key, "team", "acme", "core"))
        self.assertTrue(key_may_read(key, "company", "acme"))
        self.assertTrue(key_may_read(key, "fleet"))
        self.assertFalse(key_may_read(key, "agent", "acme", "core", "other"))
        self.assertFalse(key_may_read(key, "team", "acme", "other"))
        self.assertFalse(key_may_read(key, "company", "otherco"))

    def test_agent_key_writes_only_own_stream(self):
        key = Scope("acme", "core", "sentinel")
        self.assertTrue(key_may_write(key, "agent", "acme", "core",
                                      "sentinel"))
        self.assertFalse(key_may_write(key, "team", "acme", "core"))
        self.assertFalse(key_may_write(key, "company", "acme"))
        self.assertFalse(key_may_write(key, "fleet"))

    def test_team_key_reaches_team_and_agents(self):
        key = Scope("acme", "core")
        self.assertTrue(key_may_write(key, "team", "acme", "core"))
        self.assertTrue(key_may_write(key, "agent", "acme", "core", "a1"))
        self.assertFalse(key_may_write(key, "agent", "acme", "other", "a1"))
        self.assertFalse(key_may_write(key, "company", "acme"))

    def test_unscoped_key_reaches_everything(self):
        key = Scope()
        for kind, dims in [("fleet", (None, None, None)),
                           ("company", ("acme", None, None)),
                           ("agent", ("acme", "core", "s"))]:
            self.assertTrue(key_may_write(key, kind, *dims))
            self.assertTrue(key_may_read(key, kind, *dims))

    def test_agent_writer_rule(self):
        agent = Scope("acme", "core", "sentinel")
        self.assertTrue(agent_may_write(agent, "agent", "acme", "core",
                                        "sentinel"))
        self.assertTrue(agent_may_write(agent, "team", "acme", "core"))
        self.assertTrue(agent_may_write(agent, "company", "acme"))
        self.assertTrue(agent_may_write(agent, "fleet"))
        self.assertFalse(agent_may_write(agent, "agent", "acme", "core",
                                         "other"))
        self.assertFalse(agent_may_write(agent, "team", "acme", "other"))
        self.assertFalse(agent_may_write(agent, "company", "otherco"))

    def test_fleet_write_roles(self):
        self.assertTrue(fleet_write_allowed("issuer"))
        self.assertTrue(fleet_write_allowed("admin"))
        self.assertFalse(fleet_write_allowed("verifier"))


if __name__ == "__main__":
    unittest.main()
