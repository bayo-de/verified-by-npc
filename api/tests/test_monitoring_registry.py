"""Registry-lane monitoring: standing and freshness from the
subject's own attestation history. A revocation regresses
status_continuity to a drift flag; an expired attestation zeroes
the validity window; no history is skipped, never fabricated.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from npc_verify import monitoring  # noqa: E402
from npc_verify.models import Attestation  # noqa: E402
from npc_verify.monitoring_registry import make_registry_audit_runner  # noqa: E402
from npc_verify.store import Store  # noqa: E402

T1 = "2026-11-11T12:00:00Z"
T2 = "2026-11-12T12:00:00Z"


def attestation(att_id, expires_at, tested_at=T1):
    return Attestation(
        id=att_id, subject_type="agent", subject_id="agent_1",
        verdict="registered", scope={}, tested_at=tested_at,
        expires_at=expires_at, findings_summary="fixture",
        created_at=tested_at)


class MonitoringRegistryCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_monitoring_registry_")
        self.store = Store(os.path.join(self.tmp, "t.db"))
        self.store.upsert_monitoring_subject(
            "agent_1", None, "2027-01-01T00:00:00Z", "2026-11-11T00:00:00Z")

    def tearDown(self):
        self.store.close()

    def runner(self, at):
        return make_registry_audit_runner(self.store, now_fn=lambda: at)

    def test_standing_and_fresh_scores_full(self):
        self.store.add_attestation(attestation("att_1", "2027-01-01T00:00:00Z"))
        result = monitoring.run_once(self.store, T1, self.runner(T1))
        self.assertEqual([e["event_type"] for e in result["events"]],
                         ["reaudit_completed"])
        dims = self.store.list_monitoring_subjects()[0]["last_audit"]["dimensions"]
        self.assertEqual(dims["status_continuity"]["score"], 1.0)
        self.assertEqual(dims["validity_window"]["score"], 1.0)
        self.assertEqual(dims["validity_window"]["conclusion_strength"],
                         "established")

    def test_no_history_is_skipped(self):
        result = monitoring.run_once(self.store, T1, self.runner(T1))
        self.assertEqual(result["skipped_no_evidence"], ["agent_1"])
        self.assertEqual(result["events"], [])

    def test_revocation_regresses_to_drift_flag(self):
        self.store.add_attestation(attestation("att_1", "2027-01-01T00:00:00Z"))
        monitoring.run_once(self.store, T1, self.runner(T1))
        self.store.revoke_attestation("att_1", "rev_1", "fixture reason",
                                      "c2ln", "key_1", T2)
        # The revocation is itself the newest record in the history.
        rows = self.store.attestations_for_subject("agent", "agent_1")
        self.assertTrue(rows[-1]["revoked"])
        result = monitoring.run_once(self.store, T2, self.runner(T2))
        types = [e["event_type"] for e in result["events"]]
        self.assertEqual(types, ["reaudit_completed", "drift_flag"])
        flag = result["events"][1]
        self.assertIn("status_continuity",
                      flag["detail"]["comparison"]["flagged_dimensions"])

    def test_expired_attestation_zeroes_validity_window(self):
        self.store.add_attestation(attestation("att_1", "2026-11-11T13:00:00Z"))
        monitoring.run_once(self.store, T1, self.runner(T1))
        result = monitoring.run_once(self.store, T2, self.runner(T2))
        dims = self.store.list_monitoring_subjects()[0]["last_audit"]["dimensions"]
        self.assertEqual(dims["validity_window"]["score"], 0.0)
        types = [e["event_type"] for e in result["events"]]
        self.assertIn("drift_flag", types)


if __name__ == "__main__":
    unittest.main()
