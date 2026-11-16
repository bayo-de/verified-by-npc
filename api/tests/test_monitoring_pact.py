"""Continuous monitoring over the PACT feed: the runner scores only
what the grant's own record layer proves, a tampered chain regresses
to a drift flag, and an ungranted scope dents scope discipline.

Fixtures follow tests/test_pact.py's PactUnitCase pattern.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from npc_verify import monitoring, pact  # noqa: E402
from npc_verify.canonical import canonical_sha256_hex  # noqa: E402
from npc_verify.keys import KeyRegistry  # noqa: E402
from npc_verify.monitoring_pact import make_pact_audit_runner  # noqa: E402
from npc_verify.store import Store  # noqa: E402

GRANT_ID = "grant_01K8PACT7X3QZK4M9D2F6H8W1E"
SESSION = {
    "grant_id": GRANT_ID,
    "pa_iss": "http://localhost:3002",
    "pa_sub": "demo-user-sub-7f3a",
    "brand_id": "01M3R53Q5SZQ6FQSMSDBSSREAA",
    "user_id_at_brand": "alex.rivera@example.com",
    "scopes_requested": ["flights:history:read", "flights:rebook",
                         "flights:upcoming:read"],
    "scopes_granted": ["flights:history:read", "flights:upcoming:read"],
    "shown_at": "2026-10-14T23:55:00+00:00",
    "granted_at": "2026-10-14T23:55:42+00:00",
    "expires_at": "2027-10-15T00:55:42+00:00",
}
T1 = "2026-11-11T12:00:00Z"
T2 = "2026-11-12T12:00:00Z"


def receipt(tool, scopes, ts, args=None):
    return {
        "grantId": GRANT_ID,
        "user": SESSION["user_id_at_brand"],
        "pa": SESSION["pa_iss"],
        "brand": SESSION["brand_id"],
        "scopesUsed": scopes,
        "actions": [{"tool": tool,
                     "argsHash": canonical_sha256_hex(args or {})}],
        "ts": ts,
    }


class MonitoringPactCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_monitoring_pact_")
        self.store = Store(os.path.join(self.tmp, "t.db"))
        self.keys = KeyRegistry(self.store, os.path.join(self.tmp, "keys"))
        self.keys.ensure_bootstrap()
        rec = pact.mint_consent_record(self.store, self.keys, dict(SESSION))
        self.assertIsNotNone(rec)
        self.store.upsert_monitoring_subject(
            GRANT_ID, None, SESSION["expires_at"], SESSION["granted_at"])

    def tearDown(self):
        self.store.close()

    def fill(self, receipts):
        entries = [pact.append_receipt(self.store, self.keys, GRANT_ID, r)
                   for r in receipts]
        self.assertTrue(all(e is not None for e in entries))

    def runner(self, at):
        return make_pact_audit_runner(self.store, self.keys,
                                      now_fn=lambda: at)

    def test_first_pass_scores_chain_and_scope(self):
        self.fill([
            receipt("flights.listUpcoming", ["flights:upcoming:read"],
                    "2026-10-14T23:56:35+00:00"),
            receipt("flights.getHistory", ["flights:history:read"],
                    "2026-10-14T23:58:30+00:00"),
        ])
        result = monitoring.run_once(self.store, T1, self.runner(T1))
        self.assertEqual([e["event_type"] for e in result["events"]],
                         ["reaudit_completed"])
        subject = self.store.list_monitoring_subjects()[0]
        dims = subject["last_audit"]["dimensions"]
        self.assertEqual(dims["evidence_chain_integrity"]["score"], 1.0)
        self.assertEqual(dims["evidence_chain_integrity"]
                         ["conclusion_strength"], "established")
        self.assertEqual(dims["scope_discipline"]["score"], 1.0)
        self.assertEqual(subject["last_audit"]["trace_count"], 2)

    def test_tampered_chain_regresses_to_drift_flag(self):
        self.fill([
            receipt("flights.listUpcoming", ["flights:upcoming:read"],
                    "2026-10-14T23:56:35+00:00"),
            receipt("flights.getHistory", ["flights:history:read"],
                    "2026-10-14T23:58:30+00:00"),
        ])
        monitoring.run_once(self.store, T1, self.runner(T1))
        row = self.store.db.execute(
            "SELECT record_json FROM pact_audit_entries"
            " WHERE grant_id=? AND seq=2", (GRANT_ID,)).fetchone()
        entry = json.loads(row["record_json"])
        entry["receipt_claims"]["actions"][0]["tool"] = "flights.rebook"
        self.store.db.execute(
            "UPDATE pact_audit_entries SET record_json=?"
            " WHERE grant_id=? AND seq=2",
            (json.dumps(entry), GRANT_ID))
        self.store.db.commit()
        result = monitoring.run_once(self.store, T2, self.runner(T2))
        types = [e["event_type"] for e in result["events"]]
        self.assertEqual(types, ["reaudit_completed", "drift_flag"])
        flag = result["events"][1]
        self.assertIn("evidence_chain_integrity",
                      flag["detail"]["comparison"]["flagged_dimensions"])

    def test_ungranted_scope_dents_scope_discipline(self):
        self.fill([
            receipt("flights.listUpcoming", ["flights:upcoming:read"],
                    "2026-10-14T23:56:35+00:00"),
            receipt("flights.rebook", ["flights:rebook"],
                    "2026-10-14T23:58:30+00:00"),
        ])
        monitoring.run_once(self.store, T1, self.runner(T1))
        dims = self.store.list_monitoring_subjects()[0]["last_audit"]["dimensions"]
        self.assertEqual(dims["scope_discipline"]["score"], 0.5)
        self.assertEqual(dims["evidence_chain_integrity"]["score"], 1.0)

    def test_unknown_grant_is_skipped_not_fabricated(self):
        self.store.upsert_monitoring_subject(
            "grant_unknown", None, None, "2026-11-11T00:00:00Z")
        result = monitoring.run_once(self.store, T1, self.runner(T1))
        self.assertIn("grant_unknown", result["skipped_no_evidence"])
        subjects = {s["subject_id"]: s
                    for s in self.store.list_monitoring_subjects()}
        self.assertIsNone(subjects["grant_unknown"]["last_audit"])


if __name__ == "__main__":
    unittest.main()
