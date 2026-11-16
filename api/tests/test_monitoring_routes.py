"""Continuous monitoring over HTTP (server wiring, 2026-11-15).

End to end through the API: enrollment, due computation, a scheduler
pass that publishes signed monitoring event records (resolvable at
GET /v1/records/{id}, signatures verified), a drift regression after
an ungranted-scope receipt, the ratchet comparison endpoint, and the
cross-check attach/disagreement records. Role gates mirror the PACT
section: reads and the pure comparison are verifier+, enrollment,
runs, and cross-check attaches are issuer.

PACT fixtures follow tests/test_monitoring_pact.py's shapes.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.helpers import ApiTestCase  # noqa: E402
from npc_verify import pact  # noqa: E402
from npc_verify.canonical import canonical_sha256_hex  # noqa: E402

GRANT_ID = "grant_01K8MONR7X3QZK4M9D2F6H8W1Z"
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
T1 = "2026-11-15T12:00:00Z"
T2 = "2026-11-16T13:00:00Z"  # T1 + 25h: past the 24h default cadence

BASELINE = {"dimensions": {
    "instruction_following": {"score": 0.90, "evidence_tier": "native",
                              "conclusion_strength": "established"},
    "tool_choice": {"score": 0.80, "evidence_tier": "native",
                    "conclusion_strength": "supported"},
}}
REGRESSED = {"dimensions": {
    "instruction_following": {"score": 0.70, "evidence_tier": "native",
                              "conclusion_strength": "established"},
    "tool_choice": {"score": 0.80, "evidence_tier": "native",
                    "conclusion_strength": "indicative"},
}}


def receipt(scopes, ts):
    return {
        "grantId": GRANT_ID,
        "user": SESSION["user_id_at_brand"],
        "pa": SESSION["pa_iss"],
        "brand": SESSION["brand_id"],
        "scopesUsed": scopes,
        "actions": [{"tool": "search",
                     "argsHash": canonical_sha256_hex({})}],
        "ts": ts,
    }


class MonitoringRoutesCase(ApiTestCase):

    def body(self, data):
        return json.loads(data.decode())

    def enroll(self, subject_id, key=None, **extra):
        payload = {"subject_id": subject_id}
        payload.update(extra)
        return self.post("/v1/monitoring/subjects", payload,
                         key=key or self.issuer_key)

    # -- enrollment + reads -------------------------------------------
    def test_enroll_and_read_subjects(self):
        status, _, data = self.enroll("subj-routes-1")
        self.assertEqual(status, 201)
        created = self.body(data)
        self.assertEqual(created["subject_id"], "subj-routes-1")
        self.assertEqual(created["due_reason"], "never_audited")
        self.assertIsNone(created["last_audit"])

        status, headers, data = self.get("/v1/monitoring/subjects",
                                         key=self.verifier_key)
        self.assertEqual(status, 200)
        self.check_signature(headers, data)
        listed = {s["subject_id"]: s
                  for s in self.body(data)["subjects"]}
        self.assertEqual(listed["subj-routes-1"]["due_reason"],
                         "never_audited")

        status, _, data = self.get("/v1/monitoring/due",
                                   key=self.verifier_key)
        self.assertEqual(status, 200)
        due = {s["subject_id"]: s["due_reason"]
               for s in self.body(data)["due"]}
        self.assertEqual(due.get("subj-routes-1"), "never_audited")

    def test_enroll_updates_schedule_not_baseline(self):
        self.enroll("subj-routes-2", cadence_hours=24)
        status, _, data = self.enroll("subj-routes-2", cadence_hours=48)
        self.assertEqual(status, 201)
        self.assertEqual(self.body(data)["cadence_hours"], 48)

    def test_enroll_validation(self):
        status, _, _ = self.post("/v1/monitoring/subjects", {},
                                 key=self.issuer_key)
        self.assertEqual(status, 400)
        status, _, _ = self.enroll("subj-x", cadence_hours=-1)
        self.assertEqual(status, 400)
        status, _, _ = self.enroll("subj-x", cadence_hours="daily")
        self.assertEqual(status, 400)
        status, _, _ = self.enroll("subj-x", expires_at="banana")
        self.assertEqual(status, 400)

    def test_role_gates(self):
        status, _, _ = self.get("/v1/monitoring/subjects")
        self.assertEqual(status, 401)
        status, _, _ = self.get("/v1/monitoring/due")
        self.assertEqual(status, 401)
        status, _, _ = self.enroll("subj-gated", key=self.verifier_key)
        self.assertEqual(status, 403)
        status, _, _ = self.post("/v1/monitoring/run", {},
                                 key=self.verifier_key)
        self.assertEqual(status, 403)
        status, _, _ = self.post(
            "/v1/monitoring/compare",
            {"baseline": BASELINE, "current": REGRESSED})
        self.assertEqual(status, 401)
        status, _, _ = self.post(
            "/v1/monitoring/crosscheck",
            {"subject_id": "subj-gated",
             "npc_comparison": {"status": "regressed"},
             "external_verdict": {"stance": "clear"}},
            key=self.verifier_key)
        self.assertEqual(status, 403)

    # -- scheduler pass -------------------------------------------------
    def test_run_publishes_signed_records_and_flags_drift(self):
        status, _, _ = self.post("/v1/pact/grants", dict(SESSION),
                                 key=self.issuer_key)
        self.assertEqual(status, 201)
        status, _, _ = self.post(
            f"/v1/pact/grants/{GRANT_ID}/receipts",
            {"receipt": receipt(["flights:history:read"],
                                "2026-11-15T11:00:00Z")},
            key=self.issuer_key)
        self.assertEqual(status, 201)
        status, _, _ = self.enroll(GRANT_ID)
        self.assertEqual(status, 201)
        self.enroll("subj-ghost-no-evidence")

        # First pass: first audit, one completion event, one record.
        status, _, data = self.post("/v1/monitoring/run", {"now": T1},
                                    key=self.issuer_key)
        self.assertEqual(status, 200)
        result = self.body(data)
        self.assertIn(GRANT_ID, result["due_subject_ids"])
        self.assertIn("subj-ghost-no-evidence",
                      result["skipped_no_evidence"])
        events = [e for e in result["events"]
                  if e["subject_id"] == GRANT_ID]
        self.assertEqual([e["event_type"] for e in events],
                         ["reaudit_completed"])
        self.assertTrue(events[0]["detail"]["first_audit"])
        records = [r for r in result["records"]
                   if r["subject_id"] == GRANT_ID]
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["kind"], "monitoring_event")
        self.assertEqual(rec["record_type"],
                         "npc.registry.monitoring_event")
        self.assertEqual(rec["event_type"], "reaudit_completed")
        self.assertTrue(pact.verify_record(self.app.keys, rec))

        # The published record resolves publicly, signature intact.
        status, _, data = self.get(f"/v1/records/{rec['record_id']}")
        self.assertEqual(status, 200)
        fetched = self.body(data)
        self.assertEqual(fetched["record_id"], rec["record_id"])
        self.assertTrue(pact.verify_record(self.app.keys, fetched))

        # An ungranted-scope receipt dents scope discipline; the next
        # pass (past cadence) regresses and raises a drift flag.
        status, _, _ = self.post(
            f"/v1/pact/grants/{GRANT_ID}/receipts",
            {"receipt": receipt(["flights:rebook"],
                                "2026-11-16T11:00:00Z")},
            key=self.issuer_key)
        self.assertEqual(status, 201)
        status, _, data = self.post("/v1/monitoring/run", {"now": T2},
                                    key=self.issuer_key)
        self.assertEqual(status, 200)
        result = self.body(data)
        events = [e for e in result["events"]
                  if e["subject_id"] == GRANT_ID]
        self.assertEqual([e["event_type"] for e in events],
                         ["reaudit_completed", "drift_flag"])
        flag = [e for e in events if e["event_type"] == "drift_flag"][0]
        self.assertEqual(
            flag["detail"]["comparison"]["flagged_dimensions"],
            ["scope_discipline"])
        records = [r for r in result["records"]
                   if r["subject_id"] == GRANT_ID
                   and r["event_type"] == "drift_flag"]
        self.assertEqual(len(records), 1)
        self.assertTrue(pact.verify_record(self.app.keys, records[0]))

    def test_run_rejects_bad_clock(self):
        status, _, _ = self.post("/v1/monitoring/run",
                                 {"now": "banana"}, key=self.issuer_key)
        self.assertEqual(status, 400)

    # -- comparison -----------------------------------------------------
    def test_compare_endpoint(self):
        status, _, data = self.post(
            "/v1/monitoring/compare",
            {"baseline": BASELINE, "current": REGRESSED},
            key=self.verifier_key)
        self.assertEqual(status, 200)
        comp = self.body(data)
        self.assertEqual(comp["status"], "regressed")
        self.assertEqual(set(comp["flagged_dimensions"]),
                         {"instruction_following", "tool_choice"})
        status, _, _ = self.post("/v1/monitoring/compare",
                                 {"baseline": BASELINE},
                                 key=self.verifier_key)
        self.assertEqual(status, 400)

    # -- cross-check ------------------------------------------------------
    def test_crosscheck_records_disagreement(self):
        self.enroll("subj-xcheck")
        status, _, data = self.post(
            "/v1/monitoring/crosscheck",
            {"subject_id": "subj-xcheck",
             "npc_comparison": {"status": "regressed"},
             "external_verdict": {"stance": "clear"}},
            key=self.issuer_key)
        self.assertEqual(status, 201)
        out = self.body(data)
        self.assertTrue(out["evaluation"]["disagreement"])
        self.assertEqual(
            [r["event_type"] for r in out["records"]],
            ["crosscheck_attached", "crosscheck_disagreement"])
        attached = out["records"][0]
        self.assertTrue(attached["detail"]["third_party"])
        self.assertEqual(attached["detail"]["source"],
                         "external_crosscheck")
        for rec in out["records"]:
            self.assertTrue(pact.verify_record(self.app.keys, rec))
            status, _, _ = self.get(f"/v1/records/{rec['record_id']}")
            self.assertEqual(status, 200)

        # Agreement records the attach only, no disagreement event.
        status, _, data = self.post(
            "/v1/monitoring/crosscheck",
            {"subject_id": "subj-xcheck",
             "npc_comparison": {"status": "regressed"},
             "external_verdict": {"stance": "flag"}},
            key=self.issuer_key)
        self.assertEqual(status, 201)
        out = self.body(data)
        self.assertFalse(out["evaluation"]["disagreement"])
        self.assertEqual([r["event_type"] for r in out["records"]],
                         ["crosscheck_attached"])

    def test_crosscheck_validation(self):
        self.enroll("subj-xcheck-2")
        status, _, _ = self.post(
            "/v1/monitoring/crosscheck",
            {"subject_id": "subj-never-enrolled",
             "npc_comparison": {"status": "regressed"},
             "external_verdict": {"stance": "clear"}},
            key=self.issuer_key)
        self.assertEqual(status, 404)
        status, _, _ = self.post(
            "/v1/monitoring/crosscheck",
            {"subject_id": "subj-xcheck-2",
             "npc_comparison": {"status": "regressed"},
             "external_verdict": {"stance": "banana"}},
            key=self.issuer_key)
        self.assertEqual(status, 422)
        status, _, _ = self.post(
            "/v1/monitoring/crosscheck",
            {"subject_id": "subj-xcheck-2",
             "npc_comparison": {"status": "regressed"}},
            key=self.issuer_key)
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
