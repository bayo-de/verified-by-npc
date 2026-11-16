"""Smoke test for the continuous monitoring scaffold (2026-11-11).

Run: python3 test_monitoring_scaffold.py
Exercises due computation, the ratchet comparison, event payloads,
and the cross-check disagreement rule with fixed timestamps.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from npc_verify import monitoring as m

NOW = "2026-11-11T12:00:00Z"
failures = []


def check(label, cond):
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        failures.append(label)


# --- due computation ---
subjects = [
    {"subject_id": "a", "last_audit_at": None, "expires_at": None},
    {"subject_id": "b", "last_audit_at": "2026-11-11T11:00:00Z", "expires_at": None},
    {"subject_id": "c", "last_audit_at": "2026-11-09T11:00:00Z", "expires_at": None},
    {"subject_id": "d", "last_audit_at": "2026-11-11T11:00:00Z",
     "expires_at": "2026-11-13T00:00:00Z"},
    {"subject_id": "e", "last_audit_at": "2026-11-11T11:30:00Z",
     "expires_at": "2026-12-30T00:00:00Z"},
]
due = {s["subject_id"]: s["due_reason"] for s in m.due_subjects(subjects, NOW)}
check("never audited is due", due.get("a") == "never_audited")
check("audited 1h ago not due", "b" not in due)
check("cadence 24h exceeded is due", due.get("c") == "cadence_due")
check("expiry within 72h is due", due.get("d") == "expiry_due")
check("fresh audit, far expiry not due", "e" not in due)

# --- ratchet comparison ---
baseline = {"dimensions": {
    "instruction_following": {"score": 0.90, "evidence_tier": "native",
                              "conclusion_strength": "established"},
    "tool_choice": {"score": 0.80, "evidence_tier": "native",
                    "conclusion_strength": "supported"},
}}
stable = {"dimensions": {
    "instruction_following": {"score": 0.91, "evidence_tier": "native",
                              "conclusion_strength": "established"},
    "tool_choice": {"score": 0.79, "evidence_tier": "native",
                    "conclusion_strength": "supported"},
}}
regressed = {"dimensions": {
    "instruction_following": {"score": 0.70, "evidence_tier": "native",
                              "conclusion_strength": "established"},
    "tool_choice": {"score": 0.80, "evidence_tier": "native",
                    "conclusion_strength": "indicative"},
}}
check("small movements are stable",
      m.compare_audits(baseline, stable)["status"] == "stable")
comp = m.compare_audits(baseline, regressed)
check("score drop regresses", comp["status"] == "regressed")
check("both regressions flagged",
      set(comp["flagged_dimensions"]) == {"instruction_following", "tool_choice"})
check("strength weakening recorded",
      comp["strength_changes"].get("tool_choice", {}).get("to") == "indicative")
partial = {"dimensions": {"instruction_following": stable["dimensions"]["instruction_following"]}}
check("one-sided dimension reported, not dropped",
      m.compare_audits(baseline, partial)["insufficient_evidence_dimensions"] == ["tool_choice"])

# --- event payload ---
payload = m.monitoring_event_payload("reg_x", "drift_flag", comp, NOW)
check("payload shape", payload["kind"] == "monitoring_event"
      and payload["subject_id"] == "reg_x"
      and payload["event_type"] == "drift_flag"
      and payload["at"] == "2026-11-11T12:00:00Z")

# --- cross-check disagreement ---
check("flag vs clear disagrees",
      m.crosscheck_disagreement(comp, {"stance": "clear"})["disagreement"] is True)
check("flag vs flag agrees",
      m.crosscheck_disagreement(comp, {"stance": "flag"})["disagreement"] is False)
check("unusable external verdict handled",
      m.crosscheck_disagreement(comp, {"stance": "banana"})["disagreement"] is False)

# --- store persistence + run_once scheduler pass ---
import tempfile

from npc_verify.store import Store

GOOD = {"audited_at": "2026-11-11T12:00:00Z", "dimensions": {
    "instruction_following": {"score": 0.9, "evidence_tier": "native",
                              "conclusion_strength": "established"}}}
WORSE = {"audited_at": "2026-11-12T12:00:00Z", "dimensions": {
    "instruction_following": {"score": 0.6, "evidence_tier": "native",
                              "conclusion_strength": "established"}}}

with tempfile.TemporaryDirectory() as tmp:
    store = Store(str(Path(tmp) / "monitor.db"))
    store.upsert_monitoring_subject("subj-1", None, None, "2026-11-11T00:00:00Z")
    store.upsert_monitoring_subject("subj-2", None, None, "2026-11-11T00:00:00Z")
    listed = {s["subject_id"]: s for s in store.list_monitoring_subjects()}
    check("subjects persist", set(listed) == {"subj-1", "subj-2"})
    check("no baseline before first audit", listed["subj-1"]["last_audit"] is None)

    def runner_first(subject):
        return GOOD if subject["subject_id"] == "subj-1" else None

    result = m.run_once(store, NOW, runner_first)
    check("both subjects due on first pass",
          set(result["due_subject_ids"]) == {"subj-1", "subj-2"})
    check("no-evidence subject skipped", result["skipped_no_evidence"] == ["subj-2"])
    check("first audit emits one completion event",
          len(result["events"]) == 1
          and result["events"][0]["event_type"] == "reaudit_completed"
          and result["events"][0]["detail"]["first_audit"] is True)
    after = {s["subject_id"]: s for s in store.list_monitoring_subjects()}
    check("baseline recorded", after["subj-1"]["last_audit"]["dimensions"]
          ["instruction_following"]["score"] == 0.9)
    check("audited subject no longer due",
          m.due_subjects(store.list_monitoring_subjects(), NOW) == [
              s for s in m.due_subjects(store.list_monitoring_subjects(), NOW)
              if s["subject_id"] == "subj-2"])

    def runner_worse(subject):
        return WORSE

    result2 = m.run_once(store, "2026-11-12T12:00:00Z", runner_worse)
    types = [e["event_type"] for e in result2["events"]
             if e["subject_id"] == "subj-1"]
    check("regression pass emits completion + drift flag",
          types == ["reaudit_completed", "drift_flag"])
    store.close()

print("\n%d failure(s)" % len(failures))
sys.exit(1 if failures else 0)
