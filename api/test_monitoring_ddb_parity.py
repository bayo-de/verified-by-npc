"""Parity test: DynamoDBStore monitoring methods behave like Store's.

Run with boto3 importable (production provides it; locally:
PYTHONPATH=/tmp/boto3test python3 test_monitoring_ddb_parity.py).
Uses an in-memory fake table implementing get_item / put_item /
query over the (pk, sk, data) item shape.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from npc_verify.ddb_store import DynamoDBStore
from npc_verify import monitoring as m

failures = []


def check(label, cond):
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        failures.append(label)


class FakeTable:
    def __init__(self):
        self.items = {}

    def get_item(self, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def put_item(self, Item, ConditionExpression=None):
        if ConditionExpression is not None:
            raise AssertionError("parity test does not use conditional puts")
        self.items[(Item["pk"], Item["sk"])] = dict(Item)
        return {}

    def query(self, KeyConditionExpression, ScanIndexForward=True,
              Limit=None, ExclusiveStartKey=None):
        expr = KeyConditionExpression.get_expression()
        pk = expr["values"][1]
        rows = [dict(v) for (p, _s), v in sorted(self.items.items())
                if p == pk]
        if not ScanIndexForward:
            rows.reverse()
        if Limit is not None:
            rows = rows[:Limit]
        return {"Items": rows}


store = DynamoDBStore(table=FakeTable())
store.upsert_monitoring_subject("subj-1", None, None, "2026-11-11T00:00:00Z")
store.upsert_monitoring_subject("subj-2", 12, "2026-12-01T00:00:00Z",
                                "2026-11-11T00:00:00Z")
listed = {s["subject_id"]: s for s in store.list_monitoring_subjects()}
check("ddb subjects persist", set(listed) == {"subj-1", "subj-2"})
check("ddb cadence round-trips", listed["subj-2"]["cadence_hours"] == 12)
check("ddb no baseline initially", listed["subj-1"]["last_audit"] is None)

GOOD = {"audited_at": "2026-11-11T12:00:00Z", "dimensions": {
    "instruction_following": {"score": 0.9, "evidence_tier": "native",
                              "conclusion_strength": "established"}}}
result = m.run_once(store, "2026-11-11T12:00:00Z",
                    lambda s: GOOD if s["subject_id"] == "subj-1" else None)
check("ddb run_once audits the due subject",
      [e["subject_id"] for e in result["events"]] == ["subj-1"])
after = {s["subject_id"]: s for s in store.list_monitoring_subjects()}
check("ddb baseline recorded",
      after["subj-1"]["last_audit"]["dimensions"]
      ["instruction_following"]["score"] == 0.9)

# Upsert after an audit must not wipe the baseline (SQLite parity).
store.upsert_monitoring_subject("subj-1", 48, None, "2026-11-11T00:00:00Z")
after2 = {s["subject_id"]: s for s in store.list_monitoring_subjects()}
check("ddb upsert preserves baseline",
      after2["subj-1"]["last_audit"] is not None
      and after2["subj-1"]["cadence_hours"] == 48)

# record_monitoring_audit on an unknown subject is a silent no-op.
store.record_monitoring_audit("ghost", "2026-11-11T12:00:00Z", GOOD)
check("ddb unknown subject audit is a no-op",
      "ghost" not in {s["subject_id"] for s in store.list_monitoring_subjects()})

print("\n%d failure(s)" % len(failures))
sys.exit(1 if failures else 0)
