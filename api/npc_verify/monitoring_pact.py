"""PACT-fed audit runner for continuous monitoring.

The first real evidence feed for npc_verify.monitoring. A monitoring
subject whose subject_id is a PACT grant id is re-audited from the
grant's own record layer: npc_verify.trace_audit_adapter projects the
grant's consent, audit entries, and chain verification into the
Verified Trace Audit model, and this runner scores only what that
feed actually proves:

- evidence_chain_integrity: the signed, hash-chained audit log
  verifies end to end (1.0) or it does not (0.0). Native evidence,
  established strength when entries exist.
- scope_discipline: the share of execution records whose used scopes
  stay inside the scopes the consent actually granted. A record that
  exercises an ungranted scope is exactly the drift monitoring exists
  to catch. With no records the score is vacuously 1.0 and the
  strength says so (inconclusive), never established.

Nothing else is scored. The other Trace Audit dimensions need the
client's other evidence layers, which a PACT feed does not carry;
they are absent from the result, and the monitoring comparison
reports them as insufficient evidence rather than inventing numbers.
Layer presence and trace count ride along as coverage context.

A subject with no consent record yields no audit (the runner returns
None and the monitoring pass skips it): monitoring never fabricates
a subject. A broken chain still yields an audit, scored 0.0, because
a broken chain is a monitoring finding, not silence.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .trace_audit_adapter import audit_feed_for_grant


def _utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit_result_from_feed(feed, subject_id, audited_at):
    """One monitoring audit result from a Trace Audit PACT feed."""
    chain = feed["chain"]
    granted = set(feed["grant"]["scopes_granted"] or [])
    records = feed["records"]
    if records:
        compliant = sum(
            1 for r in records
            if all(s in granted for s in (r.get("scopes_used") or [])))
        scope_score = compliant / len(records)
        scope_strength = "supported" if chain["valid"] else "indicative"
    else:
        scope_score = 1.0
        scope_strength = "inconclusive"
    return {
        "subject_id": subject_id,
        "audited_at": audited_at,
        "source": "pact_feed",
        "feed_status": feed["audit"]["status"],
        "trace_count": feed["audit"]["scope"]["trace_count"],
        "layer_presence": feed["layer_presence"],
        "dimensions": {
            "evidence_chain_integrity": {
                "score": 1.0 if chain["valid"] else 0.0,
                "evidence_tier": "native",
                "conclusion_strength": (
                    "established" if chain["entries"] else "inconclusive"),
            },
            "scope_discipline": {
                "score": round(scope_score, 6),
                "evidence_tier": "native",
                "conclusion_strength": scope_strength,
            },
        },
    }


def make_pact_audit_runner(store, keys, now_fn=None):
    """An audit_runner for npc_verify.monitoring.run_once.

    The subject's id is its PACT grant id. `now_fn` supplies the
    audit timestamp (ISO text); it defaults to the current UTC time
    and exists so tests and replays can pin the clock.
    """
    now_fn = now_fn or _utc_now_iso

    def runner(subject):
        grant_id = subject["subject_id"]
        feed = audit_feed_for_grant(store, keys, grant_id)
        if feed is None:
            return None
        return audit_result_from_feed(feed, grant_id, now_fn())

    return runner
