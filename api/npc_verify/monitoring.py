"""Continuous monitoring core for NPC Verify.

Ordered by Bayo, 2026-11-11; launch target 2026-11-23/24 with the
desktop app. Build plan:
goals/npc-labs/files/continuous-monitoring-and-extension-build-plan-2026-11-11.md

Continuous monitoring is the Verified Trace Audit (trust-tab/
verified-trace-audit/SPEC.md) run on a cadence instead of once. This
module is the engine room, deliberately narrow:

- It tracks monitoring subjects (certified records under monitoring),
  their schedules, and which of them are due for a re-audit, whether by
  cadence, by approaching expiry, or because they have never been
  audited.
- It compares a fresh audit result with the last signed one under the
  SPEC's ratchet rule and two-axis findings discipline (evidence tier
  and conclusion strength are never merged into one number).
- It shapes monitoring events as registry record payloads.

It does NOT score traces (scoring belongs to the audit, fed by
npc_verify.trace_audit_adapter and the Trust tab submission path), and
it signs nothing: payloads produced here are signed through the
registry's normal record path, with NPC's server-side keys, exactly
like every other record. It never touches a client's running agent.

Status: BUILDING (2026-11-11; server wiring added 2026-11-15, local
only, not deployed). Due/comparison logic, store persistence (SQLite
and DynamoDB parity, both smoked), and a run-once scheduler pass are
in; the HTTP surface lives in server.py (/v1/monitoring/*), which
publishes this module's events as signed registry records through
npc_verify.registry.mint_monitoring_event. The standing scheduler
loop lands next per the build plan.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

# Default re-audit cadence for a monitored subject, in hours, when the
# subject carries no cadence of its own. Fleet dogfood default; tier
# policy can override per subject.
DEFAULT_CADENCE_HOURS = 24

# A subject whose record expires within this window is due for
# re-verification ahead of the lapse, so an expiry never arrives
# unexamined.
EXPIRY_WARNING_HOURS = 72

# A scored dimension whose score drops by more than this between the
# baseline audit and the current one is a regression flag. Any drop in
# conclusion strength is a flag regardless of score movement.
REGRESSION_SCORE_TOLERANCE = 0.05

# Conclusion strength ordering for the two-axis comparison, weakest to
# strongest. Mirrors the SPEC's vocabulary; unknown values compare as
# the weakest rather than crashing the comparison.
_STRENGTH_ORDER = {"inconclusive": 0, "indicative": 1, "supported": 2, "established": 3}


def _parse_ts(value):
    """ISO-8601 text -> aware datetime. None passes through."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def due_reason(subject, now):
    """Why a subject is due for re-audit at `now`, or None if not due.

    A subject is a dict:
        subject_id:     registry record id of the certified agent
        last_audit_at:  ISO time of the last signed audit, or None
        expires_at:     ISO expiry of the underlying record, or None
        cadence_hours:  optional per-subject cadence override

    Reasons, in priority order: "never_audited", "expiry_due",
    "cadence_due". Priority is reporting order only; any reason makes
    the subject due exactly once.
    """
    now = _parse_ts(now)
    last = _parse_ts(subject.get("last_audit_at"))
    if last is None:
        return "never_audited"
    expires = _parse_ts(subject.get("expires_at"))
    if expires is not None and expires - now <= timedelta(hours=EXPIRY_WARNING_HOURS):
        return "expiry_due"
    cadence = subject.get("cadence_hours") or DEFAULT_CADENCE_HOURS
    if now - last >= timedelta(hours=cadence):
        return "cadence_due"
    return None


def due_subjects(subjects, now):
    """The due subset of `subjects` at `now`, each annotated with its
    reason under a "due_reason" key. Input dicts are not mutated."""
    now = _parse_ts(now)
    due = []
    for subject in subjects:
        reason = due_reason(subject, now)
        if reason is not None:
            entry = dict(subject)
            entry["due_reason"] = reason
            due.append(entry)
    return due


def _strength(value):
    return _STRENGTH_ORDER.get(str(value or "").strip().lower(), 0)


def compare_audits(baseline, current):
    """Compare two audit results under the ratchet rule.

    An audit result is a dict:
        subject_id, audited_at,
        dimensions: {name: {"score": float 0..1,
                            "evidence_tier": str,
                            "conclusion_strength": str}}

    Returns a comparison dict:
        status: "regressed" if any dimension regressed, else
                "improved" if any improved and none regressed, else
                "stable". A dimension present on only one side makes
                the comparison "insufficient_evidence" for that
                dimension and it is reported, never silently dropped.
        dimension_deltas: per-dimension score delta (current-baseline)
        flagged_dimensions: regressions needing a human review item
        strength_changes: dimensions whose conclusion strength moved

    The comparison never edits either audit; a regression is reported
    so the caller can append a new signed record that says what moved.
    """
    base_dims = (baseline or {}).get("dimensions") or {}
    cur_dims = (current or {}).get("dimensions") or {}
    deltas = {}
    flagged = []
    strength_changes = {}
    insufficient = []
    improved_any = False

    for name in sorted(set(base_dims) | set(cur_dims)):
        if name not in base_dims or name not in cur_dims:
            insufficient.append(name)
            continue
        base = base_dims[name]
        cur = cur_dims[name]
        delta = float(cur.get("score", 0.0)) - float(base.get("score", 0.0))
        deltas[name] = round(delta, 6)
        strength_delta = _strength(cur.get("conclusion_strength")) - _strength(
            base.get("conclusion_strength")
        )
        if strength_delta != 0:
            strength_changes[name] = {
                "from": base.get("conclusion_strength"),
                "to": cur.get("conclusion_strength"),
            }
        if delta < -REGRESSION_SCORE_TOLERANCE or strength_delta < 0:
            flagged.append(name)
        elif delta > REGRESSION_SCORE_TOLERANCE or strength_delta > 0:
            improved_any = True

    if flagged:
        status = "regressed"
    elif improved_any:
        status = "improved"
    else:
        status = "stable"

    return {
        "status": status,
        "dimension_deltas": deltas,
        "flagged_dimensions": flagged,
        "strength_changes": strength_changes,
        "insufficient_evidence_dimensions": insufficient,
    }


def monitoring_event_payload(subject_id, event_type, detail, at):
    """One monitoring event shaped as a registry record payload.

    event_type is one of: "reaudit_completed", "drift_flag",
    "expiry_due", "crosscheck_attached", "crosscheck_disagreement".
    The payload is unsigned here by design; the registry record path
    signs it. `detail` carries the comparison or cross-check summary
    the event reports, verbatim, never embellished.
    """
    return {
        "kind": "monitoring_event",
        "subject_id": subject_id,
        "event_type": event_type,
        "detail": detail,
        "at": _iso(_parse_ts(at)),
    }


def run_once(store, now, audit_runner):
    """One scheduler pass over every monitored subject.

    `store` is npc_verify.store.Store (list_monitoring_subjects /
    record_monitoring_audit). `audit_runner(subject)` performs the
    actual re-audit for one due subject (scoring lives there and in
    the audit pipeline, not here) and returns the fresh audit result
    dict, or None when there is no new evidence to audit yet, in
    which case the subject is skipped and its baseline is untouched.

    For each audited subject the fresh result becomes the stored
    baseline, and the pass returns the monitoring events the caller
    publishes through the registry's signed record path: a
    "reaudit_completed" event per audit, plus a "drift_flag" event
    when the comparison regressed. Nothing is signed here.
    """
    now = _parse_ts(now)
    events = []
    skipped = []
    due = due_subjects(store.list_monitoring_subjects(), now)
    for subject in due:
        current = audit_runner(subject)
        if current is None:
            skipped.append(subject["subject_id"])
            continue
        baseline = subject.get("last_audit")
        if baseline is not None:
            comparison = compare_audits(baseline, current)
            detail = {"comparison": comparison, "due_reason": subject["due_reason"]}
        else:
            comparison = None
            detail = {"first_audit": True, "due_reason": subject["due_reason"]}
        store.record_monitoring_audit(
            subject["subject_id"], current.get("audited_at") or _iso(now), current)
        events.append(monitoring_event_payload(
            subject["subject_id"], "reaudit_completed", detail, now))
        if comparison is not None and comparison["status"] == "regressed":
            events.append(monitoring_event_payload(
                subject["subject_id"], "drift_flag",
                {"comparison": comparison}, now))
    return {
        "due_subject_ids": [s["subject_id"] for s in due],
        "events": events,
        "skipped_no_evidence": skipped,
    }


def crosscheck_disagreement(npc_comparison, external_verdict):
    """Whether an external cross-check materially disagrees with us.

    `external_verdict` is the third party's (Humanos) read on the same
    period, shaped {"stance": "clear" | "concern" | "flag"}. NPC's own
    comparison status maps: regressed -> flag, stable/improved ->
    clear. A disagreement is material when one side flags and the
    other clears. The result feeds a human review queue item; neither
    score overwrites the other, per the cross-check protocol.
    """
    npc_stance = "flag" if (npc_comparison or {}).get("status") == "regressed" else "clear"
    ext_stance = str((external_verdict or {}).get("stance") or "").strip().lower()
    if ext_stance not in ("clear", "concern", "flag"):
        return {"disagreement": False, "reason": "external_verdict_unusable"}
    if (npc_stance == "flag") != (ext_stance == "flag"):
        return {
            "disagreement": True,
            "npc_stance": npc_stance,
            "external_stance": ext_stance,
            "reason": "one side flags, the other clears",
        }
    return {"disagreement": False, "npc_stance": npc_stance, "external_stance": ext_stance}
