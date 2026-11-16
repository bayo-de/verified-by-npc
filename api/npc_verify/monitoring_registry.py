"""Registry-lane audit runner for continuous monitoring.

The second evidence lane, beside the PACT feed
(npc_verify.monitoring_pact). Some monitored subjects are watched
for attestation freshness rather than execution traces: has the
subject's newest signed attestation been revoked, and is it still
inside its validity window? This runner answers exactly those two
questions from the registry's own records:

- status_continuity: the newest attestation for the subject stands
  (1.0) or has been revoked (0.0). A revocation is a new signed
  record, never an edit, and monitoring treats it as the finding
  it is.
- validity_window: the newest attestation is unexpired at audit
  time (1.0) or expired (0.0). An attestation with no expiry set
  scores 1.0 at the weaker "indicative" strength: no window was
  ever established, and the score does not pretend otherwise.

The verdict itself rides along as context, never as a scored
dimension: monitoring watches standing and freshness; the verdict
was the attestation's own signed statement when it was issued.

A subject with no attestations yields no audit (None): the pass
skips it rather than fabricating a standing. Subject convention:
subject_id is the attestation subject id; the subject may carry
"attestation_subject_type" (default "agent").
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import monitoring


def _utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit_result_from_attestations(rows, subject, audited_at):
    """One monitoring audit result from a subject's attestation
    history (oldest first, as both stores return it)."""
    if not rows:
        return None
    latest = rows[-1]
    revoked = bool(latest["revoked"])
    expires_at = latest["expires_at"]
    if expires_at:
        unexpired = monitoring._parse_ts(expires_at) > monitoring._parse_ts(audited_at)
        window = {"score": 1.0 if unexpired else 0.0,
                  "evidence_tier": "registry",
                  "conclusion_strength": "established"}
    else:
        window = {"score": 1.0,
                  "evidence_tier": "registry",
                  "conclusion_strength": "indicative"}
    return {
        "subject_id": subject["subject_id"],
        "audited_at": audited_at,
        "source": "registry_attestations",
        "attestation_id": latest["id"],
        "verdict": latest["verdict"],
        "dimensions": {
            "status_continuity": {
                "score": 0.0 if revoked else 1.0,
                "evidence_tier": "registry",
                "conclusion_strength": "established",
            },
            "validity_window": window,
        },
    }


def make_registry_audit_runner(store, now_fn=None):
    """An audit_runner for npc_verify.monitoring.run_once, reading
    the subject's attestation history from either store."""
    now_fn = now_fn or _utc_now_iso

    def runner(subject):
        subject_type = subject.get("attestation_subject_type") or "agent"
        rows = store.attestations_for_subject(subject_type,
                                              subject["subject_id"])
        return audit_result_from_attestations(rows, subject, now_fn())

    return runner
