"""Adapter: PACT grant audit log -> Verified Trace Audit data model.

The Verified Trace Audit (trust-tab/verified-trace-audit/SPEC.md) audits
a client's agent execution traces against a five-layer capture
standard. Layer 3 is "native execution records: structured session
histories (resume/compaction/audit grade)". A PACT grant's audit log
(npc_verify.pact) is exactly that for delegated grants: an ordered,
signed, hash-chained record of every tool call a personal agent made
under the grant, with the scopes it used. Per the PACT evaluation
(flywheel #73), the log "drops straight into the Verified Trace Audit
as native layer-3 execution records."

This module is the code-level feed: it projects one grant's consent,
audit entries, and revocation state into the SPEC's model shapes
(TraceAudit scope block + per-trace records) so the audit pipeline has
a real internal consumer for the record layer from day one. It does
not score anything and it signs nothing: scoring and the signed audit
claim belong to the audit itself, per the SPEC's flow. The portal
component remains SPEC-only; this adapter is the interface it will
read when it is built.

Honesty rules carried over from the SPEC: raw receipt claims stay
client data (the adapter passes them through untouched, never copies
them into new prose), and nothing here invents completeness: a grant
with no receipts yields an empty record list and a chain that verifies
vacuously, stated as such in the feed's chain block.
"""
from . import pact

# The SPEC's five layers; the grant audit log is a layer-3 source.
LAYER_NATIVE_EXECUTION_RECORDS = 3


def _execution_record(entry: dict) -> dict:
    """One audit entry as a layer-3 native execution record.

    Mirrors the section 5.6 receipt claims (tool + argsHash per action)
    and carries the chain coordinates (seq, entry_hash,
    prev_entry_hash) so the audit can cite the exact signed entry a
    finding came from.
    """
    claims = entry["receipt_claims"]
    actions = claims.get("actions") or [{}]
    first = actions[0] if actions else {}
    return {
        "layer": LAYER_NATIVE_EXECUTION_RECORDS,
        "source": "npc.pact.audit_entry",
        "seq": entry["seq"],
        "entry_hash": entry["entry_hash"],
        "prev_entry_hash": entry["prev_entry_hash"],
        "grant_id": entry["grant_id"],
        "tool": first.get("tool"),
        "args_hash": first.get("argsHash"),
        "actions": actions,
        "scopes_used": claims.get("scopesUsed", []),
        "ts": entry["ts"],
    }


def audit_feed_for_grant(store, keys, grant_id: str):
    """Assemble the Trace Audit feed for one grant.

    Returns None when no consent record exists for the grant (the
    audit never fabricates a subject). Otherwise a dict shaped after
    the SPEC's models:

      audit:  the TraceAudit scope block (id, client, submitted_at,
              scope {trace_count, window, agents}, status, claim_id).
              claim_id is None: no audit claim exists until an audit
              actually runs and signs one.
      layer_presence: {3: "present"|"absent"} for this source only;
              the other layers are the client's other evidence and are
              not asserted here.
      records: the layer-3 execution records, in chain order.
      chain:  the live chain verification result {valid, detail,
              entries} — the audit consumes the trail only as far as
              the chain verifies.
      grant:  consent + status context (grant_id, consent_record_id,
              status at feed time, scopes granted vs requested).
    """
    consent = store.get_pact_consent(grant_id)
    if consent is None:
        return None
    entries = store.pact_audit_entries(grant_id)
    ok, detail = pact.verify_audit_chain(keys, entries)
    records = [_execution_record(e) for e in entries]
    status = pact.grant_status_record(store, keys, grant_id)
    window = None
    if entries:
        window = {"from": entries[0]["ts"], "to": entries[-1]["ts"]}
    return {
        "audit": {
            "id": f"vta_pact_{grant_id}",
            "client": consent["brand_id"],
            "submitted_at": consent["granted_at"],
            "scope": {
                "trace_count": len(records),
                "window": window,
                "agents": [consent["pa_iss"]],
            },
            "status": "complete" if ok else "failed-closed",
            "claim_id": None,
        },
        "layer_presence": {
            str(LAYER_NATIVE_EXECUTION_RECORDS):
                "present" if entries else "absent",
        },
        "records": records,
        "chain": {"valid": ok, "detail": detail, "entries": len(entries)},
        "grant": {
            "grant_id": grant_id,
            "consent_record_id": consent["record_id"],
            "status": status["status"] if status else None,
            "scopes_requested": consent["scopes_requested"],
            "scopes_granted": consent["scopes_granted"],
        },
    }
