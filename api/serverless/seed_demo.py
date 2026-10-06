"""Demo fixtures for the public demo API (api.npclabs.xyz).

DEMO DATA ONLY. Every fixture is fictional and clearly labeled demo, so it
can never be mistaken for a real attestation, credential, product, or agent.
No PII. These fixtures exist so plugin reviewers can exercise the five
read-only operations without any account: demo-tag-001, demo-cred-001,
demo-agent-001, and the demo claim.
"""
import base64

from npc_verify.canonical import claim_hash_for_text, canonicalize
from npc_verify.models import (Attestation, Credential, Product,
                               utcnow_iso)

ANCHOR_CHAIN = "base"  # target chain; demo records are never chain-anchored.

DEMO_CLAIM_TEXT = "the product shipped on demo date"


def _sign_attestation(keys, att: Attestation) -> Attestation:
    core = {
        "id": att.id,
        "subject_type": att.subject_type,
        "subject_id": att.subject_id,
        "verdict": att.verdict,
        "scope": att.scope,
        "tested_at": att.tested_at,
        "findings_summary": att.findings_summary,
    }
    key_id, sig = keys.sign("issuer", canonicalize(core))
    att.signature_b64 = base64.b64encode(sig).decode()
    att.key_id = key_id
    import hashlib
    att.anchor_hash = hashlib.sha256(canonicalize(core)).hexdigest()
    att.anchor_status = "not_anchored"
    return att


def seed_demo(store, keys):
    """Seed the demo fixtures. Idempotent-safe on a fresh database."""
    # -- demo claim ------------------------------------------------------
    att = Attestation(
        id="att_demo_claim_001", subject_type="claim",
        subject_id="claim:" + claim_hash_for_text(DEMO_CLAIM_TEXT)[:16],
        verdict="verified",
        scope={"domain": "demo", "method": "demo-review"},
        tested_at="2026-10-06T12:00:00+00:00", expires_at=None,
        findings_summary="Demo attestation for plugin review.",
        claim_hash=claim_hash_for_text(DEMO_CLAIM_TEXT))
    att = _sign_attestation(keys, att)
    store.add_attestation(att)

    # -- demo credential ---------------------------------------------------
    cred = Credential(
        id="demo-cred-001", status="valid",
        title="Demo Verification Certificate", issuer="NPC Labs",
        holder_name="Demo Holder", holder_public=True,
        issued_at="2026-01-15T00:00:00+00:00",
        expires_at="2028-01-15T00:00:00+00:00",
        assessed_skills=["demo-verification"],
        verification_url="https://npclabs.xyz/credentials?id=demo-cred-001")
    key_id, sig = keys.sign(
        "issuer", canonicalize({"id": cred.id, "status": cred.status}))
    cred.signature_b64 = base64.b64encode(sig).decode()
    cred.key_id = key_id
    store.insert_credential(cred)

    # -- demo product ------------------------------------------------------
    product = Product(
        tag_id="demo-tag-001", status="authentic",
        name="NPC Demo Print", creator="NPC Labs",
        description="A demonstration product for the Verified by NPC "
                    "plugin review.",
        provenance=[
            {"event": "manufactured", "at": "2026-09-01T00:00:00+00:00",
             "detail": "NPC Labs demo line, lot D-1"},
            {"event": "tagged", "at": "2026-09-02T00:00:00+00:00",
             "detail": "Demo smart tag bound to product record"},
            {"event": "verified", "at": "2026-10-06T00:00:00+00:00",
             "detail": "Demo verification for plugin review"},
        ])
    store.insert_product(product)

    # -- demo agent ----------------------------------------------------------
    agent_att = Attestation(
        id="att_demo_agent_001", subject_type="agent",
        subject_id="demo-agent-001", verdict="verified",
        scope={"capabilities": ["demo-verification"],
               "limits": ["demo-only"]},
        tested_at="2026-10-01T12:00:00+00:00",
        expires_at="2027-10-01T12:00:00+00:00",
        findings_summary="Demo evaluation for plugin review.")
    agent_att = _sign_attestation(keys, agent_att)
    store.add_attestation(agent_att)
    store.insert_agent(
        "demo-agent-001", "verified",
        {"capabilities": ["demo-verification"], "limits": ["demo-only"]},
        "2026-10-01T00:00:00+00:00", "2027-10-01T00:00:00+00:00",
        agent_att.id,
        "Demonstration agent for plugin review.")
