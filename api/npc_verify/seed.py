"""Test fixtures for local development. INTERNAL — never production data.

Every fixture is fictional and prefixed test_/tag_test_/cred_test_/
agent_test_ so it can never be mistaken for a real attestation, credential,
product, or agent. No PII: holder names are fictional and marked public only
inside the fixture world.
"""
import base64
import json
import secrets

from . import ed25519
from .canonical import claim_hash_for_text, canonicalize
from .models import (Attestation, Credential, Product, AgentAttestation,
                     utcnow_iso)

ANCHOR_CHAIN = "base"  # target chain; Phase 1 performs NO chain writes.


def _att_id():
    return "att_test_" + secrets.token_hex(8)


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
    att.anchor_status = "not_anchored"  # Phase 1: hash recorded, no chain write
    return att


def seed_all(store, keys):
    """Seed fixtures. Returns dict with the plaintext API keys (show once)."""
    from .auth import Auth
    auth = Auth(store)
    verifier_key = auth.create_key("test-verifier", "verifier")
    issuer_key = auth.create_key("test-issuer", "issuer")

    # -- attestations behind claims --------------------------------------
    claims = [
        ("The test widget passes drop testing", "verified",
         "Mechanical drop test, 1.2m, 50 cycles."),
        ("Test Farms honey is single-origin", "verified_with_caveats",
         "Origin verified for 2026 harvest lots; earlier lots untested."),
    ]
    claim_att_ids = {}
    for text, verdict, summary in claims:
        att = Attestation(
            id=_att_id(), subject_type="claim",
            subject_id="claim:" + claim_hash_for_text(text)[:16],
            verdict=verdict,
            scope={"domain": "test-fixture", "method": "lab-review"},
            tested_at="2026-09-15T12:00:00+00:00", expires_at=None,
            findings_summary=summary,
            claim_hash=claim_hash_for_text(text))
        att = _sign_attestation(keys, att)
        store.add_attestation(att)
        claim_att_ids[text] = att.id

    # -- credentials ------------------------------------------------------
    creds = [
        Credential(id="cred_test_001", status="valid",
                   title="Test Artisan Certificate", issuer="NPC Labs",
                   holder_name="Test Holder", holder_public=True,
                   issued_at="2026-01-10T00:00:00+00:00",
                   expires_at="2028-01-10T00:00:00+00:00",
                   assessed_skills=["test-craft"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_001"),
        Credential(id="cred_test_002", status="revoked",
                   title="Test Artisan Certificate", issuer="NPC Labs",
                   holder_name="Test Holder", holder_public=True,
                   issued_at="2025-03-01T00:00:00+00:00", expires_at=None,
                   assessed_skills=["test-craft"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_002"),
        Credential(id="cred_test_003", status="expired",
                   title="Test Artisan Certificate", issuer="NPC Labs",
                   holder_name=None, holder_public=False,
                   issued_at="2023-01-01T00:00:00+00:00",
                   expires_at="2024-01-01T00:00:00+00:00",
                   assessed_skills=["test-craft"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_003"),
    ]
    for c in creds:
        key_id, sig = keys.sign(
            "issuer", canonicalize({"id": c.id, "status": c.status}))
        c.signature_b64 = base64.b64encode(sig).decode()
        c.key_id = key_id
        store.insert_credential(c)

    # -- products ----------------------------------------------------------
    products = [
        Product(tag_id="tag_test_authentic", status="authentic",
                name="Test Widget", creator="Test Maker",
                description="A fictional test product.",
                provenance=[
                    {"event": "manufactured", "at": "2026-08-01T00:00:00+00:00",
                     "detail": "Test Maker facility, lot T-1"},
                    {"event": "tagged", "at": "2026-08-02T00:00:00+00:00",
                     "detail": "NFC tag bound to product record"},
                ]),
        Product(tag_id="tag_test_counterfeit", status="counterfeit",
                name="Test Widget", creator="Test Maker",
                description="A fictional test product.",
                provenance=[
                    {"event": "flagged", "at": "2026-09-01T00:00:00+00:00",
                     "detail": "Tag cloned; packaging mismatch"},
                ]),
    ]
    for p in products:
        store.insert_product(p)

    # -- agents -------------------------------------------------------------
    agent_att = Attestation(
        id=_att_id(), subject_type="agent", subject_id="agent_test_scout",
        verdict="verified",
        scope={"capabilities": ["test-navigation"], "limits": ["no-payments"]},
        tested_at="2026-09-20T12:00:00+00:00",
        expires_at="2027-09-20T12:00:00+00:00",
        findings_summary="Behavioral eval passed on the test harness.")
    agent_att = _sign_attestation(keys, agent_att)
    store.add_attestation(agent_att)
    store.insert_agent(
        "agent_test_scout", "verified",
        {"capabilities": ["test-navigation"], "limits": ["no-payments"]},
        "2026-09-20T12:00:00+00:00", "2027-09-20T12:00:00+00:00",
        agent_att.id,
        "Test harness evaluation; no production access.")
    agent_att2 = Attestation(
        id=_att_id(), subject_type="agent", subject_id="agent_test_herald",
        verdict="verified_with_caveats",
        scope={"capabilities": ["test-messaging"]},
        tested_at="2026-09-21T12:00:00+00:00", expires_at=None,
        findings_summary="Passed with caveats: rate limits untested.")
    agent_att2 = _sign_attestation(keys, agent_att2)
    store.add_attestation(agent_att2)
    store.insert_agent(
        "agent_test_herald", "verified_with_caveats",
        {"capabilities": ["test-messaging"]},
        "2026-09-21T12:00:00+00:00", None, agent_att2.id,
        "Caveats documented in findings summary.")

    return {"verifier_key": verifier_key, "issuer_key": issuer_key,
            "claim_attestations": claim_att_ids}
