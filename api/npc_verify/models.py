"""Data models and validation for the Verification API v1.

Attestation record shape follows DESIGN v1 §3:
  attestations {id, subject_type, subject_id, verdict, scope, tested_at,
  expires_at, findings_summary (sanitized), signature, onchain_anchor
  {chain, tx, hash}, revoked}

Revocation is a new signed record, never an edit.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

SUBJECT_TYPES = ("claim", "credential", "product", "agent")
VERDICTS = ("verified", "verified_with_caveats", "not_verified", "unknown")
CREDENTIAL_STATUSES = ("valid", "revoked", "expired")
PRODUCT_STATUSES = ("authentic", "counterfeit", "unknown")
AGENT_VERDICTS = ("verified", "verified_with_caveats", "not_verified",
                  "unknown")
ANCHOR_STATUSES = ("not_anchored", "pending", "anchored")
ROLES = ("verifier", "issuer", "admin")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_iso8601(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


@dataclass
class Attestation:
    id: str
    subject_type: str
    subject_id: str
    verdict: str
    scope: dict
    tested_at: str
    expires_at: Optional[str]
    findings_summary: str  # sanitized; methodology never exposed
    claim_hash: Optional[str] = None
    signature_b64: str = ""
    key_id: str = ""
    anchor_chain: str = "base"
    anchor_tx: Optional[str] = None
    anchor_hash: str = ""
    anchor_status: str = "not_anchored"
    revoked: bool = False
    created_at: str = field(default_factory=utcnow_iso)

    def validate(self) -> list:
        problems = []
        if self.subject_type not in SUBJECT_TYPES:
            problems.append(f"subject_type must be one of {SUBJECT_TYPES}")
        if not self.subject_id or len(self.subject_id) > 256:
            problems.append("subject_id is required (max 256 chars)")
        if self.verdict not in VERDICTS:
            problems.append(f"verdict must be one of {VERDICTS}")
        if not isinstance(self.scope, dict):
            problems.append("scope must be an object")
        if not is_iso8601(self.tested_at):
            problems.append("tested_at must be ISO-8601")
        if self.expires_at is not None and not is_iso8601(self.expires_at):
            problems.append("expires_at must be ISO-8601 or null")
        if not self.findings_summary or len(self.findings_summary) > 4000:
            problems.append("findings_summary is required (max 4000 chars)")
        if self.anchor_status not in ANCHOR_STATUSES:
            problems.append(f"anchor_status must be one of {ANCHOR_STATUSES}")
        return problems

    def public_dict(self) -> dict:
        """Response-safe dict (findings already sanitized at issuance)."""
        return {
            "id": self.id,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "verdict": self.verdict,
            "scope": self.scope,
            "tested_at": self.tested_at,
            "expires_at": self.expires_at,
            "findings_summary": self.findings_summary,
            "signature": self.signature_b64,
            "key_id": self.key_id,
            "onchain_anchor": {
                "chain": self.anchor_chain,
                "tx": self.anchor_tx,
                "hash": self.anchor_hash,
                "status": self.anchor_status,
            },
            "revoked": self.revoked,
            "created_at": self.created_at,
        }


@dataclass
class Credential:
    id: str
    status: str
    title: str
    issuer: str
    holder_name: Optional[str]  # only if the holder made it public
    holder_public: bool
    issued_at: str
    expires_at: Optional[str]
    assessed_skills: list
    signature_b64: str = ""
    key_id: str = ""
    verification_url: str = ""

    def public_dict(self) -> dict:
        holder = self.holder_name if self.holder_public else None
        return {
            "id": self.id,
            "status": self.status,
            "title": self.title,
            "issuer": self.issuer,
            "holder_name": holder,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "assessed_skills": self.assessed_skills,
            "signature": self.signature_b64,
            "key_id": self.key_id,
            "verification_url": self.verification_url,
        }


@dataclass
class Product:
    tag_id: str
    status: str
    name: str
    creator: str
    description: str  # public metadata only
    provenance: list  # [{event, at, detail}] — public chain of custody
    attestation_id: Optional[str] = None

    def public_dict(self) -> dict:
        return {
            "tag_id": self.tag_id,
            "status": self.status,
            "verdict": ("verified" if self.status == "authentic"
                        else "not_verified" if self.status == "counterfeit"
                        else "unknown"),
            "name": self.name,
            "creator": self.creator,
            "description": self.description,
            "provenance": self.provenance,
            "attestation_id": self.attestation_id,
        }


@dataclass
class AgentAttestation:
    agent_id: str
    verdict: str
    scope: dict
    valid_from: str
    valid_until: Optional[str]
    attestation_id: str
    anchor: dict
    notes: str = ""  # sanitized

    def public_dict(self) -> dict:
        return asdict(self)
