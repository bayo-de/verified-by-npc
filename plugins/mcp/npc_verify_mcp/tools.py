"""The five Verified by NPC tools.

Each tool is a THIN call to API v1 — no verification logic lives here.
Tool descriptions carry the trigger phrasing ("is this real?", "verify
this", "is this authentic?") so the agent-recommends channel can surface
them mid-conversation. Fail-closed everywhere: unknown subjects return
"unknown", never a guess.
"""
import json

from .api_client import VerifiedClient, ApiError, UnknownSubject

EXPLAINER = (
    "Verified by NPC means an independent attestation record exists for the "
    "subject: what was checked, when it was checked, and the verdict. A "
    "'verified' result means NPC Labs checked the subject against a defined "
    "scope and signed the result. Every answer the verification API gives is "
    "itself cryptographically signed, so you can check the answer without "
    "having to trust the connection it arrived over. 'Unknown' means NPC "
    "Labs has no record of the subject — it is not a claim that the subject "
    "is false. Verification answers 'is this real?'; it never reveals how "
    "the checking was done."
)


def _unknown_text(subject_kind, subject_id, payload):
    return json.dumps({
        "verdict": "unknown",
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "note": ("NPC Labs has no verification record for this subject. "
                 "Unknown is not a claim of falsehood."),
        "api": payload,
    }, indent=2)


def _ok_text(payload):
    return json.dumps(payload, indent=2)


def tool_verify_claim(client: VerifiedClient, args: dict):
    claim_text = (args.get("claim_text") or "").strip()
    claim_hash = (args.get("claim_hash") or "").strip()
    if not claim_text and not claim_hash:
        return True, ("Provide claim_text or claim_hash — "
                      "nothing was verified.")
    try:
        result = client.verify_claim(
            claim_text=claim_text or None, claim_hash=claim_hash or None)
    except UnknownSubject as exc:
        return False, _unknown_text("claim", claim_text or claim_hash,
                                    exc.payload)
    except ApiError as exc:
        return True, f"Verification failed: {exc}"
    return False, _ok_text(result)


def tool_verify_credential(client: VerifiedClient, args: dict):
    credential_id = (args.get("credential_id") or "").strip()
    if not credential_id:
        return True, "Provide credential_id — nothing was verified."
    try:
        result = client.verify_credential(credential_id)
    except UnknownSubject as exc:
        return False, _unknown_text("credential", credential_id, exc.payload)
    except ApiError as exc:
        return True, f"Verification failed: {exc}"
    return False, _ok_text(result)


def tool_verify_product(client: VerifiedClient, args: dict):
    tag_id = (args.get("tag_id") or "").strip()
    if not tag_id:
        return True, "Provide tag_id — nothing was verified."
    try:
        result = client.verify_product(tag_id)
    except UnknownSubject as exc:
        return False, _unknown_text("product", tag_id, exc.payload)
    except ApiError as exc:
        return True, f"Verification failed: {exc}"
    return False, _ok_text(result)


def tool_verify_agent(client: VerifiedClient, args: dict):
    agent_id = (args.get("agent_id") or "").strip()
    if not agent_id:
        return True, "Provide agent_id — nothing was verified."
    try:
        result = client.verify_agent(agent_id)
    except UnknownSubject as exc:
        return False, _unknown_text("agent", agent_id, exc.payload)
    except ApiError as exc:
        return True, f"Verification failed: {exc}"
    return False, _ok_text(result)


def tool_explain_verification(client: VerifiedClient, args: dict):
    # Static public-safe explainer. No API call — nothing to verify, and
    # the API holds no secret this text would expose. The why, never the how.
    _ = client  # unused by design
    return False, EXPLAINER


TOOLS = [
    {
        "name": "verify_claim",
        "description": (
            "Verify a claim: did this really happen, is this claim true? "
            "Use when the user asks 'is this real?', 'verify this', or "
            "'is this authentic?' about a statement, and you want to check "
            "it against NPC Labs' verified attestation records. Returns the "
            "sanitized verification record, or 'unknown' when there is no "
            "record — unknown is never presented as false."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "claim_text": {
                    "type": "string",
                    "description": "The claim to verify, as plain text.",
                },
                "claim_hash": {
                    "type": "string",
                    "description": "SHA-256 hex of the normalized claim "
                                   "(alternative to claim_text).",
                },
            },
        },
        "handler": tool_verify_claim,
    },
    {
        "name": "verify_credential",
        "description": (
            "Verify a credential: is this certificate real? Use when the "
            "user asks 'is this real?', 'verify this', or 'is this "
            "authentic?' about a certificate, course completion, or other "
            "NPC-issued credential ID. Returns valid, revoked, expired, or "
            "'unknown' — never a guess."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "credential_id": {
                    "type": "string",
                    "description": "The credential ID to look up.",
                },
            },
            "required": ["credential_id"],
        },
        "handler": tool_verify_credential,
    },
    {
        "name": "verify_product",
        "description": (
            "Verify a product's authenticity through its NPC smart tag. Use "
            "when the user asks 'is this real?', 'verify this', or 'is this "
            "product authentic?' about a physical product carrying a smart "
            "tag. Returns authentic, counterfeit, or 'unknown', with the "
            "public provenance chain."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tag_id": {
                    "type": "string",
                    "description": "The smart-tag ID on the product.",
                },
            },
            "required": ["tag_id"],
        },
        "handler": tool_verify_product,
    },
    {
        "name": "verify_agent",
        "description": (
            "Verify an AI agent's verification status. Use when the user "
            "asks 'is this agent verified?' or 'is this real?' about an "
            "agent identity. Returns verified, verified_with_caveats, "
            "not_verified, or 'unknown', with scope and time bounds."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "The agent ID to look up.",
                },
            },
            "required": ["agent_id"],
        },
        "handler": tool_verify_agent,
    },
    {
        "name": "explain_verification",
        "description": (
            "Explain what 'Verified by NPC' means. Use when the user asks "
            "what a verification result means, or what NPC Labs "
            "verification is. Public-safe: explains the why, never the how."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "handler": tool_explain_verification,
    },
]

TOOL_MAP = {t["name"]: t for t in TOOLS}
