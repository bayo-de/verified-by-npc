"""The seven Verified by NPC tools.

Each tool is a THIN call to API v1 — no verification logic lives here.
Tool descriptions carry the trigger phrasing ("is this real?", "verify
this", "is this authentic?") so the agent-recommends channel can surface
them mid-conversation. Fail-closed everywhere: unknown subjects return
"unknown", never a guess.

Five tools look records up. Two tools START the process the lookups
read: register_agent and register_content call the API's public
registration endpoints and return the signed registration record
("registered, checks pending"). Registration is not verification —
no verdict is issued and no verification mark exists in that flow.
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


#: MCP tool annotations (ToolAnnotations in the protocol). The five
#: lookup tools are pure reads against the NPC Labs verification
#: registry: the four verify tools only read records (verify_claim's
#: API call is a lookup that returns a match or "unknown"; it writes
#: nothing), and explain_verification answers from static text with no
#: API call at all. None of them creates, updates, or deletes anything,
#: and none consults any system outside NPC Labs' own registry, so
#: these values are truthful for them: read-only, non-destructive,
#: closed-world. OpenAI's plugin tool scan requires all three hints as
#: explicit booleans; without them the tools stay "Not live"
#: (observed 2026-10-15 on the hosted endpoint).
TOOL_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "openWorldHint": False,
}

#: The two registration tools CREATE a record (a signed registration
#: record in NPC Labs' own registry), so they are truthfully NOT
#: read-only. Creation overwrites and deletes nothing, so they are
#: not destructive either. register_agent consults no outside system
#: (closed-world). register_content is open-world: giving the API a
#: URL locator makes the API fetch that address at intake, an
#: interaction with the open web initiated by the call.
REGISTER_AGENT_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "openWorldHint": False,
}
REGISTER_CONTENT_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "openWorldHint": True,
}


#: Human-readable tool titles (the protocol's Tool.title). Anthropic's
#: Connectors Directory review requires every tool to carry a `title`
#: alongside the readOnlyHint/destructiveHint hints; the portal flags
#: tools missing one (submission checklist + review criteria, read
#: 2026-10-15). Titles live on the tool entries in TOOLS below and are
#: projected into tools/list by the server; the annotations dict stays
#: exactly the three hints above.


#: JSON Schema type names -> Python types, for argument validation.
#: (bool is a subclass of int in Python, so booleans are explicitly
#: excluded from integer/number and only booleans satisfy boolean.)
_JSON_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float))
    and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
}


def _json_type_name(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    return type(value).__name__


def validate_tool_arguments(tool, arguments):
    """Validate tool-call arguments against the tool's inputSchema.

    Returns an actionable error string naming the field and the
    expected type, or None when the arguments are acceptable. Only
    declared properties are type-checked; undeclared extras are
    ignored (the handlers ignore them too), and missing arguments
    keep the handlers' own "provide X" answers. This exists so a
    wrong-type argument (a number where a string belongs, say) is
    answered with a fixable message instead of surfacing as a
    generic internal error (Claude Connectors Directory review
    criteria, 2026-10-15).
    """
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    for name, value in arguments.items():
        spec = props.get(name)
        if not isinstance(spec, dict):
            continue
        expected = spec.get("type")
        check = _JSON_TYPE_CHECKS.get(expected)
        if check is not None and not check(value):
            article = "an" if expected[:1] in "aeiou" else "a"
            closing = ("Nothing was registered."
                       if tool["name"].startswith("register_")
                       else "Nothing was verified.")
            return (f"Invalid arguments for {tool['name']}: "
                    f"{name} must be {article} {expected} "
                    f"(got {_json_type_name(value)}). "
                    f"{closing}")
    return None


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


def _missing_text(tool_label, fields):
    return ("Provide " + ", ".join(fields) +
            f" — nothing was {tool_label}.")


def tool_register_agent(client: VerifiedClient, args: dict):
    agent_name = (args.get("agent_name") or "").strip()
    owner_name = (args.get("owner_name") or "").strip()
    owner_email = (args.get("owner_email") or "").strip()
    homepage = (args.get("homepage") or "").strip()
    description = (args.get("description") or "").strip()
    missing = [name for name, value in (
        ("agent_name", agent_name), ("owner_name", owner_name),
        ("owner_email", owner_email)) if not value]
    if missing:
        return True, _missing_text("registered", missing)
    if not homepage and not description:
        return True, ("Provide a homepage or a description of the "
                      "agent — nothing was registered.")
    try:
        result = client.register_agent(
            agent_name, owner_name, owner_email,
            homepage=homepage or None, description=description or None)
    except ApiError as exc:
        return True, f"Registration failed: {exc}"
    return False, _ok_text(result)


def tool_register_content(client: VerifiedClient, args: dict):
    title = (args.get("title") or "").strip()
    kind = (args.get("kind") or "").strip()
    locator = (args.get("locator") or "").strip()
    creator_name = (args.get("creator_name") or "").strip()
    creator_email = (args.get("creator_email") or "").strip()
    missing = [name for name, value in (
        ("title", title), ("kind", kind), ("locator", locator),
        ("creator_name", creator_name),
        ("creator_email", creator_email)) if not value]
    if missing:
        return True, _missing_text("registered", missing)
    try:
        result = client.register_content(
            title, kind, locator, creator_name, creator_email)
    except ApiError as exc:
        return True, f"Registration failed: {exc}"
    return False, _ok_text(result)


def tool_explain_verification(client: VerifiedClient, args: dict):
    # Static public-safe explainer. No API call — nothing to verify, and
    # the API holds no secret this text would expose. The why, never the how.
    _ = client  # unused by design
    return False, EXPLAINER


TOOLS = [
    {
        "name": "verify_claim",
        "title": "Verify a claim",
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
        "annotations": dict(TOOL_ANNOTATIONS),
        "handler": tool_verify_claim,
    },
    {
        "name": "verify_credential",
        "title": "Verify a credential",
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
        "annotations": dict(TOOL_ANNOTATIONS),
        "handler": tool_verify_credential,
    },
    {
        "name": "verify_product",
        "title": "Verify a product",
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
        "annotations": dict(TOOL_ANNOTATIONS),
        "handler": tool_verify_product,
    },
    {
        "name": "verify_agent",
        "title": "Verify an agent",
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
        "annotations": dict(TOOL_ANNOTATIONS),
        "handler": tool_verify_agent,
    },
    {
        "name": "register_agent",
        "title": "Register an agent",
        "description": (
            "Register an AI agent with NPC Labs: put the agent on record "
            "and start its verification. Use when the user asks to "
            "'register this agent', 'register my agent', or 'put this "
            "agent on record'. Creates the agent's signed registration "
            "record with its own NPC ID at the status 'registered, "
            "checks pending', listing the checks that ran at "
            "registration and those still pending. Registration is NOT "
            "verification: no verdict is issued and no verification mark "
            "comes with it. Registration is free. The owner must be a "
            "named person accountable for the agent; the owner email is "
            "kept by NPC Labs for the registration only and never "
            "published in the record. Give a homepage for the agent, or "
            "a description of what it does (at least one is required)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_name": {
                    "type": "string",
                    "description": "The agent's name or identifier.",
                },
                "owner_name": {
                    "type": "string",
                    "description": "The named person accountable for "
                                   "this agent.",
                },
                "owner_email": {
                    "type": "string",
                    "description": "The owner's contact email. Kept by "
                                   "NPC Labs for the registration only; "
                                   "never published in the record.",
                },
                "homepage": {
                    "type": "string",
                    "description": "The agent's homepage (an http(s) "
                                   "URL). Optional when a description "
                                   "is given.",
                },
                "description": {
                    "type": "string",
                    "description": "What the agent does. Optional when "
                                   "a homepage is given.",
                },
            },
            "required": ["agent_name", "owner_name", "owner_email"],
        },
        "annotations": dict(REGISTER_AGENT_ANNOTATIONS),
        "handler": tool_register_agent,
    },
    {
        "name": "register_content",
        "title": "Register content",
        "description": (
            "Register a piece of content with NPC Labs: put a work on "
            "record and start its verification. Use when the user asks "
            "to 'register this', 'register my work', or 'put this on "
            "record' about an image, a piece of text, audio, video, or "
            "another work they made. Creates a signed registration "
            "record with its own NPC ID at the status 'registered, "
            "checks pending', listing the checks that ran at "
            "registration and those still pending. Registration is NOT "
            "verification. The locator is the work's web address (an "
            "http(s) URL) or its SHA-256 content hash: for an image at "
            "a URL, the first checks can run at registration (a "
            "structural read of any Content Credentials in the file, "
            "and the AI image check). The creator email is kept by NPC "
            "Labs for the registration only and never published in the "
            "record."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "The title of the work.",
                },
                "kind": {
                    "type": "string",
                    "enum": ["image", "text", "audio", "video", "other"],
                    "description": "The kind of work: image, text, "
                                   "audio, video, or other.",
                },
                "locator": {
                    "type": "string",
                    "description": "Where the work can be found: an "
                                   "http(s) URL, or its SHA-256 "
                                   "content hash.",
                },
                "creator_name": {
                    "type": "string",
                    "description": "The name of the person registering "
                                   "the work.",
                },
                "creator_email": {
                    "type": "string",
                    "description": "The creator's contact email. Kept "
                                   "by NPC Labs for the registration "
                                   "only; never published in the record.",
                },
            },
            "required": ["title", "kind", "locator", "creator_name",
                         "creator_email"],
        },
        "annotations": dict(REGISTER_CONTENT_ANNOTATIONS),
        "handler": tool_register_content,
    },
    {
        "name": "explain_verification",
        "title": "Explain a verification result",
        "description": (
            "Explain what 'Verified by NPC' means. Use when the user asks "
            "what a verification result means, or what NPC Labs "
            "verification is. Public-safe: explains the why, never the how."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "annotations": dict(TOOL_ANNOTATIONS),
        "handler": tool_explain_verification,
    },
]

TOOL_MAP = {t["name"]: t for t in TOOLS}
