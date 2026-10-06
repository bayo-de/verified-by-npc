"""Thin OpenAI-plugin helper client over the NPC Verification API v1.

Every operation below is a THIN call to API v1 - no verification logic
lives here. The HTTP transport, Ed25519 response-signature verification,
and fail-closed errors are REUSED from the Phase 2a MCP package
(``npc_verify_mcp.api_client.VerifiedClient``), which itself reuses the
signing primitives from the API reference implementation
(``npc_verify.canonical`` / ``npc_verify.ed25519``). The tool handlers are
reused from ``npc_verify_mcp.tools`` too, so the five operations behave
identically across the Claude and ChatGPT surfaces.

Reuse chain (crypto is written exactly once, in the API package)::

    npc_verify_openai -> npc_verify_mcp.api_client -> npc_verify.*

The MCP package is located via ``NPC_VERIFY_MCP_PATH``, or by resolving
``../mcp`` relative to this package, or as an installed package
(``pip install`` the Phase 2a tree). Stdlib only.

Fail-closed: every helper returns ``(is_error, text)``. Unknown subjects
surface exactly ``"verdict": "unknown"``; tampered or untrusted responses
surface errors. A verdict is never fabricated.
"""
import os
import sys


def _ensure_mcp_package():
    """Make the npc_verify_mcp package importable. Returns its base dir."""
    try:
        import npc_verify_mcp  # noqa: F401
        import npc_verify_mcp.api_client  # noqa: F401
        import npc_verify_mcp.tools  # noqa: F401
        return os.path.dirname(npc_verify_mcp.__file__)
    except ImportError:
        pass
    override = os.environ.get("NPC_VERIFY_MCP_PATH")
    candidates = []
    if override:
        candidates.append(override)
    here = os.path.dirname(os.path.abspath(__file__))
    # <program>/plugins/openai/npc_verify_openai -> <program>/plugins/mcp
    candidates.append(os.path.normpath(
        os.path.join(here, "..", "..", "mcp")))
    for cand in candidates:
        init = os.path.join(cand, "npc_verify_mcp", "__init__.py")
        if os.path.isfile(init) and cand not in sys.path:
            sys.path.insert(0, cand)
            import npc_verify_mcp  # noqa: F401
            return cand
    raise RuntimeError(
        "npc_verify_mcp package not found. Set NPC_VERIFY_MCP_PATH to the "
        "directory containing the Phase 2a mcp/ tree (the one holding "
        "npc_verify_mcp/), or pip-install npc-verify-mcp.")


_ensure_mcp_package()
from npc_verify_mcp.api_client import (  # noqa: E402
    VerifiedClient, ApiError, UnknownSubject)
from npc_verify_mcp import tools as _mcp_tools  # noqa: E402

# The five operations, identical to the MCP surface. explain_verification
# is a static public-safe explainer (the why, never the how) - no API call.
OPERATIONS = [t["name"] for t in _mcp_tools.TOOLS]
OPERATION_HANDLERS = dict(_mcp_tools.TOOL_MAP)

# Single-sourced from the MCP package, with the standing no-em-dash copy
# rule applied at the plugin boundary.
EXPLAINER = _mcp_tools.EXPLAINER.replace(
    " \u2014 ", ". ").replace("\u2014", ",")


def make_client(base_url=None, api_key=None, timeout=10):
    """Build a VerifiedClient for API v1.

    Env defaults: NPC_VERIFY_API_URL (default http://127.0.0.1:8787),
    NPC_VERIFY_API_KEY. All response-signature verification happens inside
    the reused client.
    """
    return VerifiedClient(base_url=base_url, api_key=api_key,
                          timeout=timeout)


def run_operation(client: VerifiedClient, name: str, args: dict):
    """Run one of the five operations. Returns (is_error, text).

    Raises KeyError for an unknown operation name. Fail-closed everywhere:
    unknown subjects yield verdict "unknown"; transport, auth, or signature
    problems yield an error, never data.
    """
    handler = OPERATION_HANDLERS[name]["handler"]
    return handler(client, dict(args or {}))


def verify_product(client: VerifiedClient, tag_id: str):
    """(is_error, text) for the verify_product operation."""
    return run_operation(client, "verify_product", {"tag_id": tag_id})


def verify_credential(client: VerifiedClient, credential_id: str):
    """(is_error, text) for the verify_credential operation."""
    return run_operation(client, "verify_credential",
                         {"credential_id": credential_id})


def verify_claim(client: VerifiedClient, claim_text=None, claim_hash=None):
    """(is_error, text) for the verify_claim operation."""
    return run_operation(client, "verify_claim",
                         {"claim_text": claim_text or "",
                          "claim_hash": claim_hash or ""})


def verify_agent(client: VerifiedClient, agent_id: str):
    """(is_error, text) for the verify_agent operation."""
    return run_operation(client, "verify_agent", {"agent_id": agent_id})


def explain_verification():
    """The static public-safe explainer. No API call, nothing to verify."""
    return EXPLAINER
