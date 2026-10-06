"""Verified by NPC — MCP server (local-first, internal only).

Pure standard library. Every tool is a thin call to the NPC Verification
API v1; every API response is signature-verified client-side before it is
returned to the caller. Fail-closed everywhere.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
