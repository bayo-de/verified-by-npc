"""Verified by NPC - bundled signing primitives.

Minimal package: canonical JSON (NPC-JCS-v1) and pure-Python Ed25519
(RFC 8032), reused by the Gemini extension helper to verify API response
signatures. Only the primitives needed to check signatures ship here;
the full NPC Verification API reference implementation is maintained
separately by NPC Labs.
"""
__version__ = "1.0.0"
__all__ = ["canonical", "ed25519"]
