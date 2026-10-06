"""NPC Verification API v1 — reference implementation (local-first).

Pure standard library. No third-party dependencies.

The server module is imported lazily (PEP 562): server.py pulls in the
trust-layer memory library (npc_memory), which itself reuses
npc_verify.ed25519 / npc_verify.canonical. An eager import here would
close a circular import, so create_app/run resolve on first attribute
access instead.
"""
import os
import sys

# The trust-layer memory library lives in <program>/memory/npc_memory and
# is part of this program (DESIGN v1 section 5). Make it importable before
# the server module pulls it in for the /v1/memory/ endpoints.
_PROGRAM_DIR = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
_MEMORY_DIR = os.path.join(_PROGRAM_DIR, "memory")
if os.path.isdir(_MEMORY_DIR) and _MEMORY_DIR not in sys.path:
    sys.path.insert(0, _MEMORY_DIR)

__version__ = "1.0.0"
__all__ = ["create_app", "run", "__version__"]


def __getattr__(name):
    if name in ("create_app", "run"):
        from .server import create_app, run
        return {"create_app": create_app, "run": run}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
