"""Trust-layer persistent memory v1 (DESIGN v1 section 5).

Agent memory where every memory is a signed claim on the evidence spine:
append-only, hash-chained per stream, scrubbed at the write boundary,
scoped company -> team -> agent, with recall that returns verification
status with every memory.

Pure standard library. Crypto reuses npc_verify.canonical / ed25519.
"""
from .identity import AgentIdentity
from .library import MemoryClient, MemoryError
from .remote import RemoteMemoryClient, RemoteError
from .scope import (Scope, agent_may_write, fleet_write_allowed,
                    key_may_read, key_may_write, stream_key)
from .store import MemoryStore, MemoryStoreError

__version__ = "1.0.0"
__all__ = [
    "AgentIdentity",
    "MemoryClient",
    "MemoryError",
    "MemoryStore",
    "MemoryStoreError",
    "RemoteError",
    "RemoteMemoryClient",
    "Scope",
    "agent_may_write",
    "fleet_write_allowed",
    "key_may_read",
    "key_may_write",
    "stream_key",
    "__version__",
]
