"""Agent identity: the attestation key that signs memory records.

Each agent holds an Ed25519 keypair (the "attestation key" from DESIGN v1
section 5). The private seed lives in a 0600 file on the agent's machine,
never in the database and never on the wire. The public key is registered
with the memory store (locally or via POST /v1/memory/agents) so any
reader can check the signature.

Reuses npc_verify.ed25519 directly: no duplicated crypto.
"""
import base64
import hashlib
import os

from npc_verify import ed25519


class IdentityError(Exception):
    pass


def key_id_for_public_key(pub: bytes) -> str:
    """Stable key fingerprint: ak_<first 16 hex of sha256(pubkey)>."""
    return "ak_" + hashlib.sha256(pub).hexdigest()[:16]


class AgentIdentity:
    def __init__(self, agent_id: str, seed: bytes):
        if len(seed) != 32:
            raise IdentityError("seed must be 32 bytes")
        self.agent_id = agent_id
        self._seed = bytes(seed)
        self._public = ed25519.publickey(self._seed)

    @classmethod
    def generate(cls, agent_id: str) -> "AgentIdentity":
        return cls(agent_id, os.urandom(32))

    @classmethod
    def load(cls, path: str, agent_id: str) -> "AgentIdentity":
        try:
            with open(path, "rb") as f:
                seed = f.read()
        except OSError as exc:
            raise IdentityError(f"cannot read identity file: {exc}") from exc
        return cls(agent_id, seed)

    def save(self, path: str):
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(self._seed)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    @property
    def public_key(self) -> bytes:
        return self._public

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self._public).decode()

    @property
    def key_id(self) -> str:
        return key_id_for_public_key(self._public)

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(self._seed, message)

    def sign_record_core(self, core: dict) -> str:
        """Sign the canonical signing core; returns base64 signature."""
        from npc_verify.canonical import canonicalize
        return base64.b64encode(self.sign(canonicalize(core))).decode()
