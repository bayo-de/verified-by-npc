"""API-key auth (Bearer) with roles and per-key rate limiting.

Roles: verifier (read/verify), issuer (verifier + POST /v1/attestations),
admin (issuer + key management — reserved for future use).

Keys are stored as SHA-256 hashes; the plaintext is shown once at creation.
Plaintext test keys use the "npc_test_" prefix so they can never be
mistaken for production credentials.

Rate limiting: in-memory token bucket per key. 429 responses carry
Retry-After semantics via retry_after_seconds in the body.
"""
import hashlib
import secrets
import time
from collections import defaultdict

from .models import ROLES, utcnow_iso

ROLE_RANK = {"verifier": 1, "issuer": 2, "admin": 3}
KEY_PREFIX = "npc_test_"


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def new_plaintext_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


class Auth:
    def __init__(self, store):
        self.store = store

    def create_key(self, name: str, role: str, per_minute: int = 60,
                   company_id: str = None, team_id: str = None,
                   agent_id: str = None) -> str:
        """Create an API key, optionally scoped to company/team/agent.

        Scoped keys authorize only memory streams at or below their scope
        (see npc_memory.scope). Unscoped keys keep full reach; memory
        endpoints still check the writer's registered agent scope.
        """
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        from npc_memory.scope import Scope
        scope = Scope(company_id=company_id, team_id=team_id,
                      agent_id=agent_id)
        problems = scope.validate()
        if problems:
            raise ValueError("; ".join(problems))
        plaintext = new_plaintext_key()
        self.store.add_api_key(hash_key(plaintext), name, role, per_minute,
                               utcnow_iso(), company_id, team_id, agent_id)
        return plaintext

    def authenticate(self, headers: dict):
        """Return the key row dict, or None. Headers are case-normalized."""
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return None
        plaintext = auth[7:].strip()
        if not plaintext:
            return None
        return self.store.get_api_key(hash_key(plaintext))

    @staticmethod
    def allows(key_row, required_role: str) -> bool:
        return (ROLE_RANK.get(key_row["role"], 0)
                >= ROLE_RANK.get(required_role, 99))


class RateLimiter:
    """Fixed-window per-key limiter. allowed() returns (ok, retry_after)."""

    def __init__(self):
        self._hits = defaultdict(list)
        self._limits = {}

    def set_limit(self, key_hash: str, per_minute: int):
        self._limits[key_hash] = per_minute

    def allowed(self, key_hash: str):
        limit = self._limits.get(key_hash, 60)
        now = time.monotonic()
        window_start = now - 60.0
        hits = [t for t in self._hits[key_hash] if t > window_start]
        self._hits[key_hash] = hits
        if len(hits) >= limit:
            retry_after = int(60 - (now - hits[0])) + 1
            return False, max(retry_after, 1)
        hits.append(now)
        return True, 0
