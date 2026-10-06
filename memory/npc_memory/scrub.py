"""Write-boundary secret refusal for trust-layer memory.

Same rules as the session spine (sim-gate spine.py): memory content must
never carry secrets. Write paths call these checks before anything is
signed or stored. Refusal is fail-closed: the write is rejected with a
clear error that names the offending key or pattern, never the secret
value itself.

Callers must scrub their own text before calling; this is the defense in
depth at the boundary.
"""
import re

# Keys that must never reach the store (mirrors the spine's hints).
_SECRET_KEY_HINTS = ("secret", "private_key", "privkey", "seed", "password",
                     "passwd", "pwd", "api_key", "apikey", "token", "bearer",
                     "auth_key", "client_secret", "session_key")

# High-confidence secret shapes inside free text.
_SECRET_VALUE_PATTERNS = (
    ("pem_private_key",
     re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("aws_access_key",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("stripe_live_key",
     re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("slack_token",
     re.compile(r"\bxox[abp]-[A-Za-z0-9-]{10,}\b")),
    ("npc_api_key",
     re.compile(r"\bnpc_test_[A-Za-z0-9_-]{16,}\b")),
)


class SecretRefusedError(ValueError):
    """Raised when a write carries secret-bearing material."""


def scrub_check(obj):
    """Refuse structures with secret-bearing keys (spine rule)."""
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                kl = str(k).lower()
                if any(h in kl for h in _SECRET_KEY_HINTS):
                    raise SecretRefusedError(
                        f"refusing to store secret-bearing key: {k!r}")
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)
    walk(obj)


def scrub_text(text: str):
    """Refuse free text matching a known secret shape."""
    if not isinstance(text, str):
        return
    for name, pattern in _SECRET_VALUE_PATTERNS:
        if pattern.search(text):
            raise SecretRefusedError(
                f"refusing to store text matching secret pattern: {name}")


def scrub_tag(tag: str):
    """Refuse tag identifiers that look secret-bearing."""
    if not isinstance(tag, str):
        return
    tl = tag.lower()
    if any(h in tl for h in _SECRET_KEY_HINTS):
        raise SecretRefusedError(
            f"refusing to store secret-bearing tag: {tag!r}")
