"""Canon loader and the mechanical voice rules.

The canon (CANON.md) lives one directory above the mcp-server package, at
the root of the character-vault/biblo directory. CANON_VERSION here must
match the version named in CANON.md; bump both together.
"""
from pathlib import Path

CANON_VERSION = "0.1"


def canon_path() -> Path:
    return Path(__file__).resolve().parents[2] / "CANON.md"


def load_canon() -> str:
    path = canon_path()
    if not path.exists():
        raise FileNotFoundError(
            f"Biblo canon not found at {path}. The MCP server must run "
            "from inside the character vault.")
    return path.read_text(encoding="utf-8")


# Conservative, checkable list of AI-slop tells. Deliberately short: a
# false positive here is worse than a missed tell, because the tool would
# be "correcting" text that was fine. Judgment calls stay with the agent.
BANNED_PHRASES = [
    "great question",
    "i'd be happy to help",
    "i would be happy to help",
    "as an ai language model",
    "as an ai",
    "in today's fast-paced world",
    "delve",
]

# Performative openers stripped from the START of a draft by `speak`.
# Only when they lead the text; never mid-sentence surgery.
LEADING_OPENERS = [
    "great question! ",
    "great question. ",
    "i'd be happy to help! ",
    "i'd be happy to help. ",
    "i would be happy to help! ",
    "i would be happy to help. ",
]

OWL_EMOJI = "\U0001F989"  # 🦉 — retired from Biblo's vocabulary
