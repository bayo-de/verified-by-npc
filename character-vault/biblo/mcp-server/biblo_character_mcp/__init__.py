"""Biblo character IP — MCP server (local-first, internal only).

Pure standard library. No network calls: the canon is read from the
character vault on disk, and the voice tools apply Biblo's mechanical voice
rules deterministically. Judgment-level voice work (word choice, rhythm,
subtraction) still needs an agent reading the canon — the `speak` tool says
so in its own output rather than pretending otherwise.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
