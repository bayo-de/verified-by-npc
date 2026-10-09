"""The three Biblo character tools.

get_canon:  return the canon text and its version.
speak:      apply Biblo's MECHANICAL voice rules to a draft (em-dash
            removal, owl-emoji removal, performative-opener stripping) and
            return the rewritten text plus an honest list of what was NOT
            done. This tool is a first pass, not a voice: the agent still
            reads the canon for word choice, rhythm, and subtraction.
voice_check: score a text against the canon's checkable voice rules and
            list every violation with an excerpt and a suggestion.

Fail-closed everywhere: empty input returns an error, never a guess.
"""
import json
import re

from .canon import (
    BANNED_PHRASES,
    CANON_VERSION,
    LEADING_OPENERS,
    OWL_EMOJI,
    load_canon,
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def _excerpt(text, start, end, pad=20):
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    snippet = text[lo:hi].replace("\n", " ")
    if lo > 0:
        snippet = "..." + snippet
    if hi < len(text):
        snippet = snippet + "..."
    return snippet


def tool_get_canon(args: dict):
    _ = args  # no arguments by design
    try:
        canon = load_canon()
    except FileNotFoundError as exc:
        return True, str(exc)
    return False, json.dumps({
        "character": "biblo",
        "canon_version": CANON_VERSION,
        "canon": canon,
    }, indent=2)


def _apply_mechanical_rules(draft: str):
    """Returns (rewritten, transforms). Only safe, reversible edits."""
    transforms = []
    out = draft

    em_count = out.count("\u2014")
    if em_count:
        out = out.replace(" \u2014 ", ", ")
        out = out.replace("\u2014", "")
        transforms.append(
            f"removed {em_count} em dash(es): ' \u2014 ' became ', ', "
            "any remaining bare em dash was deleted")
        out = re.sub(r" {2,}", " ", out)

    owl_count = out.count(OWL_EMOJI)
    if owl_count:
        out = out.replace(OWL_EMOJI, "")
        transforms.append(
            f"removed {owl_count} owl emoji (retired from Biblo's "
            "vocabulary); use nothing, or \U0001F3C6\U0001FAB6 sparingly")
        out = re.sub(r" {2,}", " ", out)

    lowered = out.lower()
    for opener in LEADING_OPENERS:
        if lowered.startswith(opener):
            out = out[len(opener):]
            # Capitalize the new first letter for a clean sentence start.
            out = out[:1].upper() + out[1:] if out else out
            transforms.append(
                f"stripped leading performative opener "
                f"('{opener.strip()}')")
            lowered = out.lower()

    out = out.strip()
    return out, transforms


def tool_speak(args: dict):
    draft = (args.get("draft") or "").strip()
    if not draft:
        return True, "Provide draft — nothing was rewritten."
    audience = (args.get("audience") or "").strip()
    purpose = (args.get("purpose") or "").strip()

    rewritten, transforms = _apply_mechanical_rules(draft)
    notes = [
        "Mechanical pass only. The agent must still read the canon and do "
        "the judgment work: word choice, rhythm, radical subtraction, and "
        "checking that the moral core is lived rather than preached.",
    ]
    if audience or purpose:
        notes.append(
            "Audience/purpose were noted but not acted on mechanically; "
            "use them when doing the judgment pass.")
    return False, json.dumps({
        "character": "biblo",
        "canon_version": CANON_VERSION,
        "rewritten": rewritten,
        "transforms_applied": transforms,
        "notes": notes,
    }, indent=2)


def tool_voice_check(args: dict):
    text = (args.get("text") or "").strip()
    if not text:
        return True, "Provide text — nothing was checked."
    lowered = text.lower()
    violations = []
    notes = []
    score = 100

    # Rule 1: no em dashes in human-facing copy.
    for m in re.finditer("\u2014", text):
        violations.append({
            "rule": "no_em_dash",
            "excerpt": _excerpt(text, m.start(), m.end()),
            "suggestion": "Replace with a comma or a period.",
            "penalty": 15,
        })
    # Rule 2: owl emoji retired.
    for m in re.finditer(OWL_EMOJI, text):
        violations.append({
            "rule": "no_owl_emoji",
            "excerpt": _excerpt(text, m.start(), m.end()),
            "suggestion": "Delete it. Biblo's marks are \U0001F3C6\U0001FAA6, "
                          "used sparingly.",
            "penalty": 25,
        })
    # Rule 3: AI-slop tells.
    for phrase in BANNED_PHRASES:
        start = 0
        while True:
            idx = lowered.find(phrase, start)
            if idx == -1:
                break
            violations.append({
                "rule": "no_ai_slop",
                "excerpt": _excerpt(text, idx, idx + len(phrase)),
                "suggestion": f"Remove or rewrite '{phrase}'. Say it plain.",
                "penalty": 10,
            })
            start = idx + len(phrase)

    for v in violations:
        score -= v["penalty"]
    score = max(0, score)

    # Notes (not violations): judgment-level suggestions.
    sentences = [s for s in _SENTENCE_SPLIT.split(text) if s.strip()]
    if sentences:
        avg_len = sum(len(s.split()) for s in sentences) / len(sentences)
        if avg_len > 25:
            notes.append(
                f"Average sentence length is {avg_len:.0f} words. Biblo "
                "writes short; consider radical subtraction.")
    if re.search(r"\byou should\b|\byou must\b", lowered):
        notes.append(
            "'You should' / 'you must' detected. The moral core is lived, "
            "never preached; check the sentence is not a lecture.")

    return False, json.dumps({
        "character": "biblo",
        "canon_version": CANON_VERSION,
        "score": score,
        "violations": violations,
        "notes": notes,
    }, indent=2)


TOOLS = [
    {
        "name": "get_canon",
        "description": (
            "Return Biblo's character canon: the source of truth for who "
            "Biblo is, how Biblo speaks, and what Biblo never does. Use "
            "before any 'speak as Biblo' work, and whenever you need the "
            "exact voice rules, symbols, or moral core."
        ),
        "inputSchema": {"type": "object", "properties": {}},
        "handler": tool_get_canon,
    },
    {
        "name": "speak",
        "description": (
            "Apply Biblo's mechanical voice rules to a draft: removes em "
            "dashes, removes the retired owl emoji, strips leading "
            "performative openers like 'Great question!'. This is a first "
            "mechanical pass only; the agent must still read the canon for "
            "word choice, rhythm, and subtraction. Use when polishing a "
            "draft toward Biblo's voice."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "draft": {
                    "type": "string",
                    "description": "The draft text to voice-polish.",
                },
                "audience": {
                    "type": "string",
                    "description": "Who the text is for (noted, not "
                                   "acted on mechanically).",
                },
                "purpose": {
                    "type": "string",
                    "description": "What the text must do (noted, not "
                                   "acted on mechanically).",
                },
            },
            "required": ["draft"],
        },
        "handler": tool_speak,
    },
    {
        "name": "voice_check",
        "description": (
            "Score a text against Biblo's checkable voice rules (no em "
            "dashes, no owl emoji, no AI-slop tells) and list every "
            "violation with an excerpt and a suggestion. Use to verify a "
            "draft before it ships as Biblo's voice."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to check.",
                },
            },
            "required": ["text"],
        },
        "handler": tool_voice_check,
    },
]

TOOL_MAP = {t["name"]: t for t in TOOLS}
