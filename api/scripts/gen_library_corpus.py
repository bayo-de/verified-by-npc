#!/usr/bin/env python3
"""Regenerate the Agent Library chunks of npc_verify/chat_corpus.json
from the completed fleet library manifest and the current weekly
edition, so Biblo's answers about agents and the library are
grounded in the library's own listing (names, taglines, stages,
standings) instead of deflecting.

Run from the api/ directory:
    python3 scripts/gen_library_corpus.py \
        [manifest.json] [weekly-edition.json]

Defaults point at the grand-fleet manifest and the desktop app's
bundled weekly edition. Only chunks whose source is "Agent Library"
are replaced; every other chunk is preserved as-is.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "..", "npc_verify", "chat_corpus.json")
MANIFEST = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    HERE, "..", "..", "..", "fleet-library-manifest.json")
EDITION = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
    HERE, "..", "..", "..", "..", "npc-desktop-app", "src", "shared",
    "weekly-edition.json")
SOURCE = "Agent Library"


def standing_sentence(entry):
    if entry.get("attestation_id"):
        return ("Its record carries a signed attestation with the "
                "standing verified with caveats, attestation "
                + entry["attestation_id"] + ".")
    return ("Verification pending: it carries no attestation yet, "
            "and being listed in the library is not verification.")


def main():
    with open(MANIFEST, encoding="utf-8") as f:
        manifest = json.load(f)
    entries = [e for e in manifest["entries"] if e.get("listed")]
    chunks = [{
        "source": SOURCE,
        "title": "The Agent Library",
        "text": (
            "The Agent Library is the collection of ready-made agents "
            "in the NPC desktop app. It lists %d entries today, each "
            "described by what it does, when to use it, and what it "
            "hands back. A customer adds an agent from the library "
            "with one explicit action in the app; adding registers "
            "the agent under their account. Registration records "
            "that the agent is theirs. Verification is a separate "
            "check by NPC, and its signed result is what travels. "
            "Two entries are departments: a department installs "
            "several named agents at once. Most library agents are "
            "packaged and ready to add, with verification pending. "
            "Exactly one carries a signed attestation today."
            % len(entries)),
    }]
    for e in entries:
        text = "%s. Category: %s. %s Stage: %s. %s" % (
            e["name"], e.get("category") or "General",
            e.get("tagline") or "", e.get("stage_label") or "",
            standing_sentence(e))
        if e.get("kind") == "department" and e.get("slots"):
            names = ", ".join(s["name"] for s in e["slots"])
            text += (" It is a department: one install adds %d "
                     "agents at once (%s)."
                     % (len(e["slots"]), names))
        chunks.append({"source": SOURCE, "title": e["name"],
                       "text": text})
    if os.path.exists(EDITION):
        with open(EDITION, encoding="utf-8") as f:
            edition = json.load(f)
        picks = edition.get("recommendations") or []
        if picks:
            lines = ["This week's recommendations, edition of %s. "
                     "A new edition arrives each Sunday."
                     % edition.get("week_of", "")]
            for i, rec in enumerate(picks, 1):
                lines.append("%d. %s: %s" % (
                    i, rec.get("name", ""), rec.get("promise", "")))
            chunks.append({
                "source": SOURCE,
                "title": "This week's agent recommendations",
                "text": " ".join(lines)})
    with open(CORPUS, encoding="utf-8") as f:
        corpus = json.load(f)
    kept = [c for c in corpus["chunks"] if c.get("source") != SOURCE]
    corpus["chunks"] = kept + chunks
    with open(CORPUS, "w", encoding="utf-8") as f:
        json.dump(corpus, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print("corpus: %d chunks (%d library)" % (len(corpus["chunks"]),
                                              len(chunks)))


if __name__ == "__main__":
    main()
