# ProofShot — Evidence Bundles for Verified by NPC

**Installed:** 2026-10-08 | **Source:** official GitHub repo (AmElmo/proofshot v1.6.0, MIT)
**Installed via:** `npm install -g proofshot` + `npm install -g agent-browser` (official npm packages)
**Binaries:** `/usr/bin/proofshot`, `/usr/bin/agent-browser`
**Status:** `proofshot doctor` passes — CLI, agent-browser, and ffmpeg all detected

## What It Does

ProofShot records AI agent browser sessions (video, screenshots, console/server errors)
and bundles them into reviewable proof artifacts. For Verified by NPC, this means every
agent verification session can produce an evidence bundle — the "proof" behind the
verification.

## Basic Workflow

```bash
# 1. Start a session (opens browser, begins recording, captures logs)
proofshot start --description "Verify checkout flow for NPC demo"

# 2. Drive the browser (agent does its work)
proofshot exec open https://example.com
proofshot exec snapshot
proofshot exec screenshot ./proofshot-artifacts/step-1.png

# 3. Stop and bundle
proofshot stop
# → produces timestamped evidence bundle in ./proofshot-artifacts/
```

## Integration with Verified by NPC

The evidence-bundling pattern (record → verify → bundle proof) maps directly onto the
NPC verification layer philosophy: every verification claim should carry its evidence.

Suggested use: when a verified agent completes a task, run it under `proofshot start`/`stop`
so the session produces an artifact bundle that can be attached to the verification record.

## Notes

- Headless Chromium via agent-browser. Network-restricted environments may need proxy config.
- `proofshot install` (skill installer for AI coding tools) was NOT run — the fleet has its
  own skill system. Run it manually if you want the ProofShot skill in Claude Code/Cursor/etc.
- Artifacts output to `./proofshot-artifacts/` by default; configure via `proofshot.config.json`.
