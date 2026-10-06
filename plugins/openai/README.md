# Verified by NPC: OpenAI (ChatGPT) plugin package

**Status: internal preview, submission-ready but NOT submitted.**
No developer account has been created, no submission has been made, no
public endpoint is live. Everything here runs against the local API or
documents the gated production path.

## What this is

The "Verified by NPC" ChatGPT plugin answers the question "is this real?"
inside the conversation. When verification becomes relevant mid-chat, the
plugin offers five operations:

| Operation | Question it answers | Backend |
|---|---|---|
| `verify_product` | Is this product authentic? | `GET /v1/products/{tag_id}` |
| `verify_credential` | Is this certificate real? | `GET /v1/credentials/{id}` |
| `verify_claim` | Did this really happen / is this claim true? | `POST /v1/claims/verify` |
| `verify_agent` | Is this agent verified? | `GET /v1/agents/{agent_id}/attestation` |
| `explain_verification` | What does Verified by NPC mean? | plugin-side static explainer (no API call) |

Design principles (same as the API and the MCP server): read-first, so
the plugin verifies and never issues attestations; fail-closed, so an
unknown subject returns "unknown" and never a guess; privacy-preserving,
so responses carry no PII beyond what the subject made public; and
self-verifying, so every API response is Ed25519 signature-checked before
it is trusted. `explain_verification` teaches the why, never the how.

## How it maps to API v1

This package is a thin client over the NPC Verification API v1
(`../../api/`). The mapping lives in three places:

- `openapi-plugin.yaml`: the machine-readable action surface. The four
  verification operations map 1:1 onto API v1 endpoints (paths are
  checked against the API's own `openapi.yaml` by the test suite).
  `explain_verification` is marked `x-npc-client-side: true`: a static
  operation served by the plugin, never sent to the API. Issuance
  (`POST /v1/attestations`) is deliberately absent from this spec.
- `skills/verified-by-npc/SKILL.md`: the onboarding skill the plugin
  manifest points at. Human- and model-readable description of the five
  operations, the fail-closed rules, and the HTTP details.
- `npc_verify_openai/client.py`: the thin Python helper (stdlib only).
  It reuses the Phase 2a MCP package's verified HTTP client and tool
  handlers, which reuse the API's own signing primitives. The reuse
  chain is `npc_verify_openai` → `npc_verify_mcp.api_client` →
  `npc_verify.*`. No verification logic is duplicated, and no crypto is
  reimplemented. Every operation returns `(is_error, text)`; tampered or
  untrusted responses surface errors, and unknown subjects surface
  exactly `"verdict": "unknown"`.

## The 2026 submission path (researched 2026-10-06)

OpenAI retired the 2023-era `ai-plugin.json` manifest: the official
quickstart repo is archived, the manifest docs are gone, and the legacy
file fails the current submission scan. This package therefore does NOT
ship `ai-plugin.json`. The live 2026 format is the portable Agent Plugins
manifest, which is what `plugin.json` is:

- Root `plugin.json` with `$schema` from agent-plugins.org, package
  identity (`verified-by-npc`), and OpenAI listing metadata under
  `extensions.com.openai.interface` (display name, descriptions written
  for the mid-conversation suggestion trigger, starter prompts, icons).
- `skills/` auto-discovered by the platform; the manifest's
  `onboardingSkill` points at the bundled skill.
- This package is skills-only on purpose: no `mcp.json` is declared. The
  MCP lane needs a hosted server plus domain verification, which is
  gated (see below). The platform does not allow adding an MCP server to
  a skills-only plugin later, so that lane is a separate submission
  once the hosting gate clears.
- Logo and composer-icon fields point at internal placeholder SVGs in
  `assets/`. They are NOT the "Verified by NPC" mark; public mark use
  awaits counsel clearance. Replace them with approved artwork before
  any public submission.
- Review metadata ships in the manifest: five positive and three
  negative test cases plus commerce declarations. Reviewer credentials
  and the demo video walkthrough are entered in the portal, never in
  the package.

Submission flow (portal, not done): create an OpenAI developer
organization with Apps Management write access, complete verified
individual or business identity, upload the plugin ZIP, resolve the
automated metadata findings, fill in review details, submit for review,
then publish after approval. Each of those steps needs Bayo's explicit
go-ahead.

## Validate

```bash
cd plugins/openai
python3 validate_package.py   # full end-to-end check; nonzero exit on failure
python3 -m unittest discover -s tests   # the 52-test suite on its own
```

`validate_package.py` runs the tests, checks that every manifest
reference resolves inside the package, enforces the copy rules (no
em-dashes, no invented live URLs, no money or earnings claims),
confirms the retired `ai-plugin.json` is absent, and assembles a trial
submission ZIP.

## What remains gated (explicitly NOT done)

1. OpenAI developer account + verified identity (Bayo's decision).
2. Store listing copy approval (Bayo reviews every public word).
3. Submission + publication in the plugin portal.
4. Public endpoint `https://api.npclabs.xyz/v1` (deployment + hosting budget).
5. Approved "Verified by NPC" mark artwork (counsel clearance; placeholders ship for now).
6. Reviewer test account, demo video walkthrough, and country availability for the review form.
7. Mainnet onchain anchoring (testnet until Bayo signs off).

## Files

- `plugin.json`: the 2026 live plugin manifest.
- `openapi-plugin.yaml`: OpenAPI action spec for the five operations.
- `skills/verified-by-npc/SKILL.md`: onboarding skill.
- `assets/logo.svg`, `assets/icon.svg`: internal placeholders, not the mark.
- `npc_verify_openai/client.py`: thin stdlib helper reusing the MCP client.
- `tests/`: 52 tests: manifest, spec, signature, contracts.
- `validate_package.py`: end-to-end package check.
