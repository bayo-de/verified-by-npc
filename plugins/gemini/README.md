# Verified by NPC - Gemini CLI extension (Phase 2c)

A Gemini CLI extension that answers **"is this real?"** inside the
conversation. Five slash commands, one thin helper, zero new crypto: every
answer comes from the NPC Verification API v1 and every API response is
Ed25519 signature-checked before it is used.

## What it is

- `gemini-extension.json` - the extension manifest (name, version, trigger
  phrasing, API key/URL settings). Follows the 2026 Gemini CLI extension
  manifest format.
- `commands/*.toml` - the five slash commands (`/verify-product`,
  `/verify-credential`, `/verify-claim`, `/verify-agent`,
  `/explain-verification`). Each prompt carries the trigger phrasing and the
  fail-closed rules.
- `operations.json` - the action-to-endpoint map for all five actions.
  Read-only: issuance (`POST /v1/attestations`) is intentionally absent.
- `GEMINI.md` - the context file Gemini loads with the extension: what the
  actions do, and the rules (fail closed, never fabricate, the why never
  the how).
- `npc_verify_gemini/` - the thin Python helper (stdlib only). It calls API
  v1 over HTTP, verifies the Ed25519 signature on every response using the
  API package's own `canonical` + `ed25519` modules (imported via sys.path,
  never reimplemented), and fails closed on tamper or unknown subjects.
- `tests/` - unittest suite: manifest validity, command validity, operation
  mapping coverage, signature pass/tamper/fail-closed, and Proofline-style
  contracts per action.

## API v1 mapping

| Action | Method | Endpoint |
|---|---|---|
| `verify_product` | GET | `/v1/products/{tag_id}` |
| `verify_credential` | GET | `/v1/credentials/{id}` |
| `verify_claim` | POST | `/v1/claims/verify` |
| `verify_agent` | GET | `/v1/agents/{agent_id}/attestation` |
| `explain_verification` | GET | `/v1/health` (anchor; the explainer text itself is static public copy) |

Auth: verifier API key as a Bearer token. Unknown subjects return
`{"verdict": "unknown"}` - never a guess.

## Use it locally

```bash
# 1. Start the API (from the api/ directory)
python3 -m npc_verify

# 2. Point the helper at it (or accept the settings prompts on install)
export NPC_VERIFY_API_URL="http://127.0.0.1:8787"
export NPC_VERIFY_API_KEY="<verifier key>"

# 3. Run an action directly
python3 -m npc_verify_gemini verify_product --tag-id tag_test_authentic

# 4. Link the extension into Gemini CLI for the slash commands
gemini extensions link /path/to/plugins/gemini
```

The install directory must be named `npc-verify` (it matches the manifest
`name`), so the commands find the helper under
`~/.gemini/extensions/npc-verify/npc_verify_gemini`.

## Validate the package

```bash
python3 validate_package.py
```

Runs the full check: required files, manifest schema, command files,
operation mapping (including the read-only rule), and the whole unittest
suite. Exits nonzero on any failure.

## Publishing (when Bayo approves)

Per the current Gemini CLI release docs: push the extension to a public
GitHub repo with `gemini-extension.json` at the repo root, add the
`gemini-cli-extension` topic to the repo, and the gallery crawler indexes
it automatically (daily; listing appears if it passes validation). There is
no manual submission form. Google does not vet or endorse listed extensions.

Note: this package lives at `plugins/gemini/` inside the monorepo, so the
manifest is not at a repo root today. Publishing means either a dedicated
repo for the extension or a release archive with the package contents at
the archive root.

## Explicitly NOT done (gated)

- No public repo, no gallery listing, no release tag. Publishing the
  extension is a Bayo decision.
- No public API endpoint. `https://api.npclabs.xyz/v1` is listed as the
  production target but deployment is gated; local-first until Bayo
  approves hosting.
- No public "Verified by NPC" mark artwork. Mark use awaits counsel
  clearance.
- No mainnet writes, no real secrets. All fixtures are fictional.
- No verifier API keys are provisioned or stored here.
