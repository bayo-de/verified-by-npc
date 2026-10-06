# Verified by NPC - Microsoft 365 Copilot plugin (Phase 2c)

A Copilot API plugin (plus a declarative-agent wrapper) that answers
**"is this real?"** inside Microsoft 365 Copilot. Five functions, one thin
reference helper, zero new crypto: every answer comes from the NPC
Verification API v1 and every API response is Ed25519 signature-checked
before it is used.

## What it is

- `npc-verify-apiplugin.json` - the plugin manifest (API plugin schema
  v2.2): names, trigger phrasing for the model, the five functions, the
  OpenAPI runtime, and conversation starters.
- `npc-verify-openapi.yaml` - the operations spec (OpenAPI 3.0.3): the five
  functions mapped onto API v1 endpoints, each tagged with its canonical
  `x-npc-action` name. Read-only: issuance (`POST /attestations`) is
  intentionally absent.
- `declarative-agent.json` - a declarative agent wrapper (schema v1.3) that
  references the plugin in `actions[]` and carries the fail-closed
  instructions (unknown is not false, never fabricate a verdict).
- `npc_verify_copilot/` - the thin Python reference helper (stdlib only).
  It calls API v1 over HTTP, verifies the Ed25519 signature on every
  response using the API package's own `canonical` + `ed25519` modules
  (imported via sys.path, never reimplemented), and fails closed on tamper
  or unknown subjects. Used by the tests and the validator; handy for
  checking what the plugin will return.
- `tests/` - unittest suite: manifest validity, declarative-agent validity,
  OpenAPI coverage, signature pass/tamper/fail-closed, and Proofline-style
  contracts per action.

## API v1 mapping

| Function | x-npc-action | Method | Endpoint |
|---|---|---|---|
| `verifyProduct` | `verify_product` | GET | `/v1/products/{tag_id}` |
| `verifyCredential` | `verify_credential` | GET | `/v1/credentials/{id}` |
| `verifyClaim` | `verify_claim` | POST | `/v1/claims/verify` |
| `verifyAgent` | `verify_agent` | GET | `/v1/agents/{agent_id}/attestation` |
| `explainVerification` | `explain_verification` | GET | `/v1/health` (anchor; the explainer text itself is static public copy) |

Auth: the user's verifier API key, supplied through the plugin vault
(`ApiKeyPluginVault`, reference `NPC_VERIFY_API_KEY`) and sent as a Bearer
token. Unknown subjects return `{"verdict": "unknown"}` - never a guess.

## Try the helper locally

```bash
# 1. Start the API (from the api/ directory)
python3 -m npc_verify

# 2. Point the helper at it
export NPC_VERIFY_API_URL="http://127.0.0.1:8787"
export NPC_VERIFY_API_KEY="<verifier key>"

# 3. Run an action
python3 -m npc_verify_copilot verify_product --tag-id tag_test_authentic
```

## Validate the package

```bash
python3 validate_package.py
```

Runs the full check: required files, manifest schema, OpenAPI spec,
operation mapping (including the read-only rule), and the whole unittest
suite. Exits nonzero on any failure.

## Publishing (when Bayo approves)

Per the current Microsoft docs, the path for a Copilot plugin is:

1. Enroll in the **Microsoft 365 and Copilot** program in Microsoft
   Partner Center (requires a partner account).
2. Meet the validation bar first: Microsoft Commercial Marketplace
   certification policies, the Microsoft 365 store validation guidelines
   for agents, and the Responsible AI validation checks (the optional
   Microsoft 365 App Compliance certification strengthens the listing).
3. Prepare the app package: the Teams/declarative-agent wrapper, the
   plugin manifest, the OpenAPI spec at its public URL, icons, plus
   customer-facing descriptions, privacy policy, terms, and support info.
4. Submit under the offer type **Apps and agents for Microsoft 365 and
   Copilot**. After Microsoft validates and approves, the agent appears in
   the Agent Store inside Microsoft 365 Copilot (and Teams, Outlook, and
   the Microsoft 365 apps) once an IT admin enables it.

Before that submission, still to fill in: `logo_url`, `contact_email`,
`legal_info_url`, `privacy_policy_url` in the plugin manifest (left unset
on purpose - the mark artwork and legal pages are gated), the public spec
URL must serve `npc-verify-openapi.yaml`, and the production API must be
deployed (see below).

## Explicitly NOT done (gated)

- No partner account, no Partner Center submission, no store validation.
  Nothing has been sent to Microsoft.
- No public API endpoint. `https://api.npclabs.xyz/v1` is listed as the
  production target but deployment is gated; local-first until Bayo
  approves hosting.
- No public "Verified by NPC" mark artwork. Mark use awaits counsel
  clearance.
- No mainnet writes, no real secrets. All fixtures are fictional.
- No verifier API keys are provisioned or stored here.
