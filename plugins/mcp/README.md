# npc-verify-mcp — "Verified by NPC" MCP server

<!-- mcp-name: io.github.bayo-de/npc-verify -->

Ask "is this real?" inside any MCP-capable assistant. This MCP server
puts NPC Labs verification inside Claude Desktop, Claude Code, and
friends: check a product, credential, claim, or AI agent against NPC Labs
verification records. Every tool is a **thin call to the NPC Verification
API v1** — no verification logic lives here — and every API response is
**Ed25519 signature-verified client-side** before it reaches the caller.
Fail-closed everywhere: unknown subjects return `"unknown"`, never a
guess.

- **Zero dependencies.** Pure Python standard library. The MCP JSON-RPC
  transport is implemented directly over stdio; the signing primitives are
  the API reference implementation (vendored byte-identical copies ship
  inside the package, so a PyPI install needs no repo checkout).
- **Public API by default.** Talks to the NPC Verification API at
  `https://api.npclabs.xyz` by default (override with
  `NPC_VERIFY_API_URL`, e.g. `http://127.0.0.1:8787` for a local API).
  No key setup is required: a public read-only verifier key is bundled,
  the same posture as the Chrome extension. Set `NPC_VERIFY_API_KEY` to
  use your own key.

## Layout

```
plugins/mcp/
  pyproject.toml
  README.md            # this file
  docs/TOOLS.md        # tool reference
  npc_verify_mcp/
    __init__.py
    __main__.py        # npc-verify-mcp entry point
    server.py          # MCP JSON-RPC 2.0 transport over stdio
    tools.py           # the seven tools (schemas + thin handlers)
    api_client.py      # API v1 HTTP client + signature verification
  tests/
    test_tools.py      # per-tool tests against seeded fixtures
    test_signature.py  # signature verification incl. tamper rejection
    test_contracts.py  # Proofline-style contract suite
    test_transport.py  # stdio JSON-RPC round trips
```

## Quick start

```bash
# 1. Install the MCP server
pip install npc-verify-mcp        # or: uvx npc-verify-mcp
# (from a repo checkout instead: pip install -e . in plugins/mcp)

# 2. Run it. No configuration is needed: it talks to the public API at
#    https://api.npclabs.xyz with a bundled read-only verifier key.
npc-verify-mcp

# Optional: use your own key, or point at a local API for development
export NPC_VERIFY_API_KEY="npc_..."                  # your verifier key
export NPC_VERIFY_API_URL="http://127.0.0.1:8787"    # local API override
```

Developers: the tests run against a locally seeded API fixture.
`python3 -m unittest discover -s tests` from `plugins/mcp/`.

## Claude Desktop config

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "npc-verify": {
      "command": "uvx",
      "args": ["npc-verify-mcp"]
    }
  }
}
```

No environment is required: the server defaults to the public API with
a bundled read-only verifier key. To use your own key or a local API,
add an `env` block with `NPC_VERIFY_API_KEY` and/or
`NPC_VERIFY_API_URL`. If the API is unreachable, the tools report an
error instead of guessing.

## The seven tools

| Tool | Answers | Backend |
|------|---------|---------|
| `verify_claim` | "Did this really happen / is this claim true?" | `POST /v1/claims/verify` |
| `verify_credential` | "Is this certificate real?" | `GET /v1/credentials/{id}` |
| `verify_product` | "Is this product authentic?" | `GET /v1/products/{tag_id}` |
| `verify_agent` | "Is this agent verified?" | `GET /v1/agents/{agent_id}/attestation` |
| `register_agent` | "Register this agent / put my agent on record" | `POST /v1/register/agent` |
| `register_content` | "Register this work / put this on record" | `POST /v1/register/content` |
| `explain_verification` | "What does Verified by NPC mean?" | static public-safe explainer |

Tool descriptions carry the trigger phrasing ("is this real?", "verify
this", "is this authentic?") so the agent-recommends channel can surface
them mid-conversation. Full reference: [`docs/TOOLS.md`](docs/TOOLS.md).

The two registration tools start what the verify tools later read:
they return the signed registration record ("registered, checks
pending"). Registration is not verification — no verdict, no mark.
Registration is free and needs no API key; the API's own abuse
minimums (a required email, per-email and per-IP submission caps)
govern it, and rejections surface as errors, never as registrations.

## Security model

- **Verify, don't trust.** Every API response body is canonicalized and
  Ed25519-signed by the API. The client checks the `X-NPC-Signature`
  header against the API's published keys (`GET /v1/keys`, current +
  rotation history) on every call. A failed check is fail-closed: the
  caller gets an error, never the data.
- **Fail-closed errors.** Unknown subject → `"unknown"`. Missing or bad
  arguments → error, not a guess. Unreachable API → error naming the
  fix. Tampered response → error.
- **No PII beyond public.** Tool outputs are the API's already-sanitized
  responses, passed through unchanged.
- **No mark usage.** The "Verified by NPC" mark ships only after counsel
  clearance (program gate §8). The capability builds now.

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `NPC_VERIFY_API_URL` | `https://api.npclabs.xyz` | API base URL |
| `NPC_VERIFY_API_KEY` | bundled public read-only verifier key | Verifier API key override |
| `NPC_VERIFY_API_PATH` | auto-detected | Override: dir holding the `api/` tree |

## What this does NOT do

- No attestation issuance: `POST /v1/attestations` stays NPC-internal
  and is not exposed. Registration starts verification; it issues no
  attestation and no mark.
- No mark usage in the server itself.
- No methodology exposure: `explain_verification` teaches the why only.
