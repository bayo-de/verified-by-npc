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
  reused from the API reference implementation.
- **Local-first.** Talks to the API at `http://127.0.0.1:8787` by default
  (override with `NPC_VERIFY_API_URL`).

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
    tools.py           # the five tools (schemas + thin handlers)
    api_client.py      # API v1 HTTP client + signature verification
  tests/
    test_tools.py      # per-tool tests against seeded fixtures
    test_signature.py  # signature verification incl. tamper rejection
    test_contracts.py  # Proofline-style contract suite
    test_transport.py  # stdio JSON-RPC round trips
```

## Quick start

```bash
# 1. Start the Verification API (it must be running first)
cd ~/workspace/grand-fleet/verified-by-npc/api
python3 -m npc_verify
# First run prints TEST API keys — save the verifier key.

# 2. Install the MCP server
cd ~/workspace/grand-fleet/verified-by-npc/plugins/mcp
pip install -e .

# 3. Configure the environment (or put these in the MCP client config)
export NPC_VERIFY_API_URL="http://127.0.0.1:8787"   # default
export NPC_VERIFY_API_KEY="npc_test_..."             # verifier key from step 1

# 4. Run the tests
python3 -m unittest discover -s tests
```

## Claude Desktop config

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "npc-verify": {
      "command": "npc-verify-mcp",
      "env": {
        "NPC_VERIFY_API_URL": "http://127.0.0.1:8787",
        "NPC_VERIFY_API_KEY": "npc_test_..."
      }
    }
  }
}
```

The API must be running before the client connects — start it with
`python3 -m npc_verify` in `../api/`. If the key is missing, the tools
report a configuration error instead of guessing.

## The five tools

| Tool | Answers | Backend |
|------|---------|---------|
| `verify_claim` | "Did this really happen / is this claim true?" | `POST /v1/claims/verify` |
| `verify_credential` | "Is this certificate real?" | `GET /v1/credentials/{id}` |
| `verify_product` | "Is this product authentic?" | `GET /v1/products/{tag_id}` |
| `verify_agent` | "Is this agent verified?" | `GET /v1/agents/{agent_id}/attestation` |
| `explain_verification` | "What does Verified by NPC mean?" | static public-safe explainer |

Tool descriptions carry the trigger phrasing ("is this real?", "verify
this", "is this authentic?") so the agent-recommends channel can surface
them mid-conversation. Full reference: [`docs/TOOLS.md`](docs/TOOLS.md).

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
| `NPC_VERIFY_API_URL` | `http://127.0.0.1:8787` | API base URL |
| `NPC_VERIFY_API_KEY` | (required) | Verifier API key (`npc_test_…`) |
| `NPC_VERIFY_API_PATH` | auto-detected | Override: dir holding the `api/` tree |

## What this does NOT do

- No attestation issuance (read-first; `POST /v1/attestations` is not exposed).
- No public endpoint, no directory listing, no mark usage.
- No methodology exposure — `explain_verification` teaches the why only.
