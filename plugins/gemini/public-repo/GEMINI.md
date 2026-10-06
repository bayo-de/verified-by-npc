# Verified by NPC (Gemini CLI extension)

This extension answers one question inside the conversation: **is this real?**

## The five actions

| Slash command | Action | What it answers |
|---|---|---|
| `/verify-product <tag-id>` | `verify_product` | Is this product authentic? (smart-tag lookup) |
| `/verify-credential <credential-id>` | `verify_credential` | Is this certificate real? (valid, revoked, expired, unknown) |
| `/verify-claim <claim text>` | `verify_claim` | Did this really happen? (attestation record match) |
| `/verify-agent <agent-id>` | `verify_agent` | Is this agent verified? (verdict, scope, time bounds) |
| `/explain-verification` | `explain_verification` | What does Verified by NPC mean? |

Each command runs the bundled helper (`npc_verify_gemini`), a thin client over
the NPC Verification API v1. The helper checks the Ed25519 signature on every
API response before the answer is used. The full action-to-endpoint mapping
lives in `operations.json`.

## Rules the model follows

- **Fail closed.** An unknown subject is reported as `unknown`. Unknown is not
  a claim that the subject is false, and it is never presented as verified.
- **Never fabricate.** If verification fails (bad signature, unreachable API,
  missing key), say so. Do not guess a verdict.
- **The why, never the how.** Explain what a result means. Never describe how
  verification is performed.
- **Read-only.** This extension verifies. It cannot issue attestations.

## Setup

Set the API location and key (or accept the prompts on first install):

```bash
export NPC_VERIFY_API_URL="http://127.0.0.1:8787"   # local API during development
export NPC_VERIFY_API_KEY="<verifier key>"
```

Install for local use:

```bash
gemini extensions link /path/to/npc-verify-gemini
# or, from the public repo:
gemini extensions install github.com/bayo-de/npc-verify-gemini
```

The extension directory must be named `npc-verify` (it matches the manifest
`name`), so the slash commands find the helper at
`~/.gemini/extensions/npc-verify/npc_verify_gemini`.
