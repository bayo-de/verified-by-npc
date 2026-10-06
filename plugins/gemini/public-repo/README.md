# Verified by NPC for Gemini CLI

Ask "is this real?" inside your Gemini CLI conversation, and get an answer you can check.

Verified by NPC checks products, credentials, claims, and AI agents against NPC Labs verification records. Every answer comes from the NPC Verification API v1, and every API response is signature-checked before it is used. If verification fails, the extension says so. It never guesses.

## The five slash commands

| Command | What it answers |
|---|---|
| `/verify-product <tag-id>` | Is this product authentic? (smart-tag lookup) |
| `/verify-credential <credential-id>` | Is this certificate real? (valid, revoked, expired, unknown) |
| `/verify-claim <claim text>` | Did this really happen? (attestation record match) |
| `/verify-agent <agent-id>` | Is this agent verified? (verdict, scope, time bounds) |
| `/explain-verification` | What does "Verified by NPC" mean? |

## What a result means

- **verified / authentic / valid** means NPC Labs checked the subject against a defined scope and signed the result.
- **unknown** means NPC Labs has no record of the subject. Unknown is not a claim that the subject is false, and it is never presented as verified.
- If verification cannot be completed (unreachable API, missing key, bad signature), the extension says so instead of guessing.

The extension explains what a result means. It never describes how verification is performed. It is read-only: it verifies, it cannot issue attestations.

## Install

Requires the Gemini CLI and Python 3. The helper uses the Python standard library only.

```bash
gemini extensions install github.com/bayo-de/npc-verify-gemini
```

Or link a local checkout. The directory must be named `npc-verify`, matching the extension manifest:

```bash
git clone https://github.com/bayo-de/npc-verify-gemini.git npc-verify
gemini extensions link /path/to/npc-verify
```

## Configure

You need an NPC Verification API v1 endpoint and a verifier API key. During development, point the extension at a local instance.

Accept the settings prompts on install, or set them yourself:

```bash
export NPC_VERIFY_API_URL="http://127.0.0.1:8787"
export NPC_VERIFY_API_KEY="<your verifier API key>"
```

Then, in the conversation:

```
/verify-product tag_abc123
```

Or just ask in plain words. "Is this real?" and Gemini will use the right command.

## Files

- `gemini-extension.json` - the extension manifest (name, version, settings).
- `commands/*.toml` - the five slash commands.
- `operations.json` - the action-to-endpoint map for the API.
- `GEMINI.md` - the context Gemini loads with the extension, including the rules every answer follows.
- `npc_verify_gemini/` - the thin helper. It calls the API and checks the signature on every response before the answer is used. Standard library only.
- `npc_verify/` - the signature-checking primitives bundled with the extension (canonical JSON + Ed25519), reused from the API reference implementation.

## License

MIT. See `LICENSE`.

Built by NPC Labs.
