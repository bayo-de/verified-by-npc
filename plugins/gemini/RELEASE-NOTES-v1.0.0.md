# Verified by NPC for Gemini CLI v1.0.0

Ask "is this real?" inside your Gemini CLI conversation, and get an answer you can check.

Verified by NPC checks products, credentials, claims, and AI agents against NPC Labs verification records. Every answer comes from the NPC Verification API v1, and every API response is signature-checked (Ed25519) before it is used. If verification cannot be completed, the extension says so. It never guesses.

## The five slash commands

- `/verify-product <tag-id>` - Is this product authentic? Smart-tag lookup. Returns authentic, counterfeit, or unknown.
- `/verify-credential <credential-id>` - Is this certificate real? Returns valid, revoked, expired, or unknown.
- `/verify-claim <claim text>` - Did this really happen? Checks attestation records. Returns the record or unknown.
- `/verify-agent <agent-id>` - Is this agent verified? Returns the verdict with its scope and time bounds.
- `/explain-verification` - What does "Verified by NPC" mean?

Or just ask in plain words. "Is this real?" and Gemini picks the right command.

## Ground rules, baked in

- **Fail closed.** Unknown means NPC Labs has no record of the subject. Unknown is never presented as false, and never presented as verified.
- **Read-only.** It verifies. It cannot issue attestations.
- **The why, never the how.** It explains what a result means, never how verification is performed.

## Install

```bash
gemini extensions install github.com/bayo-de/npc-verify-gemini
```

You need an NPC Verification API v1 endpoint and a verifier API key. Accept the settings prompts on install, or export `NPC_VERIFY_API_URL` and `NPC_VERIFY_API_KEY` yourself.

The bundled helper is Python 3 standard library only. MIT license. Built by NPC Labs.
