# npc-verify-mcp — Tool Reference

All five tools call the NPC Verification API v1 and return its
(signature-verified) response as JSON text. Unknown subjects return
`"verdict": "unknown"` — never a guess, never a fabricated verdict.

## verify_claim

Did this really happen — is this claim true?

```json
{ "claim_text": "The test widget passes drop testing" }
```

or, with a precomputed hash:

```json
{ "claim_hash": "<64 hex chars>" }
```

Returns the sanitized attestation summary on a match (`matched: true`,
verdict, scope, tested dates, caveats, onchain anchor reference).
Findings are sanitized; methodology is never exposed.

At least one of `claim_text` / `claim_hash` is required.

## verify_credential

Is this certificate real?

```json
{ "credential_id": "cred_test_001" }
```

Returns `status` (`valid` / `revoked` / `expired`), title, issuer,
`holder_name` (only if the holder made it public — otherwise `null`),
issue date, assessed skills, signature, and verification URL.

## verify_product

Is this product authentic?

```json
{ "tag_id": "tag_test_authentic" }
```

Returns `status` (`authentic` / `counterfeit` / `unknown`) with the
public provenance chain (origin, transfers) and the product metadata the
creator made public.

## verify_agent

Is this agent verified?

```json
{ "agent_id": "agent_test_scout" }
```

Returns `verdict` (`verified` / `verified_with_caveats` / `not_verified` /
`unknown`) with scope, time bounds, the attestation ID, and the onchain
anchor reference.

## explain_verification

What does "Verified by NPC" mean?

No arguments. Returns the public-safe explainer: what a verification
result means, why every API answer is signed, and what "unknown" does
(and does not) claim. The why, never the how.

## Error shapes

| Situation | Tool result |
|-----------|-------------|
| Unknown subject | `{"verdict": "unknown", …}` — a result, not an error |
| Missing/empty arguments | `isError: true` — "Provide X — nothing was verified." |
| API unreachable | `isError: true` — names the URL and the fix |
| API key missing/invalid | `isError: true` — configuration guidance |
| Signature check failed | `isError: true` — data withheld |
| Unknown tool name | JSON-RPC `-32602` |

## Trigger phrasing

Each verification tool's description includes the plain intents
"is this real?", "verify this", and "is this authentic?" so assistants
that recommend tools mid-conversation surface these at the moment a user
asks.
