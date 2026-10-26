# npc-verify-mcp — Tool Reference

All seven tools call the NPC Verification API v1 and return its
(signature-verified) response as JSON text. Unknown subjects return
`"verdict": "unknown"` — never a guess, never a fabricated verdict.
The two registration tools return the signed registration record —
never a verdict.

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

## register_agent

Register this agent: put an agent on record and start its verification.

```json
{ "agent_name": "Ledger Lark", "owner_name": "Wren Okafor",
  "owner_email": "wren@example.org",
  "homepage": "https://example.org/ledger-lark",
  "description": "Reconciles small-business ledgers overnight." }
```

`agent_name`, `owner_name`, and `owner_email` are required; give a
`homepage` or a `description` (at least one). Returns the signed
registration record: its own NPC ID (`record_id`), status
`registered_checks_pending` ("registered, checks pending"), the checks
that ran at registration, and those still pending. Registration is not
verification: no verdict, no mark. The owner email is kept by NPC Labs
for the registration only and never appears in the record. The API's
submission caps (per email, per IP) apply; a cap or a validation
problem returns an error carrying the API's own detail, never a record.

## register_content

Register this work: put a piece of content on record and start its
verification.

```json
{ "title": "Harbor at first light", "kind": "image",
  "locator": "https://example.org/harbor.png",
  "creator_name": "Wren Okafor", "creator_email": "wren@example.org" }
```

All five fields are required. `kind` is one of `image`, `text`,
`audio`, `video`, `other`. `locator` is the work's web address or its
SHA-256 content hash. Returns the signed registration record (same
shape as `register_agent`). For an image at a URL, the intake checks
that can run, run: the fetch and its SHA-256, a structural read of any
Content Credentials, and the AI image check as a signal; what did not
run is listed in the record with its reason. The creator email never
appears in the record.

## explain_verification

What does "Verified by NPC" mean?

No arguments. Returns the public-safe explainer: what a verification
result means, why every API answer is signed, and what "unknown" does
(and does not) claim. The why, never the how.

## Error shapes

| Situation | Tool result |
|-----------|-------------|
| Unknown subject | `{"verdict": "unknown", …}` — a result, not an error |
| Missing/empty arguments | `isError: true` — "Provide X — nothing was verified." (registration tools: "nothing was registered.") |
| API validation rejection (registration) | `isError: true` — "Registration failed: API returned 422: …" with the API's own problem list |
| API submission cap hit (registration) | `isError: true` — "Registration failed: API rate limit hit (429) — …" with the API's retry guidance |
| API unreachable | `isError: true` — names the URL and the fix |
| API key missing/invalid | `isError: true` — configuration guidance |
| Signature check failed | `isError: true` — data withheld |
| Unknown tool name | JSON-RPC `-32602` |

## Trigger phrasing

Each verification tool's description includes the plain intents
"is this real?", "verify this", and "is this authentic?" so assistants
that recommend tools mid-conversation surface these at the moment a user
asks.
