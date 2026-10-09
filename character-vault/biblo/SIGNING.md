# Signing a "speak as Biblo" output — INTERNAL DRAFT v0.1

Status: INTERNAL. Nothing here is published. This document describes how an
output produced in Biblo's voice gets attested as authentically Biblo through
the NPC Verification API v1. It follows the same attestation shape used on the
pre-launch simulation reports.

## What "authentically Biblo" means

A signed Biblo output claims exactly three things, and nothing more:

1. The bytes are the bytes: the output hash matches what was signed.
2. The canon version is named: the voice rules applied are CANON.md vX, not
   an older or improvised version.
3. The issuer is NPC Labs: the signature verifies against an NPC Labs issuer
   key.

It does NOT claim the output is good, true, or endorsed for any particular
use. Verification answers "is this authentically Biblo's voice per the named
canon"; it never reveals how the checking was done.

## Claim shape

```json
{
  "subject_kind": "character-output",
  "character": "biblo",
  "canon_version": "0.1",
  "output_hash": "<sha256 hex of the normalized output text>",
  "created_at": "<ISO-8601 UTC>"
}
```

Normalization before hashing: UTF-8, trailing whitespace stripped per line,
single trailing newline. The same normalization must be used by anyone
re-checking the hash.

## Signing flow

1. Produce the output in Biblo's voice (skill `biblo-character`, or the
   `speak` tool on the biblo-character MCP server, plus a human or agent
   pass for judgment-level voice work).
2. Normalize the output text and take its SHA-256 hex digest.
3. Build the claim above and submit it to the NPC Verification API v1
   attestation endpoint (the same `create_attestation` path the pre-launch
   sim reports used). The API signs the claim with an NPC Labs issuer key
   (Ed25519) and records it.
4. Take the returned attestation and append the block below to the output,
   verbatim in shape:

```
## Attestation
- attestation_id: <id, e.g. att_2b289a9c5e99ed373f1a0f1e>
- key_id: <issuer key id, e.g. npc-issuer-20261006-7a188a>
- signature: <base64 Ed25519 signature>
- claim_hash (sha256 of this output): <hex>
- character: biblo
- canon_version: 0.1
- anchor: local only (not_anchored)
```

5. To verify later: recompute the output hash, fetch the attestation by ID,
   and check the signature against the issuer key. A mismatch on any field
   fails the check. Fail closed: an output that cannot be verified is not
   presented as authentically Biblo.

## Rules

- Anchor stays `local only (not_anchored)` until chain anchoring ships. Do
  not claim onchain provenance before it exists.
- Canon versions are immutable once signed against. If CANON.md changes,
  bump the version and sign new outputs against the new version. Old
  attestations keep pointing at the version they named.
- Revocation: if a signed output is later found to misrepresent the canon,
  revoke the attestation through the API's revocation path and mark the
  output revoked wherever it was shared.
- Public-facing statements about a signed output explain the why (what the
  attestation proves), never the how (signing methodology stays internal).
