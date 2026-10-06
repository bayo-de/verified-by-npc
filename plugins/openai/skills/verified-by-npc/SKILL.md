---
name: verified-by-npc
description: Verify products, credentials, claims, and AI agents against NPC Labs' attestation records. Use when someone asks: is this real? verify this. is this authentic?
---

# Verified by NPC

Answer the question "is this real?" with a signed, checkable record instead of
an opinion. This skill describes the five verification operations. All of them
read from the NPC Verification API v1; none of them issue attestations, and
none of them reveal how the checking was done.

## Operations

### verify_product
Check whether a physical product is authentic through its NPC smart tag.
- Input: `tag_id` (the smart-tag ID on the product)
- API: `GET /v1/products/{tag_id}`
- Result: `authentic`, `counterfeit`, or `unknown`, plus the public provenance
  chain (origin and transfers the creator made public).

### verify_credential
Check whether a certificate or credential is real.
- Input: `credential_id`
- API: `GET /v1/credentials/{id}`
- Result: `valid`, `revoked`, `expired`, or `unknown`, with the credential
  title, issuer, and issue date. The holder's name appears only if the holder
  made it public.

### verify_claim
Check a claim against NPC Labs' attested records: did this really happen, is
this claim true?
- Input: `claim_text` or `claim_hash` (SHA-256 hex of the normalized claim)
- API: `POST /v1/claims/verify`
- Result: whether an attestation matched, and if so the sanitized attestation
  summary (verdict, scope, tested dates, caveats, onchain anchor reference).
  Findings are sanitized; methodology never leaves the building.

### verify_agent
Check an AI agent's verification status.
- Input: `agent_id`
- API: `GET /v1/agents/{agent_id}/attestation`
- Result: `verified`, `verified_with_caveats`, `not_verified`, or `unknown`,
  with scope, time bounds, attestation ID, and onchain anchor.

### explain_verification
Explain what "Verified by NPC" means, when someone asks what a result means.
This is a static, public-safe explainer served by the plugin itself. No API
call. It explains the why, never the how:
- "Verified by NPC" means an independent attestation record exists for the
  subject: what was checked, when it was checked, and the verdict.
- "verified" means NPC Labs checked the subject against a defined scope and
  signed the result.
- Every API answer is cryptographically signed, so it can be checked without
  trusting the connection it arrived over.
- "unknown" means NPC Labs has no record of the subject. It is not a claim
  that the subject is false.

## Rules that always hold

- Fail closed. An unknown subject returns `unknown`, never a guess and never
  a fabricated verdict. An unverifiable claim is reported as unverifiable,
  not as false.
- Trust the signature, not the transport. Every API response carries an
  Ed25519 signature in the `X-NPC-Signature` header with the signing key ID
  in `X-NPC-Key-ID`. Public keys are published at `GET /v1/keys`. A response
  that fails verification is discarded, and the subject is treated as
  `unknown`.
- Read only. This plugin verifies. It cannot record attestations, and it
  never asks the API to do so.
- Privacy preserving. Record contents stay local to the API; API responses
  carry no PII beyond what the subject made public.

## HTTP details

- Base URLs: `https://api.npclabs.xyz/v1` (production; deployment gated) and
  `http://127.0.0.1:8787/v1` (local development).
- Auth: Bearer API key with the `verifier` role.
- Errors: `404` returns `{"verdict": "unknown"}` for unrecognized subjects.
  `401` means the API key is missing or rejected. `429` means slow down and
  retry.
- The full machine-readable action surface is in `openapi-plugin.yaml`.
