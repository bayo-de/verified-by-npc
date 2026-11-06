# NPC Verification API v1 — API Documentation

**Version:** 1.0.0 · **Status:** Phase 1, local-first · **Internal only**

The Verification API answers one question: *is this real?* It verifies
claims, credentials, products, and agents against NPC Labs' attestation
records. v1 is read-first — it verifies; it does not issue attestations
to third parties.

Base URL (local): `http://127.0.0.1:8787/v1`
Spec: [`openapi.yaml`](../openapi.yaml) (OpenAPI 3.1)

---

## 1. Authentication

All endpoints except `GET /v1/health` and `GET /v1/keys` require a Bearer
API key:

```
Authorization: Bearer npc_test_...
```

**Roles**

| Role       | Can do |
|------------|--------|
| `verifier` | All lookups and claim verification |
| `issuer`   | Everything a verifier can, plus `POST /v1/attestations` |

A key with an insufficient role gets `403`. A missing or invalid key gets
`401`. Keys are stored as SHA-256 hashes; the plaintext is shown once at
creation. Test keys use the `npc_test_` prefix and must never be treated
as production credentials.

**Rate limits:** 60 requests/minute per key by default. Exceeding the limit
returns `429` with `retry_after_seconds` in the body.

## 2. Signed responses — verify, don't trust

Every response body is canonicalized and Ed25519-signed by NPC:

- Canonical form (NPC-JCS-v1): UTF-8, object keys sorted, no insignificant
  whitespace.
- Signature: `X-NPC-Signature` header (base64).
- Signing key: `X-NPC-Key-ID` header.
- Public keys: `GET /v1/keys` (current keys + rotation history), so you can
  verify offline.

**Reference verifier (Python, standard library only):**

```python
import base64, json, urllib.request

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

# fetch the signing key
keys = json.load(urllib.request.urlopen("http://127.0.0.1:8787/v1/keys"))
cur = keys["api_signing"]["current"]
pub = base64.b64decode(cur["public_key"])

# fetch any endpoint, then verify with the vendored Ed25519 module
from npc_verify import ed25519
req = urllib.request.Request("http://127.0.0.1:8787/v1/health")
resp = urllib.request.urlopen(req)
body = resp.read()
sig = base64.b64decode(resp.headers["X-NPC-Signature"])
assert resp.headers["X-NPC-Key-ID"] == cur["key_id"]
assert canonical(json.loads(body)) == body, "body is not canonical"
assert ed25519.verify(pub, body, sig), "bad signature"
print("verified:", json.loads(body))
```

Key rotation never breaks old signatures: retired keys stay published in
`history` with their `retired_at` timestamps.

## 3. Endpoints

### GET /v1/health

No auth. Liveness, the active signing key ID, and chain status.

```json
{
  "status": "ok",
  "version": "1.0.0",
  "key_id": "npc-api_signing-20261005-x1y2",
  "chain": {
    "network": "none",
    "anchoring": "disabled",
    "mode": "local-first",
    "note": "Phase 1 records anchor hashes locally; no chain writes until the mainnet gate clears."
  },
  "time": "2026-10-05T23:00:00+00:00"
}
```

### GET /v1/keys

No auth. Current API-signing key, its rotation history, and issuer public
keys. No private material is ever published.

### GET /v1/credentials/{id}

Credential lookup. `status` is `valid`, `revoked`, or `expired`.
`holder_name` is present only if the holder made it public — otherwise
`null`, always.

Unknown ID → `404 {"verdict": "unknown"}`.

### POST /v1/claims/verify

Body: `{"claim_text": "..."}` or `{"claim_hash": "<64 hex chars>"}`.

Claim text is normalized (trimmed, whitespace collapsed, lowercased) and
SHA-256 hashed before lookup, so minor formatting differences still match.
A match returns the sanitized attestation summary: verdict, scope, tested
dates, caveats, and the onchain anchor reference. Findings are sanitized;
methodology is never exposed.

A hash with no attestation may still match a public registration:
registrations are indexed by the hash of their locator address and by
the content hash recorded at intake (the lookup a browser extension
performs for an image on a page). That answer has `matched: true` and
`match_type: "registration"`, carries the registration's record ID,
creator, title, and registered date, and states the record's own
standing, "registered, checks pending". A registration is not a
verification: no verdict is issued and no verification mark exists for
it.

No match → `404 {"verdict": "unknown", "matched": false}`. An
unverifiable claim is reported as unknown, never as false.

### GET /v1/products/{tag_id}

Smart-tag authenticity lookup. `status` is `authentic`, `counterfeit`, or
`unknown`, with the public provenance chain (origin, transfers).

Unknown tag → `404 {"verdict": "unknown"}`.

### GET /v1/agents/{agent_id}/attestation

Agent verification status: `verified`, `verified_with_caveats`,
`not_verified`, or `unknown`, with scope, time bounds, the attestation ID,
and the onchain anchor reference.

Unknown agent → `404 {"verdict": "unknown"}`.

### POST /v1/images/ai-check

**Verifier role required.**

AI-generation check for one image, backed by the Sightengine genai
model. The request carries the image itself as base64
(`image_base64`, at most 750 KB decoded) or its address
(`image_url`); exactly one of the two. Sightengine credentials live
only in the server environment (`SIGHTENGINE_API_USER`,
`SIGHTENGINE_API_SECRET`); no client ever sees them, and the
extension only calls this API.

The answer carries the detector probability as an integer percent
(`ai_generated_percent`, 0 to 100): the signed envelope is defined
over strings, booleans, integers and nulls, and a float would not
canonicalize identically on every client. Bytes mode also returns
`image_sha256` so a result can be tied to the exact file checked.

When detection is not configured on the server, or Sightengine
cannot complete the check, the answer is `503
{"error": "detector_unavailable", ...}`. A score is never fabricated.

### POST /v1/attestations

**Issuer role required. NPC-issued only in v1.**

Records a new attestation. NPC signs the canonical attestation core with
the active issuer key and stores it. The SHA-256 anchor hash is recorded
locally; **no chain write occurs in Phase 1** — `onchain_anchor.status`
is `not_anchored` and `tx` is `null`. The hash is testnet-ready for later
anchoring via the FleetAttestationRegistry pattern
(contents stay local, hashes go onchain).

Request:

```json
{
  "subject_type": "claim",
  "subject_id": "claim:abc123",
  "verdict": "verified",
  "scope": {"domain": "electronics"},
  "tested_at": "2026-10-01T00:00:00+00:00",
  "expires_at": null,
  "findings_summary": "Lab-tested against the published spec.",
  "claim_hash": "…optional 64 hex chars…"
}
```

Response (`201`):

```json
{
  "id": "att_9f2e…",
  "signature": "base64…",
  "key_id": "npc-issuer-20261005-x1y2",
  "onchain_anchor": {
    "chain": "base",
    "tx": null,
    "hash": "…64 hex chars…",
    "status": "not_anchored"
  },
  "created_at": "2026-10-05T23:00:00+00:00"
}
```

Invalid payloads → `422` with a plain-language reason. Revocation is a
separate signed record, never an edit (see §5).

### POST /v1/memory/agents

**Issuer role required.** Registers an agent's attestation public key and
its place in the company → team tree. The API key's scope must cover the
agent's scope; agent-scoped keys cannot register agents. Registering the
same `agent_id` with the same key is idempotent (`already_registered`); a
different key for the same id is a `409` conflict.

Request:

```json
{
  "agent_id": "sentinel",
  "company_id": "acme",
  "team_id": "core",
  "public_key_b64": "base64-of-32-byte-ed25519-key"
}
```

### POST /v1/memory/records

**Verifier role or above.** Appends a signed memory record to a stream.
Records are built and signed locally (see the `npc_memory` library); the
API verifies before storing, fail-closed:

1. shape validation (`422` on problems),
2. write-boundary secret check — refused, never stored (`422`),
3. API-key scope covers the stream (`403`),
4. fleet-stream writes need an issuer key (`403`),
5. the writer is a registered agent whose scope covers the stream (`403`),
6. the Ed25519 signature verifies against the registered key (`422`),
7. `seq` continues the stream chain and `prev_hash` matches (`409` fork).

Supersede/retract records must target a live record in the same stream;
targeting a missing, retracted, or already-superseded record is a `409`.

### GET /v1/memory/records/{id}

**Verifier role or above.** Returns the record plus its verification
status: `signature` (`valid`/`invalid`/`unverifiable`), `chain_intact`,
`superseded_by`, `retracted`, and overall `standing`
(`live`/`superseded`/`retracted`). Out-of-scope reads return the same
`404` as unknown ids — existence is never confirmed across scopes.

### POST /v1/memory/recall

**Verifier role or above.** Tag, recency, and keyword recall over the
streams the key's scope covers. Omit stream filters to search all of
them, or narrow by `stream_kind` (+ dims) or exact `stream_key`. Every
hit carries its verification status. Vector recall is out of scope
for v1.

Request:

```json
{
  "tags": ["regime"],
  "q": "funding",
  "since": "2026-10-01T00:00:00+00:00",
  "limit": 50,
  "live_only": false
}
```

**Company layer.** API keys carry `company_id` / `team_id` / `agent_id`
scope (set at key creation). An agent-scoped key touches only its own
agent stream; a team-scoped key reaches the team stream and its agents;
a company-scoped key reaches the whole company; an unscoped key reaches
everything including the fleet stream (writes there still need an
issuer key). Reads are wider than writes: a key reads streams on its
branch in either direction (an agent reads its team and company streams)
plus the fleet stream. Every memory carries its verification status.

### Onchain anchoring (Base)

Registration records gain a second, independent witness: the
registry periodically batches the registrations it has not yet
anchored, computes one Merkle root over the records' canonical
hashes, and writes that root to Base mainnet in a single
transaction. The lane is off unless `NPC_ANCHOR_ENABLED=1`; the
anchoring key lives only in the Lambda environment
(`NPC_ANCHOR_PRIVATE_KEY`), the same channel as the signing seed.

**Verify a record's anchor yourself.** `GET /v1/records/{id}` on a
registration returns a read-time `anchor` section (the stored
record is never edited). When it says `"status": "anchored"`:

1. Drop the `anchor` key from the body. Canonicalize the rest
   (NPC-JCS-v1, the same canonical form the record's signature
   uses) and take SHA-256: the digest is the section's `leaf_hash`.
   The hash input is the public record only; the registrant email
   is a server-side store field and is never in a record.
2. Walk `proof`: each step names a sibling hash and its side;
   SHA-256 the pair in order, leaf level first. The walk ends at
   `merkle_root`.
3. Open the transaction (`explorer_url`) on Basescan and read its
   input: bytes 0..12 are the ASCII magic `NPC-ANCHOR-V2`, bytes
   13..45 are the batch root, bytes 45..110 are the signer
   wallet's batch signature. The root equals `merkle_root`.
4. Check the authorship: rebuild the commitment statement
   (`NPC Verify anchor batch` / `Batch: <batch_id>` /
   `Merkle root: <root>` / `Chain: Base (8453)`) and verify the
   signature recovers to the section's `signer_wallet`, which must
   be the signer authorized at the batch's time (the rotation
   history is public at `GET /v1/anchor/authority`).

Anchoring is a public timestamp, never a verification: it proves
the record existed in that exact form at the block's time, and it
never changes the record's status. Before a record's batch lands,
the section honestly says `not_anchored` or `anchor_pending`. With
the lane off and no anchor data on record, the section is absent
entirely.

**Authority: two wallets, two jobs.** The OWNER wallet is fresh,
created for this lane; its key lives only in the Lambda
environment (`NPC_ANCHOR_PRIVATE_KEY`), and it submits and relays
every anchor transaction. The onchain sender is therefore the
owner wallet. The SIGNER wallet is Bayo's main NPC wallet (the
legacy wallet, in his MetaMask since 2017); its key never comes
near this service. Every batch carries the signer wallet's EIP-191
signature over the batch commitment, obtained from Bayo through
MetaMask and carried inside the anchor transaction itself, so the
legacy wallet's authorship rides in every batch as a verified
signature. The owner wallet is also the sole rotation authority:
it alone can authorize, revoke, or rotate the signer, by an
owner-signed rotation notice (below). A compromised signer is
recoverable (the owner rotates it; its past batches stay provable
against the public rotation history), and a compromised signer
cannot install its own successor, because rotation takes the
owner key it does not have. (If the sender itself must ever be
the legacy address, the fallback is manual MetaMask submission
per batch; that is a product decision, not built here.)

### POST /v1/internal/anchor/run

**Issuer role.** One anchoring pass: finalize an open batch; or
submit a prepared batch that carries its signer signature; or
prepare the next batch (every unanchored registration, up to
`NPC_ANCHOR_BATCH_MAX`, default 500), which then stops at
`awaiting_signature` with the exact commitment statement the
signer signs. The batch and its signed transaction persist before
any broadcast, so a crash recovers by reading the chain back. The
summary answers honestly in every state: `anchored`,
`submitted`, `awaiting_signature`, `unfunded` (the owner wallet
cannot cover the fee yet; the prepared batch waits), `idle`,
`failed` (records return to the pool), `disabled`,
`not_configured`, `submit_error`, `chain_error`. The scheduled
caller is whatever cron the operator points at this endpoint.

### POST /v1/internal/anchor/sign

**Issuer role.** Records the signer wallet's signature for a
prepared batch. Body: `batch_id` and `signature` (the EIP-191
personal signature over the commitment statement). The signature
records only when it recovers to the currently authorized signer:
400 `signer_not_authorized` for a genuine signature from any
other wallet, 400 `invalid_signature` for a malformed one, 404
`unknown_batch`, 400 `batch_locked` once the batch is submitted.
On success the next run pass submits the batch.

### GET /v1/internal/anchor/status

**Issuer role.** Lane state, the owner wallet's address and
balance, batch counts, records anchored and waiting, the open
batch (with its commitment statement while it awaits a
signature), and the authority state: `signer_configured`,
`authorized_signer`, `rotations_recorded`.

### POST /v1/internal/anchor/rotate-signer

**Issuer role.** Rotates the authorized signer. Body:
`to_signer_address` and an optional `note`. The endpoint builds a
rotation notice (type `npc.anchor.signer_rotation`, version 1,
`from_signer`, `to_signer`, `issued_at`, `note`), signs it with
the OWNER key (EIP-191 over the notice's canonical NPC-JCS-v1
bytes), verifies its own signature, and only then records it.
Rotating to the current signer answers 400 `invalid_rotation`;
with no owner key configured, 409 `owner_not_configured`.

### GET /v1/anchor/authority

**Public.** The authority statement: `owner_wallet`,
`authorized_signer`, and `signer_rotations`, the complete list of
owner-signed rotation notices. Public because the authority claim
must be inspectable by the same people who verify anchor proofs.
With the lane off it fails closed (404).

**Approved next layer (not built): wallet claiming.** A
registrant will be able to claim a record with their own wallet:
the wallet signs a claim statement and the record gains a
claimed-by attestation naming that wallet. Claiming changes
nothing about the record's status or its anchor.

## Unified accounts (Gate G1)

One account per person, rooted at an email address, shared by the
main site, this API's web surface, and the desktop app (design
decided 2026-10-24). These endpoints authenticate with the
account **session token** (`Authorization: Bearer npc_sess_...`),
never with an API key: the two credential families are separate,
and neither is accepted in the other's place. Every secret at
rest (session tokens, email-link tokens, handoff secrets,
recovery codes) is stored only as a SHA-256 hash.

- `GET /auth/sign-in` — the browser sign-in page (HTML, unsigned:
  a page is not a record). Runs the passkey ceremonies, the email
  link request, and recovery code entry, and shows the account's
  signed-in devices after a sign-in.
- `POST /v1/auth/email/request` `{email, handoff_id?}` — creates
  the account if needed and emails a one-time sign-in link
  (15 minutes, single use; a fresh request retires earlier links).
  The answer never reveals whether the account already existed.
- `POST /v1/auth/email/redeem` `{token, surface?, device_label?}`
  — trades the link for a device session. On an account that
  already holds passkeys this is also the support-assisted
  recovery path: control of the email is the proof, and the
  redemption is written to the account's event log.
- `POST /v1/auth/passkeys/register/begin` (session) and
  `POST /v1/auth/passkeys/register/finish` (session) — WebAuthn
  registration. The first passkey on an account also returns ten
  one-time **recovery codes**, shown once and stored as hashes.
- `POST /v1/auth/passkeys/authenticate/begin` `{email?}` and
  `POST /v1/auth/passkeys/authenticate/finish` — WebAuthn
  authentication (discoverable when no email is given). Verified
  server-side: challenge, origin allowlist, RP hash, user
  presence, signature (ES256, EdDSA, RS256), and signature-counter
  monotonicity. Attestation formats accepted at registration:
  `none` and `packed`.
- `POST /v1/auth/recovery/redeem` `{email, code, surface?,
  device_label?}` — trades one recovery code for a session. The
  failure shape is identical for an unknown email and a wrong
  code.
- `GET /v1/auth/me` (session) — the account and the calling
  session.
- `GET /v1/auth/sessions` (session) — every live device session
  on the account, the caller's own flagged `current`.
- `POST /v1/auth/sessions/revoke` (session) `{session_id}` —
  revoke any of the account's sessions from any surface.
- `POST /v1/auth/sign-out` (session) — revokes the caller's own
  session.
- `POST /v1/auth/handoff` `{device_label?}` — the desktop app
  opens a handoff and sends the user to the returned
  `authorize_url` in their browser. `POST /v1/auth/handoff/poll`
  `{handoff_id, secret}` reports `pending`, `ready`, `consumed`,
  or `expired`; `POST /v1/auth/handoff/exchange` `{handoff_id,
  secret}` trades a ready handoff, once, for the app's own
  desktop device session. The secret never leaves the app; the
  browser only ever sees the handoff id.

Configuration is environment only: `NPC_AUTH_RP_ID`,
`NPC_AUTH_RP_NAME`, `NPC_AUTH_ORIGINS`, `NPC_AUTH_SITE_BASE`,
`NPC_AUTH_SESSION_TTL_DAYS`. The email link rides the mailer's
own configuration; locally, `NPC_MAIL_STUB=1` (with
`NPC_MAIL_STUB_FILE`) carries it end to end without SES.

## 4. Errors — fail closed

| Code | Shape | Meaning |
|------|-------|---------|
| 400 | `{"error": "bad_request", "detail": "…"}` | Malformed input — never a 500 for client mistakes |
| 401 | `{"error": "unauthorized"}` | Missing/invalid API key |
| 403 | `{"error": "forbidden", "detail": "…"}` | Key lacks the required role |
| 404 | `{"verdict": "unknown"}` | Unknown subject — no verdict fabricated |
| 422 | `{"error": "unprocessable", "detail": "…"}` | Attestation failed validation |
| 429 | `{"error": "rate_limited", "retry_after_seconds": n}` | Slow down |

Error responses are signed like everything else.

## 5. Data model

`attestations {id, subject_type, subject_id, verdict, scope, tested_at,
expires_at, findings_summary (sanitized), signature, onchain_anchor
{chain, tx, hash, status}, revoked}`

- **Append-only.** Records are never edited.
- **Revocation** is a new signed record in `revocations`; the attestation
  row is flagged `revoked=1`. History is preserved.
- **Privacy:** no PII in responses beyond what the subject made public.
  `findings_summary` is sanitized at issuance; methodology never leaves
  the building.

## 6. Local-first operation

```bash
cd ~/workspace/grand-fleet/verified-by-npc/api
python3 -m npc_verify            # first run: generates TEST keys + fixtures
```

- Binds to `127.0.0.1` only. No public exposure.
- State lives in `.local/` (SQLite + key seeds). Delete it to reset.
- Schema is portable SQL — it moves to Postgres with minimal changes.
- Run the tests: `python3 -m unittest discover -s tests`

## 7. What v1 does NOT do

- No third-party attestation issuance (NPC-issuer keys only).
- No PII beyond what the subject made public.
- No methodology exposure in any response.
- No wallet requirement for verifiers.
- No mainnet writes (hard gate — needs Bayo's explicit word).
