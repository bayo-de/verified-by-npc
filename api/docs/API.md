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
