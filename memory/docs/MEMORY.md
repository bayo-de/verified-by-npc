# Trust-layer memory v1 — design + usage reference

Companion to DESIGN v1 section 5. Internal.

## 1. Record format

```
MemoryRecord {
  id, seq (per-stream, contiguous), ts,
  stream_kind, company_id, team_id, stream_agent_id, stream_key,
  agent_id (writer), writer_company_id, writer_team_id,
  type: "memory.assert" | "memory.supersede" | "memory.retract",
  content: { text, tags[], confidence, [target_id], [reason] },
  provenance: { derived_from[], source, [url, captured_at, hash], trust },
  prev_hash, record_hash, signature_b64, key_id
}
```

The signature covers the canonical signing core: `id, seq, stream, ts,
agent_id, writer_scope, type, content, provenance, prev_hash`
(NPC-JCS-v1 canonicalization, same as API responses). `record_hash` is
SHA-256 over that core; each record's `prev_hash` equals the previous
record's `record_hash`. Genesis `prev_hash` is 64 zeros.

`key_id` is `ak_<first 16 hex of sha256(public key)>`, bound to the
registered agent key at write time so a later rotation never rewrites
history.

## 2. Semantics

**Append-only.** Records are never edited or deleted. Corrections are
`memory.supersede` with `content.target_id` pointing at the old record;
withdrawals are `memory.retract` with `content.target_id` and an optional
`reason`.

**Standing.** A record is `retracted` when a live retract targets it,
`superseded` when a live supersede targets it, else `live`. A supersede
may target an assert or an earlier supersede; a retract may target an
assert or a supersede. Withdrawing a supersede revives the belief it had
replaced (the supersede is skipped when resolving standing). Retractions
are never targeted; to move on, assert something new. A retracted or
already-superseded record cannot be targeted again — the write is
rejected, fail-closed.

**Verification status.** Recall and single reads return each record with:

| Field | Values | Meaning |
|---|---|---|
| `signature` | `valid` / `invalid` / `unverifiable` | Ed25519 check against the registered agent key; `unverifiable` when the writer is not registered or the key id mismatches |
| `chain_intact` | bool | every hash link from the record back to genesis holds; hashes are recomputed from stored fields, never trusted |
| `superseded_by` | id or null | the live supersede targeting this record |
| `retracted` | bool | a live retract targets this record |
| `standing` | `live` / `superseded` / `retracted` | overall |

**Provenance.** `derived_from` holds event refs or memory ids.
`source` is `session`, `memory`, or `external`. External sources must be
labeled `untrusted` and carry `url` (http/https), `captured_at`
(ISO-8601), and `hash` (64 hex) — the write is rejected otherwise.

**Secrets.** The write boundary refuses secret-bearing keys (same hint
list as the session spine) and known secret shapes in free text (PEM
private keys, AWS keys, GitHub/Stripe/Slack tokens, `npc_test_` API
keys). The refusal names the key or pattern, never the value. Callers
scrub first; this is defense in depth.

## 3. Streams and the company layer

Stream kinds and keys:

- `fleet` — fleet-wide learnings, writer attribution on every record.
- `company:{company}` — shared company stream.
- `team:{company}:{team}` — shared team stream.
- `agent:{company}:{team}:{agent}` — one stream per agent.

Two credentials are checked on every API write:

1. **The API key** (transport credential, least privilege). A key writes
   a stream only when the key sits at or above the stream in the tree:
   an agent-scoped key reaches only its own agent stream; a team-scoped
   key reaches the team stream and every agent stream under it; a
   company-scoped key reaches the whole company; an unscoped key reaches
   everything. Fleet-stream writes additionally need an issuer/admin key.
2. **The writer** (registered agent identity). An agent writes its own
   agent stream, its team's stream, its company's stream, and may
   contribute to the fleet stream (attribution: `agent_id` plus writer
   company/team). Never another team, company, or agent.

Reads are wider: a key reads streams on its branch in either direction
(an agent reads its team and company streams) plus the fleet stream.
Out-of-scope reads return the same `404` as unknown ids, so existence
is never confirmed across scopes.

Agent registration (`POST /v1/memory/agents`, issuer role) binds an
`agent_id` to a public key and a company/team scope. The registering
key's scope must cover the agent's scope. Re-registering the same id
with the same key is idempotent; a different key conflicts (409).

## 4. Library

`MemoryClient(store, identity, scope)` — the primary interface:

- `register_self()` — publish the agent's public key (idempotent).
- `assert_memory(text, tags, confidence, provenance, stream="agent")`
- `supersede(target_id, text, ...)` / `retract(target_id, reason, ...)`
- `get(record_id)` → `(record, verification)` or `None`.
- `recall(tags, q, since, until, limit, stream, live_only)` — tag
  (any-match) + recency + keyword recall; every hit carries verification.
- `verify_stream(stream)` — full integrity report: record count, chain
  status, first broken seq, bad signatures.

`stream` is one of `agent` / `team` / `company` / `fleet` (the client's
own branch by default; explicit dims allowed).

`RemoteMemoryClient(base_url, api_key, identity, scope)` mirrors the
shape over HTTP: records are built and signed locally, then POSTed. API
responses are signature-checked against the published keys, fail-closed.

`AgentIdentity` holds the 32-byte seed in a 0600 file. The seed never
enters the database or the wire.

## 5. API endpoints

`POST /v1/memory/agents`, `POST /v1/memory/records`,
`GET /v1/memory/records/{id}`, `POST /v1/memory/recall` — all
authenticated, agent-scoped, every response Ed25519-signed like the rest
of API v1. Full reference in `api/docs/API.md` and `api/openapi.yaml`.

## 6. Storage

SQLite, portable SQL, one `memory_agents` table (public keys only) and
one `memory_records` table (the ledger). The store wraps a caller-owned
connection: the API shares its connection and lock; standalone use
opens its own file via `MemoryStore.open(path)`. Appends are atomic
check-and-insert under the lock: `seq` must continue the stream and
`prev_hash` must match, else the write is rejected as a fork.

## 7. What v1 does not do

- Vector/semantic recall (v2; the record shape already carries tags and
  text, so embeddings slot in without a migration).
- Agent key rotation (re-register under a new agent id).
- Cross-company sharing or public memory.
- Erasure: there is no delete. Withdrawal is `memory.retract`, and the
  history stays.
- Any public exposure: local-first, fictional fixtures, no real secrets.
