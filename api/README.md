# NPC Verification API v1 — Reference Implementation

Local-first reference implementation of the "Verified by NPC" API
(DESIGN v1 §3). **Internal only. Not published. Not hosted.**

- **Zero dependencies.** Pure Python standard library.
- **Signed responses.** Every body is canonicalized (NPC-JCS-v1) and
  Ed25519-signed (pure-Python RFC 8032, vendored from the sim-gate
  attestation core so the API shares the Fleet's signing primitive).
- **SQLite store**, portable-SQL schema (Postgres-ready).
- **Fail-closed** errors: unknown subjects → `404 {"verdict": "unknown"}`.

## Layout

```
api/
  openapi.yaml          # OpenAPI 3.1 spec for the 7 v1 endpoints
  README.md             # this file
  docs/API.md           # full API documentation
  scripts/
    gen_test_keys.py    # generate/rotate local TEST keys
  npc_verify/           # the implementation
    __init__.py
    __main__.py         # python -m npc_verify
    server.py           # router + handlers + signed-response wrapper
    models.py           # attestation/credential/product/agent models
    store.py            # SQLite store (thread-safe, portable schema)
    keys.py             # key registry, rotation, file-backed private keys
    auth.py             # Bearer API keys, roles, rate limiting
    seed.py             # fictional TEST fixtures (test_ prefixed)
    canonical.py        # NPC-JCS-v1 canonical JSON
    ed25519.py          # vendored RFC 8032 (from sim-gate)
    errors.py           # fail-closed error shapes
  tests/
    test_ed25519.py     # RFC 8032 vectors + tamper checks
    test_canonical.py   # canonicalization determinism
    test_keys.py        # generation, rotation, publish shape
    test_store.py       # schema, lifecycle, append-only revocation
    test_api.py         # end-to-end over loopback HTTP, all 7 endpoints
    test_contracts.py   # Proofline-style contract suite
```

## Quick start

```bash
cd ~/workspace/grand-fleet/verified-by-npc/api

# 1. Start the server (first run generates TEST keys + fixtures)
python3 -m npc_verify
# TEST API keys print once — save them.

# 2. In another terminal, try it (replace KEY with your verifier key)
curl -s http://127.0.0.1:8787/v1/health | python3 -m json.tool
curl -s http://127.0.0.1:8787/v1/keys | python3 -m json.tool
curl -s -H "Authorization: Bearer KEY" \
  http://127.0.0.1:8787/v1/credentials/cred_test_001 | python3 -m json.tool
curl -s -X POST -H "Authorization: Bearer KEY" \
  -H "Content-Type: application/json" \
  -d '{"claim_text": "The test widget passes drop testing"}' \
  http://127.0.0.1:8787/v1/claims/verify | python3 -m json.tool

# 3. Run the tests
python3 -m unittest discover -s tests
```

## Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/v1/health` | none | Liveness, key ID, chain status |
| GET | `/v1/keys` | none | Public keys + rotation history |
| GET | `/v1/credentials/{id}` | verifier | Credential lookup |
| POST | `/v1/claims/verify` | verifier | Claim verification |
| GET | `/v1/products/{tag_id}` | verifier | Smart-tag authenticity |
| GET | `/v1/agents/{agent_id}/attestation` | verifier | Agent verification status |
| POST | `/v1/attestations` | issuer | Record attestation (NPC only) |

## Security notes (local-first)

- Private keys live in `.local/keys/` (mode 600), never in the database,
  never in code. They are TEST keys.
- `.local/` is runtime state — delete it to reset everything.
- No hosting, no public endpoint, no mainnet writes in Phase 1.
  Onchain anchors record the content hash locally with status
  `not_anchored`; the hash is testnet-ready for the
  FleetAttestationRegistry pattern later (contents local, hashes onchain).
- Every response — including errors — carries `X-NPC-Signature` and
  `X-NPC-Key-ID`. Verify against `GET /v1/keys`.
