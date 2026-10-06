# Trust-layer memory v1

Agent memory where every memory is a signed claim on the evidence spine
(DESIGN v1 section 5). If the session log is the evidence of what an
agent *did*, memory is the evidence of what it *learned* — with the same
tamper-evidence.

- **Append-only.** Memories are asserted, never edited. A correction is
  `memory.supersede` pointing at the old record's id; a withdrawal is
  `memory.retract`. The history of what the agent believed, and when it
  changed its mind, is itself evidence.
- **Signed.** Every record is Ed25519-signed with the writer agent's
  attestation key over a canonical core. Reuses `npc_verify`'s
  canonicalization and Ed25519 — no duplicated crypto.
- **Hash-chained per stream.** `seq` is contiguous per stream;
  `prev_hash` links each record to the last. Forks and rewrites are
  detected, not silently accepted.
- **Recall carries verification.** Every recalled memory reports:
  signature valid?, chain intact?, superseded by?, retracted?, and its
  overall standing (`live` / `superseded` / `retracted`).
- **Provenance on every record.** Derived-from refs, source, and for
  external sources: labeled `untrusted` with URL, timestamp, and hash.
- **Secrets refused at the write boundary.** Same rules as the session
  spine: secret-bearing keys and known secret shapes are rejected before
  anything is signed or stored.
- **Company layer.** Streams scope as `company_id` → `team_id` →
  `agent_id`, with shared team, company, and fleet streams. API keys
  scope to company/team/agent; every read and write is authorized against
  that scope.

v1 recall is tag + recency + keyword. Vector recall is v2 (not built).

## Layout

```
memory/
  npc_memory/      the library (pure stdlib)
    __init__.py    public surface: MemoryClient, RemoteMemoryClient, ...
    records.py     MemoryRecord shape, validation, signing core, hashing
    identity.py    agent attestation keypair (0600 seed file)
    scope.py       company/team/agent scoping + stream keys + authz
    scrub.py       write-boundary secret refusal
    store.py       SQLite store (portable SQL), append-only chains
    verify.py      verification status (signature, chain, standing)
    library.py     MemoryClient: write/read/recall against a local store
    remote.py      RemoteMemoryClient: same shape over /v1/memory/ HTTP
  tests/           66 tests, all passing
  docs/MEMORY.md   full design + usage reference
```

The API endpoints live in the Verification API: `POST /v1/memory/agents`,
`POST /v1/memory/records`, `GET /v1/memory/records/{id}`,
`POST /v1/memory/recall` (see `api/docs/API.md` and `api/openapi.yaml`).

## Quickstart (local)

```python
import sys
sys.path.insert(0, "memory")
sys.path.insert(0, "api")  # for npc_verify primitives

from npc_memory import (AgentIdentity, MemoryClient, MemoryStore, Scope)

store = MemoryStore.open("/home/user/.npc/memory.db")  # or ":memory:"
ident = AgentIdentity.generate("sentinel")
ident.save("/home/user/.npc/sentinel.seed")  # 0600
client = MemoryClient(store, ident,
                      Scope(company_id="acme", team_id="core",
                            agent_id="sentinel"))
client.register_self()

client.assert_memory(
    "Funding rates spike before listings",
    tags=["regime", "funding-rates"],
    provenance={"derived_from": ["evt_9f2"], "source": "session"})

for rec, status in client.recall(tags=["regime"]):
    print(rec["content"]["text"], "->", status["standing"],
          status["signature"], "chain:", status["chain_intact"])
```

## Quickstart (remote, against the API)

```python
from npc_memory import AgentIdentity, Scope
from npc_memory.remote import RemoteMemoryClient

ident = AgentIdentity.load("/home/user/.npc/sentinel.seed", "sentinel")
client = RemoteMemoryClient("http://127.0.0.1:8787", "npc_test_...",
                            ident, Scope(company_id="acme",
                                         team_id="core",
                                         agent_id="sentinel"))
client.register_agent()          # needs an issuer key
client.assert_memory("Trimmed SOL into strength", tags=["execution"])
```

Every API response is signature-checked against the published API keys;
tampering fails closed.

## Tests

```bash
cd memory && python3 -m unittest discover -s tests
cd ../api && python3 -m unittest discover -s tests -p "test_memory.py"
```

## Dogfood note

Fleet agents' memory runs on this before any external exposure. The
library is structured so the sentinel/trading-bot use case can adopt
`MemoryClient` directly; wiring it into live agents is a separate
decision (not done here).

## What v1 does NOT do

- No vector/semantic recall (v2).
- No third-party agent registration beyond issuer-held keys.
- No key rotation for agent attestation keys (re-register under a new id).
- No cross-company sharing (isolation is the point).
- No public endpoint, no real secrets, no mainnet — local-first, like
  the rest of the program.
