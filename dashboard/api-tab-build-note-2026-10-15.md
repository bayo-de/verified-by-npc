# Build note: API tab for verify.npclabs.xyz (2026-10-15)

Status: BUILT AND STAGED ONLY. Nothing deployed. Bayo approves the deploy
after review, per his direction (2026-10-15: "We need an API section for
the site that explains to developers how to leverage our APIs in their
applications and builds. A whole tab. Next to Plugins.").

## The bundle

- Path: `dashboard/verified-dashboard-drop-2026-10-15-api.zip`
- Size: 476,921 bytes, 140 entries
- sha256: `51269fe77b1ac511174bf8d9c15fa657695d32bacc7c6899876f429d03b8ede8`
- Built tree kept at `dashboard/dist-api/` for inspection.
- Format matches today's bundles (export_static.py output zipped at the
  root). Deploy, when approved, is the usual Netlify Drop of this zip.
  Note: this bundle builds on the current source tree, the same tree the
  cycle bundle was built from; it carries everything that tree carries,
  plus the API tab and the nav entry.

## What changed (source)

- `dashboard/views.py`
  - Shared nav: "API" now sits immediately after "Plugins" on every page
    (Records, Search, Plugins, API, Verify yours, How it works).
  - New `api_view()`: the /api page, plus a `_codebox()` helper that
    renders examples in the existing keybox styling (no CSS changes).
- `dashboard/server.py`: new route `GET /api`; page title "API"; route
  list in the module docstring updated.
- `dashboard/export_static.py`: `/api` added to the export page list
  (writes `api/index.html`).
- `dashboard/README.md`: /api row added to the pages table.
- Tests: nav strings updated in test_routes.py and test_html.py; "/api"
  added to the crawl/page lists (test_html.py, test_chat_widget.py), the
  export expectations (test_static_export.py EXPECTED_PAGES +
  LOCAL_ROUTES), and smoke_test.py; new tests `test_api_page`
  (test_routes.py) and `test_api_page_rendered` (test_static_export.py)
  pin the page's endpoints, its live example records, and its honest
  bounds (no request-verification, no /v1/chat, no cryptographic
  validation claim in the page content).

## Content grounding: every claim traces to a live call

All calls made against https://api.npclabs.xyz on 2026-10-15 (evening,
America/Denver) while building:

1. `GET /v1/health` → 200, body shown verbatim on the page.
2. `GET /v1/keys` → 200; the page's keys excerpt is the document's
   current signing key and current issuer key, verbatim.
3. `POST /v1/register/agent` (Docs Example Agent, owner NPC Labs,
   hello@npclabs.xyz) with `Idempotency-Key:
   api-docs-example-2026-10-15` → 201, record
   `reg_6789fb4ca0f5363853a23dc0`, shown in full on the page. The email
   does not appear in the signed record (checked).
4. Same call repeated with the same Idempotency-Key → the same
   record_id returned; no second record. (Grounds the "Retries are
   safe" line.)
5. `POST /v1/register/content` (kind text, sha256: locator) → 201,
   record `reg_d8b68b02eb095431acc031d2`, shown in full on the page.
6. `GET /v1/records/reg_6789fb4ca0f5363853a23dc0` → 200, the same signed
   record. `GET /v1/records/reg_d8b68b02eb095431acc031d2` re-checked
   after the build → 200. Both example records are live and citable.
7. `GET /v1/records/reg_000000000000000000000000` → 404
   `{"verdict": "unknown"}`, shown on the page.
8. Signature check performed, not just described: the example record's
   Ed25519 signature was verified offline with the repo's own
   primitives (npc_verify.canonical + npc_verify.ed25519) against the
   published issuer key: verifies. One field changed: fails. (Grounds
   the page's closing line in the signature section.)
9. `POST /v1/mcp` initialize → server npc-verify; `tools/list` → 7
   tools, exactly the seven named on the page (verify_claim,
   verify_credential, verify_product, verify_agent, register_agent,
   register_content, explain_verification).
10. PyPI `npc-verify-mcp` → live version 1.0.1 (releases: 1.0.0,
    1.0.1). The page claims 1.0.1 only; 1.1.0 is not mentioned.
11. Limits read from the shipped API source (npc_verify/registry.py):
    EMAIL_DAILY_CAP 10, IP_DAILY_CAP 50, 24-hour window;
    npc_verify/server.py MAX_BODY = 1 MiB.
12. An image registration by URL was also run (record
    reg_dc4c02a7a5fd6926961482c5): the live fetcher could not fetch
    that asset at intake, and the record honestly says so
    (content_fetch: not_fetched). It is not used on the page; the
    page's image sentence stays at the sanctioned framing (C2PA
    credentials read for presence and structure; AI-generation signal
    as a percentage with uncertainty stated; a signal is not a verdict).

## Exclusions honored (not documented as available)

- Biblo chat endpoint/widget: not mentioned anywhere in the page
  content. (The sitewide chat widget script rides every page of the
  bundle, as it already does in the current source tree; the API page
  documents nothing about it.)
- Request-verification: not mentioned.
- C2PA cryptographic validation: not claimed. Image intake is described
  as a presence and structure read plus a signal.
- Chrome extension: not mentioned on the page at all.

## Verification performed

- Dashboard suite: 76 tests, all passing (`python3 -m unittest discover
  -s dashboard/tests`), including the export-parity test (the dist page
  is byte-identical to the local app's /api render, modulo the standard
  public footer deltas).
- Bundle diff vs a fresh baseline build of the unmodified tree
  (built to /tmp/dist-baseline immediately before the edits): the only
  added file is `api/index.html`; every other page differs by exactly
  the nav line (checked line-by-line on home, plugins, help, records,
  and structurally across the tree). Per-build noise (fresh seeded key
  IDs, attestation IDs, key creation timestamps) was normalized before
  diffing; after normalization the search/keys page difference reduces
  to the seeded keys' creation timestamp, which is build time.
- Nav rendering checked in the built HTML on index, records, plugins,
  help, verify, api, and 404 pages: API sits immediately after Plugins
  on every one.
- Em dashes: zero in the entire bundle (every text file scanned,
  including the new page); zero `&mdash;` entities.
- Copy rules: no meta-copy (the page never narrates the site or its
  build), no fundraising or profit language, honesty labels in customer
  words. Developer usage detail (endpoints, headers, request and
  response shapes) is documented; verification methodology internals
  are not.

## The page's full copy (plain text, for Bayo's review)

For developers

The signed record, from your own code.

The Verified by NPC API is live at api.npclabs.xyz. Register the agents and content you ship, look their records up from your own application, and check NPC's signatures yourself, against keys NPC publishes. No API key is needed, and registration is free.

What you can build

Put an agent on record

Register an agent you run and get a signed record with its own NPC ID, issued on the spot. The record names the agent's accountable owner and states what has been checked and what has not.

Put content on record

Register an image, text, audio, video, or other content, by web address or by content hash. The answer is the same kind of signed record, ready to cite wherever the content travels.

Look any record up

One call resolves an NPC ID to its signed record: registrations, credentials, products, and agents. An ID with no record answers unknown, plainly, and never a guess.

Check the signature yourself

Every record is signed with Ed25519, and the public keys are published. Your code can confirm a record came from NPC and has not been changed, without calling NPC at all.

Quickstart

Every call below is real. The examples were run against the live API while this page was written, and the records they made are live records you can look up.

1. Check the service.

curl https://api.npclabs.xyz/v1/health
{
  "chain": {
    "anchoring": "disabled",
    "mode": "local-first",
    "network": "none",
    "note": "Phase 1 records anchor hashes locally; no chain writes until the mainnet gate clears."
  },
  "key_id": "npc-demo-api-signing-20261014-e9c73a",
  "status": "ok",
  "time": "2026-10-16T02:35:14+00:00",
  "version": "1.0.0"
}

2. Register an agent. An agent registration names the agent and its accountable owner. A homepage or a description is required. The owner's email is required too, and it never appears in the public record.

curl -X POST https://api.npclabs.xyz/v1/register/agent \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: api-docs-example-2026-10-15" \
  -d '{
    "agent_name": "Docs Example Agent",
    "owner_name": "NPC Labs",
    "owner_email": "hello@npclabs.xyz",
    "description": "An example agent registered to document the Verified by NPC API."
  }'
The answer, status 201, is the signed record, issued on the spot:
{
  "record_id": "reg_6789fb4ca0f5363853a23dc0",
  "record_type": "npc.registry.agent_registration",
  "kind": "agent",
  "agent_name": "Docs Example Agent",
  "owner_name": "NPC Labs",
  "description": "An example agent registered to document the Verified by NPC API.",
  "homepage": null,
  "status": "registered_checks_pending",
  "status_label": "registered, checks pending",
  "registered_at": "2026-10-16T02:35:35+00:00",
  "checks_run": [
    {
      "check": "named_owner",
      "status": "recorded",
      "detail": "The registration names an accountable owner, as the registry requires. NPC records the owner; it does not operate the agent."
    },
    {
      "check": "registration_claim",
      "status": "issued",
      "detail": "This signed claim records the registration of the agent. Registration is not verification."
    }
  ],
  "checks_not_run": [
    {
      "check": "scope_review",
      "reason": "The agent's declared scope of authority has not been reviewed yet."
    },
    {
      "check": "human_review",
      "reason": "A person has not reviewed this registration yet."
    },
    {
      "check": "verification_decision",
      "reason": "Registration is not verification. No verification decision has been made, and no verification mark is issued at registration."
    }
  ],
  "key_id": "npc-demo-issuer-20261014-727fb5",
  "signature": "/gfFVDAqu3QufnzSM/K3RaMARDFysuAc4NiyYjAaVhfugGI1KryI7y03UroMjePTZuDLucmNRDsJnAw4rUAMBQ=="
}

The status says what the record is: registered, checks pending. Registration is the start of verification, not the result, and no verification mark is issued at registration. The record itself lists the checks that ran and the ones that have not.

3. Register content. The kind is one of image, text, audio, video, or other. The locator is a web address where the content can be fetched, or its SHA-256 hash, written as sha256: followed by the hash. Content at a web address is fetched once at intake, and its SHA-256 is recorded. This example registers by hash, so the record carries the hash the creator provided:

curl -X POST https://api.npclabs.xyz/v1/register/content \
  -H "Content-Type: application/json" \
  -d '{
    "title": "API documentation example text",
    "kind": "text",
    "locator": "sha256:6f64362c5920bee25236a3bd0783160665cf0b3c370946b5bbd20e94d2862da3",
    "creator_name": "NPC Labs",
    "creator_email": "hello@npclabs.xyz"
  }'
{
  "record_id": "reg_d8b68b02eb095431acc031d2",
  "record_type": "npc.registry.content_registration",
  "kind": "content",
  "content_kind": "text",
  "title": "API documentation example text",
  "locator": "sha256:6f64362c5920bee25236a3bd0783160665cf0b3c370946b5bbd20e94d2862da3",
  "locator_kind": "content_hash",
  "creator_name": "NPC Labs",
  "status": "registered_checks_pending",
  "status_label": "registered, checks pending",
  "registered_at": "2026-10-16T02:35:41+00:00",
  "checks_run": [
    {
      "check": "content_hash",
      "status": "provided_by_creator",
      "detail": "The creator provided this content hash. NPC has not seen the content itself.",
      "locator": "sha256:6f64362c5920bee25236a3bd0783160665cf0b3c370946b5bbd20e94d2862da3"
    }
  ],
  "checks_not_run": [
    {
      "check": "human_review",
      "reason": "A person has not reviewed this registration yet."
    },
    {
      "check": "verification_decision",
      "reason": "Registration is not verification. No verification decision has been made, and no verification mark is issued at registration."
    }
  ],
  "key_id": "npc-demo-issuer-20261014-727fb5",
  "signature": "AfnTGvaj84XJSTvRoy9RHlkRVEF6lMtatt3gwU+0B67kfpuRKtlcDVdtcRNOecqau/1B+RG6jeeRSzC5cDfIAA=="
}

For an image, intake also reads the image's C2PA content credentials, recording whether they are present and how they are structured, and records an AI-generation signal as a percentage with its uncertainty stated. A signal is information, not a verdict, and the record says which is which.

4. Look a record up. The same record answers at its own address, and Search on this site resolves the same IDs:

curl https://api.npclabs.xyz/v1/records/reg_6789fb4ca0f5363853a23dc0
An ID with no record fails closed:
curl https://api.npclabs.xyz/v1/records/reg_000000000000000000000000

404
{"verdict": "unknown"}

5. Check the signature. Records carry their signature inside them, and every API response carries one in its headers: X-NPC-Signature, with the signing key named by X-NPC-Key-ID. The public keys live at one address:

curl https://api.npclabs.xyz/v1/keys
The current keys, from that document. Retired keys are listed there too, marked retired, so older records stay checkable:
{
  "api_signing": {
    "current": {
      "algorithm": "Ed25519",
      "key_id": "npc-demo-api-signing-20261014-e9c73a",
      "public_key": "sl7vwSgymgvrTaHg8l4FIKAPzoSYvXLH3Jm2zj/Ji/A=",
      "status": "active",
      "created_at": "2026-10-15T04:26:54+00:00",
      "retired_at": null
    }
  },
  "issuers": [
    {
      "algorithm": "Ed25519",
      "key_id": "npc-demo-issuer-20261014-727fb5",
      "public_key": "9keaHrMrvoaLX9kvl/3l7pagM91FOrlCC6EPJv1VYfA=",
      "status": "active",
      "created_at": "2026-10-15T04:26:54+00:00",
      "retired_at": null
    }
  ]
}

Find the key. Take the record's key_id and find that entry in the keys document.

Canonicalize. Remove the signature field, then write what is left as NPC-JCS-v1: UTF-8, keys in sorted order, no extra whitespace.

Verify. Check the base64 Ed25519 signature against that entry's public key.

The example record above passes this check, and changing any field in it makes the check fail.

The MCP endpoint

If you build with agents, the same records are one connection away. NPC runs a hosted MCP server at https://api.npclabs.xyz/v1/mcp. Point an MCP client at that address:

{
  "mcpServers": {
    "npc-verify": {
      "url": "https://api.npclabs.xyz/v1/mcp"
    }
  }
}

Its tool list answers today with seven tools. Four verify against the records (verify_claim, verify_credential, verify_product, verify_agent), one explains an answer in plain words (explain_verification), and two register from inside the conversation (register_agent, register_content):

curl -X POST https://api.npclabs.xyz/v1/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }'

Prefer to run the server yourself: the same tools ship on PyPI as npc-verify-mcp, version 1.0.1.

pip install npc-verify-mcp

Good to know

Registration is free, and the public endpoints on this page need no API key.

A named owner is required. An agent registration names an accountable person as its owner; anonymous owners and team aliases are not accepted.

Emails stay private. The owner or creator email is required for registration. It stays on NPC's servers, for caps and contact, and never appears in the signed public record.

Retries are safe. Send an Idempotency-Key header with a registration, and repeating the same request with the same key returns the original record instead of making a second one.

Registration is capped at 10 per email address and 50 per IP address in 24 hours. Past the cap the API answers 429, and the request can be sent again later.

Requests are capped at 1 MiB.

Records are signed, not minted. A record is an Ed25519 signature kept by NPC; registering writes nothing to a blockchain.

Status means what it says. A new record starts as registered, checks pending. Its status changes only when its checks run, and the record lists which checks those were.

Which surface should you use?

SurfaceFitsUse it when

REST APIYour own application or serviceYou want registration and record lookups inside your own code.

Hosted MCPAgent frameworks and MCP clientsYou want an agent to ask, and to register, as it works, with no server of your own to run.

npc-verify-mcpYour own infrastructureYou want to run the MCP server yourself, against the same live API.

PluginsChatGPT, Gemini, and other assistantsYou want NPC checks inside an assistant your users already open. See the Plugins page.

Questions about building on the API: hello@npclabs.xyz.
