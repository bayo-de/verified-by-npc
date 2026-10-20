# Verification-start build: staging report (2026-10-14)

Status: **STAGED ONLY. Nothing deployed.** Drop zip: `verified-dashboard-drop-2026-10-15-verify.zip` (261,368 bytes, 68 files, byte-identical to `dashboard/dist/`; SHA-256 `de0eed2c9ed9ddc551d20db4ac2b563b5deb030178743b7eea4f354d752aea9b`).

## What changed, in one paragraph

Users can now start verification of their own work, creations, and agents. The API gained three public endpoints: `POST /v1/register/content` and `POST /v1/register/agent` mint real, signed NPC records at issuance (status honestly "registered, checks pending"; registration is not verification, and no verification mark exists anywhere in the flow), and `GET /v1/records/{id}` resolves any API-issued ID so Search can find them. The dashboard gained a Verify yours page (`/verify`, linked from Search and How it works) whose two forms POST from the visitor's browser to a configurable API base (the dashboard's configured API URL locally; `https://api.npclabs.xyz` in the export). Search resolves API-issued IDs twice over: server-side through the signature-verifying dashboard client, and live in the browser on the Unknown answer page, which is the primary path on the static host. If the API base is unreachable, the Verify yours page says "the verification service is not answering yet," pauses the forms, and offers the waitlist. It never fakes a submission or a result.

## Part 1: the API

Files: `api/npc_verify/registry.py` (new: validation, intake checks, minting), `api/npc_verify/c2pa.py` (new: server-side C2PA structural parse), `api/npc_verify/store.py` (registrations table + cap counters), `api/npc_verify/server.py` (routes, peer-IP injection), `api/serverless/function_src/api.py` (gateway source-IP for the caps), `api/openapi.yaml` (three paths, five schemas, one response component), `api/tests/test_register.py` (new, 15 tests).

### Endpoints, with examples

All examples were captured from a live local run of this build (seeded demo API; the image locator is a C2PA test-fixture image served locally for the run). Every response body is canonicalized and Ed25519-signed in the `X-NPC-Signature` header like all API responses; registration records are additionally signed inside the body with the issuer key (`npc-issuer-*`), so each record verifies as a portable artifact against `GET /v1/keys`.

#### POST /v1/register/content (public, no key)

Request:

```json
{"title": "Harbor at dawn, generated study", "kind": "image",
 "locator": "http://127.0.0.1:45443/c2pa.jpg",
 "creator_name": "Demo Maker", "creator_email": "maker@example.com"}
```

Response: `201`

```json
{
  "record_type": "npc.registry.content_registration",
  "record_id": "reg_453d7bbf51759b8d6ea8b9e3",
  "kind": "content",
  "status": "registered_checks_pending",
  "status_label": "registered, checks pending",
  "title": "Harbor at dawn, generated study",
  "content_kind": "image",
  "locator": "http://127.0.0.1:45443/c2pa.jpg",
  "locator_kind": "url",
  "creator_name": "Demo Maker",
  "registered_at": "2026-10-15T02:23:48+00:00",
  "checks_run": [
    {"check": "content_fetch", "status": "fetched", "bytes": 398,
     "sha256": "8cca286e86d13dc07641e3c23ffcf4cc753efa12540b2c6ea115ec7665258482",
     "detail": "The content at the locator was fetched once at intake and its SHA-256 recorded."},
    {"check": "c2pa_credentials", "status": "present_not_cryptographically_validated",
     "present": true, "validated": false, "generator": "TestGen 1.0",
     "digital_source_type": "AI-generated",
     "digital_source_type_raw": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
     "assertions": ["c2pa.actions"], "instance_id": "xmp:iid:test-0001"}
  ],
  "checks_not_run": [
    {"check": "c2pa_cryptographic_validation",
     "reason": "Structural presence is recorded at intake. The claim signature, assertion hashes, and certificate chain are not cryptographically validated yet."},
    {"check": "ai_generation_signal",
     "reason": "The AI image check is not configured on this API yet."},
    {"check": "human_review",
     "reason": "A person has not reviewed this registration yet."},
    {"check": "verification_decision",
     "reason": "Registration is not verification. No verification decision has been made, and no verification mark is issued at registration."}
  ],
  "key_id": "npc-issuer-20261015-f473d1",
  "signature": "g1bmz3JcNnqXaXJXjGhDC5VpFO0Fu3IUqHxDHOnKWpVc25uVEi2SyJI8xrZpbT6SbN1hVdiWI/otFO/NsB61Dg=="
}
```

The creator email appears nowhere in the record or the response: emails are stored server-side only (submission caps and contact) and are never published in the signed record or returned by `GET /v1/records/{id}` (test-pinned).

#### POST /v1/register/agent (public, no key)

Per the Agent Registry spec: registration is free, a named accountable owner is required (anonymous and team-alias owners fail validation), at least one of homepage or description is required, and the issued claim states registration, not verification.

Request:

```json
{"agent_name": "Harbor Helper", "owner_name": "Demo Owner",
 "owner_email": "owner@example.com",
 "homepage": "https://example.com/harbor-helper",
 "description": "Answers questions about the harbor schedule."}
```

Response: `201`

```json
{
  "record_type": "npc.registry.agent_registration",
  "record_id": "reg_b93508391d24ca6ffbb3e6fb",
  "kind": "agent",
  "status": "registered_checks_pending",
  "status_label": "registered, checks pending",
  "agent_name": "Harbor Helper",
  "owner_name": "Demo Owner",
  "homepage": "https://example.com/harbor-helper",
  "description": "Answers questions about the harbor schedule.",
  "registered_at": "2026-10-15T02:23:48+00:00",
  "checks_run": [
    {"check": "named_owner", "status": "recorded",
     "detail": "The registration names an accountable owner, as the registry requires. NPC records the owner; it does not operate the agent."},
    {"check": "registration_claim", "status": "issued",
     "detail": "This signed claim records the registration of the agent. Registration is not verification."}
  ],
  "checks_not_run": [
    {"check": "scope_review", "reason": "The agent's declared scope of authority has not been reviewed yet."},
    {"check": "human_review", "reason": "A person has not reviewed this registration yet."},
    {"check": "verification_decision", "reason": "Registration is not verification. No verification decision has been made, and no verification mark is issued at registration."}
  ],
  "key_id": "npc-issuer-20261015-f473d1",
  "signature": "l0FhAzuhNduRXCUdr3SO+5SavOEhmMGXpo6SHtXW+bcRMLOmE5Qt6n/3u3qCCV2ImnYWi1Fx94AeMJmVHz5CDg=="
}
```

#### GET /v1/records/{id} (public, no key)

Returns the signed record for any API-issued ID. For the two registration IDs above it returns the record exactly as issued (byte-identical body; test-pinned). Existing record types return exactly the body their own endpoint returns, so nothing that worked stops working:

```json
GET /v1/records/cred_test_001  ->  200
{"id": "cred_test_001", "status": "valid", "title": "Test Artisan Certificate",
 "issuer": "NPC Labs", "holder_name": "Test Holder",
 "issued_at": "2026-01-10T00:00:00+00:00", "expires_at": "2028-01-10T00:00:00+00:00",
 "assessed_skills": ["test-craft"], "signature": "fbKp7zxv...",
 "key_id": "npc-issuer-20261015-f473d1",
 "verification_url": "https://verify.npclabs.xyz/c/cred_test_001"}

GET /v1/records/reg_not_a_real_id  ->  404
{"verdict": "unknown"}
```

Resolution order: registration, credential, product, agent, attestation, PACT consent (by grant_id or record_id). Unknown IDs fail closed with the standing 404 shape.

### Checks that run at intake, and those that do not

Run, when what was provided allows it:

- **content_fetch** (URL locator, any kind): the content is fetched once, bounded at 8 MiB and 8 seconds; byte count and SHA-256 are recorded. An unreachable, unreadable, or oversize locator is recorded as `not_fetched`; registration still succeeds, honestly labeled.
- **content_hash** (hash locator): the creator-provided hash is recorded as `provided_by_creator`, with the record stating NPC has not seen the content itself.
- **c2pa_credentials** (image kind, fetched bytes): the new server-side structural parse (`npc_verify/c2pa.py`, a port of the extension staging parser: JUMBF extraction from JPEG APP11 or PNG caBX, box-tree walk, CBOR claim decode). Present credentials are recorded with generator, declared digital source type, assertion labels, and instance ID, under the standing label `present_not_cryptographically_validated` with `validated: false`. No readable claim is recorded as `not_present`. The port was verified against the extension's own fixtures before integration: identical extraction on `c2pa.jpg` / `c2pa.png` (generator "TestGen 1.0", "AI-generated", assertions, instance ID) and identical nulls on the truncated and corrupt fixtures.
- **ai_generation_signal** (image kind, fetched bytes, detector configured): recorded as an integer percent with provider and model, and the standing uncertainty wording ("A signal with uncertainty, not a verdict..."). It is never a hard stamp. When no detector is configured (the local demo above), the check is listed under `checks_not_run` with that reason; a detector failure does the same. Nothing is ever fabricated.
- **named_owner** and **registration_claim** (agent registrations): recorded at issuance, per the Agent Registry spec.

Not run at intake, and listed in every record with the reason:

- **c2pa_cryptographic_validation**: claim signature, assertion hashes, and certificate chain are not validated yet. Structural presence is never presented as validation.
- **scope_review** (agents), **human_review**, and **verification_decision**: no person has reviewed the registration, and no verification decision exists. Registration issues no verdict and no verification mark, anywhere in this flow.

### Abuse minimums

- Creator/owner email required and validated (422 otherwise); all field shapes validated in house style (400 for a non-object body, 422 with the problem list).
- Per-email cap of 10 registrations per rolling 24 hours and per-IP cap of 50 per rolling 24 hours, counted in the store layer (`registrations` table; `count_registrations_since`), answered with the signed 429 `rate_limited` shape. The client IP comes from the TCP peer (or the gateway's reported source IP in the serverless adapter), injected after client headers are read so it cannot be spoofed by a header.
- Payloads bounded by the server-wide 1 MiB body cap, plus per-field length caps; the intake fetch is separately bounded (8 MiB, 8 s, http(s) only).
- No payments anywhere; no verification-mark issuance anywhere.

## Part 2: the dashboard

Files: `dashboard/views.py` (Verify yours page + scripts, record renderers, Search and How it works copy), `dashboard/server.py` (`/verify` route, Search records fallback), `dashboard/client.py` (`get_record`), `dashboard/export_static.py` (`/verify` in the export, API-base rewrite in `_publicize`), `netlify.toml` (CSP), `dashboard/tests/test_verify.py` (new, 7 tests), updates to `tests/test_routes.py`, `tests/test_html.py`, `tests/test_static_export.py`, `smoke_test.py`, `README.md`.

### Verify yours

One page, `/verify`, linked from Search ("Verify yours" section) and from How it works (the registration section and two FAQ answers), consistent with the standing IA (Records · Search · Plugins · How it works; Verify yours is a section surface, not a nav item). It carries both forms: content registration (title, kind, locator, creator name, creator email) and agent registration (agent name, owner name, owner email, homepage, description). The forms POST as JSON from the visitor's browser to the API base in the page's `data-api-base`: the dashboard's configured API URL in the local app, rewritten by the exporter to `https://api.npclabs.xyz` in the static artifact. On success the page shows the issued NPC ID, the status "Registered, checks pending," the checks that ran and those that have not, and a link into Search for the record. API rejections (422 validation, 429 caps) surface the API's own detail or a plain cap message. One deliberate platform change rides along: the Netlify CSP in `netlify.toml` now allows the inline scripts (`script-src 'unsafe-inline'`) and names the API base in `connect-src`; without it the deployed site's `default-src 'none'` would block both the form posts and the live lookup. If the API base ever changes, the CSP and the baked `data-api-base` must change together (noted in the README and the toml comment).

### Search resolution, and the _redirects defect

Search resolves API-issued IDs live, as the primary path, and does not depend on the `_redirects` rules:

1. **Live browser lookup**: the Unknown answer (the baked `/search/unknown/` page and the dynamically rendered Unknown result) carries a small script that asks `GET {api-base}/v1/records/{id}` for the ID in the query. A registration record replaces the Unknown notice with the record card; a miss or an unreachable API leaves the honest Unknown exactly as it stands. This is the path a registration ID takes on the static host, since registration IDs are minted live and can never be baked.
2. **Server-side resolution** (local app): Search tries credential, product, and key lookups as before, then `GET /v1/records/{id}` through the signature-verifying dashboard client, rendering the registration (or attestation) record. Unknown still lands on Unknown.

On the defect itself: the forced-rules fix **had landed** in `export_static.py` (and its tests) when this build reached the export step, so this build inherits it unchanged: every Search rule is forced (`200!`) and emitted for both `/search` and `/search/` path forms, including the two fallback rules (114 forced rules in the built `_redirects`). The baked fixture IDs ride those rules; API-issued IDs ride the live lookup above.

### Degradation, demonstrated

Demonstrated in a real browser: headless Chromium (Chrome for Testing 153, via Playwright) driving the exported `dist/` pages themselves, served two ways with only the baked `data-api-base` retargeted (the documented configuration point): at the live seeded API (up) and at a dead port (down). 16 of 16 checks passed:

- **API up**: the status line reads "Registration is open. Your record is issued on the spot," the down-state stays hidden, and the forms are enabled. Filling and submitting the content form shows the result with a real issued ID (`reg_154901da2ef26f3e1949ed6f` in the demo run), the status "Registered, checks pending," the line "Registration is not verification," and a Search link carrying that ID.
- **Live lookup in the browser**: opening `/search/unknown/?id=<that ID>` renders the record card live and replaces the Unknown notice; an unissued ID leaves the page honestly Unknown.
- **API down**: the down-state is shown with the heading "The verification service is not answering yet" and the waitlist offered, the status line reads "Registration is paused: the verification service is not answering yet," both forms' submit buttons are disabled, and no result is shown.

The same behaviors were corroborated by executing the shipped page scripts under Node with a minimal DOM shim (18 of 18 checks), which additionally forced a submit against the dead API and confirmed nothing is faked: the error states "The verification service is not answering yet. Your registration was not sent."

Consequence to know before deploy: the export's API base is `https://api.npclabs.xyz`, which is not live yet. Until the API stands up, the deployed Verify yours page will show the down-state and the deployed Unknown page will stay Unknown for registration IDs. That is the degradation rule working as designed, and it is also why the API stand-up remains the launch-critical path.

### How it works copy

The registration section and the FAQ now describe the real flow: registration starts verification and issues a signed record with its own ID; registration is not verification and no mark is issued; the two intake checks for images are described with their standing honesty labels (the AI check covers images only and is a signal; the Content Credentials read is structural and "not a cryptographic validation"); the pending checks stay named as pending. No em dashes, no App Store mention, no portal mention, no methodology: verified by grep over the built export (0 em dashes or `&mdash;`, 0 "app store", 0 "portal", 0 badge glyphs, 0 loopback URLs).

### No-meta-copy doctrine, as applied

Every line this build wrote or touched was audited against Bayo's no-meta-copy rule (public lines never narrate the site's structure, choices, or build state) and rewritten customer-first where it failed:

- The Verify yours status line no longer explains the page's own behavior ("this page says so here"); it is a customer status: "Registration is open. Your record is issued on the spot." when the service answers, "Registration is paused: the verification service is not answering yet." when it does not. The mandated down-state heading is kept verbatim, as a status, with the assurance a customer needs: "Nothing you type is sent or saved while the service is down."
- The Search section no longer says a page "says so plainly"; it tells the visitor what is true for them: registration is free, and "If the verification service is not answering yet, the waitlist is the way to hear when registration opens."
- The How it works paragraph no longer narrates the mechanism ("The forms send your registration to the verification service... a registration is never shown as sent when it was not"). It now states the customer's guarantee in customer words: "Nothing is registered until you see your NPC ID: if you do not see one, nothing was sent."
- The live-lookup result no longer says "Found in the live record" (mechanism narration); it says "This registration was issued by NPC and signed at issuance."
- Honesty labels survive throughout, in customer words: test records labeled, registration vs verification, images-only AI check as a signal, structural-not-cryptographic credentials, waitlist as the path when a surface is not live.

## Tests

- **API: 142 tests, OK** (baseline 127 + 15 new in `tests/test_register.py`: content and agent happy paths with offline record-signature verification, validation matrices, email-never-published pins, C2PA present / not-present / unreachable intake against locally served fixtures, per-email and per-IP caps, records resolution for registrations and all existing types, fail-closed unknown, and the configured-detector path recording the AI signal at 42 percent with the C2PA parse).
- **Dashboard: 56 tests, OK** (baseline 48 + 7 new in `tests/test_verify.py` + 1 redirects test from the parallel forced-rules fix: Verify yours renders both forms field-for-field with the degradation contract in the page, Search and Help link it, Search resolves content and agent registration IDs server-side with emails never rendered, and the Unknown answers carry the live-lookup marker). Smoke: **SMOKE OK, 47 PASS** (was 40), including register-then-resolve end to end.
- One transient: a single dashboard-suite run under back-to-back full-suite load reported FAILED (failures=2) with the failing test names not captured; the suite then passed four consecutive full runs (including two back-to-back) plus every targeted run. Not reproduced; flagged here rather than smoothed over.
- OpenAPI: `openapi.yaml` parses; 20 paths including the three new ones, in house style.
- The staged Search restructure build is intact: nav unchanged on all pages, `_redirects` present at the zip root with the forced rules, the whole zip byte-identical to the rebuilt `dist/`.

## Stated limits

- The browser scripts do not verify the API's Ed25519 response signatures client-side; they render what the API returns over HTTPS and display the record's own issuer signature and key ID (the record itself is independently verifiable against the published keys, and the dashboard's server-side client verifies every response signature). Client-side signature verification is future work, not claimed here.
- The Verify yours forms require JavaScript by construction (a static page cannot POST JSON and render the issued record without it); the no-JavaScript state says so plainly and offers the waitlist and email instead of a dead form.
- Nothing was deployed, submitted, or pushed. The drop is staged for Bayo's review, zip above.
