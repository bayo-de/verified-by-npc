# "Verified by NPC" Program — DESIGN v1

**Status:** PROPOSAL — for Bayo's review before heavy build (Phase 0 deliverable).
**Commissioned:** 2026-10-05 (Bayo). **Owner:** Biblo. **Internal only** until Bayo approves release.
**Program home:** `~/workspace/grand-fleet/verified-by-npc/`

## 1. What this is

NPC Labs is the Trust Layer for Commerce. Today that trust lives in reports and PDFs. This program puts it where people actually ask "is this real?": **inside the AI assistants they already use**, as a plugin, and **underneath them**, as an API and a memory layer.

Three workstreams, one spine:

1. **NPC Verification API v1** — the backend. Verify a claim, a credential, a product, an agent. Signed responses, so the API's answers are themselves verifiable.
2. **"Verified by NPC" plugins** — thin clients over the API for ChatGPT, Claude (MCP), Gemini, and Copilot. Verification becomes a tool call away, mid-conversation.
3. **Trust-layer persistent memory v1** — agent memory where every memory is a signed claim on the evidence spine. Our own Fleet dogfoods it first.

The strategic bet (from the 2026-10-05 intel): ChatGPT now suggests plugins mid-conversation, flipping plugin discovery from user-seeks to agent-recommends. A Verified by NPC plugin rides that channel: every "is this authentic?" moment in any major assistant becomes a trust-layer touchpoint.

## 2. Product definition: what the plugin does

When someone is chatting with an AI and verification becomes relevant, the plugin answers five questions:

| # | Question | Action | Backend |
|---|----------|--------|---------|
| 1 | "Is this product authentic?" | `verify_product` | smart-tag / product record lookup |
| 2 | "Is this certificate real?" | `verify_credential` | credential ID lookup + signature + revocation check |
| 3 | "Did this really happen / is this claim true?" | `verify_claim` | attestation registry match (sanitized) |
| 4 | "Is this agent verified?" | `verify_agent` | agent attestation lookup: verdict, scope, time bounds |
| 5 | "What does Verified by NPC mean?" | `explain_verification` | public-safe explainer (the why, never the how) |

Design principles:
- **Read-first.** v1 verifies; it does not issue (issuance stays NPC-internal). Third-party issuance is a later phase with its own legal review.
- **Fail-closed.** Unknown subject → "unknown," never a guess. An unverifiable claim is reported as unverifiable, not as false.
- **Privacy-preserving.** Same model as the payments attestation prototype: record contents stay local; only hashes go onchain. No PII in API responses beyond what the subject made public.
- **Self-verifying.** Every API response is Ed25519-signed by NPC. Clients can verify the answer offline against our published keys. You don't have to trust the transport; you verify the signature.
- **The mark.** The plugin surfaces the "Verified by NPC" mark on positive verdicts. NOTE: public use of the mark awaits counsel clearance (already on Anibal's review list). The capability builds now; the mark ships when counsel clears it.

## 3. NPC Verification API v1

Base URL (proposed, deployment gated): `https://api.npclabs.xyz/v1`. Local-first build; SQLite in v1, Postgres-compatible schema.

**Auth:** API keys (Bearer). Tiered rate limits (free verify tier, paid tiers later — pricing is a Bayo decision, §8).

**Signed responses:** every response body is canonicalized and Ed25519-signed. Signature travels in the `X-NPC-Signature` header (base64) with `X-NPC-Key-ID`. `GET /v1/keys` publishes current public keys with rotation history, so anyone can verify offline.

**Endpoints (v1):**

- `GET /v1/health` — liveness, key ID, chain status. No auth.
- `GET /v1/keys` — NPC public keys (API signing, issuer keys), rotation history. No auth.
- `GET /v1/credentials/{id}` — credential lookup. Returns: status (`valid` / `revoked` / `expired`), title, issuer, holder name (only if the holder made it public), issue date, assessed skills, signature, verification URL. Powers `verify.npclabs.xyz/c/{id}`.
- `POST /v1/claims/verify` — body: `{claim_text}` or `{claim_hash}`. Returns: `matched` bool, and if matched, the sanitized attestation summary (verdict, scope, tested dates, caveats, onchain anchor ref). Redaction follows the Verification Standard §8: findings sanitized, methodology never exposed.
- `GET /v1/products/{tag_id}` — smart-tag authenticity lookup. Returns: `authentic` / `counterfeit` / `unknown`, provenance chain (origin, transfers), product metadata the creator made public.
- `GET /v1/agents/{agent_id}/attestation` — agent verification status. Returns: verdict (`verified` / `verified_with_caveats` / `not_verified` / `unknown`), scope, time bounds, attestation ID, onchain anchor.
- `POST /v1/attestations` — record a new attestation. **NPC-issued only in v1** (API key with issuer role). Returns attestation ID + onchain anchor reference. High-value attestations anchor hash → Base via the existing FleetAttestationRegistry pattern.

**Data model (v1):** `attestations {id, subject_type, subject_id, verdict, scope, tested_at, expires_at, findings_summary (sanitized), signature, onchain_anchor {chain, tx, hash}, revoked}`. Revocation is a new signed record, never an edit.

**Errors:** fail-closed shapes. `404` with `{"verdict": "unknown"}` for unrecognized subjects — never a fabricated verdict. Rate-limit `429` with retry guidance.

**What v1 does NOT do:** no third-party issuance, no PII beyond public, no methodology exposure, no wallet requirements for verifiers.

## 4. Provider matrix

| Priority | Provider | Integration surface | Capabilities (from §2) | What it needs (gate) |
|----------|----------|--------------------|-----------------------|---------------------|
| 1 | OpenAI | ChatGPT plugin / GPT Action (2026 plugin channel) | all five actions | OpenAI developer account + plugin submission |
| 2 | Anthropic | MCP server `npc-verify` | all five as MCP tools | none for self-hosted; directory listing later |
| 3 | Google | Gemini extension | all five actions | Google developer account + extension review |
| 4 | Microsoft | Copilot plugin / declarative agent | all five actions | Microsoft partner account + validation |

**Build order rationale:** MCP first (no store gate, works with every MCP client, fastest to real users), then OpenAI (largest distribution, needs the account gate), then Gemini and Copilot.

**Per-provider notes:**
- **OpenAI:** the 2026 plugin channel suggests plugins mid-conversation. The plugin manifest description must be written for the suggestion trigger: plain verification intents ("is this real?", "verify this", "is this authentic?"). Manifest (`ai-plugin.json`) + OpenAPI spec pointing at the NPC API. Implementation targets the live 2026 submission path, confirmed against current docs at build time.
- **Anthropic:** MCP tools `verify_claim`, `verify_credential`, `verify_product`, `verify_agent`, `explain_verification`. Tool descriptions carry the same trigger phrasing. Shipped as a pip-installable server; no duplicated logic — every tool is a thin call to API v1.
- **Google/Microsoft:** same five actions, adapted to each extension manifest format. Queued behind the account gates.

**Quality gate:** every plugin action gets a Proofline contract before it ships (correct endpoint, well-formed args, fail-closed errors, no fabricated verdicts).

## 5. Trust-layer persistent memory v1

**The idea:** agent memory where each memory is a signed claim on the evidence spine. If the session log is the evidence of what an agent *did*, memory is the evidence of what it *learned* — with the same tamper-evidence.

**Record format** (compatible with the sim-gate spine event schema):

```
MemoryRecord {
  id, seq (per-agent stream, contiguous),
  ts, agent_id,
  type: "memory.assert" | "memory.supersede" | "memory.retract",
  content: { text, tags[], confidence },
  provenance: { derived_from: [event refs | memory ids], source },
  prev_hash, signature (agent's attestation key)
}
```

**Semantics:**
- **Append-only.** Memories are asserted, never edited. A correction is `memory.supersede` pointing at the old record's ID; a withdrawal is `memory.retract`. The history of what the agent believed, and when it changed its mind, is itself evidence.
- **Recall returns verification status.** Every recalled memory carries: signature valid?, chain intact?, superseded by?, retracted? The agent (and any auditor) sees not just the memory but its standing.
- **Provenance.** Each memory records what it was derived from: session events, other memories, or external sources (labeled untrusted with URL/timestamp/hash per Standard §12).
- **Secrets scrubbed** at the write boundary, same rules as the spine.
- **Identity:** per-agent streams (`agent_id` namespaces). A shared `fleet` stream holds Fleet-wide learnings with writer attribution. Cross-session: the agent's stream persists; mounting it in a new session re-derives its memory.
- **Company layer (2026-10-05, Bayo requirement):** multiple team members in one company share company-wide agents and context, all on the verification layer. Memory streams scope as `company_id` → `team_id` → `agent_id`, with a shared company stream alongside the fleet stream. API keys scope to company/team; every read and write is authorized against that scope, and every memory carries its verification status. This is what lets a whole company run on verified agents with shared context — the Tasklet-style collaboration model, with cryptographic trust underneath instead of permissions alone.

**v1 scope:** tag + recency + keyword recall (vector recall is v2). Write/read/recall API (Python library + API v1 endpoints under `/v1/memory/` — authenticated, agent-scoped). **Dogfood first:** Fleet agents' memory runs on it (sentinel learnings, trading-bot regime notes) before any external exposure.

**What it is not:** not a vector database product, not shared public memory, not a replacement for the session log (the log is what happened; memory is what was learned).

## 6. Consistency with existing assets

- **Verification Standard (internal):** the API's attestation records follow §7's format; public outputs obey §8 redaction (methodology never leaves the building). The plugin's `explain_verification` teaches the why only.
- **Session spine:** memory records reuse the spine's event shape (`seq, ts, type, actor, payload, prev_hash` + signature) and its guarantees (append-only, hash-chained, contiguous seq, secret scrubbing).
- **Onchain pattern:** high-value attestations anchor hash → Base via the FleetAttestationRegistry pattern from `attest-payment.py`. Contents stay local; hashes go onchain. Testnet first; mainnet is a Bayo-gated step.
- **Proofline:** every plugin action and every API endpoint gets Proofline contracts (golden-trace + fail-closed error handling) before release. The API ships with its own contract suite in CI.
- **Certification credentials:** `verify.npclabs.xyz/c/{id}` becomes a consumer of `GET /v1/credentials/{id}`. One verification backend, many surfaces.

## 7. Build order

- **Phase 0 (this doc):** design review with Bayo. ← we are here
- **Phase 1:** API v1 — OpenAPI spec → reference implementation (lean deps, FastAPI or stdlib-minimal) → signed responses + key publishing → SQLite store → tests + contract suite → API docs.
- **Phase 2a:** MCP server (no store gate).
- **Phase 2b:** OpenAI plugin (account + submission gate).
- **Phase 2c:** Gemini extension + Copilot plugin (account gates).
- **Phase 3:** Memory v1 library + API endpoints → Fleet dogfood → v1 tag.
- Each phase: tests for everything, docs to the bar, no real secrets in code.

## 8. Hard gates — exact asks for Bayo

| # | Gate | When | What Bayo decides |
|---|------|------|-------------------|
| 1 | Design approval | now | this doc: capabilities, API surface, memory design, build order |
| 2 | OpenAI developer account + plugin submission | Phase 2b ready | create/approve the account, approve the store listing copy |
| 3 | Google developer account + Gemini extension review | Phase 2c ready | same |
| 4 | Microsoft partner account + Copilot validation | Phase 2c ready | same |
| 5 | Hosting spend / public endpoint (`api.npclabs.xyz`) | before any public traffic | hosting choice + budget |
| 6 | Public "Verified by NPC" mark use | before any public surface | counsel clearance (already on Anibal's list) |
| 7 | Mainnet onchain anchoring | before any mainnet write | chain + budget sign-off (testnet until then) |

Nothing crosses a gate without his explicit word. Local-first build until then.

## 9. Open questions for Bayo (design review)

1. **Pricing:** free verification lookups (distribution; the trust layer as top-of-funnel) vs paid API tiers from day one? Recommendation: free verify, paid issuance + enterprise — verification is the funnel, issuance is the product.
2. **Issuance:** NPC-only attestation issuance in v1, or third-party issuance with review? Recommendation: NPC-only in v1; third-party issuance is a legal product with its own review.
3. **Domain:** `api.npclabs.xyz` for the public API? (Alternative: `verify.npclabs.xyz/api`.)
4. **Memory streams:** per-agent streams plus one shared fleet stream (recommended), or a single shared stream?
5. **Plugin name:** "Verified by NPC" everywhere, or provider-specific naming? Recommendation: one name everywhere — the mark is the brand.
6. **Priority check:** MCP first (no gate), then OpenAI — or does he want OpenAI first despite the account gate?

## 10. What success looks like

- A developer can `pip install npc-verify-mcp`, point Claude at it, and verify a product mid-conversation.
- A ChatGPT user typing "is this authentic?" gets the plugin suggested and a signed, verifiable answer.
- Every API answer carries a signature anyone can check against our published keys.
- Our own agents remember things as signed claims — and we can prove what they knew and when.
- The trust layer stops being a document and starts being infrastructure.

## 11. Launch vehicle: the dashboard web app (Bayo, 2026-10-05)

The plugins do not launch alone. They ship **with the NPC Labs dashboard web app** — one launch, one story:

- **Dashboard web app** = the home base. Users manage their verified goods, credentials, and attestations; see verification activity; hold their NPC identity. This is where "Verified by NPC" lives as a product you can see and touch.
- **Plugins** = the distribution. Every "is this real?" moment inside ChatGPT, Claude, Gemini, and Copilot resolves against the same API and the same attestation records the dashboard shows. The plugin is the trust layer meeting people where they already ask.
- **API v1** = the spine underneath both. One backend, two surfaces.

Launch sequencing: API v1 (local-first) → MCP server → dashboard web app + plugin submissions together. The dashboard gives the plugins somewhere to point ("see the full verification record"); the plugins give the dashboard its growth loop (every in-conversation verification is a dashboard signup waiting to happen).

**Market validation (2026-10-05):** Greg Isenberg flagged ChatGPT's mid-conversation plugin recommendations as a distribution unlock comparable to early Facebook/iPhone apps — developer Pietro Schirano reported 2,000%+ plugin growth after the announcement. The agent-recommends channel in §1 is now confirmed by the market, not just our read.

**Build start:** 2026-10-05. Phase 1 (API v1, local-first) begins today per Bayo's go-ahead. Hard gates (§8) unchanged: developer accounts, store submissions, public endpoint, the mark, and mainnet all still need his explicit word.

**2026-10-05 evening — Phase 1 + Phase 2a COMPLETE (verified).**
- Phase 1: NPC Verification API v1 — `~/workspace/grand-fleet/verified-by-npc/api/`. OpenAPI 3.1 spec, zero-dependency stdlib reference implementation, Ed25519-signed responses with key rotation, SQLite store (Postgres-ready), fail-closed errors, 50 tests passing, docs. Live boot verified on 127.0.0.1:8787.
- Phase 2a: MCP server `npc-verify` — `~/workspace/grand-fleet/verified-by-npc/plugins/mcp/`. Five tools (thin calls to API v1, no duplicated logic), client-side signature verification on every response (fail-closed on tamper), zero-dependency stdio JSON-RPC transport, pip-installable, 40 tests passing, live smoke test through the installed entry point.
- No gates crossed: no public endpoint, no store submissions, no mark usage, no mainnet writes, no real secrets. All fixtures fictional, internal only.
- Next: Phase 2b (OpenAI plugin — needs the developer account gate), Phase 2c (Gemini + Copilot), Phase 3 (memory v1), dashboard web app build (launch vehicle per §11).

**2026-10-06 ~midnight MDT — Phase 2b + Phase 2c + dashboard COMPLETE (verified, all local).**
- Phase 2b: OpenAI plugin package — 2026-live `plugin.json` manifest (deliberate deviation: OpenAI retired `ai-plugin.json`; the legacy file fails the 2026 submission scan, so the current Plugins-platform format ships instead), OpenAPI 3.1 action spec for the five verification operations (read-only; no issuance), stdlib thin client reusing the Phase 2a MCP client's verification chain (`npc_verify_openai` → `npc_verify_mcp.api_client` → `npc_verify.*`), fail-closed on tamper/unknown, trigger phrasing in descriptions, 52 tests passing, `validate_package.py` exits 0 (PACKAGE VALID). Internal placeholder logo assets labeled NOT the counsel-gated mark.
- Phase 2c: Gemini CLI extension (`plugins/gemini/`: `gemini-extension.json`, five `commands/*.toml` slash commands, `GEMINI.md`, thin stdlib client, 36 tests passing, validator exit 0) + Microsoft 365 Copilot API plugin (`plugins/copilot/`: v2.2 plugin manifest, OpenAPI 3.0.3 spec, v1.3 declarative-agent wrapper, thin stdlib client, 45 tests passing, validator exit 0). Both packages read-only, signature-checked, fail-closed, submission-ready.
- Dashboard web app (launch vehicle, §11) — `~/workspace/grand-fleet/verified-by-npc/dashboard/`. Stdlib `http.server`, binds 127.0.0.1 only (default port 8790). Pages: `/` home, `/records`, `/credentials`, `/products`, `/keys`, `/plugins`. Every API response signature-checked client-side before render; unknown → "Unknown", unreachable → "Unavailable", never invented. 31 tests passing + 21/21 smoke checks against localhost. Restrained Yeezy/Apple-bar design; no badge/checkmark artwork; no em-dashes in user-facing copy.
- No gates crossed across the wave: no developer/partner accounts created, no store or portal submissions made, no public endpoint, no public mark use, no mainnet writes, no real secrets. All fixtures fictional.
- Next: Phase 3 (memory v1). Gated items awaiting Bayo's explicit word: OpenAI developer org + verified identity + listing copy + portal submission; Gemini extension publication (public repo + `gemini-cli-extension` topic); Microsoft Partner Center enrollment + Copilot validation; public hosting + budget; mark artwork (counsel); reviewer test accounts/demo video/country availability; mainnet anchoring.

**2026-10-06 ~morning MDT — Phase 3 (memory v1) COMPLETE (verified, all local).**
- Library `~/workspace/grand-fleet/verified-by-npc/memory/npc_memory/` — pure stdlib: `MemoryRecord` (`memory.assert` / `memory.supersede` / `memory.retract`), Ed25519-signed with the agent's attestation key over the canonical core (reuses `npc_verify` canonical/Ed25519, no duplicated crypto), per-stream hash chains with contiguous `seq`, write-boundary secret refusal (spine rules), provenance with external sources labeled `untrusted` (+URL/timestamp/hash). Recall is tag + recency + keyword (vector is v2); every recall returns verification status (signature valid?, chain intact?, superseded by?, retracted?, standing). `MemoryClient` (local SQLite) + `RemoteMemoryClient` (HTTP, signature-checks every API response, fail-closed).
- Company layer (Bayo's 2026-10-05 requirement): streams scope `company_id` → `team_id` → `agent_id` plus shared team, company, and fleet streams with writer attribution. API keys carry company/team/agent scope; every API write checks key scope AND the writer's registered agent scope AND the signature AND the chain; reads are branch-scoped (out-of-scope reads 404 like unknown). Fleet writes need an issuer key.
- API endpoints: `POST /v1/memory/agents` (issuer; key registration), `POST /v1/memory/records` (verifier+), `GET /v1/memory/records/{id}`, `POST /v1/memory/recall` — all authenticated, agent-scoped, every response Ed25519-signed like the rest of v1. Spec in `api/openapi.yaml`, docs in `api/docs/API.md` + `memory/docs/MEMORY.md`.
- 66 library tests + 30 API endpoint tests, all passing; full API suite 80/80 green. Dogfood-ready: structured so sentinel/trading-bot can adopt `MemoryClient`, not wired into live agents (separate decision).
- No gates crossed: no public endpoint, no real secrets, no mainnet, fixtures fictional and labeled.
- Next: Fleet dogfood, then v1 tag. Gated items unchanged.

**2026-10-06 ~morning MDT — Gated launch wave PREPARED (Bayo: "Yes proceed").**
- Track 1 OpenAI: package re-validated (52/52 tests, PACKAGE VALID). Submission research complete: org creation $0, identity verification $0, only cost is the $5 minimum prepaid API credit purchase; no submission fee; review timeline unpublished (budget weeks). Runbook `plugins/openai/SUBMISSION-RUNBOOK.md` with listing copy draft (name "Verified by NPC", tagline "Is this real? Verify it.", why-never-how), demo-account plan (none required, read-only v1), and 9-shot demo video plan. Gaps before upload: privacy/terms/support URLs on npclabs.xyz, listing screenshots, version 1.0.0 release notes, demo video, live production API with demo fixtures.
- Track 2 Gemini: package re-validated (36/36 tests). Public repo staged at `plugins/gemini/public-repo/` (17 files at root, vendored signature primitives, public README, MIT license, zero private references/secrets). Runbook `plugins/gemini/PUBLISH-RUNBOOK.md` executes repo creation + `gemini-cli-extension` topic + push with a transient PAT (never stored). Nothing created or pushed; private repo untouched.
- Track 3 Microsoft: package re-validated (45/45 tests, all checks passed). Partner Center fees: Individual FREE, Company ~$99 one-time (recommended for NPC Labs business distribution; irreversible choice). Runbook `plugins/copilot/SUBMISSION-RUNBOOK.md` with full validation bar, listing copy draft, and 10 asks. Two pre-submit hardening flags: description_for_model trigger phrasing near the instructional-phrase ban; declarative-agent wrapper at schema v1.3 (re-check v1.6 at build time).
- Track 4 public hosting: Netlify static export recommended (existing team). Build script `dashboard/export_static.py` → `dashboard/dist/` (12 pages, 96K); `netlify.toml` with query redirects + security headers; 40/40 tests pass, zero secrets in artifact. API v1 STAYS local-first: public front is a labeled static snapshot of test fixtures with fail-closed semantics; no hosted API, no keys. Runbook `dashboard/DEPLOY-RUNBOOK.md`. Domain recommendation: `verify.npclabs.xyz` (DNS untouched).
- Track 5 mark artwork: real mark designed under `brand/` (primary + small + mono-black + mono-white SVG, 28 PNG exports, review contact sheet, usage rules; NPC Orange #FF6A00, single check, no circle). Placeholders untouched, nothing shipped. Awaits Bayo's final tap + counsel clearance.
- Track 6 = Phase 3 above.
- Nothing crossed a gate: no accounts created, no payments made, no submissions, no deployments, no DNS changes, no public mark use, no mainnet. All asks for Bayo consolidated in the coordinator's final report.

---

*End of Phase 0 design. Awaiting Bayo's review before heavy build.*
