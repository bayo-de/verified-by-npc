# "Verified by NPC" Program — ROADMAP v2

**Status:** WORKING ROADMAP — integrates the 2026-10-08 top-10 AI app teardown (REA).
**Supersedes:** DESIGN-v1.md build order (§7) where noted. Design intent (§1–§6, §8 gates) unchanged.
**Owner:** Biblo. **Internal only.**
**Program home:** `~/workspace/grand-fleet/verified-by-npc/`

---

## 1. Current build state (2026-10-08)

| Workstream | State | Location |
|---|---|---|
| API v1 | DONE, verified (50 tests) | `api/` — OpenAPI 3.1, stdlib impl, Ed25519-signed responses, SQLite |
| MCP server `npc-verify` | DONE, verified (40 tests) | `plugins/mcp/` — 5 tools, thin calls to API v1 |
| OpenAI plugin | DONE, submission-ready (52 tests) | `plugins/openai/` — awaiting account gate |
| Gemini extension | DONE, publish-ready (36 tests) | `plugins/gemini/` — awaiting repo + publish |
| Copilot plugin | DONE, validation-ready (45 tests) | `plugins/copilot/` — awaiting Partner Center |
| Dashboard web app | DONE locally (31 tests + 21 smoke) | `dashboard/` — static export ready, `verify.npclabs.xyz` planned |
| Memory v1 | DONE, verified (96 tests) | `memory/` — signed records, company/team/agent scoping |
| Brand mark | Designed, NOT shipped | `brand/` — Bayo's final tap pending; counsel gate WAIVED by Bayo 2026-10-08 (§7.4) |
| Desktop app | CONCEPT ONLY — no code yet | Bayo 2026-10-06: "the desktop app IS the client portal" |

**Teardown verdict on current state:** The API/MCP/plugin/memory spine is sound and already aligned with several teardown patterns (MCP-first, fail-closed, signed responses, no-telemetry-without-opt-in). The gaps are: (a) no desktop app architecture — the highest-leverage missing piece; (b) provenance is a feature, not yet a first-class API; (c) agent UX patterns (tool-progress strings, async completion, SSE) not yet specified for dashboard/desktop surfaces.

---

## 2. Teardown insight → roadmap item map

### P0 — Architecture (build these first; retrofitting is expensive)

| # | Insight (source) | Roadmap item | Workstream | Owner |
|---|---|---|---|---|
| P0-1 | Narrow waist + Footprint Ladder (Hermes) | Desktop app: minimal agent core; all capability at edges via the 6-rung ladder (CLI+skill → service-gated tool → plugin → MCP → core tool, last resort). Every new capability gets a ladder placement decision before code. | Desktop app | Fleet |
| P0-2 | Three-party separation (Hermes) | Desktop app: Electron owns machine / Renderer owns experience / Backend owns work, clean seams. No shared-state shortcuts. | Desktop app | Fleet |
| P0-3 | State by authority (Hermes) | Desktop app: backend owns shared truth, renderer caches, Electron owns machine facts. Written as an explicit invariant, enforced in review. | Desktop app | Fleet |
| P0-4 | Provenance as API, model-agnostic (OpenAI SDK) | Promote provenance from a `verify_product` field to a first-class API surface: `POST /v1/provenance/verify` accepting any creator, any model, physical + digital goods. OpenAI's C2PA/SynthID checks only cover OpenAI outputs — ours covers everything. This is the moat; build it as the headline API, not a sub-feature. | API v1 | Fleet |
| P0-5 | Prompt cache sacredness (Hermes) | All agent-facing system prompts (desktop app, dashboard assistant, Fleet agents) designed byte-stable per conversation from day 1. Deferred invalidation for mid-session toolset changes. Direct cost + latency win; free if designed in, expensive if retrofitted. | Desktop app, Dashboard | Fleet |

### P1 — Product (integrate into current build)

| # | Insight (source) | Roadmap item | Workstream | Owner |
|---|---|---|---|---|
| P1-1 | Tool-progress strings (Grok, ChatGPT) | Agent UX standard: live natural-language status per action ("Reading Slack thread", "Checking provenance chain") — never generic spinners. Applies to dashboard agent surfaces, desktop app, and Fleet's own agent UX. | Dashboard, Desktop app | Fleet |
| P1-2 | Async completion (Grok Heavy, ChatGPT) | Long-running agent work never blocks: "answer is ready" / "you'll be notified" pattern with notification hook. Dashboard + desktop app. | Dashboard, Desktop app | Fleet |
| P1-3 | Server-mediated approvals (Dots) | Human-in-the-loop formalized: approval is a server decision, client renders the outcome. Add `POST /v1/approvals` request/decision flow to API v1; plugins surface via MCP elicitation-style UI. Extends the existing fail-closed posture into a real approval primitive. | API v1, Plugins | Fleet |
| P1-4 | Feature flags + exposure logging (ChatGPT, Claude, Grok) | Server-driven flag evaluation layer with built-in A/B exposure logging. Not toggles — an experimentation spine. Dashboard and desktop app read flags from the API; every check logs exposure. | API v1, Dashboard, Desktop app | Fleet |
| P1-5 | Onboarding variants (Claude) | Variant system for onboarding with persona support from day 1 — not one flow. Dashboard first, desktop app at launch. | Dashboard, Desktop app | Fleet |
| P1-6 | SSE for streaming, never WebSocket for chat (unanimous) | Standard: fetch + `text/event-stream` for all AI streaming surfaces. WebSocket reserved for telemetry/collaboration only. Write it as a build rule so no one deviates. | Dashboard, Desktop app | Fleet |
| P1-7 | Skills as managed resources (Anthropic) | Verified Agent registry: skills versioned and managed server-side (API), not just client config. Extends memory v1's company layer into a skill registry with versions, signatures, revocation. | API v1, Memory | Fleet |
| P1-8 | Session durability (Hermes) | Crash-resilient transcripts: user message persisted before agent starts. Dashboard chat + desktop app sessions. | Dashboard, Desktop app | Fleet |
| P1-9 | Optimistic UI, honest rollback (Hermes) | Paint immediately, reconcile visibly on failure. Dashboard interaction standard. | Dashboard | Fleet |

### P2 — Later (specified now, built after P0/P1)

| # | Insight (source) | Roadmap item | Workstream | Owner |
|---|---|---|---|---|
| P2-1 | Multi-surface code sharing (Claude) | Web codebase structured to adapt to desktop/browser-extension surfaces via surface detection. Don't build three apps; build one that adapts. | Desktop app, Dashboard | Fleet |
| P2-2 | Streaming polling fallback (ChatGPT) | Instrumented SSE fallback (retry count, terminal states) for when streams break. Don't assume streams never fail. | Dashboard, Desktop app | Fleet |
| P2-3 | "Connectors are now called Apps" (OpenAI) | Naming decision: our "verified connectors" vs OpenAI's "Apps" rebrand. Needs Bayo's call before public copy. | Brand/API naming | Bayo |

**Cut by radical subtraction** (valid patterns, not earning a place in v1): TanStack-style granular code-splitting (implementation detail, decide at build time), CMS-driven marketing pages (nice-to-have; static export already works), composer-as-subsystem (later, when the input box earns it), layout-based code-splitting (same as first).

---

## 3. What changes vs DESIGN-v1

**NEW workstream: Desktop app architecture.** v1 named the desktop app as the client portal (Bayo, 2026-10-06) but specified nothing about how to build it. The teardown supplies the architecture: three-party separation, narrow waist, state by authority, prompt-cache-first. This is now the P0 build — the shell the rest of the program grows into.

**NEW headline API: provenance.** v1 had provenance as fields inside `verify_product`. The teardown (OpenAI shipping first-party provenance checks) says provenance is becoming table stakes — and theirs is model-locked. Ours becomes a first-class, model-agnostic API surface. This is the single biggest moat item in the roadmap.

**NEW product standards.** Tool-progress strings, async completion, SSE-only streaming, onboarding variants, server-mediated approvals, and the feature-flag spine are new specified standards. None contradict v1; v1 simply didn't specify agent UX.

**REPRIORITIZED.** Desktop app architecture moves ahead of plugin store submissions in build order (see §4). The plugins are done and waiting on gates; the desktop app is where new build energy goes.

**ALREADY ALIGNED (teardown validates, no change).** MCP-first build order. Ed25519-signed responses. Fail-closed errors. Read-first v1. Privacy-preserving (no PII beyond public). No telemetry without opt-in (Hermes independently validates this as architecture, not policy). Thin plugin clients over one API. Proofline contracts before ship.

**UNCHANGED.** All §8 hard gates. Pricing/issuance open questions (§9) — plus two new ones in §5.

---

## 4. Sequencing

```
NOW ──────────────────────────────────────────────────────► LAUNCH
 │ Phase A          │ Phase B              │ Phase C
 │ (spine)          │ (surfaces)           │ (growth)
─────────────────────┼────────────────────────┼─────────────────
P0-4 provenance API │ P1-1 tool-progress   │ P2-1 multi-surface
  (extends API v1)  │   strings            │   adaptivity
P0-1/2/3 desktop    │ P1-2 async completion│ P2-2 stream fallback
  app skeleton      │ P1-5 onboarding      │
  (three-party,     │   variants           │ Gate-dependent:
  narrow waist,     │ P1-6 SSE standard    │ plugin submissions,
  state authority)  │ P1-8 session         │ public hosting,
P0-5 prompt-cache   │   durability         │ mark (counsel gate WAIVED 2026-10-08),
  prompt design     │ P1-9 optimistic UI   │ mainnet anchoring
P1-3 approvals API  │                      │
P1-4 flag spine     │ Dashboard applies    │
P1-7 skill registry │ P1-1/2/5/6/8/9      │
  (extends memory)  │                      │
```

**Dependencies:**
- P0-4 (provenance API) extends the finished API v1 — no blockers, starts immediately.
- P0-1/2/3 (desktop skeleton) — shell resolved: Electron, approved by Bayo 2026-10-08 (§7.1). No blockers; build underway.
- P1-3 (approvals) extends API v1; plugins consume it when built.
- P1-4 (flag spine) is a precondition for P1-5 (onboarding variants) — flags first.
- P1-7 (skill registry) extends memory v1's company layer.
- Dashboard P1 items apply to the existing local dashboard; no rebuild.
- Plugin store submissions remain gate-blocked (accounts, counsel) independent of this sequencing.

**Rule for the build:** no new capability enters the desktop app without a Footprint Ladder placement decision. The ladder is the gate.

---

## 5. Decisions needed from Bayo

| # | Decision | Context | Needed before |
|---|---|---|---|
| 1 | ~~Desktop app shell: Electron?~~ — RESOLVED (§7.1): Electron + three-party separation per Hermes playbook. | Build underway per §7 | Desktop skeleton |
| 2 | ~~"Connectors" vs "Apps" naming~~ — RESOLVED (§7.2): use "Apps" in all public copy. | — | Any public copy |
| 3 | ~~Provenance API pricing~~ — RESOLVED (§7.3 + pricing finalized): freemium, distribution-first; free tier 1,000 verification lookups/mo, free build report 1/account EVER, referral +500; provenance API + volume paid; enterprise white-label/SLA. | — | Public API launch |
| 4 | (existing, unchanged) | All DESIGN-v1 §8 gates + §9 open questions stand, EXCEPT the mark's counsel gate — waived by Bayo 2026-10-08 (§7.4) | — |

---

## 6. Teardown source index

Full evidence: `~/workspace/grand-fleet/eval-2026-10-08/rea-study/top10-teardown/`
- `TOP10-APP-TEARDOWN.md` — master report (this roadmap's input)
- Per-app: `hermes-findings.md`, `chatgpt-findings.md`, `claude-findings.md`, `copilot-findings.md`, `dots-findings.md`, `gemini-findings.md`, `grok-findings.md`, `grokbot-findings.md`, `meta-muse-findings.md`, `sdk-findings.md`
- REA evidence bundles: `evidence/` · raw bundles: `raw/`
- Blocked (documented, no bypass): Perplexity (Cloudflare), Meta Muse (edge bot-mitigation) — candidates for browser-session follow-up, parent delegation.

*End of ROADMAP v2. Working document — update as phases land.*

---

## 7. Bayo's decisions (2026-10-08)

1. **Desktop shell: Electron — APPROVED.** Proceed with Electron + three-party separation per Hermes playbook.
2. **Naming: "Apps"** — follow the category flow (OpenAI's rebrand). Use "Apps" in all public copy.
3. **Pricing: freemium, distribution-first.** Free tier (generous verification lookups) as funnel; paid provenance API + usage tiers above the free threshold. Enterprise tier for white-label/SLA. Reverse-engineering concern addressed architecturally: API is server-side only, methodology never ships to clients; Cloudflare + rate limits (P0 infra) prevent bulk scraping.
4. **Mark: PROCEED WITHOUT counsel clearance.** Bayo explicitly overrode the §8 counsel gate (2026-10-08): "Proceed without the counsel clearance. The mark is fine." Anibal unavailable (no funds); Bayo's call as principal. Risk noted: certification-mark use without counsel review carries trademark exposure. Proceeding on his direct instruction.

**Protection: APPROVED as P0 infrastructure.** Cloudflare in front of the API — bot fight mode, WAF, rate limiting, signed-request requirements for provenance endpoints. Spec as part of API deployment, not after.

### Pricing decisions finalized (2026-10-08, Bayo)
- **Free tier:** 1,000 verification lookups/month. Power users burn through it in ~a week; small businesses may stay free indefinitely. Distribution first.
- **Referral program:** referrer + invitee each get +500 verifications when the invitee signs up with the referral code. Dropbox-style growth loop.
- **Free verified build report:** 1 per account, ONE EVER (not monthly) — anti-farming guardrail. The "first hit free" wedge: they see the full system on their own build, then pay for more.
- **Paid tiers:** provenance API + volume above free tier; enterprise for white-label/SLA. Exact price points TBD.
