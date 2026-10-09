# Morning fixes — one-pager for Bayo (2026-10-09)

Source: the 7 pre-launch sims (2026-10-07) + tonight's locked decisions (2026-10-08).
Rule: Bayo's call on all four, one step at a time. Nothing here is a verdict — each item
ends with the specific decision he needs to make.

## 1. Liability answer (the gate)

**The objection (highest-ranked across all sims):** "When your agent makes a $10k
mistake, who pays?" The material has NO answer. Enterprise "for hire" conversations
cannot start until this exists. Silence reads as unserious to the first serious prospect.

**What we already have in the material:**
- Sim-gate v0.2: per-client thresholds ($1,000 default / $10,000 / $0), 3-strikes suspension,
  human adjudication.
- P1-3 approvals: human-in-the-loop as a server decision — approval is rendered, never assumed.
- Fail-closed posture everywhere; paper-only revenue bots until explicit approval.

**Decision for Bayo:** sign an interim liability position for "for hire" work. Suggested shape:
tiers of exposure (default / elevated / opt-in), approval gates at each, and an explicit
"interim policy, counsel review when funded" label. A licensing/business-structure call —
his instruction to a lawyer drafts it; the morning decision is only the policy shape.

## 2. Root-of-trust package

**The objection (cross-cutting #1 across all launches):** "Who verifies the verifier?"
"Signed by whom? Themselves?" Every trust-layer launch gets this; we have never answered
it in one place.

**What we already have in the material:**
- Every API response Ed25519-signed by NPC; clients verify offline against published keys.
- Hashes onchain; record contents stay local (payments attestation prototype).
- The Oct 30 fix list already calls for "one-sentence verification explainer."

**Decision for Bayo:** approve the one-sentence root-of-trust answer for public copy.
Suggested draft (his line-by-line approval required — he rewrites these):
*"NPC Labs signs every verification with keys we publish, so anyone can check the
answer without trusting us."*
Full package = that sentence + the Ed25519/offline-verification paragraph + the key
registry. Customer-facing: why it works, never how the methodology works.

## 3. Plugin sequencing

**The situation:** MCP server npc-verify is built and verified (Phase 2a, 40 tests).
OpenAI plugin package validated (52 tests) but needs dev-account gates: org + verified
identity + listing copy + portal submission. OpenAI submission flow documented in
OPENAI-SUBMISSION-BAYO-STEPS.md. Counsel gate on the mark now waived (2026-10-08),
so the mark is no longer the sequencing blocker.

**Decision for Bayo:** confirm MCP-first, OpenAI-after-submission — or reorder. The
sequencing question is pure priority: does the MCP developer lane ship before the
OpenAI store lane gets its submission paperwork? Tonight's decisions don't change the
remaining gates: OpenAI dev org, verified identity, reviewer test accounts, country
availability, hosting budget. None created.

## 4. CRM freshness owner

**The objection (highest-ranked in the CRM sim):** internal tools rot from neglect, not
design. "Who owns freshness if the Sunday cron fails silently?" The verify-the-scheduler
lesson: scheduled doesn't mean done.

**The three fixes the sim demands (Bayo to sign):**
1. Assign a freshness owner + a scheduler check. Stale edition = visible warning banner.
2. Write the client data-access model before any client sees it — who sees what, enforced
   where. One page.
3. Define the money boundary: CRM tracks relationships and recommendations; money lives
   in the Coin Purser. Say it in the UI.

**Decision for Bayo:** name the owner (a person or an agent with a named human accountable),
and approve the visible-stale banner rule. Suggestion: the freshness owner is a standing
agent with a named human (Francis? Bayo?) as backstop — his call.

---

*End. Four decisions, one step at a time.*
