# Pre-launch sim report: Client CRM internal dashboard (2026-10-07)

**Method:** synthetic-audience-simulation (MiroFish pattern). 6 personas, 3 rounds, compressed time. Sandboxed: no real audiences, no spend, nothing published.
**Seed (real):** space:client-crm (ts-spaces/client-crm); Certified Agent Menu (client-safe weekly feed) + Crew Brief (internal full-context view); why-first-never-how split between client and crew surfaces.
**Seed gaps:** no client data-access model documented; no freshness owner if the Sunday refresh cron fails; money boundary undefined (Coin Purser vs CRM); no integration story with existing tools.
**Note:** internal tool — the "launch" is crew + pilot-client rollout. Internal launches don't fail publicly; they rot silently.

## Crowd
Francis (NPC co-founder, Head of Product) · Puneet (Head of Technology) · Tim (SPC partner) · Client-A (pilot client) · Ayanna (ops/finance) · Skeptic-ops ("we tried a CRM before," internal skeptic)

## Rounds
**R1 — CRM goes live internally.** Francis: "If the menu stays fresh it's my shortlist; if it goes stale it's a graveyard." Puneet: "Another database?" Tim: "Is the SPC view scoped right?" Client-A: "My business data in a tool your agents can read — explain the access model." Ayanna: "Show me the money trail or it's a toy." Skeptic-ops: "Nobody updated the last CRM after week 3."
**R2 — the rot question.** Adoption dominates: internal tools die from neglect, not design. Francis: "Who owns freshness? What if the Sunday cron fails silently?" — the verify-the-scheduler lesson, live. Client-A's access question has no answer in the material. Ayanna's money question reveals scope blur.
**R3 — settled.** Mostly neutral (Francis, Puneet, Tim, Ayanna at 0), 2 negative (Client-A, Skeptic-ops).

## Sentiment trajectory
Polite open → the rot question takes over → settles at skeptical-neutral. Nobody hates it; nobody will save it either.

## Ranked objections
1. **Adoption rot.** "Nobody updated the last CRM after week 3." The #1 killer of internal tools. (Skeptic-ops) — HIGHEST
2. **Client data-access model unclear.** (Client-A)
3. **Freshness ownership.** Who keeps the Agent Menu alive if the cron fails silently? (Francis)
4. **Scope blur.** Money questions go where — CRM or Coin Purser? (Ayanna)
5. **Another silo.** Integration with existing tools unaddressed. (Puneet)

## Failure modes
- **Silent rot:** the Sunday cron fails once, the menu goes stale, nobody notices for a month, the tool is dead.
- **Client trust:** one unclear access answer and pilot clients won't put data in.
- **Scope creep:** it becomes the junk drawer for everything the Fleet tracks.

## Decision: FIX (Bayo to sign)
1. **Assign a freshness owner + a scheduler check.** Stale edition = visible warning banner. The boring-parts rule: scheduled doesn't mean done.
2. **Write the client data-access model before any client sees it.** Who sees what, enforced where. One page.
3. **Define the money boundary explicitly.** CRM tracks relationships and recommendations; money lives in the Coin Purser. Say it in the UI.

---
*Simulated 2026-10-07 by the Fleet (coordinator). Not a prediction of numbers — a map of who objects and why. Human decision: Bayo.*
*Verification: attestation below (Ed25519, NPC Verification API v1).*

## Attestation
- attestation_id: att_28d8ff430a9c5f55d1eb953e
- key_id: npc-issuer-20261006-7a188a
- signature: 0EHrhUiJmVUwSsKP7I6YO2ti2gYvSxcoLBRUHDnW9foWQgicfnD/WUIG5g1F7EIScYiy4FQtfgxI1YFt7COiDg==
- claim_hash (sha256 of this report): 130f2aa8fdc0b7daf97083f5ae850a4aee0a77e217140852e945606b7d983a9a
- anchor: local only (not_anchored)
