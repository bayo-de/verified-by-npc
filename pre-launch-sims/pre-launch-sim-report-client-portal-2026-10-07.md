# Pre-launch sim report: Desktop app / client portal (2026-10-07)

**Method:** synthetic-audience-simulation (MiroFish pattern). 8 personas, 3 rounds, compressed time. Sandboxed: no real audiences, no spend, nothing published.
**Seed (real):** four-tab artifact (Fleet, Trust, Builder, Sentinel-guarded Biblo); purpose: production, analysis, and verification of NPC-certified agents; Certified Agent Menu weekly feed (client-safe recommendations, why-first-never-how); Builder tab one-click agent library.
**Seed gaps:** no one-sentence pitch (non-technical buyers bounce); no documented customization path past one-click; no switching-cost story vs incumbents; verification headline buried behind tabs.

## Crowd
Diane (ops director, tool-fatigued) · Victor ("another AI dashboard" cynic, skeptic) · Grace (founder, wants agents but doesn't trust them) · Henry (non-technical exec) · Fiona (AI power user) · Carl (competitor's customer, skeptic) · Beth (compliance-minded) · Eddie (developer)

## Rounds
**R1 — portal launches.** Grace loves the Certified Agent Menu ("someone vets agents weekly — that's what I need"); Fiona wants the Sentinel-guarded Biblo interface; Beth lights up at audit trails. Skeptics: Victor ("every AI startup has a dashboard"), Carl (switching costs?), Eddie (customization cliff?), Henry ("who manages this?").
**R2 — the differentiation fight.** Grace counters Victor with verification — "every agent action signed, show me another dashboard that does that." Victor: "Signed by whom? Themselves?" — root-of-trust again. Eddie's customization question has no answer in the material. Henry's confusion reveals the pitch gap.
**R3 — settled.** 4 positive (Diane, Grace, Fiona, Beth), 2 neutral (Henry, Eddie), 2 negative (Victor, Carl).

## Sentiment trajectory
Curious open → differentiation debate (verification is the only moat, and it's questioned) → settles at operator-interest. The compliance angle (Beth) is the sleeper strength nobody else picked up.

## Ranked objections
1. **"Another AI dashboard."** Category fatigue; verification must be the headline, not tab 2. (Victor) — HIGHEST
2. **Root-of-trust recursion.** "Signed by whom?" follows every trust-layer launch. (Victor)
3. **Customization cliff.** One-click is great until it isn't; no answer on what happens after. (Eddie)
4. **Positioning muddle.** "Who manages this?" — the one-sentence pitch is missing. (Henry)
5. **Switching costs** from incumbent agent tools unaddressed. (Carl)

## Failure modes
- Launched as "a dashboard" it dies in the noise; the verification story must lead or nothing differentiates.
- Non-technical buyers bounce off complexity before reaching the Builder tab.
- The compliance buyer (Beth) is real but needs the audit-trail story front and center.

## Decision: FIX (Bayo to sign)
1. **Headline is verification, not tabs.** "Every agent action signed and auditable" is the entire pitch. The four tabs are the proof, not the promise.
2. **Write the one-sentence version.** For Henry: "It's a control room where every AI agent's work is checked and signed off." If he doesn't get it, nobody new does.
3. **Document the customization path before launch.** What happens after one-click — API, editing, export. Eddie's question will come from every developer.

---
*Simulated 2026-10-07 by the Fleet (coordinator). Not a prediction of numbers — a map of who objects and why. Human decision: Bayo.*
*Verification: attestation below (Ed25519, NPC Verification API v1).*

## Attestation
- attestation_id: att_fd2aac9a5b7af7ac9d42dd31
- key_id: npc-issuer-20261006-7a188a
- signature: SXr5pjmkrFRvPmHYWiX5C99mfa2k7NGNmotLf5Ck4+ofIQT36WrHXvYTttHw3MmbFQRyPly73vRpW4cK8q29CA==
- claim_hash (sha256 of this report): d939c48227643fd563780acd7724a83825ef59268b090ab27d9a2d8ae5764c11
- anchor: local only (not_anchored)
