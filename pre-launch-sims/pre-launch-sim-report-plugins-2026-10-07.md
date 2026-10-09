# Pre-launch sim report: Verified by NPC plugins (OpenAI + MCP) (2026-10-07)

**Method:** synthetic-audience-simulation (MiroFish pattern). 8 personas, 3 rounds, compressed time. Sandboxed: no real audiences, no spend, nothing published.
**Seed (real):** plugins/openai/README.md (1.0.0, package validated, NOT submitted — dev account and Bayo's taps still gated); plugins/mcp/ (built, 40 tests, 5 tools). Positioning: "is this real?" inside the conversation; 5 ops (verify_product, verify_credential, verify_claim, verify_agent, explain_verification); read-first, fail-closed, signature-checked client-side.
**Seed gaps:** OpenAI plugin not submitted — announcing it now is announcing vaporware; no answer to "is the ChatGPT plugin platform still alive?"; no reproducible-builds story for the plugin supply chain.

## Crowd
Sam (ChatGPT power user) · Nina (MCP/Claude early adopter) · Greg ("plugins are spyware," skeptic) · Omar (developer, "why not the API?") · Lisa (AI safety, skeptic) · Ben (founder, curious) · Kate (plugin-graveyard veteran, skeptic) · Jay (crypto/AI crossover)

## Rounds
**R1 — plugins announced.** Sam wants the "is this real?" button daily; Nina says the MCP side is the real play; Ben sees embed potential. Skeptics fire: Greg (plugins see your whole conversation), Lisa (a verification plugin is the ultimate single point of trust failure), Kate ("plugins died in 2024 — ghost ship").
**R2 — platform risk.** Kate's "is the platform even alive?" hits hardest — even Sam pauses, and the launch material has no answer. Lisa's supply-chain point gets a partial technical answer (Nina: responses are signature-checked client-side, plugin can only fail closed) — Lisa: "until the plugin itself updates maliciously." Stands. Omar's "just use the API" gets Ben's distribution counter.
**R3 — settled.** 4 positive (Sam, Nina, Ben, Jay), 1 neutral (Omar), 3 negative hardened (Greg, Lisa, Kate).

## Sentiment trajectory
Enthusiastic open from users → platform-existential doubt hijacks → settles at MCP-interest with the OpenAI track under a cloud.

## Ranked objections
1. **"ChatGPT plugins are dead/dying."** Platform risk — the launch vehicle may not exist. (Kate) — HIGHEST, existential
2. **Supply-chain trust.** Who verifies the plugin itself; a compromised plugin is the ultimate misinformation vector. (Lisa, Greg)
3. **"Why not just the API/MCP?"** The plugin's value-add is distribution, not capability. (Omar)
4. **Not submitted yet.** Announcing vaporware; "package validated" isn't shipped. (All)
5. **Single point of trust failure.** One plugin, one keyholder. (Lisa)

## Failure modes
- Platform deprecation kills the OpenAI track outright.
- Security framing ("who watches the watchmen") dominates the conversation.
- Announcing before submission invites vaporware accusations that stick to the whole program.

## Decision: FIX (Bayo to sign)
1. **Lead with MCP, not OpenAI.** The MCP server is built and the Claude platform is alive — announce that now. Frame the OpenAI plugin as "in submission," never as "launched."
2. **Publish the plugin's own verification story.** Reproducible builds, signed releases, third-party audit path — the verifier must be verifiable.
3. **Don't announce the OpenAI plugin until it's submitted.** One announcement, one truth: "live" means live.

---
*Simulated 2026-10-07 by the Fleet (coordinator). Not a prediction of numbers — a map of who objects and why. Human decision: Bayo.*
*Verification: attestation below (Ed25519, NPC Verification API v1).*

## Attestation
- attestation_id: att_39bd1b325c24feb5990c04b7
- key_id: npc-issuer-20261006-7a188a
- signature: hQbwnTOgtK1+DRzzbDKJ08qWYhAXmgmax6AFG4yyalAXzl7o8pd24PPzxphh+II9Hp0T+VzFdJUX8VP6JGgADw==
- claim_hash (sha256 of this report): df57e6517fd49934e497ea23470ea385919c6af4f6b786972fa70eba0a38f7fd
- anchor: local only (not_anchored)
