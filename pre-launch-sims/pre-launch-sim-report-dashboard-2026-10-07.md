# Pre-launch sim report: Verified by NPC web dashboard (2026-10-07)

**Method:** synthetic-audience-simulation (MiroFish pattern). 8 personas, 3 rounds, compressed time. Sandboxed: no real audiences, no spend, nothing published.
**Seed (real):** dashboard/README.md — 6 pages (why, records, credentials, products, keys, plugins); local-first, read-first, fail-closed; Ed25519 signature-verified client-side; static export to Netlify planned. Positioning: "see the full verification record" (the why, never the method).
**Seed gaps:** no launch-announcement copy; no migration story for competitor users; chain anchoring still "not_anchored" (Phase 2); no enterprise compliance story.

## Crowd
Dana (CTO evaluating verification, expert) · Rob ("trust badge" cynic, skeptic) · Elena (indie hacker, open-source lean) · Marcus (competitor's user, skeptic) · Priya (crypto native) · Tom (enterprise security, skeptic) · Aisha (founder, curious) · Leo (design nerd)

## Rounds
**R1 — dashboard launches.** Dana respects the fail-closed API design; Elena loves the stdlib purity; Leo loves the restraint. Skeptics fire: Rob ("the company selling verification is the verifier"), Priya ("not anchored = a local SQLite file?"), Tom ("no SOC 2, enterprise can't touch this").
**R2 — root of trust.** Rob's "who verifies the verifier" becomes the thread. Elena counters: "keys are published, you check the math yourself." Rob: "And who verifies the key belongs to NPC?" — the recursion sticks. Priya concedes the honesty ("not_anchored" is disclosed) but not the claim. Tom's enterprise objection stands unopposed. Marcus's migration question has no answer in the material.
**R3 — settled.** 4 positive (Dana, Elena, Aisha, Leo), 1 neutral (Priya — "call me when it's onchain"), 3 negative (Rob, Tom, Marcus).

## Sentiment trajectory
Respectful open from builders → root-of-trust debate becomes the whole conversation → settles at developer-interest with enterprise and crypto passing.

## Ranked objections
1. **"Who verifies the verifier?"** Root-of-trust recursion; self-issued keys need an independent anchor. (Rob) — HIGHEST
2. **Not onchain yet.** "not_anchored" is honest but deflates the trust claim. (Priya)
3. **Enterprise unreadiness.** No SOC 2, no audit, no SLA. (Tom)
4. **No migration story** from competitor attestation services. (Marcus)
5. **"Another trust badge" fatigue.** The category is crowded with stickers. (Rob)

## Failure modes
- Root-of-trust debate becomes the entire launch conversation.
- Crypto natives dismiss without chain anchoring; enterprise passes entirely.
- Launched to the wrong audience (enterprise) it dies on compliance.

## Decision: FIX (Bayo to sign)
1. **Lead with the root-of-trust answer.** Published keys + independent key-signing ceremony plan + chain-anchoring roadmap with dates. Put it on the homepage, not in the docs.
2. **Ship a "verify it yourself in 60 seconds" path.** The strongest counter to "who verifies the verifier" is a working demo, not a paragraph.
3. **Position developer-first, not enterprise.** Don't pitch Tom's world yet — win Dana and Elena first.

---
*Simulated 2026-10-07 by the Fleet (coordinator). Not a prediction of numbers — a map of who objects and why. Human decision: Bayo.*
*Verification: attestation below (Ed25519, NPC Verification API v1).*

## Attestation
- attestation_id: att_09a6042b50881266e19e6d69
- key_id: npc-issuer-20261006-7a188a
- signature: Tv6ce9Ld+f0agToYvkVy3PM6kwoOdR46j1g0QR0f+Ijw9V+R0b380XsO45RvU26YpbbR6oG6Px8mI2jYg3OgCg==
- claim_hash (sha256 of this report): aa4e8165edf3ab8d2a131149228053c327b7a4ddd75d13736b7de1804f27050a
- anchor: local only (not_anchored)
