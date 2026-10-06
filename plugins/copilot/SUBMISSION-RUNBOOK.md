# Verified by NPC - Microsoft Partner Center Enrollment + Copilot Validation Runbook

**Track 3.** Status: package built and verified locally (2026-10-06). Nothing submitted, no accounts created, no payments made, no Microsoft contacted. Internal document. Approval gates for Bayo are called out explicitly at each step.

Companion assets: `npc-verify-apiplugin.json` (manifest v2.2), `npc-verify-openapi.yaml` (OpenAPI 3.0.3), `declarative-agent.json` (schema v1.3), `npc_verify_copilot/` thin client, `validate_package.py` + 45-test unittest suite. Design doc: `~/workspace/grand-fleet/verified-by-npc/docs/DESIGN-v1.md` (Phase 2c, hard gate #4).

---

## 0. Current state (verified 2026-10-06)

```
python3 validate_package.py
Ran 45 tests in 4.986s: OK
== ALL CHECKS PASSED ==
```

- All required files present; manifest schema v2.2; five functions mapped to the OpenAPI spec; read-only (no issuance); fail-closed; no em-dashes in user-facing strings.
- Signature pass/tamper/fail-closed tests green. Proofline-style contracts per action green.
- Gaps before submission are in Section 3. None of them need a browser; all of them are noted as build steps below.

## 1. Enrollment facts (researched 2026-10-06, current Microsoft docs)

### 1.1 Account types and fees

Partner Center developer accounts come in two types. **The choice is irreversible.** You cannot convert an Individual account to a Company account later; you would have to create a new Company account.

| Account type | Fee | Who it is for |
|---|---|---|
| Individual | **Free** worldwide, no registration fee (the legacy ~$19 one-time fee still appears in older community guides, but current Microsoft Learn docs list Individual as free) | Hobbyists, amateurs, personal projects. Shorter verification process. |
| Company | **~$99 USD one-time** (varies by country/region; no renewal ever) | Businesses and organizations: corporations, LLCs, partnerships. Greater verification: business identity documents stored 6 months after account closure. Company contact info (email, business address, phone) is **public on the listing page**. |

**Recommendation:** Company account. Verified by NPC is distributed in relation to NPC Labs' business, which is exactly Microsoft's stated criterion for Company over Individual. An Individual account would misrepresent the publisher and cannot be upgraded.

What is NOT needed for this track:
- Solutions Partner designation ($4,730 to $4,875/year) is a separate partner-badge program. Not required to publish agents. Skip.
- Microsoft 365 and Copilot program enrollment itself carries no separate fee beyond the partner account. You accept the Microsoft Publisher Agreement during enrollment.
- No payout/tax profile for this offer: the plugin is distributed through the store but value flows through NPC's own verifier API keys, not a transactable marketplace offer. If a transactable SaaS offer is ever added, the payout/tax profile becomes a required step (bank + tax docs, typically weeks).

### 1.2 Identity and business verification

- **Verifiable Credentials via AU10TIX.** The primary contact completes identity verification: government-issued ID (passport or driver's license) plus a mobile device with the Microsoft Authenticator app. Budget about 15 to 30 minutes. The name on the ID must match the Partner Center primary contact **exactly**, same language. You have 30 days to complete the verification once requested.
- **Enrollment verification timeline (Microsoft):** most cases complete in **3 to 5 business days**; business verification typically 1 to 2 business days; employment verification about 2 hours. Some checks take longer if Microsoft requests additional information. **You cannot publish until overall status is "Authorized."**
- All verification emails and status updates go to the **primary contact's email**. Other users can complete some steps, but only the primary contact gets the notices.
- MAICPP (Microsoft AI Cloud Partner Program) enrollment must be done by a **Global admin** on the Entra tenant.

### 1.3 Program enrollment for Copilot agents

1. Sign in to Partner Center, go to **Account settings > Programs**.
2. On the **Microsoft 365 and Copilot** tile, click **Get Started** and accept the Microsoft Publisher Agreement.
3. Create offers via **Marketplace offers > + New offer > "Apps and agents for Microsoft 365 and Copilot"**. (If that offer type appears in the list, the program is enrolled. There is no separate "Microsoft 365 and Copilot" tab.)
4. This is a free listing route. The agent appears in the Agent Store inside Microsoft 365 Copilot (plus Teams, Outlook, and the Microsoft 365 apps) once an IT admin enables it for their tenant.

## 2. The Copilot validation bar (what Microsoft reviews)

Your package must satisfy all of these before Partner Center approves it:

1. **Microsoft Commercial Marketplace certification policies** (the baseline store certification rules).
2. **Microsoft 365 store validation guidelines for agents.** For API plugins, the description rules apply to `description_for_human`, `description_for_model`, `capabilities`, `conversation_starters`, and function descriptions, plus the `description` fields in the OpenAPI spec. Must-fix items: no instructional phrases (for example, anything shaped like "if the user says X"); no URLs, emojis, or hidden characters; no grammar or punctuation errors. Good-to-fix items: no overly verbose or flowery marketing language; no superlative claims ("#1", "amazing", "best"). For declarative agents the same rules apply to `instructions` and `conversation_starters`.
3. **Responsible AI validation checks.** These run during manifest validation (sideload or publish) and during prompt processing. A failed agent cannot publish until fixed. Triggers include: encouraging harmful actions; hostile or deceptive content; attempting to bypass guidelines or manipulate the model; violating copyright.
4. **(Optional) Microsoft 365 App Compliance certification.** Strengthens the listing but is not required for v1. Defer; revisit after launch.

### 2.1 App package format

A single ZIP with these members at the root:

| File | Purpose |
|---|---|
| `manifest.json` | Teams app manifest: identity, capabilities, permissions, the agent declaration |
| `declarative-agent.json` | Agent behavior: instructions, conversation starters, actions |
| `npc-verify-apiplugin.json` | API plugin configuration |
| `npc-verify-openapi.yaml` | The API contract, also served at a public HTTPS URL |
| `color-icon.png` | 192x192 full color icon |
| `outline-icon.png` | 32x32 white outline icon, transparent |

Manifest essentials (reviewers bounce these):
- Stable GUID app ID. Never regenerate between versions.
- Semantic version that strictly increases on every submission.
- Developer block: name, website, privacy policy URL, terms URL. All HTTPS, publicly reachable, no authentication required.
- Name and short description must match the store listing. No competitor names, no unsubstantiated superlatives, no "Microsoft" in the product name in a way that implies endorsement.
- Minimum permissions and scopes. Every declared domain your agent contacts must be listed in valid domains.
- OpenAPI `server` URL must be absolute HTTPS, publicly reachable.

### 2.2 Review timeline

Microsoft publishes no fixed SLA for Copilot agent certification. Publisher community experience: **typically several days to a couple of weeks**, depending on the review queue and how many findings come back. Plan for one review round of findings plus remediation time. Preview/field validation against a real test tenant is on us before submission, not on the reviewer.

## 3. Package gaps (build steps, no browser needed)

Nothing here is started. Each is reversible internal work.

| # | Gap | Notes |
|---|---|---|
| 1 | Teams `manifest.json` wrapper | Not yet built. Needs: GUID app ID, developer block (publisher name/website/contact from the entity decision in Section 5), valid domains including `api.npclabs.xyz`, icon references. |
| 2 | Icons | 192x192 color + 32x32 outline. **Do not use the "Verified by NPC" mark artwork.** Mark use awaits counsel clearance. Use plain text/wordmark art until then. |
| 3 | Production API deployment | `https://api.npclabs.xyz/v1` is the listed production target but deployment is a gated decision (design doc gate #5: hosting choice + budget). |
| 4 | Public spec URL | `https://api.npclabs.xyz/v1/npc-verify-openapi.yaml` must serve the spec over HTTPS, no auth. Depends on gap 3. |
| 5 | Privacy policy + terms pages | Required listing fields. Need drafting and hosting on npclabs.xyz. Legal review recommended. |
| 6 | Manifest contact/legal fields | `contact_email`, `legal_info_url`, `privacy_policy_url`, `logo_url` in the plugin manifest are intentionally unset. Fill at build from the entity decision. |
| 7 | Screenshots and demo video | 3-5 screenshots showing real agent responses (no mockups of unimplemented features). Video optional, 60-180 seconds, captioned. Produce once the API is deployed and the agent is testable. |
| 8 | Schema version re-check | Our declarative-agent wrapper targets schema v1.3. Community publisher guides (2026) reference v1.6 as current. Re-verify against the live Microsoft schema at build time and bump if needed. |
| 9 | Description hardening | Our `description_for_model` uses trigger phrasing ("Use when the user asks..."). The guidelines ban instructional phrases shaped like "if the user says X" as a must-fix. Our phrasing is defensible and Microsoft's own samples use similar language, but reviewers vary. Recommended reword to descriptive language (example: "Answers questions such as 'is this real?'...") before submission. This is a Bayo decision (Section 5). |
| 10 | Reviewer test access | Validation must be reproducible. Provide setup instructions, expected prompts and results, and a demo verifier API key through Partner Center's private submission notes. Never put credentials in ordinary email and never weaken production auth. |
| 11 | Pricing and verifier keys | The plugin authenticates each user with their own NPC verifier API key (ApiKeyPluginVault). Who gets keys, and at what price, is a Bayo decision. Listing copy must state the prerequisite accurately. |

## 4. Store listing copy (DRAFT, for Bayo's approval)

All human-facing copy rules observed: no em-dashes, no fundraising or profitability claims, plain product language, the why never the how.

**Offer name:** Verified by NPC
(Must stay identical across `manifest.json`, `declarative-agent.json`, and the plugin manifest. Store validation rejects the package when the three disagree.)

**Short description (one sentence):**
Check whether a product, credential, claim, or AI agent is genuinely verified, right inside Microsoft 365 Copilot.

**Long description:**
Before you buy it, share it, or trust it, check it.

Verified by NPC lets you verify things right inside Microsoft 365 Copilot. Ask whether a product is authentic, whether a credential is real, whether a claim checks out, or whether an AI agent is verified, and get a clear answer from NPC Labs' attestation records: verified, flagged, or unknown.

Why it matters: fakes and false claims cost real money and real trust. A quick check before you act means you can move with confidence. When NPC Labs has no record of something, the answer is simply "unknown," so you never mistake a guess for a verdict. Every answer is digitally signed, so it stands on its own evidence rather than on a promise.

Who it is for: anyone shopping for authentic goods, teams checking credentials and claims, and anyone who wants to know whether the AI agent in front of them carries verification.

What you need: a Microsoft 365 Copilot license, plus an NPC Labs verifier API key that you enter once in the plugin settings. The plugin verifies. It never issues attestations, and it never collects more than the identifier you ask about.

**Categories:** AI Apps and Agents, Machine Learning
(1 to 3 categories; these two put the offer in the AI discovery lanes.)

**Conversation starters (already in the package, unchanged):**
- Is this product authentic?
- Verify this credential.
- Is this claim real?
- Is this agent verified?

**Support contact:** hello@npclabs.xyz (placeholder, confirm before submission)
**Website:** https://npclabs.xyz
**Privacy policy / Terms:** to be created (gap 5)
**Logo:** to be designed (gap 2, no counsel-gated mark)

## 5. Step-by-step runbook

**Steps 1 to 3 need Bayo's explicit tap at each step. Steps 4 to 8 are build work I can do once the gates are cleared. Step 9 is a browser task for the main agent with Bayo present.**

### Step 1 - Bayo decides (Gate A)
1. Publisher entity: NPC Labs (recommended) or SPC. The legal name must match exactly what Partner Center verifies, and it is public on the listing.
2. Primary contact: the person whose government ID will be used for AU10TIX verification (name must match the ID exactly), and the working email that receives all verification notices. Use a company email, not a personal one.
3. Approve the **~$99 USD one-time** Company account registration fee (Individual is free but is for hobbyists and cannot be converted later).
4. Approve the listing copy in Section 4 (name, short and long description, categories).
5. Decide verifier-key pricing and distribution (who gets keys, free tier vs paid). The listing must state the prerequisite.
6. Decide on the description-hardening reword (gap 9), or keep the current trigger phrasing.
7. Approve production API hosting and budget for `api.npclabs.xyz` (design doc gate #5; Bayo already holds this gate).
8. Legal: privacy policy and terms drafting (and the "Verified by NPC" mark question is already on counsel's list; listing art must avoid the mark either way).

### Step 2 - Build the submission package (reversible, no browser)
1. Re-verify the current declarative-agent and plugin schema versions against the live Microsoft schemas; bump if the store expects newer than v1.3/v2.2.
2. Build the Teams `manifest.json` wrapper (GUID app ID, developer block, valid domains, icon references, semantic version 1.0.0).
3. Fill `contact_email`, `legal_info_url`, `privacy_policy_url`, `logo_url` in `npc-verify-apiplugin.json` from the Section 1 decisions.
4. Apply the description-hardening reword if Bayo approved it; re-run `validate_package.py` (must exit 0).
5. Design the two icons (192x192 color, 32x32 outline), plain wordmark art, no counsel-gated mark.
6. Assemble the ZIP with the five members at the root; validate JSON parses and the spec URL is absolute HTTPS.
7. Draft reviewer test instructions: expected prompts, expected results, demo verifier API key, setup steps. Keep credentials for the private submission notes only.

### Step 3 - Deploy and test (gates: hosting approval, API deployment)
1. Deploy API v1 to `https://api.npclabs.xyz/v1`; serve `npc-verify-openapi.yaml` at the public spec URL over HTTPS with no auth.
2. Run the full validator plus the unittest suite against the production URL.
3. Produce 3-5 real screenshots of agent responses and the optional 60-180 second captioned demo video.
4. Publish the privacy policy and terms pages; confirm every URL in the package and listing resolves over HTTPS with no login.
5. Internal golden-prompt regression pass: verify, credential, claim, agent, explainer, plus unknown-subject and tampered-response cases (fail-closed behavior must be what the reviewer sees).

### Step 4 - Create the Partner Center account (browser, Bayo present)
1. Sign in to Partner Center with the company Microsoft account.
2. Enroll as a **Company** developer account; pay the one-time fee (~$99 USD).
3. Complete business verification (typically 1-2 business days) and the AU10TIX identity flow for the primary contact (15-30 minutes, government ID + Authenticator app). Watch the primary contact email for follow-ups.
4. Confirm overall status reaches **Authorized** in Account settings > Legal info (typical total: 3-5 business days). No publishing before this.

### Step 5 - Enroll in the Microsoft 365 and Copilot program (browser)
1. Account settings > Programs > **Microsoft 365 and Copilot** tile > Get Started.
2. Accept the Microsoft Publisher Agreement.
3. Confirm enrollment by checking that Marketplace offers > **+ New offer** lists **"Apps and agents for Microsoft 365 and Copilot"** as an offer type.

### Step 6 - Create and complete the offer (browser)
1. **+ New offer > Apps and agents for Microsoft 365 and Copilot.**
2. Packages: upload the ZIP from Step 2. Wait for manifest checks to pass; fix any errors before proceeding.
3. Properties: select 1-3 categories (AI Apps and Agents, Machine Learning recommended).
4. Marketplace listings: offer name, approved short and long descriptions, screenshots, support link and monitored contact address.
5. Legal: privacy policy URL, terms URL, Standard Contract or custom EULA.
6. Private submission notes: reviewer test instructions and demo verifier API key (gap 10).

### Step 7 - Submit and respond to validation (browser, then waiting)
1. Submit the offer for validation. Expect **several days to a couple of weeks** for the review round; Microsoft publishes no fixed SLA.
2. Track findings by owner and package version. Remediate, bump the semantic version, re-upload, resubmit. Typical first submissions come back with at least minor findings; budget for one full cycle.
3. If a finding touches copy or behavior, get Bayo's approval on the change before resubmitting.

### Step 8 - Publish and enable
1. Once approved, complete the publisher release steps in Partner Center (the offer does not go live by itself).
2. The agent appears in the Agent Store inside Microsoft 365 Copilot once an IT admin enables it for their tenant. Roll out in stages: dogfood tenant first, then selected tenants, then general availability.

## 6. Exact asks for Bayo (nothing proceeds without these)

1. **Approve the ~$99 one-time Company account fee** (Individual is free but wrong for business distribution and cannot be converted).
2. **Name the publisher entity** (NPC Labs recommended vs SPC) exactly as it should appear publicly and on legal documents.
3. **Name the primary contact** for identity verification (government ID must match the name exactly) and the company email that receives verification notices.
4. **Complete the AU10TIX identity flow himself** (15-30 minutes, ID + phone with Authenticator) once the account exists.
5. **Approve the listing copy** in Section 4 (name, short description, long description, categories) line by line.
6. **Decide verifier-key pricing and distribution** (free tier vs paid; who gets keys).
7. **Approve production API hosting and budget** at api.npclabs.xyz (design doc gate #5, already on his list).
8. **Approve privacy policy and terms drafting** (legal pages are required listing fields; the mark question is already with counsel).
9. **Approve or reject the description-hardening reword** (gap 9) before we build the final package.
10. **Confirm the demo video and screenshots** can be produced once the API is deployed (or defer video to v1.1).

---

*Nothing in this runbook creates an account, pays a fee, submits a package, or contacts Microsoft. Every irreversible step stops at Bayo's explicit word.*
