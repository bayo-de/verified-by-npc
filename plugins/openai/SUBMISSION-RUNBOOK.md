# SUBMISSION RUNBOOK - Verified by NPC (OpenAI / ChatGPT plugin)

**Package:** `~/workspace/grand-fleet/verified-by-npc/plugins/openai/`
**Status as of 2026-10-06:** package validates (validate_package.py exit 0), 52/52 tests pass, NOT submitted.
**Bayo's approval 2026-10-06:** "Yes proceed" - but every money step, account step, and public listing step
needs his explicit in-the-moment tap. Nothing here is created, paid, or submitted without that.

**Track 1 progress (2026-10-06, agent work, no taps taken):**
- Demo API bundle built and locally verified: `api/serverless/npc-verify-api-netlify-drop.zip`
  (22/22 local checks green: demo fixtures, Ed25519 signatures, fail-closed unknown, write
  endpoints stripped). Deploy to api.npclabs.xyz (Netlify Drop + DNS) is Bayo's tap.
- Policy pages (privacy, terms, support) staged in `~/workspace/sites/npclabs-deploy.zip`;
  deploy is Bayo's drag-drop.
- Package at 1.0.0 with public release notes and live legal URLs; validator exit 0, 52/52 tests.
- Listing screenshots (5 real API-response cards) + 2-minute captioned demo video in
  `listing-assets/`. Bayo's tap list: `OPENAI-SUBMISSION-BAYO-STEPS.md`.

---

## 1. What is already done

- `plugin.json` - 2026-live Plugins-platform format (no retired `ai-plugin.json`), 5 positive + 3 negative
  test cases embedded, release notes, keywords, trigger phrasing for the mid-conversation suggestion channel.
- `openapi-plugin.yaml` - five read-only operations (`verify_product`, `verify_credential`,
  `verify_claim`, `verify_agent`, `explain_verification`). Issuance is intentionally absent.
- `npc_verify_openai` - thin client; verifies Ed25519 signature on every API response, treats
  unverifiable answers as "unknown", never fabricates a verdict.
- `skills/verified-by-npc/SKILL.md` - onboarding skill shipped in the package.
- `assets/logo.svg`, `assets/icon.svg`.
- `validate_package.py` - also assembles the submission ZIP (16 files) and enforces the copy rules
  (no em-dashes, no invented URLs, no funding or profitability claims).
- Reviewer test cases in `plugin.json` use demo fixtures (`demo-tag-001`, `demo-cred-001`, `demo-agent-001`).

## 2. What the submission actually needs (current 2026 path)

Source: OpenAI Developers plugin submission guide (read 2026-10-06, docs dated Sep 27, 2026).

1. **An OpenAI Platform organization** (create at platform.openai.com). Free to create.
2. **Verified publisher identity** - individual (Bayo, government-issued ID) or business (NPC Labs,
   business documents). Verification is free and takes a few minutes. The directory displays the
   verified name. Note: a business identity means the listing shows the company name.
3. **Apps Management Write permission** on the submitting account (owners have it by default; other
   members get it from an owner via organization roles).
4. **Upload the ZIP** at platform.openai.com/plugins ("Upload new or existing plugin"), choose the
   verified developer identity, wait for automated validation, resolve any findings.
5. **Listing info** - name, descriptions, logo, category, website URL, support URL, privacy policy URL,
   terms of service URL, country availability, release notes, starter prompts. All URLs must be
   public and match the verified publisher. Privacy/terms/support URLs are not yet in the package.
6. **Review information** - 5 positive + 3 negative test cases (already in `plugin.json`), a video
   walkthrough URL (see §6), release notes, reviewer credentials. No sign-in is required for v1,
   so reviewer credentials are marked N/A with an explanation (sample demo data lives on the public API).
7. **Policy attestations** in the submit dialog, then **Submit for review**. Review is tracked in the
   portal; feedback arrives by email. There is no published review timeline. OpenAI's current wording:
   "Review timelines may vary as OpenAI builds and scales the review process." Budget weeks, not days.
8. **After approval, explicitly publish from the portal.** Submission alone does not publish.
   Updates re-enter review.

## 3. Costs (exact figures, verified 2026-10-06)

| Item | Cost | Source |
|---|---|---|
| OpenAI developer account / organization creation | $0 | OpenAI docs |
| Individual identity verification (government ID, a few minutes) | $0 | OpenAI Help Center - no spending threshold required |
| Business identity verification | $0 (business documents required) | OpenAI docs |
| **Minimum prepaid API credit purchase** | **$5** (portal may default to $10 when enabling prepaid billing) | OpenAI prepaid billing docs, Sep 2026 |
| Plugin submission fee / listing fee | **None published** - no submission or review fee was found in OpenAI's current docs as of 2026-10-06 | OpenAI docs |
| Review timeline | **No published timeline** - varies while OpenAI scales the review process | OpenAI docs |

**Money ask for Bayo (one tap):** approve up to **$10** for the minimum API credit purchase
($5 minimum; $10 is the portal default when enabling prepaid billing). Nothing else in this runbook
costs money. Note: credits are for the org's API balance, not a plugin fee.

**Caveats to confirm at submission time:**
- A third-party publisher checklist (Sep 2026) notes an organization with EU data residency enabled
  currently cannot submit for review. Set the org to a US data residency (default) and re-check the
  current portal state on submission day.
- The API backend (`api.npclabs.xyz`) must be publicly live with the demo records before review, or
  the review will fail on non-functional tools. Deployment is a separate Bayo-gated step.

## 4. Gaps to close before submission (not gated on money)

1. **Public production API deployment** - `https://api.npclabs.xyz/v1` must be live from the public
   internet, serving the demo fixtures and publishing the Ed25519 public keys at `GET /v1/keys`.
   Reviewers test against production, not localhost.
2. **Public policy pages on npclabs.xyz** - privacy policy, terms of service, support page, and the
   main website URL. These are required listing fields and must match the verified publisher.
   (Package currently has no privacy/terms/support URLs. Add to `plugin.json` interface when live.)
3. **Listing screenshots** - the portal asks for listing visuals. Prepare at least one clear screenshot
   of the plugin answering a verification question in ChatGPT.
4. **Demo video** - an accessible recording URL is required (see §6).
5. **Version + release notes** - bump from `0.1.0` ("Internal preview") to a public-facing version
   (suggest `1.0.0`) and rewrite release notes in public voice before the upload ZIP is assembled.
6. **Country availability** - choose the launch countries (suggest United States to start; expand later).

## 5. Account setup steps (Bayo taps each gate)

These are the exact steps; anything marked **[BAYO TAP]** stops until he explicitly approves it in the
moment. Do not pre-create, do not pre-pay.

**Step A - Create the OpenAI Platform account and organization**
1. Sign up at platform.openai.com with Bayo's chosen email (suggest `bayo@npclabs.xyz`; confirm with him).
2. Create the organization: name it to match the publisher choice (see Step C).

**Step B - Verify the publisher identity [BAYO TAP]**
1. Go to Settings > Organization > General > **Verify Organization**.
2. Choose individual or business:
   - *Individual:* Bayo's unexpired government-issued ID (passport, driver's license, national ID),
     full name, date of birth, clear portrait photo. Takes a few minutes. The directory shows his name.
   - *Business:* NPC Labs business documents. The directory shows "NPC Labs".
3. Bayo completes the verification himself (ID upload happens in his browser session).

**Step C - Confirm Apps Management Write access**
- The org owner has it automatically. If someone else submits, an owner grants
  "Apps Management: Write" via Settings > Organization > People > Roles.

**Step D - Fund the minimum credit balance [BAYO TAP]**
1. Billing > Add payment details. Add the card Bayo chooses.
2. Purchase credits: minimum **$5**, portal may suggest **$10**. Bayo approves the exact amount first.
3. This is a prepaid API balance, not a plugin fee. Nothing is owed beyond what he approves.

**Step E - Assemble and validate the final package (agent work, no Bayo tap)**
1. Close the §4 gaps (public URLs in `plugin.json`, bump version to 1.0.0, public release notes).
2. Re-run `python3 validate_package.py` (must exit 0) and the unittest suite (must be 52/52 OK).
3. Assemble the submission ZIP via the validator. Inspect contents; no secrets, no private data.

**Step F - Upload the draft [BAYO TAP to upload]**
1. Open platform.openai.com/plugins > **Upload new or existing plugin**.
2. Select the verified developer identity (the directory will show this name).
3. Upload the ZIP. Wait for automated validation and check **Metadata & Skills** for Issues.
4. Resolve any findings by editing the package and re-uploading ("Upload plugin to fix issues").

**Step G - Complete review information (agent prep + Bayo approval)**
1. Confirm the 5 positive + 3 negative test cases imported from the ZIP into Review details.
2. Mark reviewer credentials N/A with the note: "No sign-in required. The API is public and read-only;
   demo records (demo-tag-001, demo-cred-001, demo-agent-001) are preloaded for testing."
3. Paste the video walkthrough URL (§6).
4. Enter country availability and starter prompts.
5. Bayo approves the final listing copy (§7) before anything is submitted.

**Step H - Submit for review [BAYO TAP]**
1. Choose **Submit for review**, complete the policy attestations, submit.
2. Track under **Review status**; review feedback comes by email. No published timeline; plan for weeks.

**Step I - Publish after approval [BAYO TAP]**
1. When approved, Bayo chooses the go-live moment and selects **Publish plugin** in the portal.
2. Only then does the listing appear in the ChatGPT and Codex plugin directory.
3. Keep the demo API live, the demo records loaded, and keys published; OpenAI re-scans hosted
   servers daily and updates re-enter review.

## 6. Reviewer materials

### Demo account plan
**No demo account is required.** The plugin's API is public and read-only; v1 has no login, no OAuth,
no API key requirement for the reviewer. The review-details entry reads:

> Sign-in: not required. All five operations run against the public NPC Verification API at
> https://api.npclabs.xyz/v1. Use the preloaded demo fixtures: product smart tag `demo-tag-001`,
> credential ID `demo-cred-001`, agent ID `demo-agent-001`. Every API response is Ed25519-signed;
> keys are published at https://api.npclabs.xyz/v1/keys for independent checking.

Use sample data only. Never hand reviewers a real user account, real credentials, or real private
records.

### Demo video plan (required - accessible recording URL)
Target: 2–3 minutes, screen recording with Bayo's voiceover or captions. Host as an unlisted video
(linkable without a login). Shot list:

1. **Title card (5s):** "Verified by NPC - verify what you are looking at, inside the conversation."
2. **Install/connect (15s):** open the ChatGPT plugin directory, find "Verified by NPC", add it.
3. **Verify a product (25s):** "Is this product authentic? The smart tag reads demo-tag-001."
   Show the signed verdict and the public provenance chain.
4. **Verify a credential (20s):** "Verify this certificate. The credential ID is demo-cred-001."
   Show valid/revoked/expired status handling.
5. **Verify a claim (20s):** "Is this claim real?" Show a matched attestation summary.
6. **Verify an AI agent (20s):** "Is this agent verified?" Show verdict with scope and time bounds.
7. **What it means (15s):** "What does Verified by NPC mean?" Show the plain-language explainer.
8. **Fail-closed behavior (30s):** ask about an unknown subject - show "unknown," never a guess.
   Ask the plugin to issue an attestation or explain its checking methodology - show both refusals.
9. **Close (5s):** "Verified by NPC. Is this real? Verify it."

## 7. Listing copy (draft - needs Bayo's line-by-line approval)

Copy rules enforced: no em-dashes, no raised-funds or profitability claims, plain product language,
why not how.

- **Name:** Verified by NPC
- **Tagline:** Is this real? Verify it.
- **Short description:** Check whether a product, certificate, claim, or AI agent is verified by NPC Labs.
- **Long description:**
  > Verified by NPC answers the question "is this real?" right inside your conversation. Check whether
  > a product is authentic. Check whether a certificate or credential is valid. Check a claim against
  > NPC Labs' records. Check an AI agent's verification status. Or ask what a verification result means.
  >
  > Every answer comes back signed by NPC Labs, so the answer can be checked independently of the
  > connection it arrived over. When NPC Labs has no record of what you asked about, the answer is
  > "unknown." Unknown is never a guess, and it is never a claim that something is false. The plugin
  > verifies only; it cannot issue verifications.
- **Trigger phrasing** (for the mid-conversation suggestion channel): "is this real?", "verify this",
  "is this authentic?", "is this certificate valid?", "did this really happen?", "is this agent
  verified?", "what does Verified by NPC mean?"
- **Starter prompts:**
  1. "Is this product authentic?"
  2. "Verify this certificate."
  3. "Is this claim real?"

## 8. The exact asks for Bayo

1. **Approve the money:** one tap for the minimum API credit purchase (min **$5**; portal may default
   to **$10**) with the card of his choice. No other fee exists.
2. **Complete identity verification** at platform.openai.com > Settings > Organization > General >
   Verify Organization (his browser, his government ID; individual or business, his choice).
3. **Choose the publisher identity:** individual "Bayode Okusanya" or business "NPC Labs."
4. **Approve the listing copy** in §7 line by line before upload.
5. **Approve the account email** for the developer org (suggested: bayo@npclabs.xyz).
6. **Approve country availability** (suggested: United States at launch).
7. **Gate the production API deployment** - the public API at api.npclabs.xyz with demo fixtures must
   be live before review.
8. **Approve publish timing** after approval - submission alone never publishes.

---
*Runbook version 1.0 - 2026-10-06. Re-check OpenAI's submission guide on submission day; the 2026
plugin channel is still evolving (Dev Day Sep 2026 added review tracking, human-review requests, and
tool updates without restarting submission).*
