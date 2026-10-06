# Verified by NPC (OpenAI plugin) - Bayo's tap list

Everything below is in click order. Nothing here is done until you tap it.
Each section says exactly what to do and what to check.

---

## STEP 1 - Put the demo API live at api.npclabs.xyz (about 10 minutes)

The deploy bundle is ready and verified:
`~/workspace/grand-fleet/verified-by-npc/api/serverless/npc-verify-api-netlify-drop.zip`
(48 KB, stdlib-only Python function, read-only demo fixtures, every
response Ed25519-signed).

1. Go to **https://app.netlify.com/drop** (log in to your Netlify account,
   team "Bayo's Grand Fleet").
2. Drag `npc-verify-api-netlify-drop.zip` onto the drop zone. Netlify
   creates a new site (it will get a random name like
   `shiny-panda-123abc`).
3. Rename it: **Site settings > General > Site details > Change site
   name** to `npc-verify-api`.
4. Add the custom domain: **Site settings > Domain management > Add
   custom domain** > type `api.npclabs.xyz` > Add. Netlify will show
   "Check DNS configuration" and provision HTTPS automatically once DNS
   resolves (this can take a few minutes).
5. Point DNS at it: open **GoDaddy > npclabs.xyz > DNS**, add a **CNAME**
   record: Host `api`, Points to `npc-verify-api.netlify.app`, TTL 1 hour.
   (If GoDaddy will not take a CNAME for this, use Netlify's A-record
   address shown on the domain page instead.)
6. Wait for Netlify to show **"Netlify DNS" / HTTPS active** on the domain
   page (usually 2 to 10 minutes after the DNS record propagates).
7. Verify, in this order:
   - `https://api.npclabs.xyz/v1/health` shows `"status": "ok"`.
   - `https://api.npclabs.xyz/v1/keys` shows the public signing keys with
     key IDs starting `npc-demo-api-signing-`.
   - Tell Biblo it is live; he will run the full signature verification
     from his side before anything is submitted.

Do not skip the verify step. Nothing submits until the API answers from
the public internet.

---

## STEP 2 - Publish the site update with Privacy, Terms, Support (5 minutes)

The site bundle already includes the three new pages:
`~/workspace/sites/npclabs-deploy.zip` (now 36 KB; adds `privacy.html`,
`terms.html`, `support.html`, plus footer links on the home page).

1. Go to **https://app.netlify.com/projects/magenta-tanuki-7c105a/deploys**
   (the existing npclabs.xyz site).
2. Drag `npclabs-deploy.zip` onto the **Deploys** page drop zone.
3. When it finishes, open `https://npclabs.xyz/privacy`,
   `https://npclabs.xyz/terms`, and `https://npclabs.xyz/support` and
   confirm all three render.

The plugin listing links to these three URLs, so they must be live
before submission.

---

## STEP 3 - Create the OpenAI developer account and organization (5 minutes)

1. Go to **https://platform.openai.com** and sign up with
   **bayo@npclabs.xyz**.
2. Create the organization: name it **NPC Labs** (to match the verified
   publisher identity in Step 4).
3. Confirm you are the org **Owner** (owners get Apps Management write
   access automatically). Check: **Settings > Organization > People**.
   Your row should say Owner.
---

## STEP 4 - Verify the business identity: NPC Labs (a few minutes)

1. Go to **Settings > Organization > General > Verify Organization**.
2. Choose **business** verification (the listing will show "NPC Labs",
   per your approved decision).
3. Upload NPC Labs business documents when asked and complete the steps.
   This is free and usually takes a few minutes.
4. Confirm the verified name reads **NPC Labs** before continuing.

---

## STEP 5 - Add the $5 API credit (one tap, NPC Labs business card)

This is the only money step. Minimum is **$5**. The portal may suggest
**$10**; choose **$5**. Use the NPC Labs business card. If the portal
will not let you complete it at $5, stop and tell Biblo.

1. Go to **Billing** (left sidebar) **> Add payment details**.
2. Add the NPC Labs business card.
3. **Billing > Buy credits** (or Add funds): enter **$5.00**, confirm.
4. Confirm the org balance shows **$5.00** in credit.

This buys prepaid API balance for the org. It is not a plugin fee; there
is no submission or listing fee.

---

## STEP 6 - Upload the plugin and fill in review info (10 minutes)

The submission ZIP is assembled and validated (16 files, 52/52 tests
pass). Biblo hands you the exact file at upload time.

1. Go to **platform.openai.com/plugins > Upload new or existing plugin**.
2. Select the verified developer identity **NPC Labs**.
3. Upload the ZIP. Wait for automated validation; open **Metadata &
   Skills** and resolve any Issues it lists (tell Biblo about any finding
   and he will fix the package and give you a fresh ZIP).
4. **Review details** - confirm the 5 positive + 3 negative test cases
   imported from the ZIP.
5. **Reviewer credentials:** mark N/A with this note:
   "No sign-in required. The API is public and read-only; demo records
   (demo-tag-001, demo-cred-001, demo-agent-001) are preloaded for
   testing."
6. **API authentication:** the plugin calls the API with a bearer token.
   Paste the demo verifier API key Biblo gives you (starts with
   `npc_demo_`) into the plugin's auth configuration.
7. **Video walkthrough URL:** paste the demo video link Biblo gives you.
8. **Country availability:** United States only.
9. **Starter prompts:** keep the three from the package ("Is this product
   authentic?", "Verify this certificate.", "Is this claim real?").
10. Read the listing copy once more (name, tagline, descriptions). It is
    the approved text; change nothing without saying so.

---

## STEP 7 - Submit for review (one tap)

1. Choose **Submit for review**, complete the policy attestations, submit.
2. Track it under **Review status**. Feedback arrives by email. There is
   no published timeline; plan for weeks, not days.

## STEP 8 - Publish after approval (one tap, your timing)

Submission alone does not publish. When the approval lands, you choose
the go-live moment: open the plugin in the portal and select **Publish
plugin**. Only then does it appear in the ChatGPT plugin directory.

---

## Order of operations (do not reorder)

1. API live and verified (Step 1) - reviewers test against production.
2. Policy pages live (Step 2) - the listing links to them.
3. Account, org, identity (Steps 3-4).
4. $5 credit (Step 5).
5. Upload, review info, submit (Steps 6-7).
6. Publish after approval (Step 8).

## What Biblo already finished (no tap needed)

- Demo API bundle built and verified locally (22/22 checks: fixtures,
  signatures, fail-closed unknown, write endpoints stripped).
- Privacy, Terms, Support pages written and staged in the site bundle.
- Plugin package at 1.0.0: public release notes, live legal URLs,
  validator exit 0, 52/52 tests pass, 16-file submission ZIP assembles.
- Listing screenshots (5 real API-response cards) and a 2-minute demo
  video with captions.
- 1.0.0 release notes.
