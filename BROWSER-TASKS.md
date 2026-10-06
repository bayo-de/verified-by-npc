# Verified by NPC - browser task specs (GitHub repo + Netlify site)

Bayo approved 2026-10-06. Both steps run on his logged-in sessions.
If GitHub asks for 2FA or the session is not logged in: STOP, do not
attempt workarounds, report exactly what is needed.

## Task A - Create the public GitHub repo

Session: github.com as bayo-de (verify the logged-in account FIRST).

1. Try creating org `npc-labs` first (github.com/account/organizations/new,
   plan: free). The name was verified available earlier.
2. Inside the org, create repo `verified-by-npc`:
   - Visibility: PUBLIC
   - Do NOT add README, .gitignore, or license (local repo has everything)
   - Description: "Verified by NPC - public verification dashboard and
     trust-layer plugins. Ask 'is this real?'"
3. If org creation hits any friction (name taken, verification wall,
   paid-plan upsell): fall back to `bayo-de/verified-by-npc` (public).
4. Report back the EXACT repo URL created (org or fallback).

Do NOT clone, push, or add files. The push happens separately with
Bayo's transient PAT.

## Task B - Import into Netlify and deploy the dashboard

Prerequisite: Task A done AND the push complete (repo has main at the
two local commits). Session: app.netlify.com, team "Bayo's Grand Fleet".

1. Add new site > Import an existing project > GitHub > select the
   public repo from Task A.
2. Build settings (must match netlify.toml at the repo root):
   - Build command: `python3 dashboard/export_static.py`
   - Publish directory: `dashboard/dist`
   - No base directory (repo root IS verified-by-npc/)
3. Deploy. Wait for the build to succeed.
4. 5-point verification on the live *.netlify.app URL:
   a. Home page loads, shows "Internal preview. Test fixtures only."
   b. /records, /credentials, /products, /keys, /plugins all load
   c. A fixture detail page (e.g. /credentials/demo-cred-001/) renders
   d. Every page carries the "Internal preview. Test fixtures only."
      labeling (footer or banner)
   e. No 404s on the nav links
5. Report the live *.netlify.app URL and the pass/fail of each check.

## Task C - Custom domain (settings only, NO DNS)

In the new site's Site settings > Domain management > Add custom domain:
type `verify.npclabs.xyz`. Netlify will show "Check DNS configuration" -
THAT WARNING STAYS. Do NOT touch GoDaddy DNS; Bayo flips DNS himself
later. Report that the domain is configured pending DNS.

HARD RULES: no DNS changes anywhere. No accounts created beyond the
org/repo above. Nothing published to any directory/listing. Secrets
transient only.
