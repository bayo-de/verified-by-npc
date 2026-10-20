# Deploy runbook: Verified by NPC dashboard (public static hosting)

Status: artifact built and tested. Nothing deployed. Bayo said "Yes proceed"
on public hosting for the dashboard (2026-10-06). This runbook is the exact
path from here to live.

## 1. What ships

A static export of the dashboard pages, built by
`dashboard/export_static.py`:

- `/`, `/records`, `/search`, `/search/keys`, `/search/unknown`,
  `/archive`, `/plugins`, `/privacy`, `/help`
- baked Search detail pages for every credential, product, archive, and
  public key ID in the build (`/search?id=cred_test_001`,
  `/search?id=tag_test_authentic`, ...)
- a generated `_redirects` file for Search query routing
- the dashboard's own 404 page as `404.html`

Every page is rendered through the full local stack at build time: the
seeded API v1 answers, and the dashboard signature-verifies each response
before rendering, exactly as the local app does. The build runs
`server.py` unmodified on ephemeral loopback ports. The loopback-only bind
refusal is never touched: nothing in the artifact listens on any port.

Build output goes to `dashboard/dist/` (gitignored pattern: build it at
deploy time, do not commit it).

## 2. Recommended host: Netlify

- The existing Netlify team already hosts bayoofficial.com, so the
  dashboard lands on infrastructure Bayo's team already owns. One team,
  one bill, one place to manage domains.
- Zero runtime. The export is plain HTML, which is the cheapest and
  safest shape for a read-first trust surface: no server to patch, no
  environment variables to leak, no cold starts.
- Netlify handles the one dynamic-looking piece the static export needs:
  query-string redirects from the generated `_redirects` file
  (`/search?id=X` rewrites to the baked Search page for a known ID, and
  to `/search/unknown/` for every other ID; GitHub Pages cannot do this
  server-side).
- Build runs the export itself (`python3 dashboard/export_static.py`),
  so every deploy re-renders from the current fixtures. Free tier is
  plenty for this traffic shape.

Alternatives considered: Vercel (same shape, but no existing team
relationship), Cloudflare Pages (same, no existing relationship),
GitHub Pages (no query redirects; would need client-side JS hacks),
Netlify Functions wrapper around the dashboard (would put a live API on
the public internet and cross the public-endpoint gate in DESIGN-v1
section 8; rejected).

## 3. The API story (decision)

**The API v1 stays local-first. No public API ships with this deploy.**

- No hosted API, no API keys in the deploy, no bearer tokens anywhere in
  the artifact (proven by `test_zero_secrets_in_artifact`).
- The public front renders the local test fixtures with honest
  labeling in customer words: every page footer reads "Every record
  shown is a sample." plus "Sample records. Updated <build date>".
  Fixture IDs are all
  `test_`/`tag_test_`/`cred_test_`/`agent_test_` prefixed by design and
  can never be mistaken for real records.
- Fail-closed semantics are preserved in static form: the static
  preview is labeled as fixture records where that is true, and an
  unmatched Search ID lands on the honest Unknown answer, never an
  invented record and never a raw 404.
- Signed responses are still verified, at build time, client-side,
  before anything renders. The public key list inside Search publishes
  the build's public signing keys (public halves only; private material
  never leaves the build machine and is excluded from the artifact by test).

When the public API (`api.npclabs.xyz`) is later approved and hosted
(DESIGN-v1 section 8, gate 5: hosting spend + public endpoint), the
dashboard can switch to a live client. Until then, this static front is
the honest public face.

## 4. Exact deploy steps

Do these in the Netlify dashboard (a prior bayoofficial.com deploy went
through the browser; the `netlify` CLI is not installed in the build
environment and there is no token there, so the dashboard UI is the
primary path).

**Step 0: put verified-by-npc in git.** The directory is not a git repo
yet. Recommended: push it as its own repo (e.g.
`npc-labs/verified-by-npc`), so the dashboard deploys independently of
the API and plugins. Alternative: keep it as a subdirectory of a larger
repo and set `base = "path/to/verified-by-npc"` in `netlify.toml`.

**Step 1: new site from git.** Netlify dashboard > the existing team
(the one hosting bayoofficial.com) > Add new site > Import an existing
project > connect the repo from Step 0.

**Step 2: build settings.** Netlify auto-reads `netlify.toml` at the
repo root. Confirm:

- Build command: `python3 dashboard/export_static.py`
- Publish directory: `dashboard/dist`
- (Optional) Environment > `PYTHON_VERSION = 3.12`. The build is pure
  stdlib and works on older Pythons, but pinning keeps renders stable.

**Step 3: deploy.** Trigger the first deploy. Netlify runs the export,
publishes `dist/`, and applies the redirects and security headers from
`netlify.toml`.

**Step 4: post-deploy verification** (do not announce until these pass):

1. Open `/`, `/records`, `/search`, `/search/keys`, `/plugins`, and
   `/help`. All render; the fixture pages' footer reads "Internal
   preview. Test fixtures only." with a build date.
2. Open `/search?id=cred_test_001` and
   `/search?id=tag_test_authentic`. Both resolve to their baked Search
   detail pages through the generated query redirects.
3. Open `/search?id=does_not_exist`. You get the Search Unknown answer
   with status 200, not an invented record and not a raw 404.
4. Check response headers include `Content-Security-Policy`,
   `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
5. View source on any page: no `127.0.0.1`, no `localhost`, no
   `npc_test_` strings.

**Rollback:** Netlify dashboard > the site > Deploys > pick the previous
successful deploy > Publish deploy. One click, no rebuild needed.

## 5. Domain (recommendation only; do NOT buy or configure DNS)

Recommended: **`verify.npclabs.xyz`** for the dashboard site.

- DESIGN-v1 already points consumers there: credential records carry
  `verification_url: https://verify.npclabs.xyz/c/{id}`, and section 4
  names `verify.npclabs.xyz/c/{id}` as the certification-credential
  consumer surface.
- Reserve **`api.npclabs.xyz`** for the future public API. Do not point
  it anywhere yet; the public endpoint is still gated (section 8).

When the domain is chosen: Netlify dashboard > the site > Domain
settings > Add custom domain > `verify.npclabs.xyz`, then add the DNS
record at the registrar (Netlify shows the exact target). Future work:
add `/c/{id}` redirects so the seeded `verify.npclabs.xyz/c/{id}` URLs
resolve (currently the dashboard serves `/search?id={id}`).

## 6. What remains gated (unchanged)

Per DESIGN-v1 section 8, still needs Bayo's explicit word:

1. Public API endpoint (`api.npclabs.xyz`) and any live client against it.
2. Public "Verified by NPC" mark use (plain text labels only, as now;
   counsel clearance already on Anibal's review list).
3. Plugin submissions and store listings.
4. Mainnet onchain anchoring.
5. Real data (production keys, real credentials, real products).

## 7. Asks for Bayo

1. **Approve the Netlify deploy** to the existing team (same team as
   bayoofficial.com). The artifact is ready; deploy itself takes one
   dashboard session.
2. **Repo shape:** push `verified-by-npc/` as its own repo
   (recommended), or as a subdirectory of a larger repo (then set
   `base` in `netlify.toml`).
3. **Choose the domain:** `verify.npclabs.xyz` (recommended) or a
   different host. DNS is not touched until he picks.
4. **Confirm the labeling:** ship now with every record labeled a
   sample in customer words (recommended; it demonstrates the product
   honestly), or hold the public launch until real records exist.
5. **Note, no action:** the public API stays local-first and gated.
   This deploy does not cross that gate.
