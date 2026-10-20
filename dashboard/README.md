# Verified by NPC dashboard (local preview)

The launch home base for the "Verified by NPC" trust layer (DESIGN v1 §11).
The plugins answer "is this real?" inside AI assistants; this dashboard is
where "see the full verification record" points. Internal only, local only.

- **Zero dependencies.** Pure Python standard library.
- **Local-first.** Binds `127.0.0.1` only (default port `8790`, configurable).
  `run()` refuses any non-loopback host. No public endpoint.
- **Thin client over API v1.** Every API response is Ed25519
  signature-verified client-side before it is rendered. Signing primitives
  are reused from the API package (`npc_verify.canonical`,
  `npc_verify.ed25519`); no duplicated crypto.
- **Fail-closed.** Unknown subjects render "unknown"; unreachable or
  unverifiable API answers render "unavailable". Data is never invented.
- **Read-first.** The dashboard verifies; it never issues attestations.

## Layout

```
dashboard/
  README.md          # this file
  __init__.py
  __main__.py        # python -m dashboard
  server.py          # stdlib HTTP server, routes, loopback-only bind
  client.py          # verified thin client over API v1
  views.py           # HTML views (quiet, restrained pages)
  fixtures.py        # preview-only known fixture subjects (clearly labeled)
  smoke_test.py      # boots API + dashboard, checks every page
  tests/
    helpers.py           # seeded API + dashboard on ephemeral ports
    test_routes.py       # every page renders with real seed data
    test_signature.py    # signature verification incl. tamper rejection
    test_failclosed.py   # unknown -> unknown; errors -> unavailable
    test_html.py         # no broken links, no placeholders, no em-dashes
```

## Pages

| Route | What it shows |
|-------|---------------|
| `/` | What Verified by NPC is (the why, never the method), with the four main surfaces |
| `/records` | Attestation records: verdict, scope, tested dates, and sanitized findings |
| `/search[?id=]` | One lookup for credential, product, archive, and public key IDs, digital and physical; API-issued registration IDs resolve through `GET /v1/records/{id}` |
| `/search/keys` | The full published NPC public key list, as a sub-view inside Search |
| `/search/unknown` | The honest Unknown answer for an ID with no record; the page also asks the live API for the ID from the visitor's browser, so a registration ID resolves live and anything else stays Unknown |
| `/verify` | Verify yours: the content and agent registration forms. They POST from the visitor's browser to the verification API base in the page's `data-api-base` (the public API in the export); if the service is not answering, the page says so plainly and offers the waitlist. Nothing is ever faked |
| `/archive` | NPC Labs' real historical on-chain mints, reached from Records |
| `/plugins` | The plugin questions and each provider surface's honest status |
| `/api` | For developers: what the public API does, a quickstart with examples taken from live calls, the MCP endpoint, and how to check NPC signatures against the published keys |
| `/help` | How it works: Records, Search, the Archive, Plugins, and registering your own digital resources and agents on Verify yours |

## Public static export (Netlify)

`export_static.py` builds a static snapshot of the main pages plus baked
Search detail pages into `dashboard/dist/` (pure stdlib; boots the seeded
API and this dashboard on ephemeral loopback ports, so `server.py`'s
loopback-only bind is never touched). The exporter also generates
`dist/_redirects`: exact IDs in the build rewrite to their baked Search
pages, and every other ID rewrites to `/search/unknown/` with status 200.
Every rule is forced (`200!`) and emitted for both the `/search` and
`/search/` path forms: Netlify shadows an unforced rule when a static
file exists at the from-path, and its slash normalization moves
`/search` to `/search/`, so an unforced rule never fires on the live
host. Search resolution for API-issued IDs does not depend on these
rules: the live lookup described above is the primary path, and the
rules cover the baked fixture IDs.
`../../netlify.toml` wires the Netlify build and security headers. The
CSP allows the inline scripts and names the API base in `connect-src`:
the Verify yours forms and the Search live lookup run in the visitor's
browser against the live API, and if that base changes, the CSP and the
pages' `data-api-base` must change together. The API
stays local-first: no hosted API, no private keys in the artifact.
`tests/test_static_export.py` proves content parity with the local app and
zero secrets in the artifact. Deploy steps: `DEPLOY-RUNBOOK.md`.

## Quick start

```bash
# 1. Start the Verification API v1 (it must be running first)
cd ~/workspace/grand-fleet/verified-by-npc/api
python3 -m npc_verify
# First run prints TEST API keys — save the verifier key.

# 2. Start the dashboard (from the verified-by-npc directory)
cd ~/workspace/grand-fleet/verified-by-npc
NPC_VERIFY_API_KEY=<verifier-key> python3 -m dashboard
# Listening on http://127.0.0.1:8790/

# 3. Run the tests
python3 -m unittest discover -s tests -v

# 4. Run the smoke test (boots its own API + dashboard)
python3 smoke_test.py
```

Options: `--port`, `--host` (loopback only), `--api-url`, `--api-key`.
Environment: `NPC_VERIFY_API_URL` (default `http://127.0.0.1:8787`),
`NPC_VERIFY_API_KEY`, `NPC_VERIFY_API_PATH` (override for the api/ tree).

## Which API it points at

The local API v1 reference implementation at `../api/`
(`http://127.0.0.1:8787` by default). All fixture data is fictional and
`test_`-prefixed; no real secrets, no PII beyond what the fixtures make
public. The browse pages navigate the preview fixture set declared in
`fixtures.py`; every row is backed by a live, signature-verified API
response, and anything the API does not return renders "unknown".

## What remains gated (needs Bayo's explicit approval)

Per DESIGN v1 §8, nothing below ships without his word:

1. **Public endpoint** (`api.npclabs.xyz`). The static dashboard export
   (see DEPLOY-RUNBOOK.md) was approved for public hosting 2026-10-06;
   the API itself stays local-first and is not exposed.
2. **Public "Verified by NPC" mark use.** No badge or checkmark artwork is
   rendered anywhere in this preview; verdicts appear as plain text labels
   only. Counsel clearance is already on Anibal's review list.
3. **Plugin submissions and store listings** (OpenAI developer account,
   Gemini extension review, Copilot partner validation). The `/plugins`
   page states each surface's status honestly: three are unsubmitted, and
   the built MCP server was tested against the local API while the public
   API is not live.
4. **Mainnet onchain anchoring.** Phase 1 records anchor hashes locally
   with status `not_anchored`; no chain writes until the mainnet gate clears.
5. **Real data.** Fictional seed fixtures only; production keys, real
   credentials, and real products all wait on his go-ahead.
