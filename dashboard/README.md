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
| `/` | What Verified by NPC is (the why, never the method), links to the plugin pages |
| `/records` | Attestation records: verdict, scope, tested dates, sanitized findings; plus a claim-check form |
| `/credentials[?id=]` | Credential lookup and detail (`valid` / `revoked` / `expired`) |
| `/products[?tag=]` | Smart-tag authenticity lookup (`authentic` / `counterfeit` / `unknown`) with provenance |
| `/keys` | Published NPC public keys, so anyone can check signatures offline |
| `/plugins` | The five plugin actions and the provider surfaces with their gates |

## Public static export (Netlify)

`export_static.py` builds a static snapshot of all six pages plus baked
fixture detail pages into `dashboard/dist/` (pure stdlib; boots the seeded
API and this dashboard on ephemeral loopback ports, so `server.py`'s
loopback-only bind is never touched). `../../netlify.toml` wires the
Netlify build, query redirects for the lookup URLs, and security headers.
The API stays local-first: no hosted API, no keys in the artifact.
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
   page states each surface's gate honestly.
4. **Mainnet onchain anchoring.** Phase 1 records anchor hashes locally
   with status `not_anchored`; no chain writes until the mainnet gate clears.
5. **Real data.** Fictional seed fixtures only; production keys, real
   credentials, and real products all wait on his go-ahead.
