# verify.npclabs.xyz — Read-Only Site Audit (2026-10-14)

Scope: dashboard source (`dashboard/views.py`, `dashboard/server.py`, `dashboard/export_static.py`), the built export in `dashboard/dist/` (64 HTML files), the site config (`netlify.toml` at the verified-by-npc root), the plugin code under `plugins/`, and the API codebase (`api/npc_verify/server.py`, `api/openapi.yaml`). Live spot-checks were read-only GETs against `verify.npclabs.xyz` and `api.npclabs.xyz` on 2026-10-14. No files were edited and nothing was deployed.

Verdicts up front:

- **Links:** every `href` on the site resolves. There are zero placeholder links. The dead ends Bayo felt are real but they live in the **forms**, not the links (Section 1).
- **Plugins:** the page offers a visitor literally nothing to click, download, or install; three of four surfaces are unsubmitted by the page's own admission, and the one built plugin (the MCP server) runs only against a local API while the public API is not live (Section 2).
- **Records "Check":** on the live static site the form submits to nothing; it also duplicates the table directly above it (Section 3).
- **Spacing:** the entire gap between the top bar and the first body text is one fixed value, `main{padding:44px 0 64px}`, with the small-caps kicker as the first element on every page (Section 4).

---

## 1. Link inventory

Method: extracted every `href="..."` from all 64 HTML files in `dashboard/dist/`, deduplicated, grouped by page template, and checked each target against the exported files plus the redirect rules in `netlify.toml`.

**Distinct href targets: 65.**

| Class | Count | What they are |
|---|---|---|
| (a) Resolves to a real exported page | 63 | 9 site routes + 8 credential detail links + 46 product detail links |
| (b) Placeholder / dead href (`#`, empty, missing target, nonexistent anchor) | **0** | None exist anywhere in the export. There are also zero fragment (`#...`) links and zero `<script>` tags in `dist/`. |
| (c) External | 2 | `https://api.npclabs.xyz`, `mailto:hello@npclabs.xyz` |

### Class (a), the 63 resolving targets

- The 9 routes linked from the nav, the brand, and the footer of every page: `/`, `/records`, `/archive`, `/credentials`, `/products`, `/keys`, `/plugins`, `/help`, `/privacy`. Each maps to an exported file (`index.html`, `records/index.html`, etc. in `dist/`).
- 8 credential detail links of the form `/credentials?id=cred_test_001` … `cred_test_008`, emitted by `credentials_view` as the "Try:" examples (`dashboard/views.py`, `credentials_view`). They resolve through the Netlify redirect in `netlify.toml` lines 27–32 (`/credentials` with `id=:id` rewrites to `/credentials/:id/`, status 200) to the baked detail pages `dist/credentials/cred_test_00N/index.html` written by `dashboard/export_static.py` lines 144–146.
- 46 product detail links of the form `/products?tag=<id>`: 10 test tags (e.g. `tag_test_authentic`) emitted by `products_view`, and 36 archive tags (e.g. `tag_archive_seeker_hat_1`) emitted as "Full record" links by `archive_view`. Same mechanism: `netlify.toml` lines 34–39 rewrite to `/products/:tag/`; baked pages at `dist/products/<tag>/index.html` (`export_static.py` lines 147–155).

Per-template href sets (distinct, from the export): every page template (home, records, credentials index+detail, products index+detail, archive, keys, plugins, privacy, help, 404) carries the same 9 internal route links; credentials pages add the 8 `?id=` links; products pages add the 10 `?tag=tag_test_*` links; the archive page adds the 36 `?tag=tag_archive_*` links; home and help add `https://api.npclabs.xyz`; privacy and help add `mailto:hello@npclabs.xyz`.

### Class (c), the 2 external targets

- `https://api.npclabs.xyz` — linked from the home page as "Use NPC Verify today" (`views.py` line 203, `home_view`) and from the help page. The domain's root returns HTTP 200 (a Netlify-hosted static page), but it is presented to visitors as the working verification API, and the API itself is not live: `GET https://api.npclabs.xyz/v1/health` returned Netlify's "Page not found" HTML on 2026-10-14, not API JSON. The link resolves; what it promises does not yet exist at the other end.
- `mailto:hello@npclabs.xyz` — privacy page contact (`views.py`, `privacy_view`) and help page FAQ. A mailto; resolves to the visitor's mail client by design.

### Where the dead ends actually are: the forms

The export contains 58 `<form>` instances. Only one works end to end on the static host.

1. **Waitlist form (home page) — WORKS.** `<form class="lookup" name="waitlist" method="POST" data-netlify="true">` with a hidden `form-name` field (`views.py` lines 198–202; present once in `dist/index.html`). Netlify Forms intercepts the POST; this is the site's one working submission path (see Section 6).
2. **Records "Check a claim" form — DEAD on the static site.** `<form method="post" action="/records">` (`views.py` line 293). A static host has no POST handler; `netlify.toml` line 36 states it plainly in a comment: "forms POST to self (no backend)." The exporter itself appends a note to the exported records page admitting the split: "Live claim checking runs against the verification API. This static preview shows the fixture records above." (`export_static.py` lines 51–56; the note is present in `dist/records/index.html`.) The form only functions against the local dashboard server, which has a real `POST /records` route (`dashboard/server.py` line 168). Full treatment in Section 3.
3. **Credential and product lookup forms — PARTIAL.** `<form class="lookup" method="get" action="/credentials">` and `action="/products">` appear on the index pages and on every baked detail page (9 + 47 instances). A GET submission for one of the 54 baked IDs (8 credentials, 10 test products, 36 archive products) lands on its detail page via the `netlify.toml` rewrites. A GET for **any other ID** rewrites to `/credentials/<id>/` or `/products/<tag>/`, for which no file exists, so the visitor gets the 404 page. `export_static.py` lines 24–27 document this: "Anything else falls through to the dashboard 404." In the local app the same submission returns a proper "Unknown" notice; on the live static site a real-world ID therefore produces a 404, not an answer.

**Section verdict:** Bayo's "some links are window dressing" claim is **refuted for hrefs** (65 distinct targets, 63 resolving, 0 placeholders) and **confirmed for forms**: 57 of 58 form instances are either dead (records POST) or fixture-only (lookups).

---

## 2. Plugins page

### What is on the page

`plugins_view` (`dashboard/views.py` line 209) renders, in full:

- Kicker "Distribution", H1 "The plugins meet people where they ask.", and a lede paragraph.
- Five question cards under "What a plugin answers": "Is this product authentic?", "Is this certificate real?", "Did this really happen?", "Is this agent verified?", "What does Verified by NPC mean?" Each is a plain `<div class="card">` with a heading and one line of text. **None of them is a link, button, or form.** The exported plugins page's complete href set is the same 9 nav/footer links every page carries; the page adds zero links of its own (verified in `dist/plugins/index.html`).
- A status table under "Where they run" (`views.py`, `plugins_view` table): Claude — "MCP server, works in any MCP client" — **"Built, in local testing"**; ChatGPT — "Plugin / GPT action" — **"Awaiting the developer account gate"**; Gemini — "Extension" — **"Awaiting the developer account gate"**; Copilot — "Plugin" — **"Awaiting the partner account gate"**.
- A closing line that states the situation itself: "Plugin subm
...[truncated 10632 chars]