# Restage build note: registration-flow fixes drop (2026-10-16)

Bayo approved ("Yes do all the above", Fri Oct 16, 2026) shipping the
registration-flow audit fixes 2-6 in ONE dashboard drop, restaged on
the live tree now instead of waiting for the chat-key sequence.

## Bundle

- File: `dashboard/verified-dashboard-drop-2026-10-16-restage.zip`
- Size: 308,658 bytes
- sha256: `7f82d70f6e38747cd58edc53530f266be818c624b41efe6c589341a7b9bb563a`
- Tree: `dashboard/dist-restage/` (built by
  `python3 export_static.py --no-chat dist-restage`)
- NOT deployed. Deploy is the Netlify Drop upload through the
  parent's browser task, like the other dashboard drops.

## What is in it (audit gaps 1-6 + the mobile header fix)

1. Request verification is live on the web surfaces: the Search
   record card and the /verify success screen offer the ask, and a
   requested record shows "Verification requested" (the endpoints
   were already live; the UI is the cycle source, now shipped).
2. /verify success screen "Keep this record" block: NPC ID with a
   Copy button, the direct record link (/search?id=<id>) with a
   Copy button, and a Download button that saves the signed record
   JSON, all built client-side from the registration response.
3. The public record card renders the proof: signature and issuer
   key ID, content kind, creator/locator (or agent/owner), and the
   checks-run / checks-not-run lists, on both the server-rendered
   card (views.registration_result) and the live-lookup card
   (LIVE_LOOKUP_JS).
4. Search lookup interim state: the Unknown page carries a hidden
   "Looking up this ID…" pending notice; the live-lookup script
   swaps the verdict out while the API is being asked and restores
   it only on an actual miss or error. No-JS visitors still get the
   full honest Unknown answer.
5. Footer copy: "Every record shown is a sample." / "Sample
   records. Updated <date>" replaced with "Signed records, open to
   anyone to check." / "Updated <date>" (export_static constants).
   Sample records stay labeled on their own pages and records.
6. The API tab is restaged: /api page baked, API in every nav.
7. The mobile header CSS fix (nav wraps under 640px) ships in the
   shared CSS.

## Excluded: the Biblo chat widget (single-flip gate)

Chat ships DARK in this drop. The gate is one flag,
`views.CHAT_WIDGET_ENABLED` (default True), driven by one build
switch, `export_static.build(include_chat=...)` / the `--no-chat`
CLI flag. With it off, `page()` appends no widget, /help carries no
Ask Biblo section, and the exporter copies no chat button art: the
bundle contains no chat markup, no chat script, and no chat
endpoints. Only inert class names remain in the shared stylesheet;
they render nothing and load nothing.

To flip chat on in a follow-up drop (after Bayo places the Lambda
API key and the full grounding eval passes): rebuild with the
default (`python3 dashboard/export_static.py <out_dir>`), rezip,
redeploy. No code change is needed.

## Verification

- Full dashboard suite: 86/86 green (76 prior + 10 new in
  tests/test_restage_drop.py), including a default-build test that
  proves the chat gate defaults ON and the widget still ships in
  the default export.
- File-list diff vs the live-tree build (dist-register-kinds): the
  only addition is api/index.html; nothing removed. (Baked key-ID
  pages differ only in their per-build seed suffixes, as in every
  prior drop.)
- Artifact greps: zero chat markup/script, zero "sample" footer
  leftovers, zero em dashes; keep-block, pending-state, RV, and API
  nav markers present.
- Pre-existing, unrelated: smoke_test.py has one stale check
  ("plugins page is honest about status") that pins copy the
  plugins page replaced when ChatGPT/Gemini/MCP went live. Not
  touched by this build; flagged for a separate cleanup.

## Post-deploy live checks (parent, after the Drop upload)

Base: https://verify.npclabs.xyz — expect 200 on /, /records,
/search, /search/keys, /search/unknown, /plugins, /api, /privacy,
/help, /verify, /archive.

1. `curl -s https://verify.npclabs.xyz/search/unknown | grep -c 'npc-lookup-pending'` = 1 (plus the script reference), and in a browser, /search?id=reg_7957ac44c9ccef00eb5d8d0b shows the record card with Signature, "Signed with key npc-demo-issuer-20261014-727fb5", Kind "text", and both checks lists.
2. `curl -s https://verify.npclabs.xyz/verify | grep -c 'npc-download-record'` >= 1; page source also carries npc-copy-id and npc-copy-link. In a browser, one real registration shows the Keep this record block; Copy ID / Copy link fill the clipboard; Download saves <record_id>.json.
3. `curl -s https://verify.npclabs.xyz/ | grep -o 'href="/api"'` present, and `curl -s -o /dev/null -w '%{http_code}' https://verify.npclabs.xyz/api` = 200.
4. `curl -s https://verify.npclabs.xyz/ | grep -c 'Every record shown is a sample'` = 0, and 'Signed records, open to anyone to check.' present.
5. `curl -s https://verify.npclabs.xyz/ | grep -c 'npc-chat-btn'` = 0 (chat stays dark in this drop).
6. Request verification end to end in a browser: on the record from step 1, submit the registrant email (biblosoffice@gmail.com for reg_7957...) in the Request verification box and confirm the state flips to "Verification requested" and persists on reload.
7. Regression: /search?id=cred_test_001 and /search?id=tag_test_authentic still land on their baked pages; an unknown ID lands on the Unknown page with status 200; response headers still carry the CSP from _headers.
