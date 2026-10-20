# Search redirect fix, 2026-10-14

Status: fixed at the source, export rebuilt, new drop staged. NOT deployed.

## The defect (verified live)

`GET https://verify.npclabs.xyz/search?id=cred_test_001` (and the
`/search/` slashed form) returned the plain Search page instead of the
baked record page. The record pages themselves were fine:
`/search/<id>/` and `/search/unknown/` rendered correctly when hit
directly. Only the query routing never fired.

## Root cause

The generated `dist/_redirects` rules were non-forced 200 rewrites
keyed to the path `/search`. Netlify shadows a non-forced rule when a
static file exists at the from-path, and `search/index.html` exists at
`/search`, so the static page won every time. Netlify's slash
normalization (which moves `/search` to `/search/`) put the rule out
of reach of the slashed form as well. The local app and the local
static tests could not see this: both resolve the query in-process,
and neither replicates Netlify's rule precedence.

## The fix (dashboard/export_static.py)

Every generated Search rule is now FORCED and emitted for both path
forms:

- Exact ID: `/search id=<ID> /search/<ID>/ 200!` and
  `/search/ id=<ID> /search/<ID>/ 200!`
- Fallback, always the last two lines: `/search id=:id
  /search/unknown/ 200!` and `/search/ id=:id /search/unknown/ 200!`

The generated-file header comment now states the rules are forced and
why. `netlify.toml` carries no duplicate rules (the exact public key
IDs are known only at build time, which is why routing lives in the
generated file); its comments were updated to match, including a note
not to restate the rules as `[[redirects]]` blocks.

Rule counts in the rebuilt export: 56 exact IDs (8 credentials, 10
products, 36 archive items, 2 build key IDs) x 2 path forms = 112
exact rules, plus 2 fallback rules, 114 total, all forced. Every exact
rule's target page was verified present in `dist`.

## Regression guard

`tests/test_static_export.py` gained
`test_search_redirects_are_forced_and_cover_both_path_forms`: it
asserts the header states the forcing, every rule ends in `200!`,
every rule keys `/search` or `/search/`, the exact counts per form,
and the fallback pair closing the file. The existing redirects test
was updated to the forced forms. The new test's comment records the
limit plainly: local static tests cannot replicate Netlify
precedence, so the real gate is the live check after deploy (a known
ID must serve its baked page; an unknown ID must serve Unknown).

## Verification

- Unit + HTML + static-export suites: 49 tests, OK (48 before; the
  new regression test is the 49th).
- Smoke test: 40 PASS, SMOKE OK.
- The rebuilt `dist/` was built clean (stale rotated key pages from
  the earlier build were removed by rebuilding from scratch), 67
  files, matching the previous drop's file count.
- New drop: `verified-dashboard-drop-2026-10-15-search-v2.zip`,
  244,844 bytes, 67 files. Contents verified byte-identical to the
  rebuilt `dist/`, including `_redirects`.

## Deploy note

Deploy the whole v2 zip so the forced `_redirects` lands at the
publish root. After deploy, the acceptance check is live, not local:
`GET /search?id=cred_test_001` must serve the cred_test_001 record
page and `GET /search?id=nope` must serve the Unknown page.
