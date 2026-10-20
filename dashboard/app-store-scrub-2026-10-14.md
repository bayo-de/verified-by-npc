# "App Store" scrub — public dashboard copy correction (2026-10-14)

Direction (Bayo, Oct 14, 2026): the Verified App Store must not be revealed
publicly. Public copy names the Verified Agent Library and the Verified
Agent Builder instead. This pass corrects the dashboard source and rebuilds
the static export. Nothing was deployed; the deploy is a separate step.

## Scan

Pattern: `app[ _-]?store`, case-insensitive (covers "App Store",
"app-store", "app_store", "appstore", "Verified App Store"), run over the
entire dashboard tree (source + current dist) before editing.

### Hits found: 2, both the same line

| # | Location | Kind | Disposition |
|---|----------|------|-------------|
| 1 | `views.py:197` (home_view waitlist block) | Public-facing copy in source | Replaced with the exact ordered line (below) |
| 2 | `dist/index.html:109` | Previous export of the same line | Regenerated away by the rebuild; the new dist carries the corrected line |

Internal code identifiers/comments that never render publicly: **none
found.** No other public copy anywhere in the dashboard (pages, fixtures,
README, runbook, tests) mentions an app store in any spelling.

### The correction (views.py, waitlist block)

- Before: "The NPC Verify extension, the Verified App Store, and new
  releases land here first. Join the list."
- After: "The NPC Verify extension, the Verified Agent Library, the
  Verified Agent Builder, and new releases land here first. Join the list."

Nothing else in the block changed: heading "First to know.", the Netlify
form `name="waitlist"` (with its `form-name` hidden field and
`data-netlify="true"`), the "Join the waitlist" button, and the "Use NPC
Verify today" link are byte-identical, so the registered Netlify form is
undisturbed.

## Verification

- Unit tests: `python3 -m unittest discover -s tests` — **43 tests, all
  OK** (includes the static-export parity and no-em-dash checks).
- Smoke test: `python3 smoke_test.py` — **SMOKE OK**, all checks passed.
- Grep proof on the deliverables (all zero hits, grep exit 1):
  - new `dist/` tree
  - extracted contents of the new v2 zip
  - entire dashboard source tree (excluding zips and dist)

## New drop zip

- Path: `dashboard/verified-dashboard-drop-2026-10-14-v2.zip`
- Size: **192,048 bytes** (superseded live zip: 192,040 bytes)
- Entry list identical to the live zip (124 entries); extracted contents
  verified byte-identical to the new `dist/`.

## Diff vs the currently-live export

Baseline verified first: the pre-rebuild `dist/` was byte-identical to the
contents of the currently-live `verified-dashboard-drop-2026-10-14.zip`.

- **One real content change:** `index.html` — the waitlist line above.
- **Everything else is the exporter's usual per-build output**, the same
  classes of change the previous live build itself carried:
  - Footer build-date stamps roll 2026-10-14 → 2026-10-15 on every page,
    and the privacy page's "Last updated" follows the build date (both are
    build-date driven by design in `export_static.py`).
  - The export boots a freshly seeded test API each build, so its
    ephemeral fixture values rotate: the keys page's test signing/issuer
    keys (IDs, public keys, created-at) and the records page's
    `att_test_…` IDs are new this build. All rendered text — subjects,
    results, scopes, findings, dates — is unchanged. (The prior live build
    shows the same behavior: its keys were created at its own build time,
    2026-10-14T23:37Z.)
- No files added or removed.

## Notes

- The superseded `verified-dashboard-drop-2026-10-14.zip` still contains
  the old line; it remains the live artifact until the separate deploy
  step swaps in v2.
- The `preview/*.png` screenshots are internal design captures, are not
  part of the export or the drop zip, and were not text-scanned (images).
