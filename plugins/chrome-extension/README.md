# NPC Verify: Chrome extension (scaffold, v0.1.0)

**Status:** first working scaffold. Internal only. Not submitted anywhere.

A Manifest V3 extension that checks whether an image on the web is
registered with NPC Labs. It implements the layered verdict from the
[Phase 2 product brief](../../docs/CHROME-EXTENSION-BRIEF.md):

1. **Provenance** : hash the image URL, ask the verification API
   (`POST /v1/claims/verify`). A match shows the registered creator and
   date. No match means "no record found," never "fake."
2. **Forensics** : real client-side checks: file format, size,
   dimensions, embedded EXIF/PNG software tags, known generator markers,
   plus Google Lens / TinEye link-outs. Every finding is labeled for
   what it is; absence of a marker proves nothing.
3. **AI judgment** : stubbed in this scaffold. The panel says so
   plainly: the hosted Fleet backend adds a probabilistic read later,
   with its confidence stated. This version does not guess.

When no provenance is found, the panel shows the nudge: "This creator
isn't verified yet. Know them? Nudge them to get the NPC stamp." with a
copyable invite link (`https://verify.npclabs.xyz/get-verified`).

Honesty creed, enforced in copy and logic: we never claim more than we
checked. Verdicts are only ever `verified`, `no_record`, `not_checked`,
or `api_unreachable`.

## What's real vs stubbed

| Piece | State |
|---|---|
| Image collection from the page | Real (content script, DOM only) |
| File forensics (EXIF, PNG text, markers) | Real, runs on-device |
| Reverse-image link-outs | Real links, searches run on those sites |
| Provenance via API | Real code path, needs a verifier API key (see below) |
| AI judgment layer | Stubbed with honest copy, no fake output |
| Free-check counter (10) | Real local counter, no enforcement backend |
| Nudge + copy link | Real |

## Load it unpacked

1. Open `chrome://extensions`.
2. Enable "Developer mode" (top right).
3. "Load unpacked" and select this folder
   (`verified-by-npc/plugins/chrome-extension/`).
4. Open any page with images, click the NPC Verify button in the toolbar.

## Point it at an API

Provenance checks need a verifier-role API key. Two ways:

- Edit `config.js`: set `apiBase` (e.g. `https://api.npclabs.xyz/v1`)
  and `apiKey` (a `npc_...` verifier key).
- Or, at runtime in the extension's service-worker console:
  `chrome.storage.local.set({npc_api_base: "...", npc_api_key: "..."})`.

Without a key, the extension says so in Layer 1 and every other layer
still runs. The local demo API from `verified-by-npc/api` works as the
target: `python3 -m npc_verify` in that folder, then use the printed
verifier key. Note the demo only knows its seeded test fixtures, so
expect "no record found" for real-world images until the hosted
registry exists.

## Files

- `manifest.json` : MV3, minimal permissions (`activeTab`, `scripting`,
  `storage`), host access only for the API origins. No remote code, no
  analytics, no tracking.
- `content.js` : collects candidate images from the page (160px minimum,
  top 8 by area). Reads the DOM, sends nothing anywhere.
- `background.js` : service worker: runs the three-layer pipeline,
  keeps the free-check counter.
- `forensics.js` : dependency-free JPEG EXIF + PNG tEXt parser and
  generator-marker matching.
- `popup.html` / `popup.css` / `popup.js` : the verdict panel.
- `config.js` : endpoint, key, URLs, free-check total. Edit here.
- `icons/` : extension icons derived from the brand mark.

## Design notes

Yeezy-first bar: one verdict in huge type, the reasoning one tap away
in the three layer rows. The orange check appears only next to a real
`verified` verdict, per the brand usage rule. No em-dashes in copy.
