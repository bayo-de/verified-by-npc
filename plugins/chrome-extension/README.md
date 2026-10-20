# NPC Verify: Chrome extension

**Status:** v1.0.0, Web Store submission candidate (not yet submitted).
**Category (BETA):** Trust infrastructure / provenance.

NPC Verify checks whether an image on the web is registered with NPC
Labs, and says plainly what it found and what it did not check.

## The layered check

1. **Provenance (registry).** The image URL is hashed with SHA-256 in
   the service worker and the hash is sent to the NPC verification API
   (`POST /v1/claims/verify`). The API's answer is only trusted after
   its Ed25519 response signature (`X-NPC-Signature`, over the
   NPC-JCS-v1 canonical body) verifies against NPC's published keys
   (`GET /v1/keys`). A failed or unverifiable signature fails closed:
   no verdict is shown from an answer we cannot trust. Registered
   images report a verdict of **Verified** or **Verified with
   caveats**, exactly as recorded; any other standing is reported as
   not verified. No match reports **No record found**, which is not
   the same as fake.
2. **Forensics (on device).** The image bytes are read in the page's
   own context where possible (the page already loaded the file),
   falling back to a direct fetch, and parsed locally: JPEG EXIF and
   PNG text chunks, matched against known generator markers. Findings
   are reported; conclusions are not drawn. Bytes never leave the
   device for this layer.
3. **AI judgment.** Not in this version. The panel says so rather
   than guessing.

The free tier counts checks locally (10 free checks) and, on a
no-record result, offers an invite link the user can send the creator.

## Design

One language with the rest of NPC: the space grey and Inter of
npclabs.xyz, the paper and ink of the public record dashboard, one
accent (NPC orange, #ec662b) reserved for the check and the record
link. Light and dark follow the system color scheme. The verdict word
is the largest thing in the panel.

## Permissions

- `activeTab` + `scripting`: when the user opens the popup, collect
  the active tab's images and, during a check, read the selected
  image's bytes in the page context. No standing content script; the
  collector is injected on demand only.
- `storage`: the local free-check counter and optional developer
  overrides for the API base and key.
- Host permission for `https://api.npclabs.xyz/*` only: the
  verification API.

No analytics, no tracking, no remote code. The only network call is
to the NPC API, carrying a hash of the image URL, never the URL or
the image itself.

## Configuration

Production defaults live in `config.js`. For development against the
local demo API (`api/README.md` in this repo), set two storage keys
from the service worker console:

```js
chrome.storage.local.set({
  npc_api_base: "http://127.0.0.1:8787/v1",
  npc_api_key: "<verifier test key from the API's first-run output>"
});
```

The local API sends CORS headers, so no manifest change is needed.

## Files

- `manifest.json` — MV3 manifest, least-privilege permissions.
- `config.js` — API base, key, links, free-tier size.
- `background.js` — service worker: provenance with signature
  verification, verdict assembly, free-check counter.
- `forensics.js` — client-side JPEG EXIF / PNG text parsing and
  marker matching; pure byte analysis (`npcAnalyzeImageBytes`).
- `content.js` — image collector, injected on demand from the popup.
- `popup.html` / `popup.js` / `popup.css` — the panel.
- `icons/` — the NPC check at 16/32/48/128.

## Tests

Exercised end to end against the local demo API on 2026-10-13:
parser and signature unit tests (21/21) and a full Chromium run of
the production popup flow (20/20), including Verified, Verified with
caveats, No record with the creator nudge, EXIF and PNG marker
forensics, the counter, and both color schemes. Harnesses and the
full results live with the submission package:
`~/workspace/goals/npc-labs/files/extension-store-submission/`.
