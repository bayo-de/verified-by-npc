# NPC Verify: Chrome extension

**Status:** v1.2.0, built 2026-11-15 (Biblo chat, credits and usage,
video and audio AI checks). Not yet submitted. The live Web Store
listing is v1.1.1 with a v1.1.2 draft; v1.2.0 is the update staged
for the November 18 submission target.
**Category (BETA):** Trust infrastructure / provenance.

NPC Verify checks whether an image on the web is registered with NPC
Labs, and says plainly what it found and what it did not check.
v1.2.0 adds three things on the same panel: a Biblo tab (chat with
the NPC Labs AI assistant), a Usage tab (free checks, code balances,
and the Verifier Pass, read live from the credits ledger), and AI
generation checks for the videos and audio on a page.

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
3. **AI judgment (on request).** The third layer holds the AI
   generation check: its control, explanation, and result live in
   that layer. It runs only when the user presses the button. The
   image goes through the NPC API to Sightengine, an outside
   detection service, and the score it returns is stated with its
   number, inside the API's signed answer, verified like every
   other answer. Nothing runs automatically.

The free tier counts checks locally (10 free checks) and, on a
no-record result, offers an invite link the user can send the creator.
A check of an image already checked returns the earlier result and
uses no free check: completed checks are remembered locally, keyed
by the SHA-256 of the image bytes (or of its address when the bytes
could not be read), and the popup's Past checks view lists them.
Only signature-verified registry outcomes are remembered, so an
error is never cached and a retry always runs the real check.

## Credits and usage (v1.2.0)

Past the free checks, a buyer's code pays (the credits integration
spec, 2026-10-28). Two codes can be held: a Verifier Pass code in
the primary slot (while its subscription is active, registry checks
are unlimited and AI generation checks draw its monthly AI
allowance) and a one-time pack code in the second slot. Balances are
always read live from the API through the signed envelope, verified
like every registry answer; a code is charged only after a
signature-verified answer, a repeat check of the same image is
never charged twice, and a failed or unreachable check is never
charged at all. With nothing able to pay, the check does not run
and the popup shows the way to get more checks, with prices read
from the API's packs list. The Usage tab shows the same meter the
desktop app and dashboard read.

## Biblo chat (v1.2.0)

The Biblo tab talks to the same chat the website carries
(`POST /v1/chat`, public and unsigned by design: chat answers are
conversation, never records, and no verdict ever comes from chat).
The opening line and starter questions are the website's. Thumbs
feedback rides `POST /v1/chat/feedback`. The thread id lives in the
popup's memory only, so closing the popup starts a fresh
conversation. Chat quality is the API's grounded-answer quality;
the extension adds no claims of its own.

## Video and audio AI checks (v1.2.0)

The picker also lists the page's videos and audio (direct file
addresses only; streaming manifests are not offered). Their AI
generation check sends the file's address to the NPC API
(`POST /v1/videos/ai-check`, `POST /v1/audio/ai-check`), which
fetches and analyzes the file server-side and answers in the same
signed envelope, verified before anything is shown. Results use the
image check's plain words and state their number, and video answers
also report frames read, frames flagged, and the strongest frame.
**Backend status, stated plainly:** those two routes exist today
only in the detector-av staging prototype; the production API does
not serve them yet. Until it does, the panel says the check is not
live yet and shows no result. In the paid tier these checks draw on
a code's AI allowance exactly like the image AI check.

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
- `storage`: the local free-check counter, the local history of
  completed checks (this browser only; it powers the Past checks
  view and the repeat-check dedupe), the buyer's credit codes
  (bearer credentials, local only, the same treatment as the API
  key), and optional developer overrides for the API base and key.
- Host permission for `https://api.npclabs.xyz/*` only: the
  verification API. v1.2.0 adds no permissions: chat, credits, and
  the video and audio checks all call the same API host.

No analytics, no tracking, no remote code. The only network calls
go to the NPC API: a hash of the image URL for a registry check,
the media address for a video or audio check, the buyer's code for
a balance or a charge, and chat messages for Biblo.

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

- `manifest.json`: MV3 manifest, least-privilege permissions.
- `config.js`: API base, key, links, free-tier size, purchase page.
- `api-client.js`: the isolated API client. Every API contract the
  extension depends on (chat, credits, video and audio checks)
  lives in this one module, called only from the service worker.
- `background.js`: service worker: provenance with signature
  verification, verdict assembly, free-check counter, the credits
  tier gate and draw order, chat and media check handlers.
- `forensics.js`: client-side JPEG EXIF / PNG text parsing and
  marker matching; pure byte analysis (`npcAnalyzeImageBytes`).
- `content.js`: image, video, and audio collector, injected on
  demand from the popup.
- `popup.html` / `popup.js` / `popup.css`: the panel (Verify,
  Biblo, and Usage views).
- `icons/`: the NPC check at 16/32/48/128.

## Tests

Exercised end to end against the local demo API on 2026-10-13:
parser and signature unit tests (21/21) and a full Chromium run of
the production popup flow (20/20), including Verified, Verified with
caveats, No record with the creator nudge, EXIF and PNG marker
forensics, the counter, and both color schemes. Harnesses and the
full results live with the submission package:
`~/workspace/goals/npc-labs/files/extension-store-submission/`.

v1.2.0 (2026-11-15): a Node worker harness with a mocked NPC API
signing real Ed25519 answers passed 33/33: free tier unchanged,
history dedupe, the tier gate (no registry call and no charge past
the free tier without a code), pack and Pass redeem and draw order,
Pass-covered and charged notes, chat send and feedback, video and
audio check parsing with AI-kind charges, the honest not-available
answer when the API lacks the AV routes, and fail-closed behavior
on a bad credits signature. The popup's rendering was not run in a
browser in that pass (no Chromium in the build environment); the
pre-submission checklist in the build note carries the live
unpacked-extension pass. See
`~/workspace/goals/npc-labs/files/extension-biblo-chat-av-build-note-2026-11-15.md`.
