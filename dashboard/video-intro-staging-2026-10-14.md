# Video intro piece: staging note (2026-10-14)

Direction (Bayo, Oct 14, 2026): the demo film goes on the verification
website as an introduction piece, but NOT as an embedded player. A
poster image links out to the film on the NPC Labs YouTube channel.
The site is a static, no-JS export behind a strict CSP; this staging
changes no headers and adds no iframe, no <video>, no <script>.

Status: STAGED, NOT DEPLOYED. The drop zip below is ready; deploying
it is a separate step, and the YouTube URL swap (step 2 of the launch
sequence below) must happen before or with the deploy.

## What was built

**Poster asset**

- Source frame: `webdash-demo-v3.3.mp4` at **t = 10s** (Beat 1, Home,
  fully settled): the dashboard home exactly as the film opens it,
  headline "Know what is real before you act on it." with the four
  doors (Products, Credentials, Records, Keys) and the line "Trust
  should rest on something you can check." Verified visually. No
  extension scene, no dates, nothing that ages.
- Asset: `dashboard/assets/demo-poster.jpg`, 1280x720 JPEG, **41,921
  bytes**. `export_static.py` copies everything under
  `dashboard/assets/` into the export root, so it ships as
  `/demo-poster.jpg`. (Assets are files, not pages: the exporter's
  returned page list is unchanged and the page-set test stays exact.)

**Homepage block** (`views.py`, `home_view`, immediately after the
lede and before "Why it exists")

```html
<h2>See it work.</h2>
<p>The verification dashboard, walked through end to end.</p>
<a class="poster" href="https://www.youtube.com/watch?v=VIDEO_ID_PENDING"><img src="/demo-poster.jpg" alt="The Verified by NPC dashboard home page, from the demo film" width="1280" height="720"></a>
```

Two CSS lines ride along in the shared stylesheet (`.poster`,
`.poster img`: block, full width, hairline border, 12px radius, the
card idiom). One image, one heading, one sentence, one link. Nothing
else on the page moved.

## The placeholder (read this at launch)

- Token: `VIDEO_ID_PENDING`
- Exact location: **`dashboard/views.py`, line 188**, inside the
  poster's href: `https://www.youtube.com/watch?v=VIDEO_ID_PENDING`
  (a comment at views.py lines 175-179 explains it; the token is the
  only occurrence in the codebase, so `grep -rn VIDEO_ID_PENDING`
  finds it instantly).

**Swap, one step:** when the YouTube upload exists, replace that one
href in views.py line 188 with the real watch URL, rebuild
(`python3 export_static.py`), re-zip dist, deploy. Nothing else in
the block changes.

## Launch-time decision the deploy step must make: CSP img-src

The currently published `netlify.toml` header is:

```
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
```

There is no `img-src`, so image loading falls back to
`default-src 'none'`, which blocks even same-origin images. **As
staged, a browser will not render /demo-poster.jpg under these
headers**; the block would show the alt text inside the link's
border instead of the frame. This staging changed no headers, per
the direction. For the poster to render at deploy time, add one
token to the CSP in `verified-by-npc/netlify.toml`:

```
img-src 'self';
```

That is the only header change the piece needs. No other directive
is touched, and no external source is allowed: the poster is
same-origin, and the link out to YouTube is a navigation, which CSP
does not gate.

## Verification

- Unit tests: `python3 -m unittest discover -s tests`: **43 tests,
  all OK** (includes static-export parity and no-em-dash checks).
- Smoke test: `python3 smoke_test.py`: **SMOKE OK**.
- Grep proof on the new `dist/` (all HTML): zero hits for `<iframe`,
  `<video`, `<script` (grep exit 1). The block renders in
  `dist/index.html` with the placeholder href and
  `<img src="/demo-poster.jpg" ...>`; `dist/demo-poster.jpg` is
  present at 41,921 bytes.
- Diff vs the previous export (the 2026-10-14-v2 build): index.html
  gains the two `.poster` CSS lines and the four-line intro block;
  every other page gains only the same two CSS lines (shared
  template); plus the exporter's usual per-build rotation of the
  ephemeral fixture signing-key and attestation IDs. One file added:
  `demo-poster.jpg`. Nothing removed.

## Drop zip

- Path: `dashboard/verified-dashboard-drop-2026-10-15-video-intro.zip`
- Size: **234,416 bytes**, 125 files (the v2 zip's 124 + the poster).
- Extracted contents verified byte-identical to the new `dist/`.
- NOT deployed.
