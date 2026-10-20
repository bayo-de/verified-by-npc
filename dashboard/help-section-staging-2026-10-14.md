# Help section staging report (2026-10-14)

Direction (Bayo, Oct 14, 2026, evening): remove the video component
altogether and leave the site as it was; instead add a How It Works or
FAQ or Help section with helpful information on how to use the web app.

Status: BUILT AND VERIFIED, NOT DEPLOYED. The drop zip below is ready;
deploying it is a separate step.

## Part A: video component removed entirely

The video intro was staged earlier today and never deployed. All of it
is now removed from the source:

- `views.py`: the "See it work." block (heading, line, poster anchor)
  and its explanatory comment are gone from `home_view`; the two
  `.poster` CSS rules are gone from the shared stylesheet.
- `dashboard/assets/demo-poster.jpg` deleted; the now-empty
  `dashboard/assets/` directory deleted.
- `export_static.py`: the assets-copy hook at the end of `build()` is
  removed (with its now-unused `shutil` import), and the docstring
  bullet describing it is removed.

Proof:

- Grep over the rebuilt `dist/` (all files): zero hits for
  `VIDEO_ID_PENDING`, `demo-poster`, `See it work`, `youtube`,
  `<video`, `<iframe`. No poster file exists anywhere in `dist/`.
- Grep over the dashboard Python sources: the only remaining mentions
  of `VIDEO_ID_PENDING`, `demo-poster`, and `See it work` are the three
  `assertNotIn` regression guards in the new static-export test.
- The exported home page is byte-identical to the live v2 home page
  apart from the one nav line Part B adds (see the diff summary).
  The waitlist block, including the line "The NPC Verify extension,
  the Verified Agent Library, the Verified Agent Builder, and new
  releases land here first. Join the list.", is intact verbatim.
- The staged `verified-dashboard-drop-2026-10-15-video-intro.zip`
  remains on disk untouched, as history. This build supersedes it.

## Part B: the help page

New page at route `/help` (exported as `help/index.html`), title
"How it works", built in the site's exact page idiom: a `help_view()`
in `views.py`, a `GET /help` route in `server.py`, a pages-list entry
in `export_static.py`, and the default snapshot footer treatment like
every other preview page. It is reachable from the site navigation on
every page: the nav gains one link, "How it works", after Plugins.
No netlify.toml change is needed; the page serves as a plain directory
index like /privacy.

Test expectations were extended, not weakened:

- `tests/test_routes.py`: home link assertions gain `/help`; new
  `test_help_page` asserts the FAQ questions, the contact address, and
  the directed extension line.
- `tests/test_html.py`: `/help` joins the crawled page set, the
  nav-reachability set, and the nav-and-footer test. One scoped note:
  the placeholder-text guard treats "coming soon" as a stub marker on
  every page except `/help`, where that phrase is the directed status
  line for the extension (Bayo, 2026-10-14), surrounded by real
  content the route test asserts. All other placeholder markers still
  apply to `/help`, as do the em-dash and badge-glyph guards.
- `tests/test_static_export.py`: `help/index.html` joins
  EXPECTED_PAGES and LOCAL_ROUTES; new
  `test_help_page_carries_real_guidance` asserts the content, the
  snapshot footer, and the absence of every video-block trace.
- `smoke_test.py`: three new checks (help 200, guidance present,
  nav link present).

## Full final text of the help page, exactly as built

(Extracted from the rendered `dist/help/index.html`. In the "Reading a
result" section, the result words Verified, authentic, Verified with
caveats, Revoked, expired, counterfeit, and Unknown render in bold.)

---

Help

# How it works

This site answers one question in four places: is this real? Bring an
ID from a product tag or a certificate, or browse what has already
been checked, and the answer comes from a signed record, never from a
guess.

## Start with what you have

**A product tag**
Type the tag ID from the product. You get its status and the history
recorded for it, step by step.

**A credential ID**
Type the ID from a certificate. You get its current status: valid,
revoked, or expired.

**A claim**
Type the claim exactly as it was stated, or browse the records to see
what has been tested and what the findings were.

**The archive**
Real NPC Labs history from 2023 and 2024, minted on chain and kept
here the way a company keeps its first products on a shelf.

## Reading a result

Every answer is one of a few plain words. Verified and authentic mean
the record was checked and held up. Verified with caveats means it
held up, and the record carries notes worth reading alongside it.
Revoked, expired, and counterfeit mean the record says the thing
should not be trusted as presented. Unknown means we have no record
of it. Unknown is not a verdict; it is an honest answer, and we never
guess to fill the gap.

A record shows what was checked, when it was checked, the scope it
was checked under, and the findings in plain form. Where a credential
holder kept their name private, the record respects that and shows
no name.

The NPC check comes in two colors. A blue check marks a verified
human. An orange check marks a verified agent or a verified product.
The color tells you what kind of thing was verified; the record
behind it tells you the rest.

## These are sample records

The products, credentials, and records in this preview are test
samples, labeled as such, so you can see exactly how an answer looks
before anything of yours is on the line. Nothing here is a real
product, credential, or person. The one exception is the archive:
those are real items from NPC Labs' own history, and the page says
so.

## NPC Verify and the extension

NPC Verify is the same checking, pointed at images. The place to use
it today is the verification API at api.npclabs.xyz. The NPC Verify
browser extension brings the check to any page you are browsing: it
asks whether an image is registered with NPC Labs, reads the image's
embedded file information on your own device, and shows you a signed
answer it has confirmed before showing it to you. The extension is
coming soon. The privacy policy already describes exactly what it
does with data, in plain terms.

## The AI image check is a signal

One check deserves plain words. The AI image check answers with a
percentage: how likely it is that an image was generated by AI. Read
it as a signal, not a verdict. A high percentage is a reason to look
closer; a low one is not proof an image is human-made. No honest
checker can give you certainty here, and when the checker cannot
run, it says so instead of inventing a number.

## Why the keys are public

Every answer from NPC is signed. The keys page publishes the public
keys behind those signatures, so anyone can confirm an answer really
came from NPC without taking our word for the connection. Old keys
stay published after they retire, so old answers stay checkable.

## The waitlist

New surfaces land in stages. Joining the waitlist on the home page
puts you first to know when the NPC Verify extension, the Verified
Agent Library, the Verified Agent Builder, and new releases arrive.

## Questions

**What does "verified" mean here?**
It means the thing was checked against a signed NPC record and the
record held up: what it is, where it came from, and its current
status all match. The record behind the answer is the substance; the
word is just its summary.

**What if something has no record?**
The answer is unknown. That means we have no record of it. It does
not mean the thing is fake, and it does not mean it is real. We
would rather say unknown than guess.

**What do the two check colors mean?**
Blue marks a verified human. Orange marks a verified agent or a
verified product. Same standard, two kinds of subjects.

**Are the records on this site real?**
The products, credentials, and test records are samples, built so
you can see how the site answers. They are labeled as samples
wherever they appear. The archive is different: real NPC Labs items
minted on chain in 2023 and 2024, kept as company history.

**What does the AI image check actually tell me?**
A percentage likelihood that an image was AI-generated. It is one
signal with real uncertainty, useful for deciding what deserves a
closer look. It is never a hard stamp of real or fake, from us or
from anyone.

**What does "verified with caveats" mean?**
The record held up, and the record itself carries conditions or
limits, shown next to the result. Read them; they are part of the
answer, not fine print.

**Can I check an answer myself?**
Yes. Answers are signed, and the keys page publishes the keys.
Anyone can confirm a signature with them, without an account and
without asking us.

**How do I get something listed or verified?**
There is no self-serve signup yet. Join the waitlist on the home
page to hear as openings land, or write to us at
hello@npclabs.xyz.

---

## Verification

- Unit tests: `python3 -m unittest discover -s tests`: **45 tests, all
  OK** (43 before this change, plus the new route test and the new
  static-export help test). The suite includes the export-parity,
  no-em-dash, no-secrets, and no-fundraising-claims checks, all
  covering the new page.
- Smoke test: `python3 smoke_test.py`: **SMOKE OK**, including the
  three new help checks.
- Grep proof on the new `dist/`: zero `VIDEO_ID_PENDING`, zero
  `demo-poster`, zero `See it work`, zero `<video`, zero `<iframe`,
  zero `youtube`. `dist/help/index.html` exists (11,504 bytes), its
  title renders "How it works - Verified by NPC", and the link crawl
  in the test suite reaches `/help` from the nav and resolves every
  link on it.

## Diff summary vs the live v2 export

Baseline: `verified-dashboard-drop-2026-10-14-v2.zip` (the live build).

- Files: 63 in v2, 64 in the new export. Added: `help/index.html`.
  Removed: none (v2 never carried the poster; the video staging lived
  only in the superseded build).
- Every pre-existing page differs in exactly one line: the nav gains
  `<a href="/help">How it works</a>`. Verified by direct diff on the
  home page, privacy, a product detail, a credential detail, and the
  404.
- Two pages additionally carry the exporter's usual per-build
  rotation, identical in kind to every previous build: the keys page
  shows a freshly seeded fixture signing key (new key ID, public key,
  created timestamp), and the records page shows fresh `att_test_`
  attestation IDs. All verdicts, findings, and copy are unchanged.
- Footer build stamps are unchanged this build (same build date).
- The home page's waitlist block is byte-identical to live, and no
  page carries any video component, poster reference, or placeholder.

## Drop zip

- Path: `dashboard/verified-dashboard-drop-2026-10-15-help.zip`
- Size: **203,932 bytes**, 126 entries (64 files + directories).
- Extracted contents verified byte-identical to the new `dist/`.
- NOT deployed.
