# Copy doctrine fix, 2026-10-14

Bayo's ruling: no meta-copy anywhere on verify.npclabs.xyz. Public copy
never narrates the site's structure, choices, or build state; it serves
the visitor (what this is, what you can do, what happens next) and
radiates trust in the choices. Honesty labels survive every rewrite,
phrased in customer words: sample records stay labeled samples,
not-yet-live features stay honestly not-live with the waitlist as the
path, the AI check stays images-only, credentials stay "present and
read", never cryptographically validated.

Scope: every page of the build (home, records, search, search/keys,
unknown, plugins, help, privacy, 404, verify, archive, record detail
shared blocks, footer). All rewrites were made at the source
(`views.py`, `export_static.py`), never in dist HTML. Nothing deployed.

**38 lines changed.** Full before/after below.

## Footer (exporter, every page)

| # | Before | After |
|---|--------|-------|
| 1 | Internal preview. Test fixtures only. | Every record shown is a sample. |
| 2 | Static snapshot of local test fixtures, built 2026-10-15 | Sample records. Updated 2026-10-15 |
| 3 | Static snapshot of the public archive, built 2026-10-15 (archive pages, right) | On-chain records. Updated 2026-10-15 |
| 4 | Static snapshot, built 2026-10-15 (privacy page, right) | Updated 2026-10-15 |

The test-record label survives in customer words ("sample"); "static
snapshot", "local test fixtures", and "internal preview" are gone from
every exported page.

## Home

| # | Before | After |
|---|--------|-------|
| 5 | Plugins card: "See where each assistant integration stands, stated plainly." | "See where each assistant integration stands, and what it will answer." |
| 6 | Help card: "A plain guide to the record, the search, and how to read an answer." | "A guide to the record, the search, and how to read an answer." |
| 7 | "The plugins are meant to carry these answers into the assistants people already use. None is available to install yet. The Plugins page gives the current status of each one, with no download or listing promised before it is real." | "The plugins will carry these answers into the assistants people already use. None is available to install yet; the Plugins page shows the current status of each one." |
| 8 | "The API launches with the extension. Until then, this preview answers from sample records, and the waitlist is the way to hear when live checking opens." | "The API launches with the extension. Until then, the records shown are samples, and the waitlist is the way to hear when live checking opens." |
| 9 | "This preview reads from the local test fixtures. Nothing here is a real product, credential, or person." | "Everything shown is a sample record. Nothing here is a real product, credential, or person." |

## Plugins

| # | Before | After |
|---|--------|-------|
| 10 | H1: "Plugins, stated plainly." | "NPC checks, inside the assistants you use." |
| 11 | Lede: "The plugins will let people ask for an NPC check inside an assistant and follow the answer back to the record on this site. None is available to install today. This page is a status page, not a storefront." | "The plugins let you ask for an NPC check inside an assistant and follow the answer back to the signed record. None is available to install today. Each one below shows where it stands." |
| 12 | "Did this really happen?" card: "Claim matched against attested records, findings shown, method never shown." | "Claim matched against attested records, findings included." |
| 13 | "What does Verified by NPC mean?" card: "A plain-language explainer. The why, never the how." | "What a verified answer means, and what it does not." |
| 14 | Claude row: "Built and tested locally. Not submitted. It was built against the local test API, and the public API is not live." | "Built and tested. Not submitted yet. It needs the public API, which is not live yet." |
| 15 | ChatGPT row: "Not submitted. Awaiting the developer account gate and the public API." | "Not submitted. It needs a developer account and the public API." |
| 16 | Gemini row: "Not submitted. Awaiting the developer account gate and the public API." | "Not submitted. It needs a developer account and the public API." |
| 17 | Copilot row: "Not submitted. Awaiting the partner account gate and the public API." | "Not submitted. It needs a partner account and the public API." |
| 18 | "The public API is the missing piece behind every row above. When it launches, an integration can answer against live records and point back to Records or Search for the full answer. Each integration still needs its own submission and approval before anyone can install it. An API launch by itself does not make a plugin available." | "Every plugin above depends on the public API. When it launches, each integration can answer against live records, with the full answer waiting on the record itself. Each integration still needs its own submission and approval before anyone can install it." |
| 19 | "For plugin news, join the waitlist on the home page. That is the honest way to hear when one of these becomes installable." | "For plugin news, join the waitlist on the home page to hear when one of these becomes installable." |

## Records

| # | Before | After |
|---|--------|-------|
| 20 | Lede ended: "Only the sanitized findings are shown." | Sentence removed; the lede ends at "what the findings were." |
| 21 | Archive: "The archive is a footnote to this record: real NPC Labs items minted on chain in 2023 and 2024, kept as company history. It is reached from here, not from the top of the site." | "Real NPC Labs items, minted on chain in 2023 and 2024 and kept as company history." (The "Browse the archive" link below it is unchanged.) |
| 22 | "Records shown are internal test fixtures." | "Records shown are test samples." |

## Search

| # | Before | After |
|---|--------|-------|
| 23 | "The samples below show how Search answers in this preview. They are labeled test records, not real products, credentials, or people." | "The samples below show how Search answers. They are test records, not real products, credentials, or people." |
| 24 | "Archive item IDs work here too. The archive itself is reached from Records; every historical item ID it lists can be entered in this search." | "Archive item IDs work here too: enter any historical item ID from the archive, and Search will find its record." |
| 25 | "Public keys are not a separate place to browse. Enter a key ID here, or open the full list as a part of Search. The keys let anyone confirm that a signed answer came from NPC." | "Enter a key ID here, or open the full list. The keys let anyone confirm that a signed answer came from NPC." |

## Search, public keys sub-view

| # | Before | After |
|---|--------|-------|
| 26 | H1: "Public keys, inside Search." | "Public keys." |

## Archive

| # | Before | After |
|---|--------|-------|
| 27 | "They are not current offerings, and they are not the test fixtures used elsewhere in this preview." | "They are not current offerings, and they are not samples." (The honesty distinction survives: archive records are real, everything else shown is a sample.) |

## Help (How it works)

| # | Before | After |
|---|--------|-------|
| 28 | Card: "The archive, through Records" (linking to /records): "The archive is a footnote to the record: real NPC Labs items minted on chain in 2023 and 2024, kept as company history." | Card: "The archive" (linking directly to /archive): "Real NPC Labs items minted on chain in 2023 and 2024, kept as company history." |
| 29 | Plugins card: "See the honest status of each assistant integration. None is available to install yet." | "See where each assistant integration stands. None is available to install yet." |
| 30 | "Public keys live in Search" section opened: "Keys are searched, not browsed as a separate destination." | Sentence removed; the section now opens with the guidance itself: "Enter a key ID in Search, or open the full public key list from that page." (Heading kept: on a help page it answers the visitor's actual question, where the keys are.) |
| 31 | "The products, credentials, and records in this preview are test samples, labeled as such, so you can see exactly how an answer looks before anything of yours is on the line. Nothing here is a real product, credential, or person. The one exception is the archive, reached through Records: those are real items from NPC Labs' own history, and the page says so." | "The products, credentials, and records shown are test samples, labeled as such, so you can see exactly how an answer looks before anything of yours is on the line. Nothing among them is a real product, credential, or person. The archive is the exception: those are real items from NPC Labs' own history." |
| 32 | "The structural read records that credentials are present; it is not a cryptographic validation of them, and the record says so." | "The structural read records that credentials are present; it is not a cryptographic validation of them." |
| 33 | "The extension is coming soon. The privacy policy already describes exactly what it does with data, in plain terms." | "The extension is coming soon. The privacy policy describes exactly what it does with data." |
| 34 | "The Plugins page is a status page. Three integrations have not been submitted, and the one built integration was tested against the local API while the public API is not live. When the API launches, each integration can answer against live records, and each still needs its own submission and approval before it can be installed. The waitlist is the honest way to hear plugin news." | "The Plugins page tracks each one. No plugin can be installed yet: three integrations have not been submitted, and the one that is built is waiting on the public API. When the API launches, each integration can answer against live records, and each still needs its own submission and approval before it can be installed. Join the waitlist to hear plugin news." |
| 35 | FAQ "Where is the archive?": "Under Records. It is a footnote to the whole build: NPC Labs' own historical items, minted on chain in 2023 and 2024. Current lookups happen in Search." | "Under Records. The archive holds NPC Labs' own historical items, minted on chain in 2023 and 2024, kept as company history. For a current lookup, use Search." |
| 36 | FAQ "Why is there no Keys page?": "Because keys are something you look up, not a destination of their own. Search accepts a key ID, and the full public key list lives inside Search for anyone who wants to read it." | FAQ "Where do I find the public keys?": "In Search. Enter a key ID to look one up, or open the full public key list from the Search page, where anyone can read it." |
| 37 | FAQ "Are the records on this site real?": "...kept as company history and reached through Records." | "...kept as company history." |
| 38 | FAQ "Can I check an answer myself?": "the public keys are published inside Search" | "the public keys are published in Search" |

## Audited, deliberately unchanged

- **Local preview footer** ("Internal preview. Local only." /
  "Reading from <url>"): renders only in the local preview server.
  The exporter replaces both spans on every public page, so no
  customer ever sees it. Its replacement strings are items 1-4 above.
- **Verify yours page**: the verify-start build had already rewritten
  its status, down-state, and noscript lines into customer-first
  wording before this pass reached them ("Registrations are paused
  right now. Nothing you type is sent or saved while the service is
  down."). Audited line by line: no meta-copy found. The same build
  had likewise already cleaned the Search "Verify yours" section and
  the Help registration paragraphs; audited clean.
- **Privacy policy body**: a policy document staged verbatim with the
  Chrome Web Store submission package. Audited; it speaks to the
  reader throughout and carries no structure narration worth breaking
  the verbatim text for.
- **Unknown page and notices, 404, record detail blocks** (credential,
  product, registration, key cards): audited; every line states a fact
  about the record or tells the visitor what to do next. "We never
  guess" and "Unknown is not a verdict" are honesty spoken to the
  customer, not narration about the site, and stay.

## Tests and artifact

- Dashboard unit suites: **56/56 OK** (includes the forced-redirects
  regression test). Three test pins that encoded the old meta-copy
  were updated to the new wording ("Built and tested.", the keys FAQ
  question, the archive card link), and one pin was preserved by
  improving the sentence instead ("None is available to install
  today." now stands as its own sentence in the Plugins lede).
- Smoke test: **SMOKE OK**, all checks passed.
- Export rebuilt clean: 68 files. Grep over dist for every flagged
  phrase class (footnote, static snapshot, internal preview, this
  preview, status page, storefront, honest way, separate destination,
  internal/local test fixtures, inside Search) returns zero hits;
  zero em dashes.
- Drop zip: `verified-dashboard-drop-2026-10-15-copy.zip`,
  **256,832 bytes**, contents verified byte-identical to the rebuilt
  `dist/` (68 files, SHA-256 compared file by file).
- Internal docs kept true: the two footer quotes in
  `DEPLOY-RUNBOOK.md` were updated to the new footer wording.
- **Not deployed.** The live site still serves the v2 build until
  Bayo approves this drop.
