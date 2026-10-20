# Site simplification build: staging report (2026-10-14)

Status: **STAGED ONLY. Nothing deployed.** Drop zip: `verified-dashboard-drop-2026-10-15-search.zip` (237,466 bytes, 67 files: 66 HTML pages plus the generated `_redirects`; extracted contents byte-identical to `dashboard/dist/`; SHA-256 `65799819f57801287629f41e84a1d053f0412da0f0d6caad5b360653a032e0c6`).

## What changed, in one paragraph

The top of the site is now Records, Search, Plugins, and How it works. Credentials, Products, and Keys no longer exist as pages: one Search accepts a credential ID, a product tag ID, an archive item ID, or a public key ID, and the full public key list is a sub-view inside Search. The Archive still lives at /archive but is reached from Records. The Records claim form and its dead POST route are deleted. Every lookup that misses now lands on a baked Unknown answer page instead of a raw 404. The home page no longer links to the not-yet-live API. The Plugins page is an explicit status page. Help was rewritten for the new structure, including Bayo's addition: verifying and registering a visitor's own digital resources and agents is named as part of what arrives with the API launch, with the waitlist as today's path. No registration or verification form was built, because the working surface needs the live API and a capture-only form would be window dressing. No dark mode was added.

Files changed: `dashboard/views.py`, `dashboard/server.py`, `dashboard/export_static.py`, `dashboard/smoke_test.py`, `dashboard/tests/test_routes.py`, `dashboard/tests/test_html.py`, `dashboard/tests/test_failclosed.py`, `dashboard/tests/test_static_export.py`, `dashboard/README.md`, `dashboard/DEPLOY-RUNBOOK.md`, and `netlify.toml` at the repo root.

## (a) Before and after nav

Before (every page, from the audit): brand, then `Records · Archive · Credentials · Products · Keys · Plugins · How it works`; Privacy in the footer only.

After (verified in the built export: all 66 HTML pages carry exactly this nav, in this order):

```html
<a href="/records">Records</a><a href="/search">Search</a><a href="/plugins">Plugins</a><a href="/help">How it works</a>
```

Routes removed: `/credentials`, `/products`, `/keys` (each now returns the dashboard 404 in the local app and has no page in the export), and `POST /records`. Routes added: `/search`, `/search/keys`, `/search/unknown`. The export's top-level directories are only `archive`, `help`, `plugins`, `privacy`, `records`, and `search`.

## (b) Proof the Check section and claim form are gone

Grep over the whole built export (`dist/`, 66 HTML files):

| Pattern | Count |
|---|---|
| `Check a claim` | 0 |
| `claim_text` | 0 |
| `<form method="post" action="/records">` | 0 |

Route tests and smoke also assert `POST /records` returns 404. The only forms left in the export are the Search GET form (59 instances across the Search pages) and the home waitlist form (1, Netlify Forms). There is no registration form anywhere.

## (c) Proof lookups land on Unknown instead of 404

Local app (route tests and smoke): `GET /search?id=not_a_real_id` returns 200 with the Unknown notice ("We have no record of this ID. That means unknown, not false. We never guess."), and credential, product, archive, and public key IDs each resolve to their real result through the same one search.

Static export: the exporter generates `dist/_redirects` at build time with 57 rules: 56 exact rules (8 credential IDs, 10 preview product IDs, 36 archive item IDs, and the 2 public key IDs minted for this build) of the form `/search id=<ID> /search/<ID>/ 200`, followed by the fallback as the last rule:

```text
/search id=:id /search/unknown/ 200
```

Verification performed on the built artifact: every exact rule's target file exists (0 missing), and `search/unknown/index.html` exists and contains the Unknown answer (and not the 404 page's "Nothing here."). Deploy note: the whole zip must be deployed so `_redirects` lands at the publish root; `netlify.toml` no longer carries the old generic credential/product redirects.

## (d) Proof the API link no longer promises a live API

Grep over the built export: `https://api.npclabs.xyz` count 0; `Use NPC Verify today` count 0; `href="/credentials"`, `href="/products"`, and `href="/keys"` each count 0. The home page now closes with: "The API launches with the extension. Until then, this preview answers from sample records, and the waitlist is the way to hear when live checking opens." The Plugins and Help pages state the same posture in their own words (full text in section (f)).

## (e) Spacing fix: rule, value, and a correction to the audit

The brief, following the audit, pointed at `main{padding:44px 0 64px}`. Visual verification in headless Chromium showed the rendered gap was actually **0px**: the `.wrap` class rule (`padding:0 24px`) has higher specificity than the `main` element rule, so the main padding never took effect, and the kicker sat flush against the top bar, exactly what Bayo saw. The fix therefore changes the selector as well as the value:

```css
main.wrap{padding:72px 24px 64px}
```

Measured after the fix (headless Chromium, 1280x900, serving `dist/`): on Home, Records, Plugins, Help, and Search alike, the header bottom is at 64.19px, the first kicker top is at 136.19px, and the computed gap is exactly **72px**, with the "Distribution" kicker on /plugins verified specifically. Route and static-export tests now assert the new rule ships.

## Plugins page status framing (brief item 5)

No installs are faked and the page offers nothing to download. Its table states: Claude MCP server, built and tested locally, not submitted, built against the local test API while the public API is not live; ChatGPT, Gemini, and Copilot, each not submitted and awaiting its account gate and the public API. The closing section explains what the API launch changes and names the waitlist as the call to action for plugin news. Full text in section (f).

## Verify and register your own resources and agents (Bayo's addition)

Stated in three consistent places, always with no date and the waitlist as today's path: the Search page section "Your own digital resources and agents," the Help section "Verify and register your own digital resources and agents," and the Help FAQ "Can I verify or register my own digital resources or agents?" No form, button, or interactive surface was added for this, by design.

## (f) Full copy of the new and changed pages, exactly as built

The text below is extracted from the staged zip's pages (visible main content only; nav and footer omitted). Key IDs and public key values in the Search pages are the ones minted for this build, as in every prior drop.

### Home (/)

```text
NPC Labs
Know what is real before you act on it.
Verified by NPC is a trust layer for the things you buy, earn, and build with. Products, credentials, claims, and agents, each checked against signed records you can confirm yourself.
Why it exists
People are asked to trust more than ever: a product listing, a certificate, a claim in a pitch, an agent asking for access. Trust should rest on something you can check, not on a logo or a promise. Every answer here is signed by NPC, and the public keys behind those signatures are published in Search. If we do not know, we say unknown.
Records
See what has actually been tested, and what the findings were.
Search
Look up digital and physical IDs in one place: credentials, products, archive items, and public keys.
Plugins
See where each assistant integration stands, stated plainly.
How it works
A plain guide to the record, the search, and how to read an answer.
How it reaches you
The plugins are meant to carry these answers into the assistants people already use. None is available to install yet. The Plugins page gives the current status of each one, with no download or listing promised before it is real.
First to know.
The NPC Verify extension, the Verified Agent Library, the Verified Agent Builder, and new releases land here first. Join the list.
Join the waitlist
The API launches with the extension. Until then, this preview answers from sample records, and the waitlist is the way to hear when live checking opens.
This preview reads from the local test fixtures. Nothing here is a real product, credential, or person.
```

### Records (/records)

```text
Attestation records
What has been tested.
Each record is a signed statement about one subject: what was checked, when, and what the findings were. Only the sanitized findings are shown.
Looking for one thing by its ID? Use Search. Search covers credential, product, archive, and public key IDs in one place.
Subject | Result | Scope | Tested | Findings
The test widget passes drop testing
att_test_5c642622dad6b3c4 | Verified
domain: test-fixturemethod: lab-review
2026-09-15T12:00:00+00:00 | Mechanical drop test, 1.2m, 50 cycles.
Test Farms honey is single-origin
att_test_534465eff6e5e3b1 | Verified with caveats
domain: test-fixturemethod: lab-review
2026-09-15T12:00:00+00:00 | Origin verified for 2026 harvest lots; earlier lots untested.
Sample Ceramic Mug is lead-free
att_test_2c38a744396c21dd | Verified
domain: test-fixturemethod: lab-review
2026-09-18T12:00:00+00:00 | Lab assay on the sample production lot; glaze and clay body tested clear.
Demo Kiln Works fires with renewable power
att_test_1ee33b4c474d8f8e | Verified with caveats
domain: test-fixturemethod: document-review
2026-09-19T12:00:00+00:00 | Utility records reviewed for the sample studio; solar share confirmed, grid mix for peak firings undocumented.
Sample Beeswax Candle burns for 40 hours
att_test_8d17e88252847c03 | Verified
domain: test-fixturemethod: bench-test
2026-09-22T12:00:00+00:00 | Bench burn test on three sample units; observed 40 to 44 hours.
Sample Leather Wallet uses vegetable-tanned leather
att_test_8b162d04fdace04d | Not verified
domain: test-fixturemethod: document-review
2026-09-23T12:00:00+00:00 | Tannery documentation for the sampled lot did not confirm the claim.
Demo Print Studio prints are archival for 100 years
att_test_4cd15c9faf72e301 | Verified with caveats
domain: test-fixturemethod: lab-review
2026-09-24T12:00:00+00:00 | Accelerated aging tests support a long print life; the full century figure is an extrapolation, not a measurement.
agent agent_test_scout
att_test_c13e6fc0cb188fb0 | Verified
capabilities: test-navigationlimits: no-payments
2026-09-20T12:00:00+00:00 | Test harness evaluation; no production access. Anchor recorded locally; no chain write yet.
agent agent_test_herald
att_test_216b2d03f0ee520f | Verified with caveats
capabilities: test-messaging
2026-09-21T12:00:00+00:00 | Caveats documented in findings summary. Anchor recorded locally; no chain write yet.
agent agent_test_archivist
att_test_ea420d38be36a3b1 | Verified
capabilities: test-cataloginglimits: read-only, no-payments
2026-09-25T12:00:00+00:00 | Test harness evaluation; catalog tasks only. Anchor recorded locally; no chain write yet.
agent agent_test_envoy
att_test_211f2e9590376ec3 | Verified with caveats
capabilities: test-scheduling
2026-09-26T12:00:00+00:00 | Caveats documented in findings summary. Anchor recorded locally; no chain write yet.
agent agent_test_warden
att_test_fd06c50fe71bcbc1 | Not verified
capabilities: test-moderation
2026-09-27T12:00:00+00:00 | Scope violations documented in findings summary. Anchor recorded locally; no chain write yet.
Archive
The archive is a footnote to this record: real NPC Labs items minted on chain in 2023 and 2024, kept as company history. It is reached from here, not from the top of the site.
Browse the archive
Records shown are internal test fixtures.
```

### Search (/search)

```text
Search
Look up any NPC ID.
One search covers digital and physical IDs: credential IDs, product tag IDs, archive item IDs, and public key IDs. Enter an ID exactly as it appears on a certificate, a tag, a record, or a key.
Search
Sample IDs
The samples below show how Search answers in this preview. They are labeled test records, not real products, credentials, or people.
Digital IDs
cred_test_001 cred_test_002 cred_test_003 cred_test_004 cred_test_005 cred_test_006 cred_test_007 cred_test_008
Physical IDs
tag_test_authentic tag_test_counterfeit tag_test_ceramic_mug tag_test_beeswax_candle tag_test_canvas_print tag_test_leather_wallet tag_test_enamel_pin tag_test_wooden_toy tag_test_tote_bag tag_test_trail_shoe
Archive item IDs work here too. The archive itself is reached from Records; every historical item ID it lists can be entered in this search.
Public keys
Public keys are not a separate place to browse. Enter a key ID here, or open the full list as a part of Search. The keys let anyone confirm that a signed answer came from NPC.
Published keys: npc-api_signing-20261015-7e2972 npc-issuer-20261015-1b38c4
Open the full public key list
Your own digital resources and agents
There is no form on this site today that can verify or register your own digital resources or agents. That working surface needs the live verification API. When the API launches, this site is where you will be able to verify your own digital resources and your own agents, and register them into the record. Until then, join the waitlist on the home page.
```

### Search: public key list (/search/keys)

```text
Search
Public keys, inside Search.
Every signed answer can be checked against the public keys below. Enter a key ID in Search, or read the full list here. Old keys stay published after they retire, so old answers stay checkable.
Search
Current signing key
npc-api_signing-20261015-7e2972 Active
qHB8+kbTqAr5p9dnq0QTmWXvK6ptR4KMKfLKHDbWMpk=
Ed25519. Created 2026-10-15T01:48:43+00:00.
Issuer keys
These keys sign the attestation records themselves.
npc-issuer-20261015-1b38c4 Active
vtUNb98uLTQw/bOexaNgaXAJ/GPI6Qmeuag2BxpIYmU=
Ed25519. Created 2026-10-15T01:48:43+00:00.
Back to Search
```

### Search: unknown answer (/search/unknown)

```text
Search
Unknown.
We have no record of this ID. That means unknown, not false. We never guess.
Search
Unknown
Check the ID and try again, or browse Records to see what has been attested.
```

### Plugins (/plugins)

```text
Distribution
Plugins, stated plainly.
The plugins will let people ask for an NPC check inside an assistant and follow the answer back to the record on this site. None is available to install today. This page is a status page, not a storefront.
What a plugin will answer
Is this product authentic?
Smart-tag lookup, with provenance.
Is this certificate real?
Credential lookup, with status and revocation.
Did this really happen?
Claim matched against attested records, findings shown, method never shown.
Is this agent verified?
Agent attestation: verdict, scope, and time bounds.
What does Verified by NPC mean?
A plain-language explainer. The why, never the how.
Where each one stands
Assistant | Surface | Status
Claude | MCP server for MCP clients | Built and tested locally. Not submitted. It was built against the local test API, and the public API is not live.
ChatGPT | Plugin / GPT action | Not submitted. Awaiting the developer account gate and the public API.
Gemini | Extension | Not submitted. Awaiting the developer account gate and the public API.
Copilot | Plugin | Not submitted. Awaiting the partner account gate and the public API.
What the API launch changes
The public API is the missing piece behind every row above. When it launches, an integration can answer against live records and point back to Records or Search for the full answer. Each integration still needs its own submission and approval before anyone can install it. An API launch by itself does not make a plugin available.
For plugin news, join the waitlist on the home page. That is the honest way to hear when one of these becomes installable.
```

### How it works (/help)

```text
Help
How it works
Verified by NPC is a public record you can read and a search you can use. Records shows what has been attested. Search finds a credential, product, archive item, or public key by its ID. Every answer comes from a signed record, never from a guess.
Start with what you have
Records
Browse signed statements about claims and agents: what was checked, when, and what the findings were.
Search
Enter any NPC ID in one place: a credential ID, a product tag ID, an archive item ID, or a public key ID.
The archive, through Records
The archive is a footnote to the record: real NPC Labs items minted on chain in 2023 and 2024, kept as company history.
Plugins
See the honest status of each assistant integration. None is available to install yet.
Reading a result
Every answer is one of a few plain words. Verified and authentic mean the record was checked and held up. Verified with caveats means it held up, and the record carries notes worth reading alongside it. Revoked, expired, and counterfeit mean the record says the thing should not be trusted as presented. Unknown means we have no record of it. Unknown is not a verdict; it is an honest answer, and we never guess to fill the gap.
A record shows what was checked, when it was checked, the scope it was checked under, and the findings in plain form. Where a credential holder kept their name private, the record respects that and shows no name.
The NPC check comes in two colors. A blue check marks a verified human. An orange check marks a verified agent or a verified product. The color tells you what kind of thing was verified; the record behind it tells you the rest.
Public keys live in Search
Keys are searched, not browsed as a separate destination. Enter a key ID in Search, or open the full public key list from that page. Anyone can use the published keys to confirm that a signed answer came from NPC, without an account and without taking our word for the connection. Old keys stay published after they retire, so old answers stay checkable.
These are sample records
The products, credentials, and records in this preview are test samples, labeled as such, so you can see exactly how an answer looks before anything of yours is on the line. Nothing here is a real product, credential, or person. The one exception is the archive, reached through Records: those are real items from NPC Labs' own history, and the page says so.
Verify and register your own digital resources and agents
There is no form on this site today that can do this. A working surface for your own digital resources and agents needs the live verification API, because a static page can capture a request but cannot issue a record.
When the API launches, this site is where you will be able to verify your own digital resources and your own agents, and register them into the record. Until then, joining the waitlist on the home page is the way to hear when that surface opens, or you can write to hello@npclabs.xyz.
NPC Verify and the extension
NPC Verify is the same checking, pointed at images. The verification API is not public yet, so there is no live image check on this site today. The NPC Verify browser extension will bring the check to pages you browse: it asks whether an image is registered with NPC Labs, reads the image's embedded file information on your own device, and shows a signed answer it has confirmed before showing it to you. The extension is coming soon. The privacy policy already describes exactly what it does with data, in plain terms.
The AI image check is a signal
One check deserves plain words. When NPC Verify is available, its AI image check will answer with a percentage: how likely it is that an image was generated by AI. Read it as a signal, not a verdict. A high percentage is a reason to look closer; a low one is not proof an image is human-made. No honest checker can give you certainty here, and when the checker cannot run, it should say so instead of inventing a number.
Plugins are not live yet
The Plugins page is a status page. Three integrations have not been submitted, and the one built integration was tested against the local API while the public API is not live. When the API launches, each integration can answer against live records, and each still needs its own submission and approval before it can be installed. The waitlist is the honest way to hear plugin news.
The waitlist
New surfaces land in stages. Joining the waitlist on the home page puts you first to know when the NPC Verify extension, the Verified Agent Library, the Verified Agent Builder, plugin availability, and new releases arrive.
Questions
What can I search?
Any NPC ID: a credential ID from a certificate, a product tag ID from a physical item, an archive item ID, or a public key ID. Digital and physical IDs share one search because the question is the same: what does the record say?
What if something has no record?
The answer is unknown. That means we have no record of it. It does not mean the thing is fake, and it does not mean it is real. We would rather say unknown than guess.
Where is the archive?
Under Records. It is a footnote to the whole build: NPC Labs' own historical items, minted on chain in 2023 and 2024. Current lookups happen in Search.
Why is there no Keys page?
Because keys are something you look up, not a destination of their own. Search accepts a key ID, and the full public key list lives inside Search for anyone who wants to read it.
Can I verify or register my own digital resources or agents?
Not through this site today. That working surface arrives with the API launch: you will be able to verify your own digital resources and your own agents here, and register them into the record. Join the waitlist on the home page to hear when it opens, or write to hello@npclabs.xyz.
What do the two check colors mean?
Blue marks a verified human. Orange marks a verified agent or a verified product. Same standard, two kinds of subjects.
Are the records on this site real?
The products, credentials, and test records are samples, built so you can see how the site answers. They are labeled as samples wherever they appear. The archive is different: real NPC Labs items minted on chain in 2023 and 2024, kept as company history and reached through Records.
What does the AI image check actually tell me?
When it is available, a percentage likelihood that an image was AI-generated. It is one signal with real uncertainty, useful for deciding what deserves a closer look. It is never a hard stamp of real or fake, from us or from anyone.
What does "verified with caveats" mean?
The record held up, and the record itself carries conditions or limits, shown next to the result. Read them; they are part of the answer, not fine print.
Can I check an answer myself?
Yes. Answers are signed, and the public keys are published inside Search. Anyone can confirm a signature with them, without an account and without asking us.
How do I get something listed or verified?
There is no self-serve signup or registration form yet. Verification and registration for your own digital resources and agents arrive with the API launch. Join the waitlist on the home page to hear as openings land, or write to us at hello@npclabs.xyz.
```

### Archive (/archive, reached from Records)

```text
Records · Archive
Company history, on chain.
These records are real. Between 2023 and 2024, NPC Labs minted a small number of items on chain: merchandise from an early drop, a tokenized prescription product, the company's own first token, and two collections issued on Zora. They are kept here as history, the way a company keeps its first products on a shelf.
They are not current offerings, and they are not the test fixtures used elsewhere in this preview. Each one is backed by its on-chain record: chain, contract, token, and mint date are in the full record, with a link to the item. The first records below were minted to the NPC Labs wallet, 0xe8AFB7C355B68A2A9C616E7877D0ef3352c59D5a, and none has moved since. The Zora collections are different, and their records say so: the Jordan Donald tokens were minted to collectors, and the Mysteria Luna series was configured on chain and never minted.
Item | Collection | Chain | Token | Minted | Status
NPC | NPC Labs (NL) | Ethereum | ERC-1155 1 | 2023-10-07 | Authentic | Full record
Art Tee 1 | Art Tee 1 (AT1) | Base | ERC-721 1 | 2024-02-14 | Authentic | Full record
Low Profile DAD HAT - "The Seeker" by JANEDOE | TheSeekerHat (TSH) | Polygon | ERC-721 1 | 2024-04-03 | Authentic | Full record
Low Profile DAD HAT - "The Seeker" by JANEDOE | TheSeekerHat (TSH) | Polygon | ERC-721 2 | 2024-04-03 | Authentic | Full record
Low Profile DAD HAT - "The Seeker" by JANEDOE | TheSeekerHat (TSH) | Polygon | ERC-721 3 | 2024-04-03 | Authentic | Full record
Low Profile DAD HAT - "The Seeker" by JANEDOE | TheSeekerHat (TSH) | Polygon | ERC-721 4 | 2024-04-03 | Authentic | Full record
Low Profile DAD HAT - "The Seeker" by JANEDOE | TheSeekerHat (TSH) | Polygon | ERC-721 5 | 2024-04-03 | Authentic | Full record
Low Profile DAD HAT - "The Seeker" by JANEDOE | TheSeekerHat (TSH) | Polygon | ERC-721 6 | 2024-04-03 | Authentic | Full record
Low Profile DAD HAT - "The Seeker" by JANEDOE | TheSeekerHat (TSH) | Polygon | ERC-721 7 | 2024-04-03 | Authentic | Full record
Low Profile DAD HAT - "The Seeker" by JANEDOE | TheSeekerHat (TSH) | Polygon | ERC-721 8 | 2024-04-03 | Authentic | Full record
Low Profile DAD HAT - "The Seeker" by JANEDOE | TheSeekerHat (TSH) | Polygon | ERC-721 9 | 2024-04-03 | Authentic | Full record
Low Profile DAD HAT - "The Seeker" by JANEDOE | TheSeekerHat (TSH) | Polygon | ERC-721 10 | 2024-04-03 | Authentic | Full record
Short Sleeve T-Shirt - "The Seeker" by JANEDOE | TheSeekerShortSleeve (TSSS) | Polygon | ERC-721 1 | 2024-05-20 | Authentic | Full record
Short Sleeve T-Shirt - "The Seeker" by JANEDOE | TheSeekerShortSleeve (TSSS) | Polygon | ERC-721 2 | 2024-05-20 | Authentic | Full record
Short Sleeve T-Shirt - "The Seeker" by JANEDOE | TheSeekerShortSleeve (TSSS) | Polygon | ERC-721 3 | 2024-05-20 | Authentic | Full record
Short Sleeve T-Shirt - "The Seeker" by JANEDOE | TheSeekerShortSleeve (TSSS) | Polygon | ERC-721 4 | 2024-05-20 | Authentic | Full record
Short Sleeve T-Shirt - "The Seeker" by JANEDOE | TheSeekerShortSleeve (TSSS) | Polygon | ERC-721 5 | 2024-05-20 | Authentic | Full record
Short Sleeve T-Shirt - "The Seeker" by JANEDOE | TheSeekerShortSleeve (TSSS) | Polygon | ERC-721 6 | 2024-05-20 | Authentic | Full record
Short Sleeve T-Shirt - "The Seeker" by JANEDOE | TheSeekerShortSleeve (TSSS) | Polygon | ERC-721 7 | 2024-05-20 | Authentic | Full record
Short Sleeve T-Shirt - "The Seeker" by JANEDOE | TheSeekerShortSleeve (TSSS) | Polygon | ERC-721 8 | 2024-05-20 | Authentic | Full record
Short Sleeve T-Shirt - "The Seeker" by JANEDOE | TheSeekerShortSleeve (TSSS) | Polygon | ERC-721 9 | 2024-05-20 | Authentic | Full record
Short Sleeve T-Shirt - "The Seeker" by JANEDOE | TheSeekerShortSleeve (TSSS) | Polygon | ERC-721 10 | 2024-05-20 | Authentic | Full record
Nitrostat (Nitroglycerin Sublingual Tablets, USP) | Nitrostat (NST) | Base | ERC-721 1 | 2024-06-11 | Authentic | Full record
Nitrostat (Nitroglycerin Sublingual Tablets, USP) | Nitrostat (NST) | Base | ERC-721 2 | 2024-06-11 | Authentic | Full record
Nitrostat (Nitroglycerin Sublingual Tablets, USP) | Nitrostat (NST) | Base | ERC-721 3 | 2024-06-11 | Authentic | Full record
Nitrostat (Nitroglycerin Sublingual Tablets, USP) | Nitrostat (NST) | Base | ERC-721 4 | 2024-06-11 | Authentic | Full record
Nitrostat (Nitroglycerin Sublingual Tablets, USP) | Nitrostat (NST) | Base | ERC-721 5 | 2024-06-11 | Authentic | Full record
Nitrostat (Nitroglycerin Sublingual Tablets, USP) | Nitrostat (NST) | Base | ERC-721 6 | 2024-06-11 | Authentic | Full record
Nitrostat (Nitroglycerin Sublingual Tablets, USP) | Nitrostat (NST) | Base | ERC-721 7 | 2024-06-11 | Authentic | Full record
Nitrostat (Nitroglycerin Sublingual Tablets, USP) | Nitrostat (NST) | Base | ERC-721 8 | 2024-06-11 | Authentic | Full record
Nitrostat (Nitroglycerin Sublingual Tablets, USP) | Nitrostat (NST) | Base | ERC-721 9 | 2024-06-11 | Authentic | Full record
Nitrostat (Nitroglycerin Sublingual Tablets, USP) | Nitrostat (NST) | Base | ERC-721 10 | 2024-06-11 | Authentic | Full record
The Right Channels | JORDAN DONALD x NPC LABS | Base | ERC-1155 1 | 2024-07-24 | Authentic | Full record
The Rhapsody of Long Weekends | JORDAN DONALD x NPC LABS | Base | ERC-1155 2 | 2024-07-24 | Authentic | Full record
THE TAGALONG | JORDAN DONALD x NPC LABS | Base | ERC-1155 3 | 2024-07-24 | Authentic | Full record
Mysteria Luna | Mysteria Luna | Base | ERC-1155 1-11 | 2024-11-03 | Authentic | Full record
Archive records are historical mints. Current credential, product, archive, and key IDs are looked up in Search.
```

## (g) Tests and smoke

- Unit, HTML, fail-closed, signature, and static-export suites: **48 tests, all OK** (`python3 -m unittest discover -s tests -v`). The suites were extended for the new nav and routes, the removed claim form and old pages returning 404, Search resolving credential, product, archive, and key IDs, the Unknown route, the generated `_redirects` exact rules and fallback, the spacing rule, and the new Help and Plugins copy.
- Smoke: **SMOKE OK**, 40 PASS checks, 0 failures.
- Em dashes: 0 in the built export (both the literal character and the entity). Badge glyphs: none. Secrets scan in the static-export suite: clean.
- Dark mode: not added; `prefers-color-scheme` count in the export is 0.

## Note on the audit file

The audit at `dashboard/site-audit-2026-10-14.md` as delivered ends mid-sentence in section 2 (the file stops at "Plugin subm" followed by a truncation marker); sections 3 to 6 are not present in the file. Every fact this build needed from those sections was verified directly against source before editing: the dead Records POST and its note (`views.py`, `export_static.py`, `netlify.toml`), the lookup 404 behavior, the CSS rule and its specificity problem (confirmed visually), and the absence of any public register, claim, or issue path in the API. Nothing in the build rests on the missing audit text.
