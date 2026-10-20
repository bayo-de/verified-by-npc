"""Test fixtures for local development. INTERNAL — never production data.

Every fixture is fictional and prefixed test_/tag_test_/cred_test_/
agent_test_ so it can never be mistaken for a real attestation, credential,
product, or agent. No PII: holder names are fictional and marked public only
inside the fixture world.

One deliberate exception, marked in place below: the tag_archive_* products
are REAL historical records (NPC Labs' own on-chain mints, 2023-2024),
seeded for the public archive set. They are not fixtures, carry no test_
prefix, and are documented in
goals/npc-labs/files/npc-onchain-relics-inventory-2026-10-13.md and
goals/npc-labs/files/zora-mints-inventory-2026-10-13.md.
"""
import base64
import json
import secrets

from . import ed25519
from .canonical import claim_hash_for_text, canonicalize
from .models import (Attestation, Credential, Product, AgentAttestation,
                     utcnow_iso)

ANCHOR_CHAIN = "base"  # target chain; Phase 1 performs NO chain writes.


def _att_id():
    return "att_test_" + secrets.token_hex(8)


def _sign_attestation(keys, att: Attestation) -> Attestation:
    core = {
        "id": att.id,
        "subject_type": att.subject_type,
        "subject_id": att.subject_id,
        "verdict": att.verdict,
        "scope": att.scope,
        "tested_at": att.tested_at,
        "findings_summary": att.findings_summary,
    }
    key_id, sig = keys.sign("issuer", canonicalize(core))
    att.signature_b64 = base64.b64encode(sig).decode()
    att.key_id = key_id
    import hashlib
    att.anchor_hash = hashlib.sha256(canonicalize(core)).hexdigest()
    att.anchor_status = "not_anchored"  # Phase 1: hash recorded, no chain write
    return att


def seed_all(store, keys):
    """Seed fixtures. Returns dict with the plaintext API keys (show once)."""
    from .auth import Auth
    auth = Auth(store)
    # The verifier key serves the local dashboard, whose static export is
    # a batch render: one signature-verified API call per record, well over
    # the default 60/minute. Its allowance is raised for that batch job
    # only; the limiter itself and every other key keep their limits.
    verifier_key = auth.create_key("test-verifier", "verifier",
                                   per_minute=1200)
    issuer_key = auth.create_key("test-issuer", "issuer")

    # -- attestations behind claims --------------------------------------
    # (text, verdict, findings, tested_at, method). Demo claims about the
    # sample products below; verdicts are deliberately mixed, including
    # caveats and one claim the record does not support.
    claims = [
        ("The test widget passes drop testing", "verified",
         "Mechanical drop test, 1.2m, 50 cycles.",
         "2026-09-15T12:00:00+00:00", "lab-review"),
        ("Test Farms honey is single-origin", "verified_with_caveats",
         "Origin verified for 2026 harvest lots; earlier lots untested.",
         "2026-09-15T12:00:00+00:00", "lab-review"),
        ("Sample Ceramic Mug is lead-free", "verified",
         "Lab assay on the sample production lot; glaze and clay body "
         "tested clear.",
         "2026-09-18T12:00:00+00:00", "lab-review"),
        ("Demo Kiln Works fires with renewable power",
         "verified_with_caveats",
         "Utility records reviewed for the sample studio; solar share "
         "confirmed, grid mix for peak firings undocumented.",
         "2026-09-19T12:00:00+00:00", "document-review"),
        ("Sample Beeswax Candle burns for 40 hours", "verified",
         "Bench burn test on three sample units; observed 40 to 44 hours.",
         "2026-09-22T12:00:00+00:00", "bench-test"),
        ("Sample Leather Wallet uses vegetable-tanned leather",
         "not_verified",
         "Tannery documentation for the sampled lot did not confirm "
         "the claim.",
         "2026-09-23T12:00:00+00:00", "document-review"),
        ("Demo Print Studio prints are archival for 100 years",
         "verified_with_caveats",
         "Accelerated aging tests support a long print life; the full "
         "century figure is an extrapolation, not a measurement.",
         "2026-09-24T12:00:00+00:00", "lab-review"),
    ]
    claim_att_ids = {}
    for text, verdict, summary, tested, method in claims:
        att = Attestation(
            id=_att_id(), subject_type="claim",
            subject_id="claim:" + claim_hash_for_text(text)[:16],
            verdict=verdict,
            scope={"domain": "test-fixture", "method": method},
            tested_at=tested, expires_at=None,
            findings_summary=summary,
            claim_hash=claim_hash_for_text(text))
        att = _sign_attestation(keys, att)
        store.add_attestation(att)
        claim_att_ids[text] = att.id

    # -- credentials ------------------------------------------------------
    creds = [
        Credential(id="cred_test_001", status="valid",
                   title="Test Artisan Certificate", issuer="NPC Labs",
                   holder_name="Test Holder", holder_public=True,
                   issued_at="2026-01-10T00:00:00+00:00",
                   expires_at="2028-01-10T00:00:00+00:00",
                   assessed_skills=["test-craft"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_001"),
        Credential(id="cred_test_002", status="revoked",
                   title="Test Artisan Certificate", issuer="NPC Labs",
                   holder_name="Test Holder", holder_public=True,
                   issued_at="2025-03-01T00:00:00+00:00", expires_at=None,
                   assessed_skills=["test-craft"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_002"),
        Credential(id="cred_test_003", status="expired",
                   title="Test Artisan Certificate", issuer="NPC Labs",
                   holder_name=None, holder_public=False,
                   issued_at="2023-01-01T00:00:00+00:00",
                   expires_at="2024-01-01T00:00:00+00:00",
                   assessed_skills=["test-craft"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_003"),
        Credential(id="cred_test_004", status="valid",
                   title="Sample Maker Certificate: Ceramics",
                   issuer="NPC Labs",
                   holder_name="Sample Holder: Ines Duarte",
                   holder_public=True,
                   issued_at="2026-02-14T00:00:00+00:00",
                   expires_at="2028-02-14T00:00:00+00:00",
                   assessed_skills=["sample-pottery", "sample-glazing"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_004"),
        Credential(id="cred_test_005", status="valid",
                   title="Demo Creator Credential: Print",
                   issuer="NPC Labs",
                   holder_name="Sample Holder: Theo Lindqvist",
                   holder_public=True,
                   issued_at="2025-11-03T00:00:00+00:00",
                   expires_at="2027-11-03T00:00:00+00:00",
                   assessed_skills=["sample-printmaking"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_005"),
        Credential(id="cred_test_006", status="valid",
                   title="Sample Artisan Certificate: Leatherwork",
                   issuer="NPC Labs",
                   holder_name="Sample Holder: Priya Nair",
                   holder_public=True,
                   issued_at="2026-05-20T00:00:00+00:00",
                   expires_at="2028-05-20T00:00:00+00:00",
                   assessed_skills=["sample-leatherwork"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_006"),
        Credential(id="cred_test_007", status="expired",
                   title="Sample Maker Certificate: Woodwork",
                   issuer="NPC Labs",
                   holder_name=None, holder_public=False,
                   issued_at="2022-06-01T00:00:00+00:00",
                   expires_at="2024-06-01T00:00:00+00:00",
                   assessed_skills=["sample-woodwork"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_007"),
        Credential(id="cred_test_008", status="valid",
                   title="Demo Creator Credential: Photography",
                   issuer="NPC Labs",
                   holder_name="Sample Holder: June Okafor",
                   holder_public=True,
                   issued_at="2026-07-08T00:00:00+00:00",
                   expires_at="2028-07-08T00:00:00+00:00",
                   assessed_skills=["sample-photography"],
                   verification_url="https://verify.npclabs.xyz/c/cred_test_008"),
    ]
    for c in creds:
        key_id, sig = keys.sign(
            "issuer", canonicalize({"id": c.id, "status": c.status}))
        c.signature_b64 = base64.b64encode(sig).decode()
        c.key_id = key_id
        store.insert_credential(c)

    # -- products ----------------------------------------------------------
    products = [
        Product(tag_id="tag_test_authentic", status="authentic",
                name="Test Widget", creator="Test Maker",
                description="A fictional test product.",
                provenance=[
                    {"event": "manufactured", "at": "2026-08-01T00:00:00+00:00",
                     "detail": "Test Maker facility, lot T-1"},
                    {"event": "tagged", "at": "2026-08-02T00:00:00+00:00",
                     "detail": "NFC tag bound to product record"},
                ]),
        Product(tag_id="tag_test_counterfeit", status="counterfeit",
                name="Test Widget", creator="Test Maker",
                description="A fictional test product.",
                provenance=[
                    {"event": "flagged", "at": "2026-09-01T00:00:00+00:00",
                     "detail": "Tag cloned; packaging mismatch"},
                ]),
        Product(tag_id="tag_test_ceramic_mug", status="authentic",
                name="Sample Ceramic Mug", creator="Demo Kiln Works",
                description="A fictional sample product: a stoneware mug "
                            "with a demo provenance trail.",
                provenance=[
                    {"event": "formed", "at": "2026-06-10T00:00:00+00:00",
                     "detail": "Demo Kiln Works studio, batch S-12"},
                    {"event": "fired", "at": "2026-06-14T00:00:00+00:00",
                     "detail": "Second firing, sample kiln log 44"},
                    {"event": "tagged", "at": "2026-06-15T00:00:00+00:00",
                     "detail": "NFC tag bound to product record"},
                    {"event": "inspected", "at": "2026-06-20T00:00:00+00:00",
                     "detail": "Sample QC pass; glaze assay clear"},
                    {"event": "retailed", "at": "2026-07-01T00:00:00+00:00",
                     "detail": "Listed by the demo storefront"},
                ]),
        Product(tag_id="tag_test_beeswax_candle", status="authentic",
                name="Sample Beeswax Candle", creator="Demo Apiary",
                description="A fictional sample product: a poured beeswax "
                            "candle with a demo provenance trail.",
                provenance=[
                    {"event": "poured", "at": "2026-07-05T00:00:00+00:00",
                     "detail": "Demo Apiary workshop, wax lot B-3"},
                    {"event": "cured", "at": "2026-07-19T00:00:00+00:00",
                     "detail": "Two-week cure, sample batch record"},
                    {"event": "tagged", "at": "2026-07-20T00:00:00+00:00",
                     "detail": "NFC tag bound to product record"},
                    {"event": "retailed", "at": "2026-08-02T00:00:00+00:00",
                     "detail": "Listed by the demo storefront"},
                ]),
        Product(tag_id="tag_test_canvas_print", status="authentic",
                name="Sample Canvas Print", creator="Demo Print Studio",
                description="A fictional sample product: a gallery canvas "
                            "print with a demo provenance trail.",
                provenance=[
                    {"event": "printed", "at": "2026-05-11T00:00:00+00:00",
                     "detail": "Demo Print Studio, run P-88"},
                    {"event": "stretched", "at": "2026-05-12T00:00:00+00:00",
                     "detail": "Hand-stretched on sample pine frame"},
                    {"event": "tagged", "at": "2026-05-13T00:00:00+00:00",
                     "detail": "NFC tag bound to product record"},
                    {"event": "inspected", "at": "2026-05-15T00:00:00+00:00",
                     "detail": "Sample color check passed"},
                ]),
        Product(tag_id="tag_test_leather_wallet", status="authentic",
                name="Sample Leather Wallet", creator="Demo Hide & Thread",
                description="A fictional sample product: a stitched leather "
                            "wallet with a demo provenance trail.",
                provenance=[
                    {"event": "cut", "at": "2026-04-08T00:00:00+00:00",
                     "detail": "Demo Hide & Thread bench, hide lot L-7"},
                    {"event": "stitched", "at": "2026-04-09T00:00:00+00:00",
                     "detail": "Saddle stitch, sample bench record"},
                    {"event": "tagged", "at": "2026-04-10T00:00:00+00:00",
                     "detail": "NFC tag bound to product record"},
                    {"event": "retailed", "at": "2026-04-22T00:00:00+00:00",
                     "detail": "Listed by the demo storefront"},
                ]),
        Product(tag_id="tag_test_enamel_pin", status="authentic",
                name="Sample Enamel Pin Set", creator="Demo Press Collective",
                description="A fictional sample product: a three-pin enamel "
                            "set with a demo provenance trail.",
                provenance=[
                    {"event": "struck", "at": "2026-08-18T00:00:00+00:00",
                     "detail": "Demo Press Collective die, run E-5"},
                    {"event": "enameled", "at": "2026-08-20T00:00:00+00:00",
                     "detail": "Hard enamel fill, sample colorway"},
                    {"event": "tagged", "at": "2026-08-21T00:00:00+00:00",
                     "detail": "NFC tag bound to product record"},
                    {"event": "retailed", "at": "2026-09-01T00:00:00+00:00",
                     "detail": "Listed by the demo storefront"},
                ]),
        Product(tag_id="tag_test_wooden_toy", status="authentic",
                name="Sample Wooden Toy Train", creator="Demo Timber Toys",
                description="A fictional sample product: a carved wooden toy "
                            "train with a demo provenance trail.",
                provenance=[
                    {"event": "carved", "at": "2026-03-02T00:00:00+00:00",
                     "detail": "Demo Timber Toys bench, beech lot W-2"},
                    {"event": "finished", "at": "2026-03-04T00:00:00+00:00",
                     "detail": "Sanded; food-safe oil sample finish"},
                    {"event": "tagged", "at": "2026-03-05T00:00:00+00:00",
                     "detail": "NFC tag bound to product record"},
                    {"event": "inspected", "at": "2026-03-06T00:00:00+00:00",
                     "detail": "Sample safety check passed"},
                ]),
        Product(tag_id="tag_test_tote_bag", status="counterfeit",
                name="Sample Tote Bag", creator="Demo Canvas Co",
                description="A fictional sample product record: this tag "
                            "failed its authenticity check.",
                provenance=[
                    {"event": "flagged", "at": "2026-09-10T00:00:00+00:00",
                     "detail": "Tag cloned; stitch pattern mismatch"},
                ]),
        Product(tag_id="tag_test_trail_shoe", status="unknown",
                name="Sample Trail Shoe", creator="Demo Footwear Lab",
                description="A fictional sample product record: this tag "
                            "could not be matched to an origin.",
                provenance=[
                    {"event": "scanned", "at": "2026-09-12T00:00:00+00:00",
                     "detail": "Tag resolved to a different product record; "
                               "origin unconfirmed"},
                ]),
    ]
    for p in products:
        store.insert_product(p)

    # -- archive products: REAL historical on-chain records ----------------
    # Unlike everything above, these are NOT fixtures. They are NPC Labs'
    # actual on-chain mints (2023-2024), seeded so the public dashboard can
    # carry them as a company history archive set, clearly separate from
    # the test fixtures. Every fact below was read from chain data on
    # 2026-10-13 (contract metadata, mint transaction receipts, block
    # timestamps) and is recorded in
    # goals/npc-labs/files/npc-onchain-relics-inventory-2026-10-13.md.
    # Descriptions are short archive summaries written for this record,
    # not copies of the on-chain metadata text.
    NPC_WALLET = "0xe8AFB7C355B68A2A9C616E7877D0ef3352c59D5a"
    ARCHIVED_AT = "2026-10-13T00:00:00+00:00"

    def _archive_product(tag_id, name, description, chain, standard,
                         collection, contract, token_id, mint_at, mint_tx,
                         item_url):
        detail = (
            "Minted on %s as %s token %s of %s, contract %s, to the "
            "NPC Labs wallet %s. Mint transaction %s. Item record: %s"
            % (chain, standard, token_id, collection, contract, NPC_WALLET,
               mint_tx, item_url))
        return Product(
            tag_id=tag_id, status="authentic", name=name, creator="NPC Labs",
            description=description,
            provenance=[
                {"event": "minted", "at": mint_at, "detail": detail},
                {"event": "archived", "at": ARCHIVED_AT,
                 "detail": "Added to the Verified by NPC public archive as "
                           "a company history record. Archive records are "
                           "historical mints, not current products."},
            ])

    archive_products = [
        _archive_product(
            "tag_archive_npc_1155_1", "NPC",
            "Archive record. Token 1 of the NPC Labs collection on "
            "Ethereum, an ERC-1155 minted to the NPC Labs wallet in "
            "October 2023 and held there since. Its IPFS metadata "
            "description and image could not be retrieved when this entry "
            "was written, so they are recorded as unknown rather than "
            "guessed.",
            "Ethereum", "ERC-1155", "NPC Labs (NL)",
            "0x104028b6f94d93fdab4a4033e7a1416c9cee8a26", 1,
            "2023-10-07T02:05:11+00:00",
            "0x93929a9f936e3bac28ff3528989631ded3f77e08af9b2a29f0a7d6000b05ddc7",
            "https://opensea.io/item/ethereum/0x104028b6f94d93fdab4a4033e7a1416c9cee8a26/1"),
        _archive_product(
            "tag_archive_art_tee_1", "Art Tee 1",
            "Archive record. A physical art T-shirt, size Large and color "
            "Black per the on-chain attributes, tokenized by NPC Labs on "
            "Base. This token is the item's digital record, minted to the "
            "NPC Labs wallet and held there since mint.",
            "Base", "ERC-721", "Art Tee 1 (AT1)",
            "0x6a1b89377024f5e5dae416da72c1538194d9bb13", 1,
            "2024-02-14T18:50:15+00:00",
            "0x1cb23cfc247c63e51226de1e9f26c3229e9ec180211e4bd6dc4c54fd3dad4cdc",
            "https://opensea.io/item/base/0x6a1b89377024f5e5dae416da72c1538194d9bb13/1"),
    ]
    for n in range(1, 11):
        archive_products.append(_archive_product(
            "tag_archive_seeker_hat_%d" % n,
            'Low Profile DAD HAT - "The Seeker" by JANEDOE',
            "Archive record. A physical low profile dad hat from The "
            "Seeker drop by JANEDOE, made available during THE HALVENING "
            "by Nolcha Shows at NFT NYC 2024. The on-chain metadata "
            "credits manufacture to NPC Labs. This token is one hat's "
            "digital record, minted to the NPC Labs wallet and held "
            "there since mint.",
            "Polygon", "ERC-721", "TheSeekerHat (TSH)",
            "0xb0ca2cbaf6dec11964123f84809800031bf2732e", n,
            "2024-04-03T03:55:42+00:00",
            "0xe5252c9562e00533fd07f85452e2aa23ef30e0a2997114412cca0e2a98652051",
            "https://opensea.io/item/polygon/0xb0ca2cbaf6dec11964123f84809800031bf2732e/%d" % n))
    for n in range(1, 11):
        archive_products.append(_archive_product(
            "tag_archive_seeker_shirt_%d" % n,
            'Short Sleeve T-Shirt - "The Seeker" by JANEDOE',
            "Archive record. A physical short sleeve T-shirt from The "
            "Seeker drop by JANEDOE, made available during THE HALVENING "
            "by Nolcha Shows at NFT NYC 2024. The on-chain metadata "
            "credits manufacture to NPC Labs. This token is one shirt's "
            "digital record, minted to the NPC Labs wallet and held "
            "there since mint.",
            "Polygon", "ERC-721", "TheSeekerShortSleeve (TSSS)",
            "0xa43bf38b56b4ad5502fb9a11f7f58d56d0051a81", n,
            "2024-05-20T20:21:27+00:00",
            "0xf0e2ab5898cad33018724183cbd04448ec335cd173f4aa192596dd944f60a2fb",
            "https://opensea.io/item/polygon/0xa43bf38b56b4ad5502fb9a11f7f58d56d0051a81/%d" % n))
    for n in range(1, 11):
        archive_products.append(_archive_product(
            "tag_archive_nitrostat_%d" % n,
            "Nitrostat (Nitroglycerin Sublingual Tablets, USP)",
            "Archive record. A physical bottle of Nitrostat, 0.4 mg and "
            "100 tablets per the item image, tokenized by NPC Labs on "
            "Base as a pharmaceutical product record. The on-chain "
            "metadata carries the product label summary. This token is "
            "one bottle's digital record, minted to the NPC Labs wallet "
            "and held there since mint.",
            "Base", "ERC-721", "Nitrostat (NST)",
            "0x0875800f14c3054cba8c33a07b13b1db2b5b0387", n,
            "2024-06-11T05:39:51+00:00",
            "0xf26c5c13f77ed628932bd94ba68e202aa62e131652f1f33d5c6baae5553a6df1",
            "https://opensea.io/item/base/0x0875800f14c3054cba8c33a07b13b1db2b5b0387/%d" % n))

    # -- archive products: Zora mints (2024) ------------------------------
    # Also REAL records, not fixtures: the two collections NPC Labs
    # created on Zora, read from chain data on 2026-10-13 and recorded in
    # goals/npc-labs/files/zora-mints-inventory-2026-10-13.md. Unlike the
    # relics above, these were not minted to the NPC Labs wallet: the
    # Jordan Donald tokens were minted to collectors, and the Mysteria
    # Luna tokens were never minted at all. The provenance below says so
    # plainly; no supply figure is substituted anywhere.
    JORDAN_CONTRACT = "0x4c70d6947fb9692e5f8dd088d753c876e3f72936"
    JORDAN_CREATED = (
        "Contract created on Base as a Zora protocol ERC-1155, contract "
        "%s, block 17520754, transaction "
        "0xa1690c2cd4741db284114d92a1595df6818235af9f2332eb3554949180d527e7. "
        "The deployment was executed by a third-party wallet, "
        "0xf70da97812cb96acdf810712aa562db8dfa3dbef, through deployer "
        "contract 0xb90ed4c123843cbfd66b11411ee7694ef37e6e72; the NPC Labs "
        "wallet %s has been the contract owner from inception, and mint "
        "proceeds were paid to it throughout. Sale price 0.003 ETH per "
        "token; buyers paid 0.003777 ETH per token including the Zora "
        "mint fee. Item record: "
        "https://zora.co/collect/base:%s/%%d" % (JORDAN_CONTRACT,
                                                 NPC_WALLET,
                                                 JORDAN_CONTRACT))

    def _jordan_product(tag_id, token_id, name, description, minted_at,
                        minted_detail):
        return Product(
            tag_id=tag_id, status="authentic", name=name,
            creator="Jordan Donald x NPC Labs", description=description,
            provenance=[
                {"event": "created", "at": "2024-07-24T14:20:55+00:00",
                 "detail": JORDAN_CREATED % token_id},
                {"event": "minted", "at": minted_at,
                 "detail": minted_detail},
                {"event": "archived", "at": ARCHIVED_AT,
                 "detail": "Added to the Verified by NPC public archive "
                           "as a company history record. Archive records "
                           "are historical mints, not current products."},
            ])

    _jordan_tail = (
        " One copy was minted at setup to "
        "0xfc91be49bc90d263470f9d83feff46349165ae8e, and the NPC Labs "
        "wallet also appears as a mint recipient. A chain sweep of "
        "blocks through 2024-09-28 found no mints or transfers after "
        "2024-08-24.")
    archive_products += [
        _jordan_product(
            "tag_archive_jordan_donald_1", 1, "The Right Channels",
            "Archive record. \"The Right Channels\", token 1 of JORDAN "
            "DONALD x NPC LABS, an ERC-1155 art collection on Base issued "
            "on Zora in July 2024 presenting the work of artist Jordan "
            "Donald. The collection metadata states that collecting the "
            "artwork unlocks limited-edition physical prints fulfilled by "
            "NPC Labs. 125 copies of this token were minted to collectors "
            "between 2024-07-24 and 2024-08-24.",
            "2024-07-24T14:20:55+00:00",
            "125 copies minted in 123 mint events to 119 distinct "
            "recipients. First mint in the creation transaction, block "
            "17520754 (2024-07-24); last mint block 18839397 "
            "(2024-08-24)." + _jordan_tail),
        _jordan_product(
            "tag_archive_jordan_donald_2", 2,
            "The Rhapsody of Long Weekends",
            "Archive record. \"The Rhapsody of Long Weekends\", token 2 "
            "of JORDAN DONALD x NPC LABS, an ERC-1155 art collection on "
            "Base issued on Zora in July 2024 presenting the work of "
            "artist Jordan Donald. The collection metadata states that "
            "collecting the artwork unlocks limited-edition physical "
            "prints fulfilled by NPC Labs. 16 copies of this token were "
            "minted to collectors between 2024-07-24 and 2024-08-24.",
            "2024-07-24T00:00:00+00:00",
            "16 copies minted in 7 mint events to 4 distinct recipients. "
            "First mint block 17520768 (2024-07-24); last mint block "
            "18839637 (2024-08-24)." + _jordan_tail),
        _jordan_product(
            "tag_archive_jordan_donald_3", 3, "THE TAGALONG",
            "Archive record. \"THE TAGALONG\", token 3 of JORDAN DONALD "
            "x NPC LABS, an ERC-1155 art collection on Base issued on "
            "Zora in July 2024 presenting the work of artist Jordan "
            "Donald. The collection metadata states that collecting the "
            "artwork unlocks limited-edition physical prints fulfilled by "
            "NPC Labs. 17 copies of this token were minted to collectors "
            "between 2024-07-24 and 2024-08-24.",
            "2024-07-24T00:00:00+00:00",
            "17 copies minted in 8 mint events to 4 distinct recipients. "
            "First mint block 17520779 (2024-07-24); last mint block "
            "18839653 (2024-08-24)." + _jordan_tail),
        Product(
            tag_id="tag_archive_mysteria_luna", status="authentic",
            name="Mysteria Luna", creator="NPC Labs",
            description=(
                "Archive record. Mysteria Luna, a tarot card series by "
                "Dr. Xander Pratt, issued as an ERC-1155 collection on "
                "Base through Zora in November 2024. The metadata "
                "describes the deck as affirmation and prediction cards "
                "on lunar energy and manifestation, offered as a free NFT "
                "cover drop around Dubai Design Week with a physical "
                "tarot box pre-order. Eleven tokens were configured on "
                "chain (IDs 1 to 11). No copy of any token was minted in "
                "the window the chain was swept, 2024-11-03 to "
                "2024-12-09, which covers the stated drop window; the "
                "supply is recorded as zero because that is what the "
                "chain shows."),
            provenance=[
                {"event": "created", "at": "2024-11-03T19:15:23+00:00",
                 "detail": "Contract created on Base as a Zora protocol "
                           "ERC-1155, contract "
                           "0x249caa6e6b32a48e8341e14e926bdeb4013b7a54, "
                           "directly by the NPC Labs wallet %s through "
                           "the Zora creator factory "
                           "0x777777c338d93e2c7adf08d102d45ca7cc4ed021, "
                           "block 21935988, transaction "
                           "0xa8b6d9a33b0686a460136396be56c85a894cd2dcc11caff89c77817eae26ece5. "
                           "Eleven tokens configured, IDs 1 to 11: "
                           "Mysteria Luna; The Silent Step; The Hidden "
                           "Blade; The Cloak of Night; The Shadow Duel; "
                           "The Phantom Strike; The Phantom Strike (the "
                           "metadata gives tokens 6 and 7 the same name); "
                           "The Night Watcher; The Blade's Edge; The "
                           "Ninja's Breath; The Hidden Master. Token "
                           "metadata prices cards at 5 USDC and the "
                           "physical box at 100 USDC. Item record: "
                           "https://zora.co/collect/base:0x249caa6e6b32a48e8341e14e926bdeb4013b7a54/1"
                           % NPC_WALLET},
                {"event": "minted", "at": "2024-11-03T19:15:23+00:00",
                 "detail": "Zero minted. A chain sweep for "
                           "TransferSingle and TransferBatch events over "
                           "blocks 21900000 to 22300000, from contract "
                           "creation on 2024-11-03 through 2024-12-09, "
                           "recorded zero logs: no token in this contract "
                           "was minted, transferred, or burned in that "
                           "window, which covers the stated Dubai Design "
                           "Week drop window of November 5 to 10, 2024. "
                           "The owner's November 4 and 5 batch calls "
                           "configured the contract and its tokens "
                           "without minting. Supply recorded as zero; no "
                           "other figure is substituted."},
                {"event": "archived", "at": ARCHIVED_AT,
                 "detail": "Added to the Verified by NPC public archive "
                           "as a company history record. Archive records "
                           "are historical on-chain records, not current "
                           "products."},
            ]),
    ]
    for p in archive_products:
        store.insert_product(p)

    # -- agents -------------------------------------------------------------
    agent_att = Attestation(
        id=_att_id(), subject_type="agent", subject_id="agent_test_scout",
        verdict="verified",
        scope={"capabilities": ["test-navigation"], "limits": ["no-payments"]},
        tested_at="2026-09-20T12:00:00+00:00",
        expires_at="2027-09-20T12:00:00+00:00",
        findings_summary="Behavioral eval passed on the test harness.")
    agent_att = _sign_attestation(keys, agent_att)
    store.add_attestation(agent_att)
    store.insert_agent(
        "agent_test_scout", "verified",
        {"capabilities": ["test-navigation"], "limits": ["no-payments"]},
        "2026-09-20T12:00:00+00:00", "2027-09-20T12:00:00+00:00",
        agent_att.id,
        "Test harness evaluation; no production access.")
    agent_att2 = Attestation(
        id=_att_id(), subject_type="agent", subject_id="agent_test_herald",
        verdict="verified_with_caveats",
        scope={"capabilities": ["test-messaging"]},
        tested_at="2026-09-21T12:00:00+00:00", expires_at=None,
        findings_summary="Passed with caveats: rate limits untested.")
    agent_att2 = _sign_attestation(keys, agent_att2)
    store.add_attestation(agent_att2)
    store.insert_agent(
        "agent_test_herald", "verified_with_caveats",
        {"capabilities": ["test-messaging"]},
        "2026-09-21T12:00:00+00:00", None, agent_att2.id,
        "Caveats documented in findings summary.")

    sample_agents = [
        ("agent_test_archivist", "verified",
         {"capabilities": ["test-cataloging"],
          "limits": ["read-only", "no-payments"]},
         "2026-09-25T12:00:00+00:00", "2027-09-25T12:00:00+00:00",
         "Behavioral eval passed on the test harness.",
         "Test harness evaluation; catalog tasks only."),
        ("agent_test_envoy", "verified_with_caveats",
         {"capabilities": ["test-scheduling"]},
         "2026-09-26T12:00:00+00:00", None,
         "Passed with caveats: calendar edge cases untested.",
         "Caveats documented in findings summary."),
        ("agent_test_warden", "not_verified",
         {"capabilities": ["test-moderation"]},
         "2026-09-27T12:00:00+00:00", None,
         "Not verified: exceeded its stated scope in two harness "
         "scenarios.",
         "Scope violations documented in findings summary."),
    ]
    for agent_id, verdict, scope, tested, expires, findings, notes in \
            sample_agents:
        att = Attestation(
            id=_att_id(), subject_type="agent", subject_id=agent_id,
            verdict=verdict, scope=scope,
            tested_at=tested, expires_at=expires,
            findings_summary=findings)
        att = _sign_attestation(keys, att)
        store.add_attestation(att)
        store.insert_agent(agent_id, verdict, scope, tested, expires,
                           att.id, notes)

    return {"verifier_key": verifier_key, "issuer_key": issuer_key,
            "claim_attestations": claim_att_ids}
