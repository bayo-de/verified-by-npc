"""Preview-only known fixtures for the dashboard's browse views.

The NPC Verification API v1 is read-first and has no list endpoint, so the
dashboard's browse pages (records, example lookups) navigate a small,
explicitly declared set of fixture subjects that ship with the local API
seed (see ../api/npc_verify/seed.py). Every fixture is fictional and
test_-prefixed so it can never be mistaken for a real record.

Ground rules for using these:
- Each row is backed by a LIVE, signature-verified API response. If the
  API does not return the subject (unknown) or the response cannot be
  verified (tamper, error), the row renders "unknown" or "unavailable".
- These IDs are never presented as real-world credentials, products, or
  agents. The pages label the dataset as an internal preview.
- Nothing here is user input and nothing here bypasses verification.
"""

PREVIEW_CLAIMS = [
    "The test widget passes drop testing",
    "Test Farms honey is single-origin",
    "Sample Ceramic Mug is lead-free",
    "Demo Kiln Works fires with renewable power",
    "Sample Beeswax Candle burns for 40 hours",
    "Sample Leather Wallet uses vegetable-tanned leather",
    "Demo Print Studio prints are archival for 100 years",
]

PREVIEW_AGENTS = [
    "agent_test_scout",
    "agent_test_herald",
    "agent_test_archivist",
    "agent_test_envoy",
    "agent_test_warden",
]

PREVIEW_CREDENTIALS = [
    "cred_test_001",
    "cred_test_002",
    "cred_test_003",
    "cred_test_004",
    "cred_test_005",
    "cred_test_006",
    "cred_test_007",
    "cred_test_008",
]

PREVIEW_PRODUCTS = [
    "tag_test_authentic",
    "tag_test_counterfeit",
    "tag_test_ceramic_mug",
    "tag_test_beeswax_candle",
    "tag_test_canvas_print",
    "tag_test_leather_wallet",
    "tag_test_enamel_pin",
    "tag_test_wooden_toy",
    "tag_test_tote_bag",
    "tag_test_trail_shoe",
]

# -- Archive: REAL on-chain records (not fixtures) ------------------------
# NPC Labs' own historical mints (2023-2024), seeded in the API seed as
# tag_archive_* products and browsed on the /archive page only. They never
# join the PREVIEW_* lists above: the demo surfaces and the records table
# keep their fixture-only composition. Facts were read from chain data on
# 2026-10-13; see goals/npc-labs/files/
# npc-onchain-relics-inventory-2026-10-13.md. The last four entries are
# the Zora collections (2024), documented in
# zora-mints-inventory-2026-10-13.md: three Jordan Donald tokens minted
# to collectors, and one collection-level Mysteria Luna record whose
# on-chain supply is honestly zero. ARCHIVE_META mirrors the
# chain facts for display; the signed product record in the API remains
# the source each row is rendered from.
ARCHIVE_PRODUCTS = (
    ["tag_archive_npc_1155_1", "tag_archive_art_tee_1"]
    + ["tag_archive_seeker_hat_%d" % n for n in range(1, 11)]
    + ["tag_archive_seeker_shirt_%d" % n for n in range(1, 11)]
    + ["tag_archive_nitrostat_%d" % n for n in range(1, 11)]
    + ["tag_archive_jordan_donald_%d" % n for n in range(1, 4)]
    + ["tag_archive_mysteria_luna"]
)


def _archive_meta(chain, standard, collection, token_id):
    return {"chain": chain, "standard": standard,
            "collection": collection, "token_id": token_id}


ARCHIVE_META = {
    "tag_archive_npc_1155_1": _archive_meta(
        "Ethereum", "ERC-1155", "NPC Labs (NL)", 1),
    "tag_archive_art_tee_1": _archive_meta(
        "Base", "ERC-721", "Art Tee 1 (AT1)", 1),
}
for _n in range(1, 11):
    ARCHIVE_META["tag_archive_seeker_hat_%d" % _n] = _archive_meta(
        "Polygon", "ERC-721", "TheSeekerHat (TSH)", _n)
    ARCHIVE_META["tag_archive_seeker_shirt_%d" % _n] = _archive_meta(
        "Polygon", "ERC-721", "TheSeekerShortSleeve (TSSS)", _n)
    ARCHIVE_META["tag_archive_nitrostat_%d" % _n] = _archive_meta(
        "Base", "ERC-721", "Nitrostat (NST)", _n)
for _n in range(1, 4):
    ARCHIVE_META["tag_archive_jordan_donald_%d" % _n] = _archive_meta(
        "Base", "ERC-1155", "JORDAN DONALD x NPC LABS", _n)
ARCHIVE_META["tag_archive_mysteria_luna"] = _archive_meta(
    "Base", "ERC-1155", "Mysteria Luna", "1-11")
