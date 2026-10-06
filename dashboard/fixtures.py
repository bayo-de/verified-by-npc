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
]

PREVIEW_AGENTS = [
    "agent_test_scout",
    "agent_test_herald",
]

PREVIEW_CREDENTIALS = [
    "cred_test_001",
    "cred_test_002",
    "cred_test_003",
]

PREVIEW_PRODUCTS = [
    "tag_test_authentic",
    "tag_test_counterfeit",
]
