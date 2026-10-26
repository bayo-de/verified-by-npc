"""KYA display (Know Your Agent): the dashboard half.

The API adds a `kya` block to agent records only while
NPC_KYA_FIELDS=1. These tests pin the dashboard side of that
contract: a record carrying the block renders a Know Your Agent
section with the four named fields, in the record's own values;
a record without the block renders exactly as before, with no
section at all; a reputation entry with no score prints that
plainly rather than inventing one; and payload text is escaped.
The browser-side renderers (the post-registration card and the
live lookup card) ship the same four-field block builder.
"""
import unittest

try:
    from tests import helpers  # noqa: F401  (puts the package on path)
except ImportError:  # pragma: no cover - direct invocation
    import helpers  # noqa: F401

from dashboard import views  # noqa: E402

KYA = {
    "principal": {"name": "Test Owner", "role": "accountable_owner"},
    "permissions": {"capabilities": ["test-navigation"]},
    "constraints": {"limits": ["no-payments"],
                    "valid_until": "2027-09-20T12:00:00+00:00",
                    "revoked": False},
    "reputation": {
        "score": None, "computed": False, "state": "not_computed",
        "based_on": {"verdict": "verified", "revoked": False},
        "detail": "No reputation score is computed from signed "
                  "records yet.",
    },
}

AGENT_REC = {
    "record_type": "npc.registry.agent_registration",
    "record_id": "reg_kya", "kind": "agent",
    "agent_name": "Harbor Helper", "owner_name": "Test Owner",
    "registered_at": "2026-10-20T00:00:00+00:00",
    "key_id": "k1", "checks_run": [], "checks_not_run": [],
    "kya": {
        "principal": {"name": "Test Owner",
                      "role": "accountable_owner"},
        "permissions": None, "constraints": None, "reputation": None,
    },
}

AGENT_ATTESTATION_REC = {
    "agent_id": "agent_test_scout", "verdict": "verified",
    "attestation_id": "att_test_kya", "notes": "Harness notes.",
    "kya": KYA,
}

RATED_KYA = {
    "principal": {"name": "Test Owner", "role": "accountable_owner",
                  "registration_record_id": "reg_kya"},
    "permissions": {"capabilities": ["test-navigation"]},
    "constraints": {"limits": ["no-payments"], "revoked": False},
    "reputation": {
        "rating": 100.0, "state": "rated", "computed": True,
        "rule": "npc-agent-rating", "rule_version": "1.0.0",
        "as_of": "2026-10-21T00:00:00+00:00",
        "based_on": {"attestations": 2,
                     "by_verdict": {"verified": 2},
                     "revocations": 0,
                     "latest_verdict": "verified",
                     "latest_revoked": False,
                     "latest_expired": False},
        "detail": "This agent's rating, computed by the NPC agent "
                  "rating rule from its attestation history.",
    },
}


class KyaHtmlTests(unittest.TestCase):

    def test_renders_the_four_fields_in_record_words(self):
        html = views.kya_html({"kya": KYA})
        self.assertIn("Know Your Agent", html)
        for label in ("Principal", "Permissions", "Constraints",
                      "Reputation"):
            self.assertIn("<dt>%s</dt>" % label, html)
        self.assertIn("Test Owner", html)
        self.assertIn("test-navigation", html)
        self.assertIn("no-payments", html)

    def test_reputation_without_a_score_says_so_plainly(self):
        html = views.kya_html({"kya": KYA})
        self.assertIn("No reputation score yet.", html)
        self.assertIn("verdict: verified", html)

    def test_rated_reputation_prints_the_rating_and_its_basis(self):
        html = views.kya_html({"kya": RATED_KYA})
        self.assertIn("Rating: 100.0", html)
        self.assertIn("NPC agent rating rule v1.0.0", html)
        self.assertIn("based on 2 attestations, 0 revoked", html)
        self.assertNotIn("No reputation score yet.", html)
        self.assertNotIn("—", html)

    def test_rated_reputation_on_the_attestation_card(self):
        rec = dict(AGENT_ATTESTATION_REC, kya=RATED_KYA)
        html = views.record_result(rec)
        self.assertIn("Know Your Agent", html)
        self.assertIn("Rating: 100.0", html)

    def test_null_fields_print_as_not_on_this_record(self):
        html = views.kya_html({"kya": AGENT_REC["kya"]})
        self.assertIn("Not on this record.", html)

    def test_renders_nothing_without_the_block(self):
        self.assertEqual(views.kya_html({}), "")
        self.assertEqual(views.kya_html({"kya": None}), "")
        self.assertEqual(views.kya_html(None), "")
        self.assertEqual(views.kya_html("nope"), "")

    def test_escapes_payload_text(self):
        hostile = {"kya": dict(
            KYA, principal={"name": "<script>alert(1)</script>"})}
        html = views.kya_html(hostile)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_no_em_dashes_in_the_section(self):
        self.assertNotIn("—", views.kya_html({"kya": KYA}))


class KyaWiringTests(unittest.TestCase):

    def test_agent_registration_card_shows_the_block(self):
        html = views.registration_result(AGENT_REC)
        self.assertIn("Know Your Agent", html)
        self.assertIn("Test Owner", html)

    def test_registration_card_without_block_is_unchanged(self):
        rec = {k: v for k, v in AGENT_REC.items() if k != "kya"}
        html = views.registration_result(rec)
        self.assertNotIn("Know Your Agent", html)

    def test_content_registration_card_never_shows_the_block(self):
        rec = {
            "record_type": "npc.registry.content_registration",
            "record_id": "reg_kya_content", "kind": "content",
            "title": "A work", "content_kind": "text",
            "creator_name": "Test Maker", "locator": "sha256:ab",
            "registered_at": "2026-10-20T00:00:00+00:00",
            "key_id": "k1", "checks_run": [], "checks_not_run": [],
            "kya": KYA,
        }
        self.assertNotIn("Know Your Agent",
                         views.registration_result(rec))

    def test_agent_attestation_card_shows_the_block(self):
        html = views.record_result(AGENT_ATTESTATION_REC)
        self.assertIn("Know Your Agent", html)
        self.assertIn("no-payments", html)

    def test_agent_attestation_card_without_block_is_unchanged(self):
        rec = {k: v for k, v in AGENT_ATTESTATION_REC.items()
               if k != "kya"}
        self.assertNotIn("Know Your Agent", views.record_result(rec))

    def test_browser_renderers_ship_the_block_builder(self):
        # VERIFY_JS renders the post-registration card; LIVE_LOOKUP_JS
        # renders a looked-up registration. Both build the block
        # only when the record carries one.
        self.assertIn("kyaBlock(rec.kya)", views.VERIFY_JS)
        self.assertIn("Know Your Agent", views.VERIFY_JS)
        self.assertIn("Know Your Agent", views.LIVE_LOOKUP_JS)
        self.assertIn("kyaBlock(rec.kya)", views.LIVE_LOOKUP_JS)


if __name__ == "__main__":
    unittest.main()
