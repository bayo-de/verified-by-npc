"""Route tests: every page renders against the seeded API."""
try:
    from tests.helpers import DashTestCase
except ImportError:  # pragma: no cover - direct invocation
    from helpers import DashTestCase


class RoutesTest(DashTestCase):
    def test_home(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("Verified by NPC", body)
        self.assertIn("Know what is real before you act on it.", body)
        for link in ("/records", "/credentials", "/products", "/keys",
                     "/plugins"):
            self.assertIn('href="%s"' % link, body)

    def test_records_lists_attestations(self):
        status, body = self.get("/records")
        self.assertEqual(status, 200)
        # claim attestations from the seed
        self.assertIn("The test widget passes drop testing", body)
        self.assertIn("Test Farms honey is single-origin", body)
        # agent attestations from the seed
        self.assertIn("agent_test_scout", body)
        self.assertIn("agent_test_herald", body)
        # verdict + sanitized findings, never methodology internals
        self.assertIn("Verified", body)
        self.assertIn("Mechanical drop test, 1.2m, 50 cycles.", body)

    def test_keys_page(self):
        status, body = self.get("/keys")
        self.assertEqual(status, 200)
        self.assertIn("npc-api_signing", body)
        self.assertIn("Check our answers yourself.", body)

    def test_credential_detail_valid(self):
        status, body = self.get("/credentials?id=cred_test_001")
        self.assertEqual(status, 200)
        self.assertIn("Test Artisan Certificate", body)
        self.assertIn("Valid", body)
        self.assertIn("NPC Labs", body)

    def test_credential_detail_revoked(self):
        status, body = self.get("/credentials?id=cred_test_002")
        self.assertEqual(status, 200)
        self.assertIn("Revoked", body)

    def test_credential_lookup_form(self):
        status, body = self.get("/credentials")
        self.assertEqual(status, 200)
        self.assertIn("Is this certificate real?", body)
        self.assertIn("cred_test_001", body)  # example link

    def test_product_authentic(self):
        status, body = self.get("/products?tag=tag_test_authentic")
        self.assertEqual(status, 200)
        self.assertIn("Authentic", body)
        self.assertIn("Test Widget", body)
        self.assertIn("manufactured", body)  # provenance chain

    def test_product_counterfeit(self):
        status, body = self.get("/products?tag=tag_test_counterfeit")
        self.assertEqual(status, 200)
        self.assertIn("Counterfeit", body)

    def test_claim_check_matched(self):
        status, body = self.post_form(
            "/records", {"claim_text": "The test widget passes drop testing"})
        self.assertEqual(status, 200)
        self.assertIn("Matched a record", body)

    def test_claim_check_unknown(self):
        status, body = self.post_form(
            "/records", {"claim_text": "no such claim exists anywhere"})
        self.assertEqual(status, 200)
        self.assertIn("Unknown", body)

    def test_plugins_page(self):
        status, body = self.get("/plugins")
        self.assertEqual(status, 200)
        self.assertIn("MCP", body)
        self.assertIn("ChatGPT", body)

    def test_404(self):
        status, body = self.get("/no-such-page")
        self.assertEqual(status, 404)
        self.assertIn("Nothing here.", body)
