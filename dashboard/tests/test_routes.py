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
        # The spacing rule must beat the .wrap class padding, or the
        # first kicker sits flush against the top bar.
        self.assertIn("main.wrap{padding:72px 24px 64px}", body)
        # The header uses .wrap for its horizontal inset; .top-in may
        # set vertical padding only, or the brand sits flush against
        # the left edge on mobile (Bayo, 2026-10-16).
        self.assertIn(
            ".top-in{display:flex;align-items:baseline;"
            "justify-content:space-between;flex-wrap:wrap;"
            "padding-top:18px;padding-bottom:18px;gap:12px}", body)
        self.assertIn(
            "@media(max-width:640px){nav{display:flex;flex-wrap:wrap;"
            "gap:8px 18px}nav a{margin-left:0}}", body)
        for link in ("/records", "/search", "/plugins", "/api", "/verify",
                     "/help"):
            self.assertIn('href="%s"' % link, body)
        self.assertIn(
            '<a href="/records">Records</a><a href="/search">Search</a>'
            '<a href="/plugins">Plugins</a><a href="/api">API</a>'
            '<a href="/verify">Verify yours</a>'
            '<a href="/help">How it works</a>',
            body)
        for old in ("/archive", "/credentials", "/products", "/keys"):
            self.assertNotIn('href="%s"' % old, body)

    def test_home_registration_section(self):
        # The front page carries the registration path in plain steps,
        # after the surface cards and before the waitlist (Bayo,
        # 2026-10-15: encourage registration, make it look easy).
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("Put your own work on record.", body)
        self.assertIn("Register your work or your agent.", body)
        self.assertIn(
            "Get a signed record with its own NPC ID, on the spot.", body)
        self.assertIn(
            "Your checks run, and the record updates as they complete.",
            body)
        self.assertIn(
            "Registration is free, and it takes about a minute.", body)
        section = body.split("Put your own work on record.", 1)[1]
        self.assertIn('<a href="/verify"', section.split(
            "First to know.", 1)[0])

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
        # The claim form is gone: Records is a read surface, and the
        # Archive is linked from it.
        self.assertNotIn("Check a claim", body)
        self.assertNotIn("claim_text", body)
        self.assertIn('<a href="/archive">Browse the archive</a>', body)

    def test_search_page_merges_all_ids(self):
        status, body = self.get("/search")
        self.assertEqual(status, 200)
        self.assertIn("Look up any NPC ID.", body)
        self.assertIn("Digital IDs", body)
        self.assertIn("Physical IDs", body)
        self.assertIn("cred_test_001", body)
        self.assertIn("tag_test_authentic", body)
        self.assertIn("npc-api_signing-", body)
        # Verify yours is the registration surface, linked from Search.
        self.assertIn("Verify yours", body)
        self.assertIn('href="/verify"', body)
        self.assertIn("Registration is not verification", body)
        self.assertIn('href="/search/keys"', body)

    def test_search_keys_subview(self):
        status, body = self.get("/search/keys")
        self.assertEqual(status, 200)
        self.assertIn("Public keys.", body)
        self.assertIn("npc-api_signing", body)
        self.assertIn("Current signing key", body)

    def test_search_credential_detail_valid(self):
        status, body = self.get("/search?id=cred_test_001")
        self.assertEqual(status, 200)
        self.assertIn("Test Artisan Certificate", body)
        self.assertIn("Valid", body)
        self.assertIn("NPC Labs", body)

    def test_search_credential_detail_revoked(self):
        status, body = self.get("/search?id=cred_test_002")
        self.assertEqual(status, 200)
        self.assertIn("Revoked", body)

    def test_search_product_authentic(self):
        status, body = self.get("/search?id=tag_test_authentic")
        self.assertEqual(status, 200)
        self.assertIn("Authentic", body)
        self.assertIn("Test Widget", body)
        self.assertIn("manufactured", body)  # provenance chain

    def test_search_product_counterfeit(self):
        status, body = self.get("/search?id=tag_test_counterfeit")
        self.assertEqual(status, 200)
        self.assertIn("Counterfeit", body)

    def test_search_archive_product(self):
        status, body = self.get("/search?id=tag_archive_seeker_hat_1")
        self.assertEqual(status, 200)
        self.assertIn("tag_archive_seeker_hat_1", body)
        self.assertIn("minted", body)

    def test_search_public_key(self):
        doc = self.api_app.keys.publish()
        key_id = doc["api_signing"]["current"]["key_id"]
        status, body = self.get("/search?id=" + key_id)
        self.assertEqual(status, 200)
        self.assertIn("Public key found", body)
        self.assertIn(key_id, body)

    def test_search_unknown_and_unknown_route(self):
        status, body = self.get("/search?id=not_a_real_id")
        self.assertEqual(status, 200)
        self.assertIn("Unknown", body)
        self.assertIn("never guess", body)
        status, body = self.get("/search/unknown")
        self.assertEqual(status, 200)
        self.assertIn("Unknown.", body)
        self.assertNotIn("Nothing here.", body)

    def test_archive_reached_as_a_record_page(self):
        status, body = self.get("/archive")
        self.assertEqual(status, 200)
        self.assertIn("Records · Archive", body)
        self.assertIn("Company history, on chain.", body)
        self.assertIn('href="/search?id=tag_archive_seeker_hat_1"', body)

    def test_old_top_level_pages_and_claim_post_are_gone(self):
        for path in ("/credentials", "/products", "/keys"):
            status, _body = self.get(path)
            self.assertEqual(status, 404, path)
        status, _body = self.post_form(
            "/records", {"claim_text": "The test widget passes drop testing"})
        self.assertEqual(status, 404)

    def test_privacy_page(self):
        status, body = self.get("/privacy")
        self.assertEqual(status, 200)
        self.assertIn("NPC Verify Privacy Policy", body)
        self.assertIn("SHA-256 hash", body)
        self.assertIn("hello@npclabs.xyz", body)
        # the footer links here from every page
        self.assertIn('href="/privacy"', body)

    def test_help_page(self):
        status, body = self.get("/help")
        self.assertEqual(status, 200)
        self.assertIn("How it works", body)
        # the FAQ answers a first-time visitor's real questions
        self.assertIn("What if something has no record?", body)
        self.assertIn("What does the AI image check actually tell me?",
                      body)
        self.assertIn("How do I get something listed or verified?", body)
        self.assertIn("hello@npclabs.xyz", body)
        # customer-first language: where things are found, never
        # narration of the site's structure (Bayo, 2026-10-14)
        self.assertIn("Public keys live in Search", body)
        self.assertIn("Where do I find the public keys?", body)
        self.assertIn('<a href="/archive">The archive</a>', body)
        # Verifying and registering a visitor's own digital resources
        # and agents is a real surface now (Verify yours): registration
        # starts verification, states its honesty labels, and links the
        # working page. The API base itself is not printed here.
        self.assertIn("Verify and register your own digital resources "
                      "and agents", body)
        self.assertIn("Can I verify or register my own digital "
                      "resources or agents?", body)
        self.assertIn('href="/verify"', body)
        self.assertIn("Registration is not verification", body)
        self.assertIn("registered, checks pending", body)
        # Cycle completion (2026-10-15): C2PA manifests are now
        # validated cryptographically at intake, and the help copy
        # says so; the pre-v5.5 "structural read only" line is gone.
        self.assertIn("validated cryptographically", body)
        self.assertIn("The signer is reported exactly as its "
                      "certificate presents it", body)
        self.assertNotIn("not a cryptographic validation", body)
        # ...and a registrant can request step two from their record
        self.assertIn("request verification from your record", body)
        self.assertNotIn("https://api.npclabs.xyz", body)
        # extension status is Bayo's directed language: coming soon,
        # never a date promise
        self.assertIn("The extension is coming soon.", body)

    def test_plugins_page(self):
        status, body = self.get("/plugins")
        self.assertEqual(status, 200)
        self.assertIn("MCP", body)
        self.assertIn("ChatGPT", body)
        # Status lines updated 2026-10-15 to the verified states:
        # ChatGPT, Gemini, and the MCP server are live; Copilot is in
        # enrollment with Microsoft; the public API is live.
        self.assertIn("Three are live today.", body)
        self.assertIn("In enrollment with Microsoft.", body)
        self.assertIn("npc-verify-mcp", body)
        self.assertIn("The public API is live", body)
        self.assertNotIn("Not submitted.", body)
        self.assertNotIn("not live yet", body)
        self.assertIn("join the waitlist", body)

    def test_api_page(self):
        # The developer tab (Bayo, 2026-10-15): documents only what the
        # live API does today, with examples taken from live calls.
        status, body = self.get("/api")
        self.assertEqual(status, 200)
        self.assertIn("The signed record, from your own code.", body)
        self.assertIn("https://api.npclabs.xyz/v1/register/agent", body)
        self.assertIn("https://api.npclabs.xyz/v1/register/content", body)
        self.assertIn("https://api.npclabs.xyz/v1/records/", body)
        self.assertIn("https://api.npclabs.xyz/v1/keys", body)
        self.assertIn("https://api.npclabs.xyz/v1/health", body)
        self.assertIn("https://api.npclabs.xyz/v1/mcp", body)
        # the live example records from the documentation calls
        self.assertIn("reg_6789fb4ca0f5363853a23dc0", body)
        self.assertIn("reg_d8b68b02eb095431acc031d2", body)
        self.assertIn("registered, checks pending", body)
        self.assertIn("Idempotency-Key", body)
        self.assertIn("npc-verify-mcp", body)
        self.assertIn("1.0.1", body)
        # the seven live MCP tools, named as tools/list answers them
        for tool in ("verify_claim", "verify_credential", "verify_product",
                     "verify_agent", "register_agent", "register_content",
                     "explain_verification"):
            self.assertIn(tool, body)
        # honest bounds: nothing documented that is not live. Scoped
        # to the page's own content; the sitewide chat widget's script
        # (which rides every page) is not this page's documentation.
        main = body.split("<main", 1)[1].split("</main>", 1)[0]
        self.assertNotIn("request-verification", main)
        self.assertNotIn("/v1/chat", main)
        self.assertNotIn("cryptographic validation", main)

    def test_404(self):
        status, body = self.get("/no-such-page")
        self.assertEqual(status, 404)
        self.assertIn("Nothing here.", body)
