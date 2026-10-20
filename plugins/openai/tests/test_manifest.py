"""Manifest tests: plugin.json validity against the 2026 OpenAI plugin format.

Checked against the live (2026) plugin submission docs: portable Agent
Plugins manifest (root plugin.json), $schema, package identity, listing
metadata under extensions.com.openai.interface, onboarding skill,
review/publication metadata, and internal-only logo/legal placeholders.

Also enforces the standing copy rules: no em-dashes in human-facing text,
and no invented live URLs in the package.
"""
import json
import os
import re
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_manifest():
    with open(os.path.join(BASE, "plugin.json"), encoding="utf-8") as f:
        return json.load(f)


TRIGGER_PHRASES = ["is this real?", "verify this", "is this authentic?"]
EM_DASH = "\u2014"


class TestManifestSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load_manifest()
        cls.iface = cls.m["extensions"]["com.openai"]["interface"]

    def test_valid_json(self):
        # load_manifest would already have raised; explicit is better.
        self.assertIsInstance(self.m, dict)

    def test_schema_marker(self):
        self.assertEqual(
            self.m["$schema"],
            "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json")

    def test_package_identity(self):
        self.assertEqual(self.m["name"], "verified-by-npc")
        self.assertLessEqual(len(self.m["name"]), 64)
        self.assertRegex(self.m["name"], r"^[a-z0-9-]+$")
        self.assertRegex(self.m["version"], r"^\d+\.\d+\.\d+$")
        self.assertEqual(self.m["author"]["name"], "NPC Labs")

    def test_listing_fields_required(self):
        iface = self.iface
        self.assertEqual(iface["displayName"], "Verified by NPC")
        self.assertLessEqual(len(iface["displayName"]), 30)
        self.assertLessEqual(len(iface["shortDescription"]), 30)
        self.assertLessEqual(len(iface["longDescription"]), 4000)
        self.assertEqual(iface["developerName"], "NPC Labs")
        self.assertLessEqual(len(iface["developerName"]), 80)
        self.assertTrue(iface["category"])

    def test_suggestion_trigger_phrasing(self):
        # Mid-conversation suggestion trigger: plain verification intents.
        desc = self.m["description"]
        iface = self.iface
        for text in (desc, iface["shortDescription"],
                     iface["longDescription"]):
            lowered = text.lower()
            self.assertTrue(
                any(p in lowered for p in TRIGGER_PHRASES),
                f"listing text lacks trigger phrasing: {text[:60]!r}")

    def test_starter_prompts(self):
        prompts = self.iface["defaultPrompt"]
        self.assertLessEqual(len(prompts), 3)
        for p in prompts:
            self.assertLessEqual(len(p), 128)

    def test_capabilities_cover_five_operations(self):
        caps = " ".join(self.iface["capabilities"]).lower()
        for word in ("product", "credential", "claim", "agent"):
            self.assertIn(word, caps)

    def test_logo_fields_are_internal_package_paths(self):
        # No invented live URLs; icons ship inside the package and exist.
        iface = self.iface
        for field in ("logo", "composerIcon"):
            path = iface[field]
            self.assertTrue(path.startswith("./assets/"),
                            f"{field} must be a package-relative asset")
            full = os.path.normpath(os.path.join(BASE, path))
            self.assertTrue(os.path.isfile(full),
                            f"{field} asset missing: {path}")
        self.assertNotIn("logoDark", iface)  # optional, omitted by design

    def test_legal_urls_present(self):
        # The four listing URLs are live on npclabs.xyz (privacy, terms,
        # and support pages ship with the site bundle). They must point at
        # the publisher's own domain, never anywhere invented.
        iface = self.iface
        expected = {
            "websiteURL": "https://npclabs.xyz",
            "supportURL": "https://npclabs.xyz/support",
            "privacyPolicyURL": "https://npclabs.xyz/privacy",
            "termsOfServiceURL": "https://npclabs.xyz/terms",
        }
        for field, url in expected.items():
            self.assertEqual(iface.get(field), url,
                             f"{field} must be the live publisher URL")

    def test_onboarding_skill_reference(self):
        ext = self.m["extensions"]["com.openai"]
        ref = ext["onboardingSkill"]
        self.assertEqual(ref, "./skills/verified-by-npc/SKILL.md")
        full = os.path.normpath(os.path.join(BASE, ref))
        self.assertTrue(os.path.isfile(full))
        with open(full, encoding="utf-8") as f:
            text = f.read()
        self.assertTrue(text.startswith("---\n"))
        frontmatter = text.split("---")[1]
        self.assertIn("name:", frontmatter)
        self.assertIn("description:", frontmatter)

    def test_review_cases(self):
        review = self.m["extensions"]["com.openai"]["review"]
        self.assertFalse(review["commerce"])
        # OpenAI submission field reference: plugin-level
        # review.test_cases is the placement for a plugin with exactly
        # one MCP server; per-server declarations are for multiple
        # servers and can't be combined with the plugin-level placement.
        # The package declares exactly one server (the hosted production
        # endpoint), so the cases live at plugin level. (The 2026-10-14
        # finding fired when plugin-level cases coexisted with multiple
        # declared servers; the 2026-10-15 per-server detour ended when
        # the package went back to one server.)
        with open(os.path.join(BASE, "mcp.json"), encoding="utf-8") as f:
            mcp = json.load(f)
        servers = mcp["mcpServers"]
        self.assertEqual(sorted(servers), ["production"])
        for name, entry in servers.items():
            self.assertNotIn("review", entry,
                             f"{name}: cases belong at plugin level "
                             f"for a one-server package")
        cases = review["test_cases"]
        pos = cases["positive"]
        neg = cases["negative"]
        self.assertEqual(len(pos), 5, "positive count")
        self.assertEqual(len(neg), 3, "negative count")
        for case in pos:
            for field in ("description", "prompt", "tools_triggered",
                          "expected_behavior"):
                self.assertTrue(case.get(field),
                                f"positive case missing {field}")
        for case in neg:
            for field in ("description", "prompt"):
                self.assertTrue(case.get(field),
                                f"negative case missing {field}")
        # fail-closed language in every expected behavior
        joined = " ".join(c["expected_behavior"] for c in pos).lower()
        self.assertIn("unknown", joined)

    def test_demo_recording_url(self):
        # Submission field reference: the demo recording URL is
        # optional in the ZIP only for skills-only plugins; an MCP
        # plugin's review requires a reviewer-accessible walkthrough
        # URL. Without it the portal keeps an "Incomplete review
        # information" finding even with every form section filled
        # (observed 2026-10-15).
        review = self.m["extensions"]["com.openai"]["review"]
        url = review.get("demo_recording_url")
        self.assertTrue(url, "review.demo_recording_url is required "
                             "for MCP review")
        self.assertTrue(url.startswith("https://npclabs.xyz/"), url)
        self.assertTrue(url.endswith(".mp4"), url)

    def test_publication(self):
        pub = self.m["extensions"]["com.openai"]["publication"]
        self.assertTrue(pub["release_notes"])
        self.assertNotIn("countries", pub)  # no targeting claims pre-launch

    def test_no_em_dashes_in_human_text(self):
        texts = [self.m["description"],
                 self.iface["displayName"],
                 self.iface["shortDescription"],
                 self.iface["longDescription"]]
        cases = self.m["extensions"]["com.openai"]["review"]["test_cases"]
        texts += [c["description"] for c in
                  cases["positive"] + cases["negative"]]
        texts += [c.get("expected_behavior", "") for c in
                  cases["positive"]]
        texts.append(self.m["extensions"]["com.openai"]["publication"]["release_notes"])
        for t in texts:
            self.assertNotIn(EM_DASH, t, f"em-dash found in: {t[:60]!r}")

    def test_no_funding_or_profitability_claims(self):
        blob = json.dumps(self.m).lower()
        for phrase in ("raised", "profitable", "profitability", "funding",
                       "$18m", "seed round"):
            self.assertNotIn(phrase, blob)

    def test_no_ai_plugin_json_legacy(self):
        # The 2023-era ai-plugin.json is retired and fails the 2026
        # submission scan; the package must not ship it.
        self.assertFalse(
            os.path.exists(os.path.join(BASE, "ai-plugin.json")))


def load_validator():
    import importlib.util
    path = os.path.join(BASE, "validate_package.py")
    spec = importlib.util.spec_from_file_location("validate_package", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_mcp():
    with open(os.path.join(BASE, "mcp.json"), encoding="utf-8") as f:
        return json.load(f)


class TestMcpDeclaration(unittest.TestCase):
    """The MCP declaration the portal parses (2026-10-15 diagnosis).

    The v2 package declared the production server with type "http",
    the Codex .mcp.json spelling, inside the portable mcp.json. That
    value matches no server definition in the Agent Plugins MCP
    schema (remote constants are "streamable-http" and "sse"), and
    the draft's MCPs tab reported that the plugin "does not reference
    any MCP server" even though the endpoint was live. These tests
    pin the documented portable shape so the defect cannot return.
    """

    @classmethod
    def setUpClass(cls):
        cls.mcp = load_mcp()
        cls.entry = cls.mcp["mcpServers"]["production"]
        cls.validator = load_validator()

    def test_mcp_schema_marker(self):
        self.assertEqual(
            self.mcp["$schema"],
            "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json")

    def test_single_production_server(self):
        self.assertEqual(sorted(self.mcp["mcpServers"]), ["production"])

    def test_remote_entry_shape(self):
        self.assertEqual(self.entry["type"], "streamable-http")
        self.assertEqual(self.entry["url"], "https://api.npclabs.xyz/v1/mcp")
        self.assertLessEqual(set(self.entry),
                             {"type", "url", "headers", "extensions",
                              "review"})

    def test_auth_declaration_for_no_auth_server(self):
        # The portal reads authentication settings from mcp.json; a
        # public no-auth server declares auth.type "none" (Package
        # your plugin, "Configure MCP authentication").
        auth = self.entry["extensions"]["com.openai"]["auth"]
        self.assertEqual(auth["type"], "none")

    def test_validator_accepts_shipped_entry(self):
        self.assertEqual(
            self.validator.mcp_entry_problems("production", self.entry),
            [])

    def test_validator_rejects_codex_http_spelling(self):
        # Negative control: the exact 2026-10-15 v2 defect.
        bad = dict(self.entry, type="http")
        problems = self.validator.mcp_entry_problems("production", bad)
        self.assertTrue(any("streamable-http" in p for p in problems),
                        problems)

    def test_validator_rejects_missing_auth_declaration(self):
        bad = {k: v for k, v in self.entry.items() if k != "extensions"}
        problems = self.validator.mcp_entry_problems("production", bad)
        self.assertTrue(any("authentication" in p for p in problems),
                        problems)

    def test_validator_rejects_undocumented_key(self):
        bad = dict(self.entry, transport="streamable-http")
        problems = self.validator.mcp_entry_problems("production", bad)
        self.assertTrue(any("outside the documented" in p
                            for p in problems), problems)

    def test_validator_rejects_plain_http_url(self):
        bad = dict(self.entry, url="http://api.npclabs.xyz/v1/mcp")
        problems = self.validator.mcp_entry_problems("production", bad)
        self.assertTrue(any("HTTPS" in p for p in problems), problems)
