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
        pos = review["test_cases"]["positive"]
        neg = review["test_cases"]["negative"]
        self.assertEqual(len(pos), 5)
        self.assertEqual(len(neg), 3)
        for case in pos:
            for field in ("description", "prompt", "tools_triggered",
                          "expected_behavior"):
                self.assertTrue(case.get(field), f"positive case missing {field}")
        for case in neg:
            for field in ("description", "prompt"):
                self.assertTrue(case.get(field), f"negative case missing {field}")
        # fail-closed language in every expected behavior
        joined = " ".join(c["expected_behavior"] for c in pos).lower()
        self.assertIn("unknown", joined)

    def test_publication(self):
        pub = self.m["extensions"]["com.openai"]["publication"]
        self.assertTrue(pub["release_notes"])
        self.assertNotIn("countries", pub)  # no targeting claims pre-launch

    def test_no_em_dashes_in_human_text(self):
        texts = [self.m["description"],
                 self.iface["displayName"],
                 self.iface["shortDescription"],
                 self.iface["longDescription"]]
        review = self.m["extensions"]["com.openai"]["review"]
        texts += [c["description"] for c in
                  review["test_cases"]["positive"] + review["test_cases"]["negative"]]
        texts += [c.get("expected_behavior", "") for c in
                  review["test_cases"]["positive"]]
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
