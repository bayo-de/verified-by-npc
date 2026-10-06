"""Copilot package manifest validity.

Checks npc-verify-apiplugin.json against the documented Microsoft 365
Copilot API plugin manifest schema v2.2 (schema_version, name_for_human,
namespace, descriptions, functions, runtimes, conversation starters) and
the declarative-agent.json wrapper (v1.3) that references it.
"""
import json
import os
import re
import unittest

COPILOT_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EXPECTED_FUNCTIONS = {
    "verifyProduct",
    "verifyCredential",
    "verifyClaim",
    "verifyAgent",
    "explainVerification",
}

TRIGGER_PHRASES = ("is this real", "verify this", "is this authentic",
                   "is this agent verified")


def _load(name):
    with open(os.path.join(COPILOT_BASE, name), encoding="utf-8") as f:
        return json.load(f)


class TestPluginManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = _load("npc-verify-apiplugin.json")

    def test_schema_version_is_current(self):
        self.assertEqual(self.manifest.get("schema_version"), "v2.2")

    def test_schema_url_matches_version(self):
        schema = self.manifest.get("$schema", "")
        self.assertIn("copilot/plugin/v2.2", schema)

    def test_name_for_human(self):
        name = self.manifest.get("name_for_human", "")
        self.assertTrue(name.strip())
        self.assertLessEqual(len(name), 20)

    def test_namespace_format(self):
        ns = self.manifest.get("namespace", "")
        self.assertRegex(ns, r"^[A-Za-z0-9]+$")

    def test_descriptions_present(self):
        self.assertTrue(self.manifest.get("description_for_human", "").strip())

    def test_description_for_model_carries_trigger_phrasing(self):
        desc = self.manifest.get("description_for_model", "").lower()
        for phrase in TRIGGER_PHRASES:
            self.assertIn(phrase, desc,
                          f"description_for_model missing {phrase!r}")

    def test_five_functions_declared(self):
        fns = self.manifest.get("functions", [])
        self.assertEqual({f["name"] for f in fns}, EXPECTED_FUNCTIONS)

    def test_each_function_has_trigger_description(self):
        for fn in self.manifest["functions"]:
            if fn["name"] == "explainVerification":
                continue  # the explainer answers "what does it mean?", not a trigger
            with self.subTest(function=fn["name"]):
                lowered = fn.get("description", "").lower()
                self.assertTrue(
                    any(p in lowered for p in TRIGGER_PHRASES),
                    "function description missing trigger phrasing")

    def test_runtime_is_openapi(self):
        runtimes = self.manifest.get("runtimes", [])
        self.assertEqual(len(runtimes), 1)
        rt = runtimes[0]
        self.assertEqual(rt.get("type"), "OpenApi")
        self.assertEqual(set(rt.get("run_for_functions", [])),
                         EXPECTED_FUNCTIONS)

    def test_runtime_auth_declared(self):
        auth = self.manifest["runtimes"][0].get("auth", {})
        self.assertIn(auth.get("type"),
                      {"ApiKeyPluginVault", "OAuthPluginVault", "None"})

    def test_spec_url_is_https(self):
        url = self.manifest["runtimes"][0]["spec"]["url"]
        self.assertTrue(url.startswith("https://"))

    def test_conversation_starters_present(self):
        starters = self.manifest.get("capabilities", {}).get(
            "conversation_starters", [])
        self.assertGreaterEqual(len(starters), 3)
        for starter in starters:
            self.assertTrue(starter.get("text", "").strip())

    def test_no_mark_artwork_or_secrets(self):
        """Optional brand/legal fields stay unset until the gates clear.
        The auth reference_id names an env var; it is not a secret value."""
        raw = json.dumps(self.manifest)
        self.assertNotIn("logo_url", raw)
        auth = self.manifest["runtimes"][0]["auth"]
        self.assertEqual(auth.get("reference_id"), "NPC_VERIFY_API_KEY")
        for key in ("secret", "bearer "):
            self.assertNotIn(key, raw.lower())


class TestDeclarativeAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = _load("declarative-agent.json")

    def test_schema_version(self):
        self.assertIn("copilot/declarative-agent/v1.3",
                      self.agent.get("$schema", ""))
        self.assertEqual(self.agent.get("version"), "v1.3")

    def test_references_plugin_manifest(self):
        actions = self.agent.get("actions", [])
        files = [a.get("file") for a in actions]
        self.assertIn("npc-verify-apiplugin.json", files)

    def test_instructions_fail_closed(self):
        instructions = self.agent.get("instructions", "").lower()
        self.assertIn("unknown", instructions)
        self.assertTrue(
            any(w in instructions
                for w in ("never fabricate", "never guess")),
            "instructions must forbid fabricated verdicts")

    def test_conversation_starters_present(self):
        starters = self.agent.get("conversation_starters", [])
        self.assertGreaterEqual(len(starters), 3)


if __name__ == "__main__":
    unittest.main()
