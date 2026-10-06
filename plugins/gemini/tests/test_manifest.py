"""Manifest + slash-command validity for the Gemini CLI extension package.

Checks the gemini-extension.json manifest against the documented 2026
Gemini CLI extension schema (required name/version, known optional fields,
trigger phrasing in the description) and validates each commands/*.toml
slash command.
"""
import json
import os
import re
import sys
import tomllib
import unittest

GEMINI_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EXPECTED_COMMANDS = {
    "verify-product": "verify_product",
    "verify-credential": "verify_credential",
    "verify-claim": "verify_claim",
    "verify-agent": "verify_agent",
    "explain-verification": "explain_verification",
}

KNOWN_MANIFEST_FIELDS = {
    "name", "version", "description", "mcpServers", "contextFileName",
    "excludeTools", "settings", "plan", "migratedTo", "hooksDir",
    "skillsDir", "themes",
}

TRIGGER_PHRASES = ("is this real", "verify this", "is this authentic")


def load_manifest():
    with open(os.path.join(GEMINI_BASE, "gemini-extension.json"),
              encoding="utf-8") as f:
        return json.load(f)


class TestManifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load_manifest()

    def test_valid_json(self):
        self.assertIsInstance(self.manifest, dict)

    def test_required_name(self):
        name = self.manifest.get("name")
        self.assertIsInstance(name, str)
        self.assertTrue(name, "manifest name is required")
        self.assertRegex(name, r"^[a-z0-9-]+$",
                         "name must be lowercase, numbers, dashes")

    def test_required_version_semver(self):
        version = self.manifest.get("version")
        self.assertIsInstance(version, str)
        self.assertRegex(version, r"^\d+\.\d+\.\d+$",
                         "version must be a semver string")

    def test_description_carries_trigger_phrasing(self):
        desc = self.manifest.get("description", "")
        lowered = desc.lower()
        for phrase in TRIGGER_PHRASES:
            self.assertIn(phrase, lowered,
                          f"description missing trigger phrase {phrase!r}")

    def test_no_unknown_top_level_fields(self):
        unknown = set(self.manifest) - KNOWN_MANIFEST_FIELDS
        self.assertEqual(unknown, set(),
                         f"unknown manifest fields: {unknown}")

    def test_context_file_exists(self):
        ctx = self.manifest.get("contextFileName", "GEMINI.md")
        self.assertTrue(
            os.path.isfile(os.path.join(GEMINI_BASE, ctx)),
            f"context file {ctx} missing")

    def test_settings_declare_no_secrets(self):
        for setting in self.manifest.get("settings", []):
            self.assertIn("envVar", setting)
            # Settings declare env var names, never secret values.
            self.assertNotIn("value", setting)


class TestCommands(unittest.TestCase):
    def _load(self, name):
        path = os.path.join(GEMINI_BASE, "commands", name + ".toml")
        self.assertTrue(os.path.isfile(path), f"missing command {path}")
        with open(path, "rb") as f:
            return tomllib.load(f)

    def test_all_five_commands_present(self):
        files = {f[:-5] for f in os.listdir(
            os.path.join(GEMINI_BASE, "commands")) if f.endswith(".toml")}
        self.assertEqual(files, set(EXPECTED_COMMANDS))

    def test_each_command_has_description_and_prompt(self):
        for name in EXPECTED_COMMANDS:
            with self.subTest(command=name):
                cmd = self._load(name)
                self.assertIn("description", cmd)
                self.assertIn("prompt", cmd)
                self.assertTrue(cmd["description"].strip())
                self.assertTrue(cmd["prompt"].strip())

    def test_command_prompts_reference_their_action(self):
        for name, action in EXPECTED_COMMANDS.items():
            with self.subTest(command=name):
                cmd = self._load(name)
                self.assertIn(action, cmd["prompt"],
                              "prompt must name the action it runs")

    def test_command_descriptions_carry_trigger_phrasing(self):
        for name in EXPECTED_COMMANDS:
            if name == "explain-verification":
                continue
            with self.subTest(command=name):
                lowered = self._load(name)["description"].lower()
                self.assertTrue(
                    any(p in lowered for p in TRIGGER_PHRASES),
                    "command description missing trigger phrasing")

    def test_command_prompts_fail_closed(self):
        for name in EXPECTED_COMMANDS:
            with self.subTest(command=name):
                lowered = self._load(name)["prompt"].lower()
                self.assertIn("unknown", lowered)
                self.assertNotIn("methodology", lowered)


if __name__ == "__main__":
    unittest.main()
