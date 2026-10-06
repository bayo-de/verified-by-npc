"""operations.json coverage: every action maps to a real, read-only API v1
endpoint, and the helper's action registry matches the file.
"""
import json
import os
import sys
import unittest

GEMINI_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, GEMINI_BASE)

from npc_verify_gemini.client import ACTIONS  # noqa: E402

EXPECTED = {
    "verify_product": ("GET", "/v1/products/{tag_id}"),
    "verify_credential": ("GET", "/v1/credentials/{id}"),
    "verify_claim": ("POST", "/v1/claims/verify"),
    "verify_agent": ("GET", "/v1/agents/{agent_id}/attestation"),
    "explain_verification": ("GET", "/v1/health"),
}


def load_operations():
    with open(os.path.join(GEMINI_BASE, "operations.json"),
              encoding="utf-8") as f:
        return json.load(f)


class TestOperations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = load_operations()
        cls.by_name = {a["name"]: a for a in cls.ops["actions"]}

    def test_all_five_actions_mapped(self):
        self.assertEqual(set(self.by_name), set(EXPECTED))

    def test_correct_endpoint_per_action(self):
        for name, (method, path) in EXPECTED.items():
            with self.subTest(action=name):
                self.assertEqual(self.by_name[name]["method"], method)
                self.assertEqual(self.by_name[name]["path"], path)

    def test_each_action_has_trigger_description(self):
        for name, action in self.by_name.items():
            with self.subTest(action=name):
                desc = action.get("description", "").lower()
                self.assertTrue(desc.strip())
                if name != "explain_verification":
                    self.assertTrue(
                        any(p in desc for p in
                            ("is this real", "verify this", "is this authentic",
                             "is this agent verified")),
                        "action description missing trigger phrasing")

    def test_read_only_no_issuance(self):
        """No action may map to the attestation-issuance endpoint: verify
        only. (The notes may name the endpoint to forbid it; the check is
        on the action paths themselves.)"""
        for name, action in self.by_name.items():
            with self.subTest(action=name):
                self.assertNotIn("attestations", action["path"],
                                 "issuance endpoint must not be mapped")
        methods = {(a["method"], a["path"]) for a in self.ops["actions"]}
        self.assertNotIn(("POST", "/v1/attestations"), methods)

    def test_helper_registry_matches_operations_file(self):
        self.assertEqual(set(ACTIONS), set(EXPECTED))

    def test_unknown_action_rejected(self):
        from npc_verify_gemini.client import run_action
        with self.assertRaises(KeyError):
            run_action(None, "issue_attestation", {})


if __name__ == "__main__":
    unittest.main()
