"""npc-verify-openapi.yaml coverage: every action maps to a real, read-only
API v1 endpoint, function names match the plugin manifest, and the
helper's action registry matches the spec's x-npc-action mapping.
"""
import json
import os
import sys
import unittest

COPILOT_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, COPILOT_BASE)
sys.path.insert(0, os.path.join(COPILOT_BASE, "tests"))

from _yaml_subset import parse as yaml_parse  # noqa: E402
from npc_verify_copilot.client import ACTIONS  # noqa: E402

EXPECTED = {
    # x-npc-action: (method, path, operationId)
    "verify_product": ("get", "/products/{tag_id}", "verifyProduct"),
    "verify_credential": ("get", "/credentials/{id}", "verifyCredential"),
    "verify_claim": ("post", "/claims/verify", "verifyClaim"),
    "verify_agent": ("get", "/agents/{agent_id}/attestation", "verifyAgent"),
    "explain_verification": ("get", "/health", "explainVerification"),
}


def load_spec():
    with open(os.path.join(COPILOT_BASE, "npc-verify-openapi.yaml"),
              encoding="utf-8") as f:
        return yaml_parse(f.read())


def load_manifest():
    with open(os.path.join(COPILOT_BASE, "npc-verify-apiplugin.json"),
              encoding="utf-8") as f:
        return json.load(f)


def operations_by_action(spec):
    out = {}
    for path, path_item in spec["paths"].items():
        for method, op in path_item.items():
            action = op.get("x-npc-action")
            if action:
                out[action] = (method, path, op.get("operationId"), op)
    return out


class TestOpenApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = load_spec()
        cls.ops = operations_by_action(cls.spec)

    def test_openapi_version(self):
        self.assertTrue(
            str(self.spec.get("openapi", "")).startswith("3.0."),
            "Copilot plugins target OpenAPI 3.0.x")

    def test_servers_present(self):
        servers = self.spec.get("servers", [])
        self.assertTrue(servers)
        self.assertTrue(
            any("api.npclabs.xyz" in s.get("url", "") for s in servers))

    def test_bearer_security_defined(self):
        schemes = self.spec.get("components", {}).get("securitySchemes", {})
        self.assertIn("bearerAuth", schemes)
        self.assertEqual(schemes["bearerAuth"].get("scheme"), "bearer")

    def test_all_five_actions_mapped(self):
        self.assertEqual(set(self.ops), set(EXPECTED))

    def test_correct_endpoint_per_action(self):
        for action, (method, path, op_id) in EXPECTED.items():
            with self.subTest(action=action):
                got_method, got_path, got_id, _ = self.ops[action]
                self.assertEqual(got_method, method)
                self.assertEqual(got_path, path)
                self.assertEqual(got_id, op_id)

    def test_operation_ids_match_manifest_functions(self):
        manifest = load_manifest()
        fn_names = {f["name"] for f in manifest["functions"]}
        op_ids = {op_id for (_, _, op_id, _) in self.ops.values()}
        self.assertEqual(fn_names, op_ids)

    def test_each_operation_has_trigger_description(self):
        for action, (_, _, _, op) in self.ops.items():
            with self.subTest(action=action):
                lowered = op.get("description", "").lower()
                self.assertTrue(
                    any(p in lowered for p in
                        ("is this real", "verify this", "is this authentic",
                         "is this agent verified", "what 'verified by npc'")),
                    "operation description missing trigger phrasing")

    def test_read_only_no_issuance(self):
        """POST /attestations must never appear: verify only."""
        for path, path_item in self.spec["paths"].items():
            with self.subTest(path=path):
                self.assertNotIn("attestations", path)
        methods = {(m, p) for p, item in self.spec["paths"].items()
                   for m in item}
        self.assertNotIn(("post", "/attestations"), methods)

    def test_helper_registry_matches_spec(self):
        self.assertEqual(set(ACTIONS), set(EXPECTED))

    def test_unknown_action_rejected(self):
        from npc_verify_copilot.client import run_action
        with self.assertRaises(KeyError):
            run_action(None, "issue_attestation", {})


if __name__ == "__main__":
    unittest.main()
