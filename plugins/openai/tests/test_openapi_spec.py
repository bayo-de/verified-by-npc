"""OpenAPI spec tests: openapi-plugin.yaml validity and operation mapping.

The spec is parsed with the package's restricted-YAML subset parser
(stdlib only). Tests assert: the spec is well-formed, the five plugin
operations map onto the correct API v1 endpoints, every operation is
read-only (no attestation issuance), and the API-backed operations are a
subset of the API's own openapi.yaml (same paths, same methods, same
operation semantics).
"""
import os
import unittest

from tests._yaml_subset import parse, YAMLError
from tests.helpers import OpenAITestCase  # noqa: F401  (path setup only)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_SPEC = os.path.normpath(os.path.join(BASE, "..", "..", "api",
                                         "openapi.yaml"))

EXPECTED_OPS = {
    # operationId: (path, method, api_operationId)
    "verify_product": ("/v1/products/{tag_id}", "get", "getProduct"),
    "verify_credential": ("/v1/credentials/{id}", "get", "getCredential"),
    "verify_claim": ("/v1/claims/verify", "post", "verifyClaim"),
    "verify_agent": ("/v1/agents/{agent_id}/attestation", "get",
                     "getAgentAttestation"),
    "explain_verification": ("/explain/verification", "get", None),
}


def load_plugin_spec():
    with open(os.path.join(BASE, "openapi-plugin.yaml"),
              encoding="utf-8") as f:
        return parse(f.read())


def load_api_spec():
    with open(API_SPEC, encoding="utf-8") as f:
        return parse(f.read())


class TestSpecValidity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = load_plugin_spec()

    def test_parses_within_subset(self):
        self.assertIsInstance(self.spec, dict)

    def test_openapi_version(self):
        self.assertEqual(self.spec["openapi"], "3.1.0")

    def test_info(self):
        info = self.spec["info"]
        self.assertIn("Verified by NPC", info["title"])
        self.assertTrue(info["version"])

    def test_servers(self):
        urls = [s["url"] for s in self.spec["servers"]]
        self.assertIn("https://api.npclabs.xyz/v1", urls)
        self.assertIn("http://127.0.0.1:8787/v1", urls)

    def test_security_bearer(self):
        self.assertEqual(self.spec["security"], [{"bearerAuth": []}])
        self.assertEqual(
            self.spec["components"]["securitySchemes"]["bearerAuth"]["type"],
            "http")

    def test_all_schemas_referenced_resolve(self):
        schemas = self.spec["components"]["schemas"]
        blob = str(self.spec["paths"])
        for line in blob.split("#/components/schemas/")[1:]:
            name = line.split("'")[0].split('"')[0].split("}")[0].strip()
            if name:
                self.assertIn(name, schemas, f"unresolved schema {name!r}")

    def test_explain_verification_is_client_side(self):
        op = self.spec["paths"]["/explain/verification"]["get"]
        self.assertEqual(op["operationId"], "explain_verification")
        self.assertTrue(op.get("x-npc-client-side"),
                        "explain_verification must be marked client-side: "
                        "it performs no API call")

    def test_no_em_dashes(self):
        with open(os.path.join(BASE, "openapi-plugin.yaml"),
                  encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("—", text)


class TestOperationMapping(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = load_plugin_spec()
        cls.api = load_api_spec()
        cls.ops = {}
        for path, methods in cls.spec["paths"].items():
            for method, op in methods.items():
                cls.ops[op["operationId"]] = (path, method, op)

    def test_five_operations_present(self):
        self.assertEqual(sorted(self.ops),
                         sorted(EXPECTED_OPS))

    def test_correct_endpoints(self):
        for op_id, (path, method, _) in EXPECTED_OPS.items():
            got_path, got_method, _ = self.ops[op_id]
            self.assertEqual((got_path, got_method), (path, method),
                             f"{op_id} mapped to wrong endpoint")

    def test_trigger_phrasing_in_descriptions(self):
        triggers = ["is this real?", "verify this", "is this authentic?"]
        for op_id in ("verify_product", "verify_credential", "verify_claim"):
            desc = self.ops[op_id][2].get("description", "")
            self.assertTrue(any(p in desc for p in triggers),
                            f"{op_id} description lacks trigger phrasing")

    def test_matches_api_spec_subset(self):
        # Every API-backed plugin operation must exist in the API's own
        # openapi.yaml with the same path, method, and semantics. The API
        # spec puts the /v1 prefix in its servers' base URL, so normalize.
        api_paths = self.api["paths"]
        for op_id, (path, method, api_op) in EXPECTED_OPS.items():
            if api_op is None:
                continue
            api_path = path[3:] if path.startswith("/v1") else path
            self.assertIn(api_path, api_paths,
                          f"{op_id}: path missing in API spec")
            self.assertIn(method, api_paths[api_path],
                          f"{op_id}: method missing in API spec")
            self.assertEqual(api_paths[api_path][method]["operationId"],
                             api_op)

    def test_read_only_no_issuance(self):
        # The plugin must not expose attestation issuance: the only POST
        # allowed anywhere in the spec is /v1/claims/verify (a read-only
        # verification call), and /v1/attestations must be absent.
        self.assertNotIn("/v1/attestations", self.spec["paths"])
        post_paths = [p for p, ms in self.spec["paths"].items()
                      if "post" in ms]
        self.assertEqual(post_paths, ["/v1/claims/verify"],
                         "the only POST allowed is the read-only claim verify")

    def test_404_shapes_are_fail_closed(self):
        for op_id in ("verify_product", "verify_credential", "verify_agent"):
            path, method, _ = self.ops[op_id]
            responses = self.spec["paths"][path][method]["responses"]
            ref = str(responses.get("404", ""))
            self.assertIn("UnknownVerdict", ref,
                          f"{op_id}: 404 must use the UnknownVerdict shape")


class TestYamlSubsetParser(unittest.TestCase):
    def test_rejects_tabs(self):
        with self.assertRaises(YAMLError):
            parse("a:\n\tb: 1\n")

    def test_rejects_garbage(self):
        with self.assertRaises(YAMLError):
            parse("just a string\n: broken\n")
