"""Lambda v5 adapter: the hosted MCP endpoint at POST /v1/mcp.

The endpoint reuses the published MCP server implementation
(npc_verify_mcp) behind an adapter intercept: App.dispatch
canonicalizes + signs every body as JSON, so JSON-RPC envelopes are
answered before dispatch and stay byte-plain, while the tools
themselves call the REST app in-process through the bridge
(mcp_bridge.DispatchClient) and keep full Ed25519 response
verification. These tests assemble the v5 package layout exactly as
build_lambda_v5.py stages it, import the packaged adapter, and
invoke its handler -- no AWS, no network.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
API_DIR = os.path.dirname(TESTS_DIR)
PROJECT = os.path.dirname(API_DIR)
LAMBDA_V5 = os.path.join(API_DIR, "serverless", "lambda_v5")
SPEC_SRC = os.path.join(
    PROJECT, "plugins", "copilot", "npc-verify-openapi.yaml")
V1_ZIP = os.path.join(
    PROJECT, "api-deploy", "npc-verify-api-lambda-2026-10-14.zip")
MCP_PATH = "/v1/mcp"
SEED_RECORD_PATH = os.path.join(LAMBDA_V5, "records_seed.json")
SOURCE_IP = "203.0.113.9"

# The repo's MCP package, for the tools/list parity projection.
sys.path.insert(0, os.path.join(PROJECT, "plugins", "mcp"))
from npc_verify_mcp.tools import TOOLS as STDIO_TOOLS  # noqa: E402


def _event(method, path, body=None, raw=None, headers=None):
    if raw is not None:
        body_text = raw
    elif body is not None:
        body_text = json.dumps(body)
    else:
        body_text = None
    return {
        "httpMethod": method,
        "path": path,
        "headers": headers or {},
        "body": body_text,
        "isBase64Encoded": False,
        "requestContext": {"identity": {"sourceIp": SOURCE_IP}},
    }


def _rpc(msg_id, method, params=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if msg_id is not None:
        msg["id"] = msg_id
    if params is not None:
        msg["params"] = params
    return msg


def _init_params(version=None):
    params = {"capabilities": {},
              "clientInfo": {"name": "route-test", "version": "0"}}
    if version is not None:
        params["protocolVersion"] = version
    return params


class TestMcpRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_lambda_v5_test_")
        pkg = os.path.join(cls.tmp, "pkg")
        pkgs = os.path.join(pkg, "api_pkgs")
        os.makedirs(pkgs)
        shutil.copy2(os.path.join(LAMBDA_V5, "api.py"), pkg)
        shutil.copy2(SPEC_SRC, os.path.join(pkg, "npc-verify-openapi.yaml"))
        shutil.copy2(os.path.join(LAMBDA_V5, "fullapp.py"), pkgs)
        shutil.copy2(os.path.join(LAMBDA_V5, "records_seed.json"), pkgs)
        shutil.copy2(os.path.join(LAMBDA_V5, "mcp_bridge.py"), pkgs)
        shutil.copy2(os.path.join(API_DIR, "serverless", "seed_demo.py"),
                     pkgs)
        for src_abs in (os.path.join(PROJECT, "api", "npc_verify"),
                        os.path.join(PROJECT, "memory", "npc_memory"),
                        os.path.join(PROJECT, "plugins", "mcp",
                                     "npc_verify_mcp")):
            shutil.copytree(
                src_abs, os.path.join(pkgs, os.path.basename(src_abs)),
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        with zipfile.ZipFile(V1_ZIP) as zf:
            demo_env = zf.read("api_pkgs/demo_env.json")
        with open(os.path.join(pkgs, "demo_env.json"), "wb") as f:
            f.write(demo_env)
        cls.demo_verifier_key = json.loads(
            demo_env.decode("utf-8"))["demo_verifier_key"]

        cls._saved_data_dir = os.environ.get("NPC_DATA_DIR")
        os.environ["NPC_DATA_DIR"] = os.path.join(cls.tmp, "data")
        spec = importlib.util.spec_from_file_location(
            "npc_lambda_v5_api", os.path.join(pkg, "api.py"))
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)
        cls.pkg = pkg
        cls.pkgs = pkgs

        with open(SEED_RECORD_PATH, encoding="utf-8") as f:
            cls.seed_record = json.load(f)[0]

    @classmethod
    def tearDownClass(cls):
        if cls._saved_data_dir is None:
            os.environ.pop("NPC_DATA_DIR", None)
        else:
            os.environ["NPC_DATA_DIR"] = cls._saved_data_dir
        # Evict every module this class loaded from the assembled
        # package (fullapp, mcp_bridge, packaged submodules) so other
        # packaged-layout tests (test_spec_route) import their own
        # copies instead of inheriting this class's temp paths.
        for name, mod in list(sys.modules.items()):
            mod_file = getattr(mod, "__file__", None) or ""
            if mod_file.startswith(cls.tmp):
                del sys.modules[name]
        sys.path[:] = [p for p in sys.path
                       if not p.startswith(cls.tmp)]
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- helpers --------------------------------------------------------
    def post_rpc(self, msg):
        return self.api.handler(_event("POST", MCP_PATH, body=msg), None)

    def call_tool(self, name, arguments):
        r = self.post_rpc(_rpc(7, "tools/call",
                               {"name": name, "arguments": arguments}))
        self.assertEqual(r["statusCode"], 200, r["body"][:200])
        return json.loads(r["body"])["result"]

    # -- initialize / negotiation ---------------------------------------
    def test_initialize_negotiates_each_supported_version(self):
        for version in ("2025-06-18", "2025-03-26", "2024-11-05"):
            r = self.post_rpc(_rpc(1, "initialize",
                                   _init_params(version)))
            self.assertEqual(r["statusCode"], 200)
            result = json.loads(r["body"])["result"]
            self.assertEqual(result["protocolVersion"], version)

    def test_initialize_unknown_version_gets_newest_supported(self):
        r = self.post_rpc(_rpc(1, "initialize",
                               _init_params("2099-01-01")))
        result = json.loads(r["body"])["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")

    def test_initialize_missing_version_gets_newest_supported(self):
        r = self.post_rpc(_rpc(1, "initialize", _init_params()))
        result = json.loads(r["body"])["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")

    def test_initialize_shape(self):
        r = self.post_rpc(_rpc(1, "initialize",
                               _init_params("2025-06-18")))
        result = json.loads(r["body"])["result"]
        self.assertEqual(result["serverInfo"]["name"], "npc-verify")
        self.assertIn("tools", result["capabilities"])

    # -- tools/list -------------------------------------------------------
    def test_tools_list_parity_with_stdio_server(self):
        r = self.post_rpc(_rpc(2, "tools/list"))
        self.assertEqual(r["statusCode"], 200)
        hosted = json.loads(r["body"])["result"]["tools"]
        expected = [{"name": t["name"],
                     "title": t["title"],
                     "description": t["description"],
                     "inputSchema": t["inputSchema"],
                     "annotations": t["annotations"]}
                    for t in STDIO_TOOLS]
        self.assertEqual(hosted, expected)
        self.assertEqual([t["name"] for t in hosted],
                         ["verify_claim", "verify_credential",
                          "verify_product", "verify_agent",
                          "register_agent", "register_content",
                          "explain_verification"])

    def test_tools_list_annotations_explicit_booleans(self):
        # OpenAI's plugin tool scan requires explicit boolean values
        # for readOnlyHint, destructiveHint, and openWorldHint on
        # every tool; tools without them stay "Not live" (portal
        # finding, 2026-10-15). The five lookup tools are pure reads
        # against the NPC registry (read-only, non-destructive,
        # closed-world). The two registration tools create a record,
        # so they are truthfully not read-only; register_content
        # also fetches a caller-supplied URL at intake, so it is
        # open-world too. Creation overwrites and deletes nothing,
        # so neither registration tool is destructive.
        r = self.post_rpc(_rpc(2, "tools/list"))
        self.assertEqual(r["statusCode"], 200)
        hosted = json.loads(r["body"])["result"]["tools"]
        self.assertEqual(len(hosted), 7)
        lookup = {"readOnlyHint": True,
                  "destructiveHint": False,
                  "openWorldHint": False}
        expected = {
            "verify_claim": lookup,
            "verify_credential": lookup,
            "verify_product": lookup,
            "verify_agent": lookup,
            "explain_verification": lookup,
            "register_agent": {"readOnlyHint": False,
                               "destructiveHint": False,
                               "openWorldHint": False},
            "register_content": {"readOnlyHint": False,
                                 "destructiveHint": False,
                                 "openWorldHint": True},
        }
        for t in hosted:
            ann = t.get("annotations")
            self.assertIsInstance(ann, dict, t["name"])
            self.assertEqual(ann, expected[t["name"]], t["name"])
            for key in expected[t["name"]]:
                self.assertIs(type(ann[key]), bool,
                              f"{t['name']}.{key} must be a boolean")

    def test_tools_list_titles_present(self):
        # Anthropic's Connectors Directory review requires every tool
        # to carry a human-readable `title` alongside the annotation
        # hints; the portal flags tools missing one (submission
        # checklist + review criteria, read 2026-10-15).
        r = self.post_rpc(_rpc(2, "tools/list"))
        self.assertEqual(r["statusCode"], 200)
        hosted = json.loads(r["body"])["result"]["tools"]
        self.assertEqual(len(hosted), 7)
        expected_titles = {
            "verify_claim": "Verify a claim",
            "verify_credential": "Verify a credential",
            "verify_product": "Verify a product",
            "verify_agent": "Verify an agent",
            "register_agent": "Register an agent",
            "register_content": "Register content",
            "explain_verification": "Explain a verification result",
        }
        for t in hosted:
            self.assertEqual(t.get("title"),
                             expected_titles[t["name"]], t["name"])

    # -- tools/call round trips -------------------------------------------
    def test_tools_call_verify_product_demo(self):
        result = self.call_tool("verify_product",
                                {"tag_id": "demo-tag-001"})
        self.assertNotIn("isError", result)
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(payload["tag_id"], "demo-tag-001")
        self.assertEqual(payload["status"], "authentic")

    def test_tools_call_verify_credential_demo(self):
        result = self.call_tool("verify_credential",
                                {"credential_id": "demo-cred-001"})
        self.assertNotIn("isError", result)
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(payload["id"], "demo-cred-001")
        self.assertEqual(payload["status"], "valid")

    def test_tools_call_verify_agent_demo(self):
        result = self.call_tool("verify_agent",
                                {"agent_id": "demo-agent-001"})
        self.assertNotIn("isError", result)
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(payload["verdict"], "verified")

    def test_tools_call_verify_claim_demo(self):
        result = self.call_tool(
            "verify_claim",
            {"claim_text": "the product shipped on demo date"})
        self.assertNotIn("isError", result)
        payload = json.loads(result["content"][0]["text"])
        self.assertTrue(payload["matched"])
        self.assertEqual(payload["attestation"]["id"],
                         "att_demo_claim_001")

    def test_tools_call_explain_verification(self):
        result = self.call_tool("explain_verification", {})
        self.assertNotIn("isError", result)
        self.assertIn("Verified by NPC",
                      result["content"][0]["text"])

    def test_seed_record_resolves_through_the_bridge(self):
        # The recovered production record (records_seed.json) is a
        # registry record: on the DynamoDB backend fullapp restores it
        # put-if-absent; this assembled layout uses the SQLite store,
        # so install it through the store's own append-only path,
        # exactly as a live registration lands.
        store = self.api.APP.store
        if store.get_registration(self.seed_record["record_id"]) is None:
            store.add_registration(self.seed_record,
                                   "seed@npclabs.xyz", "")
        # The REST resolution path serves it byte-identical.
        r = self.api.handler(
            _event("GET", f"/v1/records/{self.seed_record['record_id']}"),
            None)
        self.assertEqual(r["statusCode"], 200)
        self.assertEqual(json.loads(r["body"]), self.seed_record)
        # And the hosted MCP stack resolves it through the very seam
        # the tools use: a DispatchClient over this app's dispatch,
        # with Ed25519 response verification enforced by the client.
        bridge_spec = importlib.util.spec_from_file_location(
            "npc_v5_mcp_bridge", os.path.join(self.pkgs, "mcp_bridge.py"))
        bridge = importlib.util.module_from_spec(bridge_spec)
        bridge_spec.loader.exec_module(bridge)
        client = bridge.DispatchClient(self.api.APP.dispatch,
                                       self.demo_verifier_key)
        got = client.request(
            "GET", f"/v1/records/{self.seed_record['record_id']}")
        self.assertEqual(got, self.seed_record)
        self.assertEqual(got["signature"],
                         self.seed_record["signature"])

    def test_tools_call_unknown_subject_fails_closed(self):
        result = self.call_tool("verify_product",
                                {"tag_id": "tag-never-registered"})
        # A successful JSON-RPC result whose verdict is unknown:
        # never a JSON-RPC error, never a guess.
        self.assertNotIn("isError", result)
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(payload["verdict"], "unknown")
        self.assertEqual(payload["subject_id"], "tag-never-registered")

    def test_tools_call_missing_argument_is_error_result(self):
        result = self.call_tool("verify_product", {})
        self.assertTrue(result.get("isError"))
        self.assertIn("tag_id", result["content"][0]["text"])

    def test_unknown_tool_returns_invalid_params(self):
        r = self.post_rpc(_rpc(3, "tools/call",
                               {"name": "verify_everything",
                                "arguments": {}}))
        self.assertEqual(r["statusCode"], 200)
        self.assertEqual(json.loads(r["body"])["error"]["code"], -32602)

    def test_unknown_method_returns_method_not_found(self):
        r = self.post_rpc(_rpc(3, "tools/dance"))
        self.assertEqual(r["statusCode"], 200)
        self.assertEqual(json.loads(r["body"])["error"]["code"], -32601)

    def test_hosted_results_match_stdio_results(self):
        # Parity (scope risk R6): the same McpServer + bridge client,
        # driven directly (the stdio server's handle path), must
        # produce byte-identical tool results to the HTTP endpoint
        # against identical app state.
        bridge_spec = importlib.util.spec_from_file_location(
            "npc_v5_mcp_bridge_parity",
            os.path.join(self.pkgs, "mcp_bridge.py"))
        bridge = importlib.util.module_from_spec(bridge_spec)
        bridge_spec.loader.exec_module(bridge)
        direct = bridge.build_mcp_server(self.api.APP.dispatch,
                                         self.demo_verifier_key)
        for arguments in ({"tag_id": "demo-tag-001"},
                          {"tag_id": "tag-never-registered"}):
            msg = _rpc(11, "tools/call",
                       {"name": "verify_product", "arguments": arguments})
            direct_reply = direct.handle(msg)
            hosted_reply = json.loads(self.post_rpc(msg)["body"])
            self.assertEqual(hosted_reply["result"],
                             direct_reply["result"])

    # -- transport shape ----------------------------------------------------
    def test_malformed_json_returns_parse_error(self):
        r = self.api.handler(
            _event("POST", MCP_PATH, raw="{not json"), None)
        self.assertEqual(r["statusCode"], 400)
        self.assertEqual(json.loads(r["body"])["error"]["code"], -32700)

    def test_non_object_body_returns_invalid_request(self):
        r = self.api.handler(_event("POST", MCP_PATH, raw="42"), None)
        self.assertEqual(r["statusCode"], 400)
        self.assertEqual(json.loads(r["body"])["error"]["code"], -32600)

    def test_array_body_returns_invalid_request(self):
        r = self.api.handler(
            _event("POST", MCP_PATH,
                   raw=json.dumps([_rpc(1, "tools/list")])), None)
        self.assertEqual(r["statusCode"], 400)
        self.assertEqual(json.loads(r["body"])["error"]["code"], -32600)

    def test_oversized_body_returns_400(self):
        big = " " * (self.api.MCP_MAX_BODY + 1)
        r = self.api.handler(_event("POST", MCP_PATH, raw=big), None)
        self.assertEqual(r["statusCode"], 400)
        self.assertEqual(json.loads(r["body"])["error"]["code"], -32600)

    def test_notification_returns_202_empty(self):
        r = self.post_rpc(_rpc(None, "notifications/initialized"))
        self.assertEqual(r["statusCode"], 202)
        self.assertEqual(r["body"], "")

    def test_get_and_delete_return_405(self):
        for method in ("GET", "DELETE", "PUT"):
            r = self.api.handler(_event(method, MCP_PATH), None)
            self.assertEqual(r["statusCode"], 405, method)
            self.assertEqual(r["headers"].get("Allow"), "POST")

    def test_options_preflight_still_204_for_mcp_path(self):
        r = self.api.handler(_event("OPTIONS", MCP_PATH), None)
        self.assertEqual(r["statusCode"], 204)

    def test_mcp_responses_carry_cors_including_mcp_headers(self):
        r = self.post_rpc(_rpc(2, "tools/list"))
        self.assertEqual(
            r["headers"].get("Access-Control-Allow-Origin"), "*")
        allow = r["headers"].get("Access-Control-Allow-Headers", "")
        for name in ("Mcp-Session-Id", "Mcp-Protocol-Version",
                     "Last-Event-Id"):
            self.assertIn(name, allow)

    def test_mcp_envelope_is_not_signed(self):
        # The JSON-RPC envelope stays byte-plain: dispatch never sees
        # it, so no X-NPC-Signature header rides on MCP responses.
        # (The trust property lives inside the tool results, which
        # are built from signature-verified REST payloads.)
        r = self.post_rpc(_rpc(2, "tools/list"))
        self.assertNotIn("X-NPC-Signature", r["headers"])
        self.assertEqual(r["headers"].get("Content-Type"),
                         "application/json")

    def test_rest_surface_undisturbed(self):
        h = self.api.handler(_event("GET", "/v1/health"), None)
        self.assertEqual(h["statusCode"], 200)
        self.assertEqual(json.loads(h["body"]).get("status"), "ok")
        s = self.api.handler(
            _event("GET", "/v1/npc-verify-openapi.yaml"), None)
        self.assertEqual(s["statusCode"], 200)
        with open(SPEC_SRC, "rb") as f:
            self.assertEqual(s["body"].encode("utf-8"), f.read())


if __name__ == "__main__":
    unittest.main()
