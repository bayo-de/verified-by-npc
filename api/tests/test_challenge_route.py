"""Lambda v5.1 adapter: the OpenAI Apps domain-verification
challenge at GET /.well-known/openai-apps-challenge.

Connecting the hosted MCP server in OpenAI's portal requires
serving a portal-issued token at that fixed domain-root path, and
the portal byte-compares the body. App.dispatch canonicalizes +
signs every body as JSON, so the adapter answers the route before
dispatch, from the NPC_OPENAI_APPS_CHALLENGE environment variable
(read at request time): set -> 200 with the token byte-exact and
unsigned; unset or empty -> 404, never a placeholder. These tests
assemble the v5.1 package layout exactly as build_lambda_v5_1.py
stages it, import the packaged adapter, and invoke its handler --
no AWS, no network.
"""
import contextlib
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
LAMBDA_V5_1 = os.path.join(API_DIR, "serverless", "lambda_v5_1")
SPEC_SRC = os.path.join(
    PROJECT, "plugins", "copilot", "npc-verify-openapi.yaml")
V1_ZIP = os.path.join(
    PROJECT, "api-deploy", "npc-verify-api-lambda-2026-10-14.zip")
CHALLENGE_PATH = "/.well-known/openai-apps-challenge"
CHALLENGE_ENV_VAR = "NPC_OPENAI_APPS_CHALLENGE"
# A token with the punctuation a portal-issued value may carry; the
# body must come back byte-for-byte whatever it contains.
TOKEN = "npc-apps-challenge_Token-0123.abcXYZ=="
SOURCE_IP = "203.0.113.9"


def _event(method, path, body=None, headers=None):
    return {
        "httpMethod": method,
        "path": path,
        "headers": headers or {},
        "body": body,
        "isBase64Encoded": False,
        "requestContext": {"identity": {"sourceIp": SOURCE_IP}},
    }


@contextlib.contextmanager
def _challenge_env(value):
    """Set the challenge env var (None = unset) for one test and
    restore whatever the outer environment had afterwards."""
    sentinel = object()
    old = os.environ.get(CHALLENGE_ENV_VAR, sentinel)
    if value is None:
        os.environ.pop(CHALLENGE_ENV_VAR, None)
    else:
        os.environ[CHALLENGE_ENV_VAR] = value
    try:
        yield
    finally:
        if old is sentinel:
            os.environ.pop(CHALLENGE_ENV_VAR, None)
        else:
            os.environ[CHALLENGE_ENV_VAR] = old


class TestChallengeRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_lambda_v5_1_test_")
        pkg = os.path.join(cls.tmp, "pkg")
        pkgs = os.path.join(pkg, "api_pkgs")
        os.makedirs(pkgs)
        shutil.copy2(os.path.join(LAMBDA_V5_1, "api.py"), pkg)
        shutil.copy2(SPEC_SRC, os.path.join(pkg, "npc-verify-openapi.yaml"))
        shutil.copy2(os.path.join(LAMBDA_V5_1, "fullapp.py"), pkgs)
        shutil.copy2(os.path.join(LAMBDA_V5_1, "records_seed.json"), pkgs)
        shutil.copy2(os.path.join(LAMBDA_V5_1, "mcp_bridge.py"), pkgs)
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

        cls._saved_data_dir = os.environ.get("NPC_DATA_DIR")
        os.environ["NPC_DATA_DIR"] = os.path.join(cls.tmp, "data")
        spec = importlib.util.spec_from_file_location(
            "npc_lambda_v5_1_api", os.path.join(pkg, "api.py"))
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)
        cls.pkg = pkg

    @classmethod
    def tearDownClass(cls):
        if cls._saved_data_dir is None:
            os.environ.pop("NPC_DATA_DIR", None)
        else:
            os.environ["NPC_DATA_DIR"] = cls._saved_data_dir
        # Evict every module this class loaded from the assembled
        # package (fullapp, mcp_bridge, packaged submodules) so other
        # packaged-layout tests (test_mcp_route, test_spec_route)
        # import their own copies instead of inheriting this class's
        # temp paths. Same eviction as test_mcp_route.
        for name, mod in list(sys.modules.items()):
            mod_file = getattr(mod, "__file__", None) or ""
            if mod_file.startswith(cls.tmp):
                del sys.modules[name]
        sys.path[:] = [p for p in sys.path
                       if not p.startswith(cls.tmp)]
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- the challenge itself -----------------------------------------
    def test_env_set_serves_token_byte_exact(self):
        with _challenge_env(TOKEN):
            r = self.api.handler(_event("GET", CHALLENGE_PATH), None)
        self.assertEqual(r["statusCode"], 200)
        # Byte-exact: no trailing newline added, nothing stripped.
        self.assertEqual(r["body"].encode("utf-8"),
                         TOKEN.encode("utf-8"))
        self.assertFalse(r["body"].endswith("\n"))
        self.assertEqual(r["headers"].get("Content-Type"),
                         "text/plain")
        self.assertEqual(r["headers"].get("Content-Length"),
                         str(len(TOKEN.encode("utf-8"))))
        # CORS rides along like every other adapter response.
        self.assertEqual(
            r["headers"].get("Access-Control-Allow-Origin"), "*")

    def test_env_unset_returns_404(self):
        with _challenge_env(None):
            r = self.api.handler(_event("GET", CHALLENGE_PATH), None)
        self.assertEqual(r["statusCode"], 404)
        self.assertEqual(r["body"], "")

    def test_env_empty_returns_404(self):
        with _challenge_env(""):
            r = self.api.handler(_event("GET", CHALLENGE_PATH), None)
        self.assertEqual(r["statusCode"], 404)
        self.assertEqual(r["body"], "")

    def test_challenge_response_is_not_signed(self):
        # The token is not an API payload: no X-NPC-Signature header
        # rides on it, and the body is the bare token, not a signed
        # JSON envelope.
        with _challenge_env(TOKEN):
            r = self.api.handler(_event("GET", CHALLENGE_PATH), None)
        self.assertNotIn("X-NPC-Signature", r["headers"])
        self.assertNotIn("X-NPC-Key-ID", r["headers"])

    def test_post_is_not_served_the_token(self):
        with _challenge_env(TOKEN):
            r = self.api.handler(
                _event("POST", CHALLENGE_PATH, body="{}"), None)
        self.assertNotEqual(r["statusCode"], 200)
        self.assertNotIn(TOKEN, r["body"])

    def test_near_miss_path_is_not_served_the_token(self):
        # Only the exact fixed path is the challenge: a trailing
        # slash falls through to dispatch and its fail-closed 404.
        with _challenge_env(TOKEN):
            r = self.api.handler(
                _event("GET", CHALLENGE_PATH + "/"), None)
        self.assertNotEqual(r["statusCode"], 200)
        self.assertNotIn(TOKEN, r["body"])

    def test_token_rotation_needs_no_reload(self):
        # The value is read at request time: a new value is served
        # by the already-imported adapter, and clearing it reverts
        # the route to 404.
        with _challenge_env("first-token"):
            r1 = self.api.handler(_event("GET", CHALLENGE_PATH), None)
        with _challenge_env("second-token"):
            r2 = self.api.handler(_event("GET", CHALLENGE_PATH), None)
        with _challenge_env(None):
            r3 = self.api.handler(_event("GET", CHALLENGE_PATH), None)
        self.assertEqual(r1["body"], "first-token")
        self.assertEqual(r2["body"], "second-token")
        self.assertEqual(r3["statusCode"], 404)

    # -- the rest of the v5.1 surface is undisturbed -------------------
    def test_rest_spec_and_mcp_surfaces_undisturbed(self):
        with _challenge_env(TOKEN):
            h = self.api.handler(_event("GET", "/v1/health"), None)
            s = self.api.handler(
                _event("GET", "/v1/npc-verify-openapi.yaml"), None)
            m = self.api.handler(
                _event("POST", "/v1/mcp",
                       body=json.dumps(
                           {"jsonrpc": "2.0", "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2025-06-18",
                                "capabilities": {},
                                "clientInfo": {"name": "challenge-test",
                                               "version": "0"}}})),
                None)
        self.assertEqual(h["statusCode"], 200)
        self.assertEqual(json.loads(h["body"]).get("status"), "ok")
        # REST responses stay signed even while the challenge does not.
        self.assertIn("X-NPC-Signature", h["headers"])
        self.assertEqual(s["statusCode"], 200)
        with open(SPEC_SRC, "rb") as f:
            self.assertEqual(s["body"].encode("utf-8"), f.read())
        self.assertEqual(m["statusCode"], 200)
        self.assertEqual(
            json.loads(m["body"])["result"]["protocolVersion"],
            "2025-06-18")


if __name__ == "__main__":
    unittest.main()
