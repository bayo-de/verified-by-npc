"""Lambda v4 adapter: the Copilot OpenAPI spec route.

The Copilot plugin manifest (npc-verify-apiplugin.json) declares
https://api.npclabs.xyz/v1/npc-verify-openapi.yaml and Microsoft
fetches that URL live. App.dispatch canonicalizes + signs every body
as JSON, so the spec is served by the Lambda adapter itself, from the
bundled file, before dispatch. These tests assemble the v4 package
layout exactly as build_lambda_v4.py stages it, import the packaged
adapter, and invoke its handler — no AWS, no network.
"""
import hashlib
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
LAMBDA_V4 = os.path.join(API_DIR, "serverless", "lambda_v4")
SPEC_SRC = os.path.join(
    PROJECT, "plugins", "copilot", "npc-verify-openapi.yaml")
V1_ZIP = os.path.join(
    PROJECT, "api-deploy", "npc-verify-api-lambda-2026-10-14.zip")
SPEC_PATH = "/v1/npc-verify-openapi.yaml"


def _event(method, path, headers=None):
    return {
        "httpMethod": method,
        "path": path,
        "headers": headers or {},
        "body": None,
        "isBase64Encoded": False,
        "requestContext": {"identity": {"sourceIp": "203.0.113.9"}},
    }


class TestSpecRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_lambda_v4_test_")
        pkg = os.path.join(cls.tmp, "pkg")
        pkgs = os.path.join(pkg, "api_pkgs")
        os.makedirs(pkgs)
        shutil.copy2(os.path.join(LAMBDA_V4, "api.py"), pkg)
        shutil.copy2(SPEC_SRC, os.path.join(pkg, "npc-verify-openapi.yaml"))
        shutil.copy2(os.path.join(LAMBDA_V4, "fullapp.py"), pkgs)
        shutil.copy2(os.path.join(LAMBDA_V4, "records_seed.json"), pkgs)
        shutil.copy2(os.path.join(API_DIR, "serverless", "seed_demo.py"),
                     pkgs)
        for src_name in (os.path.join("api", "npc_verify"),
                         os.path.join("memory", "npc_memory")):
            shutil.copytree(
                os.path.join(PROJECT, src_name),
                os.path.join(pkgs, os.path.basename(src_name)),
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        with zipfile.ZipFile(V1_ZIP) as zf:
            demo_env = zf.read("api_pkgs/demo_env.json")
        with open(os.path.join(pkgs, "demo_env.json"), "wb") as f:
            f.write(demo_env)

        cls._saved_data_dir = os.environ.get("NPC_DATA_DIR")
        os.environ["NPC_DATA_DIR"] = os.path.join(cls.tmp, "data")
        spec = importlib.util.spec_from_file_location(
            "npc_lambda_v4_api", os.path.join(pkg, "api.py"))
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

        with open(SPEC_SRC, "rb") as f:
            cls.spec_bytes = f.read()

    @classmethod
    def tearDownClass(cls):
        if cls._saved_data_dir is None:
            os.environ.pop("NPC_DATA_DIR", None)
        else:
            os.environ["NPC_DATA_DIR"] = cls._saved_data_dir
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_spec_route_returns_200(self):
        r = self.api.handler(_event("GET", SPEC_PATH), None)
        self.assertEqual(r["statusCode"], 200)
        # CORS rides along like every other adapter response.
        self.assertEqual(
            r["headers"].get("Access-Control-Allow-Origin"), "*")
        # And the app behind the adapter is undisturbed.
        h = self.api.handler(_event("GET", "/v1/health"), None)
        self.assertEqual(h["statusCode"], 200)
        self.assertEqual(json.loads(h["body"]).get("status"), "ok")

    def test_spec_route_serves_exact_source_bytes(self):
        r = self.api.handler(_event("GET", SPEC_PATH), None)
        served = r["body"].encode("utf-8")
        self.assertEqual(
            hashlib.sha256(served).hexdigest(),
            hashlib.sha256(self.spec_bytes).hexdigest())
        self.assertEqual(served, self.spec_bytes)
        self.assertEqual(self.api.SPEC_BYTES, self.spec_bytes)
        self.assertEqual(
            int(r["headers"]["Content-Length"]), len(self.spec_bytes))

    def test_spec_route_content_type_is_yaml(self):
        r = self.api.handler(_event("GET", SPEC_PATH), None)
        ctype = r["headers"].get("Content-Type", "")
        self.assertIn("yaml", ctype.lower())

    def test_spec_route_is_public_no_key_required(self):
        # No headers at all: no Authorization, no API key anywhere.
        r = self.api.handler(_event("GET", SPEC_PATH, headers={}), None)
        self.assertEqual(r["statusCode"], 200)
        self.assertEqual(r["body"].encode("utf-8"), self.spec_bytes)
        # A bogus key changes nothing: the route never consults auth.
        r2 = self.api.handler(
            _event("GET", SPEC_PATH,
                   headers={"authorization": "Bearer not-a-real-key"}),
            None)
        self.assertEqual(r2["statusCode"], 200)
        self.assertEqual(r2["body"], r["body"])


if __name__ == "__main__":
    unittest.main()
