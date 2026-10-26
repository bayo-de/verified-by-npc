"""Deployment-supplied signing key (audit item D1).

When NPC_SIGNING_SEED + NPC_SIGNING_KEY_ID are set in the Lambda
environment, the app signs responses with that key — loaded from the
environment, never bundled — while the bundled demo key stays
published in GET /v1/keys history, so both keys are listed and old
signatures stay verifiable. Unset, today's demo behavior is exact.

The env key used here is an obvious THROWAWAY test key, generated
for these tests only; it is not used anywhere else.
"""
import base64
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import keys as keys_mod  # noqa: E402
from npc_verify.models import utcnow_iso  # noqa: E402
from npc_verify.server import create_app  # noqa: E402
from tests.helpers import ApiTestCase  # noqa: E402

# Throwaway test-only key material. NOT a production key.
TEST_SEED = b"npc-TEST-env-signing-seed-000000"
assert len(TEST_SEED) == 32
TEST_SEED_B64 = base64.b64encode(TEST_SEED).decode()
TEST_KEY_ID = "npc-api_signing-test-env-000000"
TEST_ENV = {keys_mod.SIGNING_SEED_ENV: TEST_SEED_B64,
            keys_mod.SIGNING_KEY_ID_ENV: TEST_KEY_ID}


class EnvSigningKeyHttpTest(ApiTestCase):
    def test_env_key_signs_and_is_published_alongside_demo(self):
        _, _, d = self.get("/v1/health")
        demo_key_id = json.loads(d)["key_id"]
        self.assertNotEqual(demo_key_id, TEST_KEY_ID)

        with mock.patch.dict(os.environ, TEST_ENV):
            parsed = keys_mod.env_signing_key()
        self.assertEqual(parsed, (TEST_KEY_ID, TEST_SEED))
        self.app.keys.register_external_key(
            "api_signing", parsed[0], parsed[1], utcnow_iso())

        # responses now sign with the env key, verifiably
        status, headers, data = self.get("/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-NPC-Key-ID"), TEST_KEY_ID)
        body = self.check_signature(headers, data)
        self.assertEqual(body["key_id"], TEST_KEY_ID)

        # /v1/keys publishes BOTH: env key current, demo key in history
        _, _, d = self.get("/v1/keys")
        doc = json.loads(d)
        self.assertEqual(doc["api_signing"]["current"]["key_id"],
                         TEST_KEY_ID)
        history = {e["key_id"]: e["status"]
                   for e in doc["api_signing"]["history"]}
        self.assertEqual(history.get(demo_key_id), "retired")


class EnvSigningKeyUnitTest(unittest.TestCase):
    def _fresh_app(self):
        tmp = tempfile.mkdtemp(prefix="npc_envkey_")
        return create_app(os.path.join(tmp, "t.db"),
                          os.path.join(tmp, "keys"))

    def test_unset_env_reproduces_demo_behavior(self):
        self.assertIsNone(keys_mod.env_signing_key({}))
        app = self._fresh_app()
        code, headers, payload = app.dispatch("GET", "/v1/health",
                                              {}, b"")
        self.assertEqual(code, 200)
        active = app.keys.active_key_id("api_signing")
        self.assertEqual(json.loads(payload)["key_id"], active)
        self.assertEqual(headers["X-NPC-Key-ID"], active)
        doc = app.keys.publish()
        self.assertEqual(doc["api_signing"]["current"]["key_id"],
                         active)
        self.assertEqual(doc["api_signing"]["history"], [])

    def test_half_configured_env_fails_loudly(self):
        with self.assertRaises(ValueError):
            keys_mod.env_signing_key(
                {keys_mod.SIGNING_SEED_ENV: TEST_SEED_B64})
        with self.assertRaises(ValueError):
            keys_mod.env_signing_key(
                {keys_mod.SIGNING_KEY_ID_ENV: TEST_KEY_ID})

    def test_malformed_seed_fails_loudly(self):
        with self.assertRaises(ValueError):
            keys_mod.env_signing_key({
                keys_mod.SIGNING_SEED_ENV: "not!base64",
                keys_mod.SIGNING_KEY_ID_ENV: TEST_KEY_ID})
        short = base64.b64encode(b"too-short").decode()
        with self.assertRaises(ValueError):
            keys_mod.env_signing_key({
                keys_mod.SIGNING_SEED_ENV: short,
                keys_mod.SIGNING_KEY_ID_ENV: TEST_KEY_ID})

    def test_registration_is_idempotent_and_collision_loud(self):
        app = self._fresh_app()
        now = utcnow_iso()
        app.keys.register_external_key("api_signing", TEST_KEY_ID,
                                       TEST_SEED, now)
        self.assertEqual(app.keys.active_key_id("api_signing"),
                         TEST_KEY_ID)
        # cold start again with the same env key: no error, no dup
        app.keys.register_external_key("api_signing", TEST_KEY_ID,
                                       TEST_SEED, now)
        doc = app.keys.publish()
        ids = [doc["api_signing"]["current"]["key_id"]] + \
            [e["key_id"] for e in doc["api_signing"]["history"]]
        self.assertEqual(ids.count(TEST_KEY_ID), 1)
        # the same key id carrying a DIFFERENT seed is a config error
        other_seed = bytes([0x99] * 32)
        with self.assertRaises(ValueError):
            app.keys.register_external_key("api_signing", TEST_KEY_ID,
                                           other_seed, now)


if __name__ == "__main__":
    unittest.main()
