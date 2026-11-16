"""Deployment-supplied issuer key (Gate G2 cutover, W1).

The issuer counterpart of test_signing_key_env.py (audit item D1):
when NPC_ISSUER_SEED + NPC_ISSUER_KEY_ID are set in the Lambda
environment, records are signed with that key — loaded from the
environment, never bundled — while the bundled demo issuer key
stays published in GET /v1/keys as retired history, so demo-era
record signatures stay verifiable. Unset, today's demo behavior
is exact. Both pairs share one parser (keys.env_key) with
identical validation semantics.

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
from npc_verify.canonical import canonicalize  # noqa: E402
from npc_verify.models import utcnow_iso  # noqa: E402
from npc_verify.server import create_app  # noqa: E402
from tests.helpers import ApiTestCase  # noqa: E402

# Throwaway test-only key material. NOT a production key.
TEST_SEED = b"npc-TEST-env-issuer-seed-0000000"
assert len(TEST_SEED) == 32
TEST_SEED_B64 = base64.b64encode(TEST_SEED).decode()
TEST_KEY_ID = "npc-issuer-test-env-000000"
TEST_ENV = {keys_mod.ISSUER_SEED_ENV: TEST_SEED_B64,
            keys_mod.ISSUER_KEY_ID_ENV: TEST_KEY_ID}


def _issuers_by_id(doc):
    return {e["key_id"]: e["status"] for e in doc["issuers"]}


class EnvIssuerKeyHttpTest(ApiTestCase):
    def test_env_issuer_key_signs_records_and_is_published(self):
        _, _, d = self.get("/v1/keys")
        before = _issuers_by_id(json.loads(d))
        active_before = [k for k, s in before.items()
                         if s == "active"]
        self.assertEqual(len(active_before), 1)
        demo_issuer_id = active_before[0]
        self.assertNotEqual(demo_issuer_id, TEST_KEY_ID)

        with mock.patch.dict(os.environ, TEST_ENV):
            parsed = keys_mod.env_issuer_key()
        self.assertEqual(parsed, (TEST_KEY_ID, TEST_SEED))
        self.app.keys.register_external_key(
            "issuer", parsed[0], parsed[1], utcnow_iso())

        # records now mint under the env issuer key, verifiably:
        # the record's signature checks against the published key.
        status, _, d = self.post(
            "/v1/register/content",
            {"title": "Env issuer key test registration",
             "kind": "text",
             "locator": "sha256:" + "0" * 64,
             "creator_name": "NPC Labs (issuer env test)",
             "creator_email": "hello@npclabs.xyz"})
        self.assertEqual(status, 201, d)
        record = json.loads(d)
        self.assertEqual(record["key_id"], TEST_KEY_ID)
        sig = base64.b64decode(record["signature"])
        body = {k: v for k, v in record.items() if k != "signature"}
        self.assertTrue(self.app.keys.verify(
            TEST_KEY_ID, canonicalize(body), sig))

        # /v1/keys publishes BOTH issuers: env active, demo retired
        _, _, d = self.get("/v1/keys")
        issuers = _issuers_by_id(json.loads(d))
        self.assertEqual(issuers.get(TEST_KEY_ID), "active")
        self.assertEqual(issuers.get(demo_issuer_id), "retired")


class EnvIssuerKeyUnitTest(unittest.TestCase):
    def _fresh_app(self):
        tmp = tempfile.mkdtemp(prefix="npc_envissuer_")
        return create_app(os.path.join(tmp, "t.db"),
                          os.path.join(tmp, "keys"))

    def test_unset_env_returns_none(self):
        self.assertIsNone(keys_mod.env_issuer_key({}))
        # the issuer pair does not disturb the signing pair
        self.assertIsNone(keys_mod.env_signing_key({}))
        with mock.patch.dict(os.environ, TEST_ENV):
            self.assertEqual(keys_mod.env_issuer_key(),
                             (TEST_KEY_ID, TEST_SEED))

    def test_half_configured_env_fails_loudly(self):
        with self.assertRaises(ValueError):
            keys_mod.env_issuer_key(
                {keys_mod.ISSUER_SEED_ENV: TEST_SEED_B64})
        with self.assertRaises(ValueError):
            keys_mod.env_issuer_key(
                {keys_mod.ISSUER_KEY_ID_ENV: TEST_KEY_ID})

    def test_malformed_seed_fails_loudly(self):
        with self.assertRaises(ValueError):
            keys_mod.env_issuer_key({
                keys_mod.ISSUER_SEED_ENV: "not!base64",
                keys_mod.ISSUER_KEY_ID_ENV: TEST_KEY_ID})
        short = base64.b64encode(b"too-short").decode()
        with self.assertRaises(ValueError):
            keys_mod.env_issuer_key({
                keys_mod.ISSUER_SEED_ENV: short,
                keys_mod.ISSUER_KEY_ID_ENV: TEST_KEY_ID})

    def test_unsafe_key_id_fails_loudly(self):
        for bad_id in ("npc issuer/test", "npc-issuer test",
                       "npc-issuer/test", "x" * 129, ""):
            env = {keys_mod.ISSUER_SEED_ENV: TEST_SEED_B64,
                   keys_mod.ISSUER_KEY_ID_ENV: bad_id}
            if bad_id == "":
                # an empty id reads as unset-half: still an error
                # only when the seed is set; here both are "set"
                # from the parser's view via the seed, and the id
                # strips to empty, which is the half-set case.
                with self.assertRaises(ValueError):
                    keys_mod.env_issuer_key(env)
            else:
                with self.assertRaises(ValueError, msg=bad_id):
                    keys_mod.env_issuer_key(env)

    def test_shared_helper_keeps_signing_semantics(self):
        # env_key generalized the parser; the signing wrapper must
        # answer byte-identically on the signing pair.
        signing_env = {keys_mod.SIGNING_SEED_ENV: TEST_SEED_B64,
                       keys_mod.SIGNING_KEY_ID_ENV:
                           "npc-api_signing-test-env-000000"}
        self.assertEqual(
            keys_mod.env_key(keys_mod.SIGNING_SEED_ENV,
                             keys_mod.SIGNING_KEY_ID_ENV, signing_env),
            keys_mod.env_signing_key(signing_env))
        with self.assertRaises(ValueError):
            keys_mod.env_key(keys_mod.SIGNING_SEED_ENV,
                             keys_mod.SIGNING_KEY_ID_ENV,
                             {keys_mod.SIGNING_SEED_ENV: TEST_SEED_B64})

    def test_registration_is_idempotent_and_collision_loud(self):
        app = self._fresh_app()
        now = utcnow_iso()
        app.keys.register_external_key("issuer", TEST_KEY_ID,
                                       TEST_SEED, now)
        self.assertEqual(app.keys.active_key_id("issuer"),
                         TEST_KEY_ID)
        # cold start again with the same env key: no error, no dup
        app.keys.register_external_key("issuer", TEST_KEY_ID,
                                       TEST_SEED, now)
        doc = app.keys.publish()
        ids = [e["key_id"] for e in doc["issuers"]]
        self.assertEqual(ids.count(TEST_KEY_ID), 1)
        # the same key id carrying a DIFFERENT seed is a config error
        other_seed = bytes([0x77] * 32)
        with self.assertRaises(ValueError):
            app.keys.register_external_key("issuer", TEST_KEY_ID,
                                           other_seed, now)


if __name__ == "__main__":
    unittest.main()
