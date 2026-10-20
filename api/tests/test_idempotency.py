"""Idempotency-Key support on the minting POSTs (audit item D4).

POST /v1/attestations and POST /v1/register/* mint a fresh record per
call, so a client retry used to duplicate. With an Idempotency-Key
header, the first successful response is stored in the store layer
and replayed for the same key + same body; the same key with a
different body is a 409; no header keeps the old behavior exactly.
"""
import json
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from tests.helpers import ApiTestCase  # noqa: E402

SHA_LOCATOR = "sha256:" + "cd" * 32


def _att_payload(**over):
    body = {
        "subject_type": "claim",
        "subject_id": "claim:idem-1",
        "verdict": "verified",
        "scope": {"domain": "idem"},
        "tested_at": "2026-10-05T00:00:00+00:00",
        "findings_summary": "Idempotency test issuance.",
    }
    body.update(over)
    return body


class IdempotencyHttpTest(ApiTestCase):
    def post_keyed(self, path, body, key=None, idem=None):
        headers = {"Idempotency-Key": idem} if idem else None
        return self.request("POST", path, body=body, key=key,
                            headers=headers)

    def attestation_count(self):
        row = self.app.store._fetchone(
            "SELECT COUNT(*) AS n FROM attestations")
        return row["n"]

    # -- attestations -----------------------------------------------------
    def test_attestation_replay_returns_original(self):
        before = self.attestation_count()
        s1, _, d1 = self.post_keyed("/v1/attestations", _att_payload(),
                                    key=self.issuer_key, idem="att-k1")
        self.assertEqual(s1, 201)
        first = json.loads(d1)
        s2, _, d2 = self.post_keyed("/v1/attestations", _att_payload(),
                                    key=self.issuer_key, idem="att-k1")
        self.assertEqual(s2, 201)
        self.assertEqual(json.loads(d2), first)
        self.assertEqual(self.attestation_count(), before + 1)

    def test_attestation_same_key_different_body_conflicts(self):
        s1, _, _ = self.post_keyed("/v1/attestations", _att_payload(),
                                   key=self.issuer_key, idem="att-k2")
        self.assertEqual(s1, 201)
        s2, _, d2 = self.post_keyed(
            "/v1/attestations",
            _att_payload(findings_summary="A different body."),
            key=self.issuer_key, idem="att-k2")
        self.assertEqual(s2, 409)
        self.assertEqual(json.loads(d2)["error"], "conflict")

    def test_attestation_no_header_still_mints_each_time(self):
        _, _, d1 = self.post("/v1/attestations", _att_payload(),
                             key=self.issuer_key)
        _, _, d2 = self.post("/v1/attestations", _att_payload(),
                             key=self.issuer_key)
        self.assertNotEqual(json.loads(d1)["id"], json.loads(d2)["id"])

    def test_attestation_different_key_mints_again(self):
        _, _, d1 = self.post_keyed("/v1/attestations", _att_payload(),
                                   key=self.issuer_key, idem="att-k3a")
        _, _, d2 = self.post_keyed("/v1/attestations", _att_payload(),
                                   key=self.issuer_key, idem="att-k3b")
        self.assertNotEqual(json.loads(d1)["id"], json.loads(d2)["id"])

    def test_failed_validation_does_not_burn_the_key(self):
        bad = {"subject_type": "claim"}  # missing required fields
        s1, _, _ = self.post_keyed("/v1/attestations", bad,
                                   key=self.issuer_key, idem="att-k4")
        self.assertEqual(s1, 422)
        s2, _, _ = self.post_keyed("/v1/attestations", _att_payload(),
                                   key=self.issuer_key, idem="att-k4")
        self.assertEqual(s2, 201)

    def test_mapping_is_persisted_in_the_store(self):
        s, _, d = self.post_keyed("/v1/attestations", _att_payload(),
                                  key=self.issuer_key, idem="att-k5")
        self.assertEqual(s, 201)
        stored = self.app.store.get_idempotency(
            "att-k5", "POST /v1/attestations")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["status"], 201)
        self.assertEqual(stored["response"]["id"], json.loads(d)["id"])
        self.assertEqual(len(stored["body_hash"]), 64)

    # -- registrations ------------------------------------------------------
    def _register_body(self, email, **over):
        body = {
            "title": "Idempotency test story",
            "kind": "text",
            "locator": SHA_LOCATOR,
            "creator_name": "Idem Maker",
            "creator_email": email,
        }
        body.update(over)
        return body

    def test_register_content_replay_mints_once(self):
        body = self._register_body("idem-content@example.com")
        s1, _, d1 = self.post_keyed("/v1/register/content", body,
                                    idem="reg-k1")
        self.assertEqual(s1, 201)
        first = json.loads(d1)
        s2, _, d2 = self.post_keyed("/v1/register/content", body,
                                    idem="reg-k1")
        self.assertEqual(s2, 201)
        self.assertEqual(json.loads(d2)["record_id"], first["record_id"])
        # exactly one registration counted for this email: the replay
        # did not mint, so it did not consume cap budget either
        n = self.app.store.count_registrations_since(
            "email", "idem-content@example.com",
            "2000-01-01T00:00:00+00:00")
        self.assertEqual(n, 1)

    def test_register_content_same_key_different_body_conflicts(self):
        body = self._register_body("idem-conflict@example.com")
        s1, _, _ = self.post_keyed("/v1/register/content", body,
                                   idem="reg-k2")
        self.assertEqual(s1, 201)
        s2, _, d2 = self.post_keyed(
            "/v1/register/content",
            self._register_body("idem-conflict@example.com",
                                title="Another title"),
            idem="reg-k2")
        self.assertEqual(s2, 409)
        self.assertEqual(json.loads(d2)["error"], "conflict")

    def test_register_agent_replay_mints_once(self):
        body = {
            "agent_name": "Idem Agent",
            "owner_name": "Idem Owner",
            "owner_email": "idem-agent@example.com",
            "description": "An agent registered twice by retry.",
        }
        s1, _, d1 = self.post_keyed("/v1/register/agent", body,
                                    idem="reg-k3")
        self.assertEqual(s1, 201)
        s2, _, d2 = self.post_keyed("/v1/register/agent", body,
                                    idem="reg-k3")
        self.assertEqual(s2, 201)
        self.assertEqual(json.loads(d2)["record_id"],
                         json.loads(d1)["record_id"])

    def test_same_key_on_different_routes_is_independent(self):
        s1, _, _ = self.post_keyed(
            "/v1/register/content",
            self._register_body("idem-routes@example.com"),
            idem="shared-key")
        self.assertEqual(s1, 201)
        s2, _, _ = self.post_keyed("/v1/attestations", _att_payload(),
                                   key=self.issuer_key, idem="shared-key")
        self.assertEqual(s2, 201)


class IdempotencyDynamoStoreTest(unittest.TestCase):
    """The DynamoDB backend persists the mapping the same way."""

    @classmethod
    def setUpClass(cls):
        fake_dir = os.path.join(BASE, "serverless", "lambda_v3",
                                "fake_boto3")
        if fake_dir not in sys.path:
            sys.path.insert(0, fake_dir)

    def setUp(self):
        import boto3 as fake_boto3
        from npc_verify.ddb_store import DynamoDBStore
        self.store = DynamoDBStore(
            table=fake_boto3.FakeTable("npc-verify-store-idem"))

    def test_put_get_round_trip_and_race(self):
        self.assertIsNone(self.store.get_idempotency("k", "POST /x"))
        self.assertTrue(self.store.put_idempotency(
            "k", "POST /x", "hash1", 201, {"id": "att_1"},
            "2026-10-15T00:00:00+00:00"))
        got = self.store.get_idempotency("k", "POST /x")
        self.assertEqual(got["body_hash"], "hash1")
        self.assertEqual(got["status"], 201)
        self.assertEqual(got["response"], {"id": "att_1"})
        # a second put for the same (key, route) loses the race
        self.assertFalse(self.store.put_idempotency(
            "k", "POST /x", "hash2", 201, {"id": "att_2"},
            "2026-10-15T00:00:01+00:00"))
        # routes are independent namespaces for the same key
        self.assertIsNone(self.store.get_idempotency("k", "POST /y"))


if __name__ == "__main__":
    unittest.main()
