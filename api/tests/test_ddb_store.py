"""DynamoDB store: same interface as npc_verify.store.Store, proven
against a fake boto3 table (api/serverless/lambda_v3/fake_boto3).
No AWS calls anywhere in this file.
"""
import json
import os
import sys
import tempfile
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
FAKE_DIR = os.path.join(BASE, "serverless", "lambda_v3", "fake_boto3")
sys.path.insert(0, FAKE_DIR)

import boto3 as fake_boto3  # noqa: E402  (the fake; see FAKE_DIR)

from npc_verify.ddb_store import DynamoDBStore  # noqa: E402
from npc_verify.keys import KeyRegistry  # noqa: E402
from npc_verify.models import Attestation  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify.store import Store, make_store  # noqa: E402

SEED_PATH = os.path.join(BASE, "serverless", "lambda_v3",
                         "records_seed.json")
NOW = "2026-10-14T00:00:00+00:00"


def _att(**kw):
    base = dict(id="att_x1", subject_type="claim", subject_id="s1",
                verdict="verified", scope={}, tested_at=NOW,
                expires_at=None, findings_summary="ok",
                signature_b64="sig", key_id="kid")
    base.update(kw)
    return Attestation(**base)


def _record(record_id="reg_test_1", email="a@example.com"):
    return {"record_id": record_id, "kind": "content",
            "title": "T", "creator_name": "NPC Labs",
            "registered_at": "2026-10-14T12:00:00+00:00",
            "status": "registered_checks_pending", "signature": "c2ln"}


class TestDynamoDBStore(unittest.TestCase):
    def setUp(self):
        self.table = fake_boto3.FakeTable("npc-verify-store-test")
        self.store = DynamoDBStore(table=self.table)

    # -- registrations ---------------------------------------------------
    def test_registration_round_trip(self):
        rec = _record()
        self.store.add_registration(rec, "a@example.com", "203.0.113.9")
        got = self.store.get_registration("reg_test_1")
        self.assertEqual(got, rec)
        self.assertIsNone(self.store.get_registration("reg_missing"))

    def test_registration_email_accessor(self):
        # npc_verify.mailer's status-change hook reads the raw
        # address through this accessor; None when unknown or
        # after the retention purge blanks it.
        self.assertIsNone(self.store.registration_email("reg_nope"))
        self.store.add_registration(_record(), "a@example.com",
                                    "203.0.113.9")
        self.assertEqual(self.store.registration_email("reg_test_1"),
                         "a@example.com")
        self.store.purge_registration_emails("2999-01-01T00:00:00+00:00")
        self.assertIsNone(self.store.registration_email("reg_test_1"))

    def test_registration_counters(self):
        self.store.add_registration(_record("reg_1"), "a@example.com",
                                    "203.0.113.9")
        self.store.add_registration(_record("reg_2"), "a@example.com",
                                    "203.0.113.10")
        self.store.add_registration(_record("reg_3"), "b@example.com",
                                    "203.0.113.9")
        since = "2026-10-14T00:00:00+00:00"
        later = "2026-10-15T00:00:00+00:00"
        self.assertEqual(
            self.store.count_registrations_since(
                "email", "a@example.com", since), 2)
        self.assertEqual(
            self.store.count_registrations_since(
                "ip", "203.0.113.9", since), 2)
        self.assertEqual(
            self.store.count_registrations_since(
                "email", "a@example.com", later), 0)

    # -- api keys ----------------------------------------------------------
    def test_api_key_create_read(self):
        self.store.add_api_key("hash1", "demo-verifier", "verifier", 60,
                               NOW, company_id="co1")
        row = self.store.get_api_key("hash1")
        self.assertEqual(row["name"], "demo-verifier")
        self.assertEqual(row["role"], "verifier")
        self.assertEqual(row["per_minute"], 60)
        self.assertEqual(row["company_id"], "co1")
        self.assertEqual(row["revoked"], 0)
        self.assertIsNone(self.store.get_api_key("nope"))

    # -- key registry --------------------------------------------------------
    def test_key_registry_rotation_and_reactivation(self):
        s = self.store
        s.register_key("k1", "api_signing", "pub1", "2026-01-01T00:00:00+00:00")
        self.assertEqual(s.active_key_id("api_signing"), "k1")
        s.register_key("k2", "api_signing", "pub2", "2026-01-02T00:00:00+00:00")
        self.assertEqual(s.active_key_id("api_signing"), "k2")
        self.assertEqual(s.public_key_b64("k1"), "pub1")
        rows = {r["key_id"]: r for r in s.all_keys()}
        self.assertEqual(rows["k1"]["status"], "retired")
        self.assertEqual(rows["k1"]["retired_at"], "2026-01-02T00:00:00+00:00")
        self.assertEqual(rows["k2"]["status"], "active")
        self.assertTrue(s.activate_key("k1", "api_signing",
                                       "2026-01-03T00:00:00+00:00"))
        self.assertEqual(s.active_key_id("api_signing"), "k1")
        self.assertFalse(s.activate_key("ghost", "api_signing", NOW))

    # -- attestations ------------------------------------------------------
    def test_attestation_lifecycle(self):
        s = self.store
        s.add_attestation(_att(id="att_old",
                               created_at="2026-01-01T00:00:00+00:00",
                               claim_hash="h1"))
        s.add_attestation(_att(id="att_new",
                               created_at="2026-01-02T00:00:00+00:00",
                               claim_hash="h1"))
        self.assertEqual(s.get_attestation("att_new")["verdict"],
                         "verified")
        self.assertEqual(s.latest_attestation("claim", "s1")["id"],
                         "att_new")
        by_hash = s.attestations_by_claim_hash("h1")
        self.assertEqual([r["id"] for r in by_hash],
                         ["att_new", "att_old"])
        self.assertTrue(s.revoke_attestation(
            "att_new", "rev_1", "mistake", "sig", "kid",
            "2026-01-03T00:00:00+00:00"))
        self.assertEqual(s.get_attestation("att_new")["revoked"], 1)
        self.assertEqual(s.latest_attestation("claim", "s1")["id"],
                         "att_old")
        self.assertFalse(s.revoke_attestation(
            "att_new", "rev_2", "again", "sig", "kid",
            "2026-01-04T00:00:00+00:00"))
        self.assertFalse(s.revoke_attestation(
            "att_ghost", "rev_3", "ghost", "sig", "kid",
            "2026-01-04T00:00:00+00:00"))

    # -- PACT ----------------------------------------------------------------
    def test_pact_grant_receipt_audit_round_trip(self):
        s = self.store
        consent = {"record_id": "consent_1", "grant_id": "grant_1",
                   "granted_at": NOW, "scopes_granted": ["data:read"]}
        self.assertTrue(s.add_pact_consent(consent))
        self.assertFalse(s.add_pact_consent(consent))
        self.assertEqual(s.get_pact_consent("grant_1"), consent)
        self.assertEqual(s.get_pact_consent_by_record_id("consent_1"),
                         consent)
        self.assertIsNone(s.get_pact_consent("grant_missing"))

        e1 = {"grant_id": "grant_1", "seq": 1, "entry_hash": "h1",
              "kind": "grant"}
        e2 = {"grant_id": "grant_1", "seq": 2, "entry_hash": "h2",
              "kind": "receipt"}
        self.assertTrue(s.add_pact_audit_entry(e2))
        self.assertTrue(s.add_pact_audit_entry(e1))
        self.assertFalse(s.add_pact_audit_entry(e1))
        entries = s.pact_audit_entries("grant_1")
        self.assertEqual([e["seq"] for e in entries], [1, 2])
        self.assertEqual(s.last_pact_audit_entry("grant_1"), e2)
        self.assertEqual(s.pact_audit_entries("grant_none"), [])
        self.assertIsNone(s.last_pact_audit_entry("grant_none"))

        rev = {"record_id": "revoke_1", "grant_id": "grant_1",
               "revoked_at": "2026-10-14T01:00:00+00:00"}
        self.assertTrue(s.add_pact_revocation(rev))
        self.assertFalse(s.add_pact_revocation(rev))
        self.assertEqual(s.get_pact_revocation("grant_1"), rev)
        self.assertIsNone(s.get_pact_revocation("grant_none"))

    # -- demo fixture seeding parity (same seed_all as the SQLite tests) ----
    def test_seed_fixtures_present(self):
        tmp = tempfile.mkdtemp(prefix="npc_ddb_test_")
        reg = KeyRegistry(self.store, os.path.join(tmp, "keys"))
        reg.ensure_bootstrap()
        seed_all(self.store, reg)
        self.assertIsNotNone(self.store.get_credential("cred_test_001"))
        self.assertIsNotNone(self.store.get_product("tag_test_authentic"))
        self.assertIsNotNone(self.store.get_agent("agent_test_scout"))

    # -- cold-start recovery seed ---------------------------------------------
    def test_seed_put_if_absent(self):
        with open(SEED_PATH, encoding="utf-8") as f:
            records = json.load(f)
        self.assertEqual(len(records), 1)
        seed = records[0]
        self.assertEqual(self.store.install_seed_records(records), 1)
        got = self.store.get_registration(seed["record_id"])
        self.assertEqual(got, seed)
        self.assertEqual(got["signature"], seed["signature"])
        # Mutate the stored item; a second init must NOT overwrite it.
        row_item = self.table.get_item(
            Key={"pk": "REG", "sk": seed["record_id"]})["Item"]
        row = json.loads(row_item["data"])
        tampered = dict(seed, title="MUTATED")
        row["record_json"] = json.dumps(tampered)
        self.table.put_item(Item={"pk": "REG", "sk": seed["record_id"],
                                  "data": json.dumps(row)})
        self.assertEqual(self.store.install_seed_records(records), 0)
        self.assertEqual(
            self.store.get_registration(seed["record_id"])["title"],
            "MUTATED")
        # The seed carries no email/IP side data: no real submitter
        # identity has any count from it (counters start fresh), and
        # the row's own side columns are empty.
        self.assertEqual(
            self.store.count_registrations_since(
                "email", "registrant@example.com",
                "1970-01-01T00:00:00+00:00"), 0)
        self.assertEqual(
            self.store.count_registrations_since(
                "ip", "203.0.113.9", "1970-01-01T00:00:00+00:00"), 0)


class TestMakeStore(unittest.TestCase):
    def tearDown(self):
        for var in ("NPC_STORE_BACKEND", "NPC_DDB_TABLE",
                    "NPC_AWS_REGION"):
            os.environ.pop(var, None)

    def test_default_is_sqlite(self):
        os.environ.pop("NPC_STORE_BACKEND", None)
        tmp = tempfile.mkdtemp(prefix="npc_make_store_")
        store = make_store(os.path.join(tmp, "t.db"))
        self.assertIsInstance(store, Store)
        store.close()

    def test_env_selects_dynamodb(self):
        os.environ["NPC_STORE_BACKEND"] = "dynamodb"
        os.environ["NPC_DDB_TABLE"] = "npc-verify-store-make-store-test"
        store = make_store("/unused/path.db")
        self.assertIsInstance(store, DynamoDBStore)
        rec = _record("reg_env_1")
        store.add_registration(rec, "env@example.com", "")
        self.assertEqual(store.get_registration("reg_env_1"), rec)


if __name__ == "__main__":
    unittest.main()
