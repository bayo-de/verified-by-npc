"""DynamoDB store: same interface as npc_verify.store.Store, proven
against a fake boto3 table (api/serverless/lambda_v3/fake_boto3).
No AWS calls anywhere in this file.
"""
import hashlib
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

    def test_registrations_by_claim_hash(self):
        # Parity with the SQLite store: a content registration
        # answers to the hash of its locator address and to the
        # content hash recorded at intake; agent records and
        # unknown hashes answer to nothing.
        url = "https://example.com/images/cover.webp"
        content_sha = "cd" * 32
        rec = _record()
        rec.update({
            "locator": url, "locator_kind": "url",
            "content_kind": "image",
            "checks_run": [{
                "check": "content_fetch", "status": "fetched",
                "sha256": content_sha, "bytes": 10}],
        })
        self.store.add_registration(rec, "a@example.com",
                                    "203.0.113.9")
        agent = _record("reg_agent_1")
        agent["kind"] = "agent"
        self.store.add_registration(agent, "a@example.com",
                                    "203.0.113.9")
        address_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
        rows = self.store.registrations_by_claim_hash(address_hash)
        self.assertEqual([r["record_id"] for r in rows], ["reg_test_1"])
        rows = self.store.registrations_by_claim_hash(content_sha)
        self.assertEqual([r["record_id"] for r in rows], ["reg_test_1"])
        self.assertEqual(
            self.store.registrations_by_claim_hash("0" * 64), [])

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

    def test_registration_oldest_since(self):
        first = _record("reg_1")
        first["registered_at"] = "2026-10-14T01:00:00+00:00"
        second = _record("reg_2")
        second["registered_at"] = "2026-10-14T05:00:00+00:00"
        self.store.add_registration(first, "a@example.com",
                                    "203.0.113.9")
        self.store.add_registration(second, "a@example.com",
                                    "203.0.113.10")
        since = "2026-10-14T00:00:00+00:00"
        self.assertEqual(
            self.store.oldest_registration_since(
                "email", "a@example.com", since),
            "2026-10-14T01:00:00+00:00")
        self.assertEqual(
            self.store.oldest_registration_since(
                "ip", "203.0.113.10", since),
            "2026-10-14T05:00:00+00:00")
        self.assertIsNone(
            self.store.oldest_registration_since(
                "email", "nobody@example.com", since))

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


class TestDynamoDBCredits(unittest.TestCase):
    """Paid check credits on the DynamoDB backend: the same ledger
    contract the SQLite store proves in tests/test_credits.py."""

    def setUp(self):
        self.table = fake_boto3.FakeTable("npc-verify-store-test")
        self.store = DynamoDBStore(table=self.table)
        self.pack = {"id": "trio", "label": "3 checks", "checks": 3,
                     "price_cents": 300, "currency": "usd"}

    def _grant(self):
        from npc_verify import credits as credits_module
        code = credits_module.generate_code()
        code_hash = credits_module.code_hash(code)
        self.store.create_credit_purchase("cs_1", "trio", None, NOW)
        row = self.store.complete_credit_purchase(
            "cs_1", code_hash, code, self.pack, "b@example.com", NOW)
        return code, code_hash, row

    def test_credit_cycle(self):
        code, code_hash, row = self._grant()
        self.assertEqual(row["credits_total"], 3)
        # replayed completion mints nothing new
        again = self.store.complete_credit_purchase(
            "cs_1", "f" * 64, "other", self.pack, "b@example.com",
            NOW)
        self.assertEqual(again["code_hash"], code_hash)
        got, _p = self.store.take_credit_code_delivery("cs_1")
        self.assertEqual(got, code)
        got, _p = self.store.take_credit_code_delivery("cs_1")
        self.assertIsNone(got)
        redeemed = self.store.redeem_credit_code(code_hash, NOW)
        self.assertEqual(redeemed["redeemed_at"], NOW)
        ident = "sha256:" + "ab" * 32
        out = self.store.consume_credit(code_hash, ident, None,
                                        "chg_1", NOW)
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["credits_used"], 1)
        out = self.store.consume_credit(code_hash, ident, None,
                                        "chg_2", NOW)
        self.assertEqual(out["outcome"], "duplicate")
        self.assertEqual(out["code"]["credits_used"], 1)
        out = self.store.consume_credit("e" * 64, ident, None,
                                        "chg_3", NOW)
        self.assertEqual(out["outcome"], "not_found")
        self.store.consume_credit(code_hash, "sha256:" + "cd" * 32,
                                  None, "chg_4", NOW)
        out = self.store.consume_credit(
            code_hash, "sha256:" + "ef" * 32, None, "chg_5", NOW)
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["status"], "exhausted")
        out = self.store.consume_credit(
            code_hash, "sha256:" + "12" * 32, None, "chg_6", NOW)
        self.assertEqual(out["outcome"], "no_credits")

    def test_pack_only_code_funds_ai(self):
        # Pack counters fund AI checks on this backend too
        # (Bayo, 2026-10-28: "Pack credits include the AI
        # checks"): the charge lands against the counters,
        # marked funded_by "pack".
        _code, code_hash, _row = self._grant()
        view = self.store.get_credit_code(code_hash, NOW)
        self.assertEqual(view["ai_balance"], 3)
        ident = "sha256:" + "ab" * 32
        out = self.store.consume_credit(code_hash, ident, None,
                                        "chg_pa1", NOW, kind="ai")
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["credits_used"], 1)
        self.assertEqual(out["code"]["ai_balance"], 2)
        charge = self.store._get_row("CREDIT_CHARGE#" + code_hash,
                                     ident)
        self.assertEqual(charge["kind"], "ai")
        self.assertEqual(charge["funded_by"], "pack")


class TestDynamoDBPassGrants(unittest.TestCase):
    """Verifier Pass grants on the DynamoDB backend: the same
    contract the SQLite store proves in tests/test_credits.py."""

    def setUp(self):
        self.table = fake_boto3.FakeTable("npc-verify-store-test")
        self.store = DynamoDBStore(table=self.table)
        self.pack = {"id": "verifier-pass", "label": "Verifier Pass",
                     "checks": 5, "price_cents": 2500,
                     "currency": "usd", "kind": "access",
                     "ai_checks": 2, "interval": "month"}

    def _activate(self, granted_at="2026-10-28T00:00:00+00:00"):
        from npc_verify import credits as credits_module
        code = credits_module.generate_code()
        code_hash = credits_module.code_hash(code)
        self.store.create_credit_purchase(
            "cs_pass", "verifier-pass", None, granted_at)
        row = self.store.activate_pass_subscription(
            "cs_pass", code_hash, code, self.pack, "m@example.com",
            "sub_1", "cus_1", "in_1", granted_at,
            credits_module.grant_expiry(granted_at))
        return code, code_hash, row

    def test_pass_cycle(self):
        _code, code_hash, row = self._activate()
        self.assertEqual(row["grant_balance"], 5)
        self.assertEqual(row["ai_balance"], 2)
        self.assertEqual(row["subscription_status"], "active")
        # replayed activation mints and grants nothing twice
        again = self._activate()[2]
        self.assertEqual(again["code_hash"], code_hash)
        now = "2026-10-29T00:00:00+00:00"
        ident = "sha256:" + "ab" * 32
        out = self.store.consume_credit(code_hash, ident, None,
                                        "chg_1", now, kind="ai")
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["ai_balance"], 1)
        out = self.store.consume_credit(code_hash, ident, None,
                                        "chg_2", now, kind="ai")
        self.assertEqual(out["outcome"], "duplicate")
        out = self.store.consume_credit(
            code_hash, "sha256:" + "cd" * 32, None, "chg_3", now,
            kind="ai")
        self.assertEqual(out["outcome"], "charged")
        out = self.store.consume_credit(
            code_hash, "sha256:" + "ef" * 32, None, "chg_4", now,
            kind="ai")
        self.assertEqual(out["outcome"], "no_ai_credits")
        out = self.store.consume_credit(
            code_hash, "sha256:" + "ef" * 32, None, "chg_5", now)
        self.assertEqual(out["outcome"], "charged")
        # the standard check was covered by the Pass: the grant
        # (5 minus the 2 AI draws) does not move
        view = self.store.get_credit_code(code_hash, now)
        self.assertEqual(view["grant_balance"], 3)
        # renewal grants once per invoice; cancellation stops them
        res = self.store.grant_subscription_allowance(
            "sub_1", "in_2", "2026-11-28T00:00:00+00:00",
            "2027-01-01T00:00:00+00:00")
        self.assertEqual(res["outcome"], "granted")
        res = self.store.grant_subscription_allowance(
            "sub_1", "in_2", "2026-11-28T00:00:00+00:00",
            "2027-01-01T00:00:00+00:00")
        self.assertEqual(res["outcome"], "duplicate")
        self.store.cancel_subscription("sub_1",
                                       "2026-12-01T00:00:00+00:00")
        res = self.store.grant_subscription_allowance(
            "sub_1", "in_3", "2026-12-28T00:00:00+00:00",
            "2027-02-01T00:00:00+00:00")
        self.assertEqual(res["outcome"], "inactive")
        # December view: the October grant expired Dec 1, the
        # November grant (5 fresh) is what remains spendable
        view = self.store.get_credit_code(
            code_hash, "2026-12-15T00:00:00+00:00")
        self.assertEqual(view["grant_balance"], 5)
        self.assertEqual(view["subscription_status"], "canceled")

    def test_unlimited_standard_and_hourly_backstop(self):
        _code, code_hash, _row = self._activate()
        now = "2026-10-29T00:00:00+00:00"
        # standard checks are covered by the Pass while it runs:
        # more of them than the grant holds, and the grant
        # never moves
        for i in range(7):
            out = self.store.consume_credit(
                code_hash, "sha256:%064x" % i, None,
                "chg_u%d" % i, now)
            self.assertEqual(out["outcome"], "charged")
        view = self.store.get_credit_code(code_hash, now)
        self.assertEqual(view["grant_balance"], 5)
        # the hourly backstop counts Pass-covered charges too
        out = self.store.consume_credit(
            code_hash, "sha256:" + "ff" * 32, None, "chg_u9", now,
            hourly_limit=7)
        self.assertEqual(out["outcome"], "rate_limited")
        # cancellation returns standard checks to the finite pool
        self.store.cancel_subscription("sub_1", now)
        out = self.store.consume_credit(
            code_hash, "sha256:" + "ff" * 32, None, "chg_u10", now)
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 4)

    def test_ai_draws_bonus_after_pass_allowance(self):
        from npc_verify import credits as credits_module
        _code, code_hash, _row = self._activate()
        # another buyer refers the Pass code, landing a 10-check
        # referee bonus grant on it
        trio = {"id": "trio", "label": "3 checks", "checks": 3,
                "price_cents": 300, "currency": "usd"}
        ref_code = credits_module.generate_code()
        ref_hash = credits_module.code_hash(ref_code)
        self.store.create_credit_purchase(
            "cs_ref", "trio", "b@example.com",
            "2026-10-28T00:30:00+00:00")
        self.store.complete_credit_purchase(
            "cs_ref", ref_hash, ref_code, trio, "b@example.com",
            "2026-10-28T00:30:00+00:00")
        plain = credits_module.generate_code()
        self.store.ensure_referral_code(
            ref_hash, credits_module.code_hash(plain), plain,
            "2026-10-28T00:30:00+00:00")
        res = self.store.attribute_referral(
            code_hash, credits_module.code_hash(plain),
            "referee:" + code_hash, "referrer:" + code_hash,
            "2026-10-28T01:00:00+00:00",
            credits_module.grant_expiry(
                "2026-10-28T01:00:00+00:00"),
            credits_module.REFEREE_BONUS_CHECKS,
            credits_module.REFERRER_BONUS_CHECKS,
            credits_module.REFERRAL_MONTHLY_CAP_CHECKS,
            referrer_link_bonus=
            credits_module.REFERRER_LINK_BONUS_CHECKS,
            referrer_link_grant_id="referrer-link:" + code_hash)
        self.assertEqual(res["outcome"], "linked")
        now = "2026-10-29T00:00:00+00:00"
        # the Pass grant's two AI checks are drawn first
        for i in range(2):
            out = self.store.consume_credit(
                code_hash, "sha256:%064x" % i, None,
                "chg_b%d" % i, now, kind="ai")
            self.assertEqual(out["outcome"], "charged")
        view = self.store.get_credit_code(code_hash, now)
        self.assertEqual(view["ai_balance"], 10)
        grants = {g["grant_id"]: g for g in view["grants"]}
        self.assertEqual(
            grants["referee:" + code_hash]["used"], 0)
        # the third AI check draws the bonus, marked on the row
        ident = "sha256:" + "ab" * 32
        out = self.store.consume_credit(
            code_hash, ident, None, "chg_b2", now, kind="ai")
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["ai_balance"], 9)
        charge = self.store._get_row("CREDIT_CHARGE#" + code_hash,
                                     ident)
        self.assertEqual(charge["funded_by"], "bonus")


class TestDynamoDBReferrals(unittest.TestCase):
    """Referrals on the DynamoDB backend: the same contract the
    SQLite store proves in tests/test_credits.py."""

    def setUp(self):
        self.table = fake_boto3.FakeTable("npc-verify-store-test")
        self.store = DynamoDBStore(table=self.table)
        self.pack = {"id": "trio", "label": "3 checks", "checks": 3,
                     "price_cents": 300, "currency": "usd"}

    def _mint(self, session, email):
        from npc_verify import credits as credits_module
        code = credits_module.generate_code()
        code_hash = credits_module.code_hash(code)
        self.store.create_credit_purchase(session, "trio", email,
                                          NOW)
        self.store.complete_credit_purchase(
            session, code_hash, code, self.pack, email, NOW)
        return code, code_hash

    def test_referral_cycle(self):
        from npc_verify import credits as credits_module
        _a, a_hash = self._mint("cs_a", "a@example.com")
        _b, b_hash = self._mint("cs_b", "b@example.com")
        # referral code: recorded once, delivered once
        plain = credits_module.generate_code()
        self.store.ensure_referral_code(
            a_hash, credits_module.code_hash(plain), plain, NOW)
        got, _row = self.store.take_referral_code_delivery(a_hash)
        self.assertEqual(got, plain)
        got, _row = self.store.take_referral_code_delivery(a_hash)
        self.assertIsNone(got)
        # attribution lands all three bonuses, exactly once
        res = self.store.attribute_referral(
            b_hash, credits_module.code_hash(plain),
            "referee:" + b_hash, "referrer:" + b_hash, NOW,
            credits_module.grant_expiry(NOW),
            credits_module.REFEREE_BONUS_CHECKS,
            credits_module.REFERRER_BONUS_CHECKS,
            credits_module.REFERRAL_MONTHLY_CAP_CHECKS,
            referrer_link_bonus=
            credits_module.REFERRER_LINK_BONUS_CHECKS,
            referrer_link_grant_id="referrer-link:" + b_hash)
        self.assertEqual(res["outcome"], "linked")
        self.assertEqual(res["referee_bonus"], 10)
        self.assertEqual(res["referrer_link_bonus"], 10)
        self.assertEqual(res["referrer_bonus"], 100)
        b_view = self.store.get_credit_code(b_hash, NOW)
        self.assertEqual(b_view["grant_balance"], 10)
        # the bonus counts toward AI-usable balance too, and
        # each side's own 3 pack checks stand behind it: pack
        # balances fund AI checks as well (Bayo, 2026-10-28)
        self.assertEqual(b_view["ai_balance"], 10 + 3)
        a_view = self.store.get_credit_code(a_hash, NOW)
        self.assertEqual(a_view["grant_balance"], 110)
        self.assertEqual(a_view["ai_balance"], 110 + 3)
        res = self.store.attribute_referral(
            b_hash, credits_module.code_hash(plain),
            "referee:" + b_hash, "referrer:" + b_hash, NOW,
            credits_module.grant_expiry(NOW),
            credits_module.REFEREE_BONUS_CHECKS,
            credits_module.REFERRER_BONUS_CHECKS,
            credits_module.REFERRAL_MONTHLY_CAP_CHECKS,
            referrer_link_bonus=
            credits_module.REFERRER_LINK_BONUS_CHECKS,
            referrer_link_grant_id="referrer-link:" + b_hash)
        self.assertEqual(res["outcome"], "already_referred")
        stats = self.store.referral_stats(a_hash, NOW)
        self.assertEqual(stats["referred_count"], 1)
        self.assertEqual(stats["referral_bonus_this_month"], 110)
        self.assertTrue(
            self.store.referral_stats(b_hash, NOW)["referred_by"])
        # self-referral grants nothing
        res = self.store.attribute_referral(
            a_hash, credits_module.code_hash(plain),
            "referee:" + a_hash, "referrer:" + a_hash, NOW,
            credits_module.grant_expiry(NOW),
            credits_module.REFEREE_BONUS_CHECKS,
            credits_module.REFERRER_BONUS_CHECKS,
            credits_module.REFERRAL_MONTHLY_CAP_CHECKS,
            referrer_link_bonus=
            credits_module.REFERRER_LINK_BONUS_CHECKS,
            referrer_link_grant_id="referrer-link:" + a_hash)
        self.assertEqual(res["outcome"], "self_referral")
        self.assertIsNone(self.store.get_referral(a_hash))
        # the bonus funds AI checks and standard checks from the
        # one shared pool (Bayo, 2026-10-28); the AI draw takes
        # the bonus before the pack counters behind it
        out = self.store.consume_credit(
            b_hash, "sha256:" + "ab" * 32, None, "chg_r1", NOW,
            kind="ai")
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 9)
        self.assertEqual(out["code"]["ai_balance"], 9 + 3)
        self.assertEqual(out["code"]["credits_used"], 0)
        charge = self.store._get_row("CREDIT_CHARGE#" + b_hash,
                                     "sha256:" + "ab" * 32)
        self.assertEqual(charge["funded_by"], "bonus")
        out = self.store.consume_credit(
            b_hash, "sha256:" + "cd" * 32, None, "chg_r2", NOW)
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 8)

    def test_ai_draw_order_pass_then_bonus_then_pack(self):
        # The full AI draw order on one code holding all three
        # sources, mirroring the SQLite proof (Bayo, 2026-10-28):
        # a Pass grant's AI sub-allowance first, then bonus
        # grants, then the code's pack counters. The hybrid is
        # assembled directly at the store: a pack code (3
        # counters) carrying a referral bonus grant (+10) and a
        # Pass-shaped grant (2 checks, AI sub-allowance 2).
        from npc_verify import credits as credits_module
        _a, a_hash = self._mint("cs_a", "a@example.com")
        _b, b_hash = self._mint("cs_b", "b@example.com")
        plain = credits_module.generate_code()
        self.store.ensure_referral_code(
            a_hash, credits_module.code_hash(plain), plain, NOW)
        res = self.store.attribute_referral(
            b_hash, credits_module.code_hash(plain),
            "referee:" + b_hash, "referrer:" + b_hash, NOW,
            credits_module.grant_expiry(NOW),
            credits_module.REFEREE_BONUS_CHECKS,
            credits_module.REFERRER_BONUS_CHECKS,
            credits_module.REFERRAL_MONTHLY_CAP_CHECKS,
            referrer_link_bonus=
            credits_module.REFERRER_LINK_BONUS_CHECKS,
            referrer_link_grant_id="referrer-link:" + b_hash)
        self.assertEqual(res["outcome"], "linked")
        grant = {"grant_id": "hybrid_pass", "code_hash": b_hash,
                 "amount": 2, "used": 0, "ai_cap": 2, "ai_used": 0,
                 "source": "pass", "granted_at": NOW,
                 "expires_at": credits_module.grant_expiry(NOW)}
        self.store._put_row("CREDIT_GRANT#" + b_hash,
                            "hybrid_pass", grant)
        bonus_id = "referee:" + b_hash

        def view():
            return self.store.get_credit_code(b_hash, NOW)

        def grants():
            return {g["grant_id"]: g for g in view()["grants"]}

        def ai(i):
            return self.store.consume_credit(
                b_hash, "sha256:%064x" % i, None,
                "chg_3p_%d" % i, NOW, kind="ai")

        def funded_by(i):
            row = self.store._get_row(
                "CREDIT_CHARGE#" + b_hash, "sha256:%064x" % i)
            return row["funded_by"]

        # ai_balance is the whole truth: 2 Pass room + 10 bonus
        # + 3 pack
        self.assertEqual(view()["ai_balance"], 2 + 10 + 3)
        # phase 1: the Pass grant's sub-allowance pays first
        for i in range(2):
            self.assertEqual(ai(i)["outcome"], "charged")
        g = grants()
        self.assertEqual(g["hybrid_pass"]["ai_used"], 2)
        self.assertEqual(g[bonus_id]["used"], 0)
        self.assertEqual(view()["credits_used"], 0)
        self.assertEqual(funded_by(0), "")
        # phase 2: the bonus grant pays next, marked "bonus"
        self.assertEqual(ai(2)["outcome"], "charged")
        g = grants()
        self.assertEqual(g[bonus_id]["used"], 1)
        self.assertEqual(view()["credits_used"], 0)
        self.assertEqual(funded_by(2), "bonus")
        for i in range(3, 12):
            self.assertEqual(ai(i)["outcome"], "charged")
        g = grants()
        self.assertEqual(g[bonus_id]["used"], 10)
        self.assertEqual(view()["ai_balance"], 3)
        # phase 3: only now do the pack counters pay, marked
        # "pack", one per AI check
        self.assertEqual(ai(12)["outcome"], "charged")
        self.assertEqual(view()["credits_used"], 1)
        self.assertEqual(funded_by(12), "pack")
        for i in range(13, 15):
            self.assertEqual(ai(i)["outcome"], "charged")
        self.assertEqual(view()["credits_used"], 3)
        self.assertEqual(view()["ai_balance"], 0)
        # everything spent: the answer is no_credits
        self.assertEqual(ai(15)["outcome"], "no_credits")


if __name__ == "__main__":
    unittest.main()
