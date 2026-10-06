"""Store: schema, attestation lifecycle, revocation append-only, lookups."""
import json
import os
import sys
import tempfile
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify.store import Store  # noqa: E402
from npc_verify.keys import KeyRegistry  # noqa: E402
from npc_verify.models import Attestation  # noqa: E402
from npc_verify.seed import seed_all, _sign_attestation  # noqa: E402


def _att(**kw):
    base = dict(id="att_x1", subject_type="claim", subject_id="s1",
                verdict="verified", scope={}, tested_at="2026-01-01T00:00:00+00:00",
                expires_at=None, findings_summary="ok")
    base.update(kw)
    return Attestation(**base)


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_store_test_")
        self.store = Store(os.path.join(self.tmp, "t.db"))
        self.reg = KeyRegistry(self.store, os.path.join(self.tmp, "keys"))
        self.reg.ensure_bootstrap()

    def tearDown(self):
        self.store.close()

    def test_seed_fixtures_present(self):
        seed_all(self.store, self.reg)
        self.assertIsNotNone(self.store.get_credential("cred_test_001"))
        self.assertIsNotNone(self.store.get_product("tag_test_authentic"))
        self.assertIsNotNone(self.store.get_agent("agent_test_scout"))

    def test_latest_attestation_wins(self):
        a1 = _sign_attestation(self.reg, _att(id="att_old"))
        a2 = _sign_attestation(self.reg, _att(id="att_new"))
        self.store.add_attestation(a1)
        self.store.add_attestation(a2)
        latest = self.store.latest_attestation("claim", "s1")
        self.assertEqual(latest["id"], "att_new")

    def test_revocation_is_append_only(self):
        a = _sign_attestation(self.reg, _att(id="att_r1"))
        self.store.add_attestation(a)
        ok = self.store.revoke_attestation("att_r1", "rev_1", "mistake",
                                           "sig", "kid", "2026-01-02T00:00:00+00:00")
        self.assertTrue(ok)
        row = self.store.get_attestation("att_r1")
        self.assertEqual(row["revoked"], 1)
        # revocation record exists alongside, original row not edited otherwise
        rev = self.store._fetchone(
            "SELECT * FROM revocations WHERE attestation_id=?", ("att_r1",))
        self.assertIsNotNone(rev)
        self.assertEqual(rev["reason"], "mistake")
        # revoked attestations are excluded from lookups
        self.assertIsNone(self.store.latest_attestation("claim", "s1"))
        # double revoke fails closed
        self.assertFalse(self.store.revoke_attestation(
            "att_r1", "rev_2", "x", "sig", "kid", "2026-01-03T00:00:00+00:00"))

    def test_claim_hash_lookup(self):
        from npc_verify.canonical import claim_hash_for_text
        ch = claim_hash_for_text("some claim")
        a = _sign_attestation(self.reg, _att(id="att_c1", claim_hash=ch))
        self.store.add_attestation(a)
        rows = self.store.attestations_by_claim_hash(ch)
        self.assertEqual(len(rows), 1)
        self.assertEqual(self.store.attestations_by_claim_hash("0" * 64), [])

    def test_model_validation(self):
        bad = _att(verdict="maybe", tested_at="not-a-date",
                   findings_summary="")
        problems = bad.validate()
        self.assertGreaterEqual(len(problems), 3)
        good = _att()
        self.assertEqual(good.validate(), [])


if __name__ == "__main__":
    unittest.main()
