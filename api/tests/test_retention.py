"""Registration email retention (audit item D6).

Stated retention: 12 months. The store-layer sweep purges the RAW
email on registrations older than that; the signed record stays, and
the cap counters keep working because they are keyed by the email
HASH, which is not purged. The maintenance entry point is
registry.run_email_retention_sweep.
"""
import os
import sys
import tempfile
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import registry  # noqa: E402
from npc_verify.store import Store, registration_email_hash  # noqa: E402

NOW = "2026-10-15T00:00:00+00:00"
AGED_AT = "2025-09-01T00:00:00+00:00"    # 13.5 months before NOW
FRESH_AT = "2026-10-01T00:00:00+00:00"   # two weeks before NOW


def _record(record_id, registered_at):
    return {"record_id": record_id, "kind": "content",
            "title": "Retention test", "registered_at": registered_at,
            "status": "registered_checks_pending", "signature": "c2ln"}


class RetentionCutoffTest(unittest.TestCase):
    def test_twelve_months_exact(self):
        self.assertEqual(registry.retention_cutoff_iso(NOW),
                         "2025-10-15T00:00:00+00:00")

    def test_day_clamped_for_short_months(self):
        # 2025 is not a leap year: Feb 29 minus 12 months -> Feb 28.
        self.assertEqual(
            registry.retention_cutoff_iso("2024-02-29T00:00:00+00:00"),
            "2023-02-28T00:00:00+00:00")


class RetentionSweepSqliteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_retention_")
        self.store = Store(os.path.join(self.tmp, "t.db"))
        self.store.add_registration(_record("reg_aged", AGED_AT),
                                    "aged@example.com", "203.0.113.1")
        self.store.add_registration(_record("reg_fresh", FRESH_AT),
                                    "fresh@example.com", "203.0.113.2")

    def tearDown(self):
        self.store.close()

    def _row(self, record_id):
        return self.store._fetchone(
            "SELECT email, email_hash FROM registrations"
            " WHERE record_id=?", (record_id,))

    def test_aged_email_purged_fresh_untouched(self):
        purged = registry.run_email_retention_sweep(self.store,
                                                    now_iso=NOW)
        self.assertEqual(purged, 1)
        aged = self._row("reg_aged")
        self.assertEqual(aged["email"], "")
        self.assertEqual(aged["email_hash"],
                         registration_email_hash("aged@example.com"))
        fresh = self._row("reg_fresh")
        self.assertEqual(fresh["email"], "fresh@example.com")
        # the signed record itself is untouched and still resolves
        rec = self.store.get_registration("reg_aged")
        self.assertEqual(rec["record_id"], "reg_aged")
        # the sweep is idempotent
        self.assertEqual(
            registry.run_email_retention_sweep(self.store, now_iso=NOW),
            0)

    def test_cap_counters_survive_the_purge(self):
        registry.run_email_retention_sweep(self.store, now_iso=NOW)
        since = "2000-01-01T00:00:00+00:00"
        self.assertEqual(self.store.count_registrations_since(
            "email", "aged@example.com", since), 1)
        self.assertEqual(self.store.count_registrations_since(
            "email", "fresh@example.com", since), 1)
        self.assertEqual(self.store.count_registrations_since(
            "ip", "203.0.113.1", since), 1)


class RetentionSweepDynamoTest(unittest.TestCase):
    """Same sweep against the DynamoDB backend (fake table)."""

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
            table=fake_boto3.FakeTable("npc-verify-store-retention"))
        self.store.add_registration(_record("reg_aged", AGED_AT),
                                    "aged@example.com", "203.0.113.1")
        self.store.add_registration(_record("reg_fresh", FRESH_AT),
                                    "fresh@example.com", "203.0.113.2")

    def test_aged_email_purged_fresh_untouched(self):
        purged = registry.run_email_retention_sweep(self.store,
                                                    now_iso=NOW)
        self.assertEqual(purged, 1)
        aged = self.store._get_row("REG", "reg_aged")
        self.assertEqual(aged["email"], "")
        self.assertEqual(aged["email_hash"],
                         registration_email_hash("aged@example.com"))
        fresh = self.store._get_row("REG", "reg_fresh")
        self.assertEqual(fresh["email"], "fresh@example.com")
        self.assertEqual(
            self.store.get_registration("reg_aged")["record_id"],
            "reg_aged")
        since = "2000-01-01T00:00:00+00:00"
        self.assertEqual(self.store.count_registrations_since(
            "email", "aged@example.com", since), 1)


if __name__ == "__main__":
    unittest.main()
