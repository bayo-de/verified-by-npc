"""PACT record layer tests (flywheel #73).

Three layers:

- TestPactRecordLayerDemoPort ports the scratch demonstration's 9
  checks (flywheel sandbox/pact-test/extension_demo.py) one-for-one
  against the production module, with the same scripted session:
  Skyline Airways, the three advertised scopes, the user withholding
  flights:rebook, three section 5.6 receipts, then revocation.
- TestPactEndpoints exercises the HTTP surface end to end, including
  the fail-closed post-revocation path and a stored-history rewrite.
- TestTraceAuditAdapter checks the Verified Trace Audit feed shape.
"""
import base64
import copy
import json
import os
import sys
import tempfile
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import ed25519, pact  # noqa: E402
from npc_verify.canonical import canonicalize, canonical_sha256_hex  # noqa: E402
from npc_verify.keys import KeyRegistry  # noqa: E402
from npc_verify.store import Store  # noqa: E402
from npc_verify.trace_audit_adapter import audit_feed_for_grant  # noqa: E402
from tests.helpers import ApiTestCase  # noqa: E402

GRANT_ID = "grant_01K8PACT7X3QZK4M9D2F6H8W1E"
SESSION = {
    "grant_id": GRANT_ID,
    "pa_iss": "http://localhost:3002",
    "pa_sub": "demo-user-sub-7f3a",
    "brand_id": "01M3R53Q5SZQ6FQSMSDBSSREAA",
    "user_id_at_brand": "alex.rivera@example.com",
    "scopes_requested": ["flights:history:read", "flights:rebook",
                         "flights:upcoming:read"],
    "scopes_granted": ["flights:history:read", "flights:upcoming:read"],
    "shown_at": "2026-10-14T23:55:00+00:00",
    "granted_at": "2026-10-14T23:55:42+00:00",
    "expires_at": "2026-10-15T00:55:42+00:00",
}


def make_receipts():
    """The demo's three section 5.6 receipts, claims exactly as issued."""
    calls = [
        ("flights.listUpcoming", {"user": "alex.rivera@example.com"},
         ["flights:upcoming:read"], "2026-10-14T23:56:35+00:00"),
        ("flights.getHistory",
         {"user": "alex.rivera@example.com", "limit": 5},
         ["flights:history:read"], "2026-10-14T23:58:30+00:00"),
        ("flights.listUpcoming",
         {"user": "alex.rivera@example.com", "detail": True},
         ["flights:upcoming:read"], "2026-10-15T00:00:40+00:00"),
    ]
    return [{
        "grantId": GRANT_ID,
        "user": SESSION["user_id_at_brand"],
        "pa": SESSION["pa_iss"],
        "brand": SESSION["brand_id"],
        "scopesUsed": scopes,
        "actions": [{"tool": tool, "argsHash": canonical_sha256_hex(args)}],
        "ts": ts,
    } for tool, args, scopes, ts in calls]


class PactUnitCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_pact_test_")
        self.store = Store(os.path.join(self.tmp, "t.db"))
        self.keys = KeyRegistry(self.store, os.path.join(self.tmp, "keys"))
        self.keys.ensure_bootstrap()

    def tearDown(self):
        self.store.close()

    # Subclasses whose reads happen at wall-clock now (the adapter
    # reads status at feed time) override the demo's fixed expiry so
    # the grant is unexpired when read. The ported demo checks pass
    # explicit `at` values instead and keep the fixture expiry.
    SESSION_OVERRIDES = {}

    def mint(self):
        fields = dict(SESSION)
        fields.update(self.SESSION_OVERRIDES)
        rec = pact.mint_consent_record(self.store, self.keys, fields)
        self.assertIsNotNone(rec)
        return rec

    def fill_log(self):
        entries = [pact.append_receipt(self.store, self.keys, GRANT_ID, r)
                   for r in make_receipts()]
        self.assertTrue(all(e is not None for e in entries))
        return entries


class TestPactRecordLayerDemoPort(PactUnitCase):
    """The scratch demo's 9 checks, ported one-for-one."""

    def test_1_consent_record_signature_verifies(self):
        consent = self.mint()
        self.assertTrue(pact.verify_consent_record(self.keys, consent))

    def test_2_requested_vs_granted_preserved(self):
        consent = self.mint()
        self.assertEqual(consent["scopes_granted"],
                         ["flights:history:read", "flights:upcoming:read"])
        self.assertIn("flights:rebook", consent["scopes_requested"])
        self.assertNotIn("flights:rebook", consent["scopes_granted"])

    def test_3_audit_log_verifies_end_to_end(self):
        self.mint()
        self.fill_log()
        entries = self.store.pact_audit_entries(GRANT_ID)
        self.assertEqual([e["seq"] for e in entries], [1, 2, 3])
        ok, detail = pact.verify_audit_chain(self.keys, entries)
        self.assertTrue(ok, detail)
        self.assertEqual(detail, "chain intact")

    def test_4_tampered_receipt_breaks_verification_at_seq_2(self):
        self.mint()
        self.fill_log()
        entries = self.store.pact_audit_entries(GRANT_ID)
        tampered = copy.deepcopy(entries)
        # Rewrite history: pretend receipt 2 also used the withheld scope.
        tampered[1]["receipt_claims"]["scopesUsed"] = [
            "flights:history:read", "flights:rebook"]
        ok, detail = pact.verify_audit_chain(self.keys, tampered)
        self.assertFalse(ok)
        self.assertEqual(detail,
                         "seq 2: receipt claims do not match logged hash")

    def test_5_gate_passes_while_grant_is_active(self):
        self.mint()
        status = pact.grant_status_record(
            self.store, self.keys, GRANT_ID, at="2026-10-15T00:04:00+00:00")
        self.assertEqual(status["status"], "active")
        self.assertTrue(pact.gate_allows(self.keys, status))

    def test_6_revocation_record_signature_verifies(self):
        self.mint()
        rev = pact.revoke_grant(self.store, self.keys, GRANT_ID, "user",
                                "scripted user revocation",
                                revoked_at="2026-10-15T00:05:00+00:00")
        self.assertIsNotNone(rev)
        self.assertTrue(pact.verify_record(self.keys, rev))

    def test_7_signed_status_flips_to_revoked(self):
        consent = self.mint()
        rev = pact.revoke_grant(self.store, self.keys, GRANT_ID, "user",
                                "scripted user revocation",
                                revoked_at="2026-10-15T00:05:00+00:00")
        status = pact.grant_status_record(
            self.store, self.keys, GRANT_ID, at="2026-10-15T00:06:00+00:00")
        self.assertEqual(status["status"], "revoked")
        self.assertEqual(status["consent_record_id"], consent["record_id"])
        self.assertEqual(status["revocation_record_id"], rev["record_id"])
        self.assertTrue(pact.verify_status_record(self.keys, status))

    def test_8_gate_fails_closed_after_revocation(self):
        self.mint()
        pact.revoke_grant(self.store, self.keys, GRANT_ID, "user",
                          "scripted user revocation",
                          revoked_at="2026-10-15T00:05:00+00:00")
        status = pact.grant_status_record(
            self.store, self.keys, GRANT_ID, at="2026-10-15T00:06:00+00:00")
        self.assertFalse(pact.gate_allows(self.keys, status))

    def test_9_pre_revocation_status_record_untouched(self):
        self.mint()
        before = pact.grant_status_record(
            self.store, self.keys, GRANT_ID, at="2026-10-15T00:04:00+00:00")
        pact.revoke_grant(self.store, self.keys, GRANT_ID, "user",
                          "scripted user revocation",
                          revoked_at="2026-10-15T00:05:00+00:00")
        # Append-only: the earlier signed status still says active and
        # still verifies; revocation never edits history.
        self.assertEqual(before["status"], "active")
        self.assertTrue(pact.verify_status_record(self.keys, before))


class TestPactRecordLayerEdges(PactUnitCase):
    def test_status_expired_after_consent_expiry(self):
        self.mint()
        status = pact.grant_status_record(
            self.store, self.keys, GRANT_ID, at="2026-10-15T01:00:00+00:00")
        self.assertEqual(status["status"], "expired")
        self.assertFalse(pact.gate_allows(self.keys, status))

    def test_second_revocation_refused(self):
        self.mint()
        first = pact.revoke_grant(self.store, self.keys, GRANT_ID, "user",
                                  "first")
        second = pact.revoke_grant(self.store, self.keys, GRANT_ID, "user",
                                   "second")
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_missing_entry_breaks_chain_at_the_gap(self):
        self.mint()
        self.fill_log()
        entries = self.store.pact_audit_entries(GRANT_ID)
        del entries[1]  # a receipt goes missing from the trail
        ok, detail = pact.verify_audit_chain(self.keys, entries)
        self.assertFalse(ok)
        self.assertIn("seq 2", detail)

    def test_validation_rejects_granting_unrequested_scope(self):
        bad = dict(SESSION)
        bad["scopes_granted"] = ["flights:rebook", "billing:charge"]
        problems = pact.validate_consent_input(bad)
        self.assertTrue(any("subset" in p for p in problems), problems)

    def test_status_for_unknown_grant_is_none(self):
        self.assertIsNone(
            pact.grant_status_record(self.store, self.keys, "grant_nope"))


class TestPactEndpoints(ApiTestCase):
    def published_pubs(self):
        status, _, data = self.get("/v1/keys")
        self.assertEqual(status, 200)
        doc = json.loads(data)
        pubs = {}
        cur = doc["api_signing"]["current"]
        if cur:
            pubs[cur["key_id"]] = base64.b64decode(cur["public_key"])
        for h in doc["api_signing"]["history"]:
            pubs[h["key_id"]] = base64.b64decode(h["public_key"])
        for e in doc["issuers"]:
            pubs[e["key_id"]] = base64.b64decode(e["public_key"])
        return pubs

    def check_record_signature(self, record):
        pubs = self.published_pubs()
        pub = pubs.get(record["key_id"])
        self.assertIsNotNone(pub, f"key {record['key_id']} not published")
        body = {k: v for k, v in record.items() if k != "signature"}
        sig = base64.b64decode(record["signature"])
        self.assertTrue(ed25519.verify(pub, canonicalize(body), sig),
                        "record signature does not verify")

    def make_grant(self, grant_id):
        body = dict(SESSION)
        body["grant_id"] = grant_id
        # Endpoint reads (status) happen at wall-clock now, so the
        # grant must be unexpired then; the demo's fixed 2026 expiry
        # would read as expired. The record-layer port keeps the
        # fixture times because it passes explicit `at` values.
        body["expires_at"] = "2027-10-15T00:55:42+00:00"
        status, headers, data = self.post("/v1/pact/grants", body,
                                          key=self.issuer_key)
        self.assertEqual(status, 201, data)
        return self.check_signature(headers, data)

    def test_grant_issuance_mints_signed_consent(self):
        rec = self.make_grant("grant_ep_1")
        self.assertEqual(rec["record_type"], "npc.pact.consent_record")
        self.assertEqual(rec["scopes_granted"],
                         SESSION["scopes_granted"])
        self.assertIn("flights:rebook", rec["scopes_requested"])
        self.check_record_signature(rec)

    def test_grant_issuance_role_gates(self):
        body = dict(SESSION)
        body["grant_id"] = "grant_ep_roles"
        status, _, _ = self.post("/v1/pact/grants", body,
                                 key=self.verifier_key)
        self.assertEqual(status, 403)
        status, _, _ = self.post("/v1/pact/grants", body)
        self.assertEqual(status, 401)

    def test_grant_issuance_rejects_unrequested_scope(self):
        body = dict(SESSION)
        body["grant_id"] = "grant_ep_bad"
        body["scopes_granted"] = ["billing:charge"]
        status, _, data = self.post("/v1/pact/grants", body,
                                    key=self.issuer_key)
        self.assertEqual(status, 422, data)

    def test_duplicate_grant_conflicts(self):
        self.make_grant("grant_ep_dup")
        body = dict(SESSION)
        body["grant_id"] = "grant_ep_dup"
        status, _, _ = self.post("/v1/pact/grants", body,
                                 key=self.issuer_key)
        self.assertEqual(status, 409)

    def test_receipt_flow_and_audit_read(self):
        self.make_grant("grant_ep_flow")
        receipts = make_receipts()
        for r in receipts:
            r["grantId"] = "grant_ep_flow"
        for i, r in enumerate(receipts, start=1):
            status, headers, data = self.post(
                "/v1/pact/grants/grant_ep_flow/receipts", {"receipt": r},
                key=self.issuer_key)
            self.assertEqual(status, 201, data)
            entry = self.check_signature(headers, data)
            self.assertEqual(entry["seq"], i)
            self.check_record_signature(
                {k: v for k, v in entry.items() if k != "entry_hash"})
        status, headers, data = self.get(
            "/v1/pact/grants/grant_ep_flow/audit", key=self.verifier_key)
        self.assertEqual(status, 200)
        body = self.check_signature(headers, data)
        self.assertTrue(body["chain"]["valid"])
        self.assertEqual(body["chain"]["entries"], 3)
        self.assertEqual(len(body["entries"]), 3)

    def test_receipt_unknown_grant_and_mismatch(self):
        status, _, data = self.post(
            "/v1/pact/grants/grant_nope/receipts",
            {"receipt": make_receipts()[0]}, key=self.issuer_key)
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(data), {"verdict": "unknown"})
        self.make_grant("grant_ep_mismatch")
        r = make_receipts()[0]  # grantId is the SESSION grant, not the path
        status, _, _ = self.post(
            "/v1/pact/grants/grant_ep_mismatch/receipts", {"receipt": r},
            key=self.issuer_key)
        self.assertEqual(status, 422)

    def test_revoke_flips_signed_status_and_fails_closed(self):
        consent = self.make_grant("grant_ep_revoke")
        status, headers, data = self.get(
            "/v1/pact/grants/grant_ep_revoke/status",
            key=self.verifier_key)
        self.assertEqual(status, 200)
        before = self.check_signature(headers, data)
        self.assertEqual(before["status"], "active")
        self.assertEqual(before["consent_record_id"], consent["record_id"])
        self.check_record_signature(before)

        status, headers, data = self.post(
            "/v1/pact/grants/grant_ep_revoke:revoke",
            {"revoked_by": "user", "reason": "endpoint test revocation"},
            key=self.issuer_key)
        self.assertEqual(status, 201, data)
        rev = self.check_signature(headers, data)
        self.assertEqual(rev["record_type"], "npc.pact.revocation")
        self.check_record_signature(rev)

        status, headers, data = self.get(
            "/v1/pact/grants/grant_ep_revoke/status",
            key=self.verifier_key)
        after = self.check_signature(headers, data)
        self.assertEqual(after["status"], "revoked")
        self.assertEqual(after["revocation_record_id"], rev["record_id"])
        self.check_record_signature(after)
        # The pre-revocation record is a different, still-valid artifact.
        self.assertEqual(before["status"], "active")
        self.check_record_signature(before)

        status, _, _ = self.post(
            "/v1/pact/grants/grant_ep_revoke:revoke",
            {"revoked_by": "user", "reason": "again"},
            key=self.issuer_key)
        self.assertEqual(status, 409)

    def test_revoke_and_status_unknown_grant(self):
        status, _, data = self.post(
            "/v1/pact/grants/grant_nope:revoke",
            {"revoked_by": "user", "reason": "x"}, key=self.issuer_key)
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(data), {"verdict": "unknown"})
        status, _, data = self.get("/v1/pact/grants/grant_nope/status",
                                   key=self.verifier_key)
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(data), {"verdict": "unknown"})
        status, _, data = self.get("/v1/pact/grants/grant_nope/audit",
                                   key=self.verifier_key)
        self.assertEqual(status, 404)

    def test_stored_history_rewrite_breaks_audit_chain(self):
        self.make_grant("grant_ep_tamper")
        receipts = make_receipts()
        for r in receipts:
            r["grantId"] = "grant_ep_tamper"
            status, _, data = self.post(
                "/v1/pact/grants/grant_ep_tamper/receipts",
                {"receipt": r}, key=self.issuer_key)
            self.assertEqual(status, 201, data)
        # Rewrite stored history directly: receipt 2 now claims the
        # withheld scope. The audit read must catch it at seq 2.
        with self.app.store.db_lock:
            row = self.app.store.db.execute(
                "SELECT record_json FROM pact_audit_entries"
                " WHERE grant_id=? AND seq=2",
                ("grant_ep_tamper",)).fetchone()
            entry = json.loads(row["record_json"])
            entry["receipt_claims"]["scopesUsed"] = [
                "flights:history:read", "flights:rebook"]
            self.app.store.db.execute(
                "UPDATE pact_audit_entries SET record_json=?"
                " WHERE grant_id=? AND seq=2",
                (json.dumps(entry), "grant_ep_tamper"))
            self.app.store.db.commit()
        status, headers, data = self.get(
            "/v1/pact/grants/grant_ep_tamper/audit",
            key=self.verifier_key)
        self.assertEqual(status, 200)
        body = self.check_signature(headers, data)
        self.assertFalse(body["chain"]["valid"])
        self.assertEqual(body["chain"]["detail"],
                         "seq 2: receipt claims do not match logged hash")


class TestTraceAuditAdapter(PactUnitCase):
    SESSION_OVERRIDES = {"expires_at": "2027-10-15T00:55:42+00:00"}

    def test_feed_shape_for_grant_with_receipts(self):
        consent = self.mint()
        self.fill_log()
        feed = audit_feed_for_grant(self.store, self.keys, GRANT_ID)
        self.assertIsNotNone(feed)
        audit = feed["audit"]
        self.assertEqual(audit["client"], SESSION["brand_id"])
        self.assertEqual(audit["scope"]["trace_count"], 3)
        self.assertEqual(audit["scope"]["agents"], [SESSION["pa_iss"]])
        self.assertEqual(audit["scope"]["window"]["from"],
                         "2026-10-14T23:56:35+00:00")
        self.assertEqual(audit["scope"]["window"]["to"],
                         "2026-10-15T00:00:40+00:00")
        self.assertEqual(audit["status"], "complete")
        self.assertIsNone(audit["claim_id"])
        self.assertEqual(feed["layer_presence"], {"3": "present"})
        self.assertTrue(feed["chain"]["valid"])
        records = feed["records"]
        self.assertEqual([r["seq"] for r in records], [1, 2, 3])
        self.assertEqual(records[0]["layer"], 3)
        self.assertEqual(records[0]["tool"], "flights.listUpcoming")
        self.assertEqual(records[1]["scopes_used"],
                         ["flights:history:read"])
        self.assertEqual(feed["grant"]["consent_record_id"],
                         consent["record_id"])
        self.assertEqual(feed["grant"]["status"], "active")

    def test_feed_reflects_revocation(self):
        self.mint()
        self.fill_log()
        pact.revoke_grant(self.store, self.keys, GRANT_ID, "user",
                          "adapter test")
        feed = audit_feed_for_grant(self.store, self.keys, GRANT_ID)
        self.assertEqual(feed["grant"]["status"], "revoked")

    def test_feed_for_empty_and_unknown_grants(self):
        self.mint()
        feed = audit_feed_for_grant(self.store, self.keys, GRANT_ID)
        self.assertEqual(feed["audit"]["scope"]["trace_count"], 0)
        self.assertEqual(feed["layer_presence"], {"3": "absent"})
        self.assertIsNone(
            audit_feed_for_grant(self.store, self.keys, "grant_nope"))


if __name__ == "__main__":
    unittest.main()
