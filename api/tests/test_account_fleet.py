"""Account fleet (Fleet tab, 2026-11-21).

GET /v1/account/fleet serves the session account's own agent
registrations, newest first, with counts computed from the same
list: registrations are keyed by owner email, the account is
rooted at the same email, and one account never sees another's
agents. Each entry carries the full signed registration record
and, when the record declared an agent_id that has an attestation
row in the agents table, that row's summary. Registration is
never dressed as verification: no verified count is served.

Accounts come from the email-link flow against the stub mailer
(the test_accounts / test_account_checks pattern), agent
registrations are minted through the public POST
/v1/register/agent route, and attestation rows are inserted
straight into the store (the seed pattern). The DynamoDB store's
registrations_by_email is smoke-tested against the repo's fake
boto3 table (the test_ddb_store pattern).
"""
import base64
import http.client
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
FAKE_DIR = os.path.join(BASE, "serverless", "lambda_v3", "fake_boto3")
sys.path.insert(0, FAKE_DIR)

os.environ["NPC_AUTH_RP_ID"] = "localhost"
os.environ["NPC_AUTH_ORIGINS"] = "http://127.0.0.1"
os.environ["NPC_AUTH_SITE_BASE"] = "http://127.0.0.1"

import boto3 as fake_boto3  # noqa: E402  (the fake; see FAKE_DIR)

from npc_verify.server import create_app, Handler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify.mailer import StubMailer  # noqa: E402
from npc_verify import ed25519  # noqa: E402
from npc_verify.canonical import canonicalize  # noqa: E402
from npc_verify.ddb_store import DynamoDBStore  # noqa: E402

SHA_LOCATOR = "sha256:" + "ab" * 32


class AccountFleetTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_acct_fleet_")
        self.mailer = StubMailer()
        self.app = create_app(os.path.join(self.tmp, "t.db"),
                              os.path.join(self.tmp, "keys"),
                              mailer=self.mailer)
        seeded = seed_all(self.app.store, self.app.keys)
        self.verifier_key = seeded["verifier_key"]
        Handler.app = self.app
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.app.store.close()

    # -- transport ------------------------------------------------------

    def request(self, method, path, body=None, token=None, key=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        headers = {}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        if key:
            headers["Authorization"] = "Bearer " + key
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, dict(resp.getheaders()), raw

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body or {}, **kw)

    def check_signature(self, headers, body_bytes):
        """Verify X-NPC-Signature against /v1/keys; returns the body."""
        sig = base64.b64decode(headers["X-NPC-Signature"])
        key_id = headers["X-NPC-Key-ID"]
        _s, _h, kdata = self.get("/v1/keys")
        keys_doc = json.loads(kdata)
        cur = keys_doc["api_signing"]["current"]
        self.assertEqual(cur["key_id"], key_id)
        pub = base64.b64decode(cur["public_key"])
        parsed = json.loads(body_bytes)
        self.assertEqual(canonicalize(parsed), body_bytes)
        self.assertTrue(ed25519.verify(pub, body_bytes, sig))
        return parsed

    # -- flow helpers -----------------------------------------------------

    def sign_in(self, email):
        status, _h, _raw = self.post("/v1/auth/email/request",
                                     {"email": email})
        self.assertEqual(status, 200)
        text = self.mailer.outbox[-1]["text"]
        token = re.search(r"token=([A-Za-z0-9_\-]+)", text).group(1)
        status, _h, raw = self.post(
            "/v1/auth/email/redeem",
            {"token": token, "surface": "desktop",
             "device_label": "Test desktop"})
        self.assertEqual(status, 200, raw)
        return json.loads(raw)["session_token"]

    def register_agent(self, email, agent_name="Harbor Helper",
                       agent_id=None):
        body = {"agent_name": agent_name,
                "owner_name": "Fleet Owner",
                "owner_email": email,
                "homepage": "https://example.com/" +
                            agent_name.lower().replace(" ", "-")}
        if agent_id is not None:
            body["agent_id"] = agent_id
        status, _h, raw = self.post("/v1/register/agent", body)
        self.assertEqual(status, 201, raw)
        return json.loads(raw)

    def register_content(self, email):
        status, _h, raw = self.post("/v1/register/content", {
            "title": "Fleet Test Essay", "kind": "text",
            "locator": SHA_LOCATOR, "creator_name": "Fleet Owner",
            "creator_email": email})
        self.assertEqual(status, 201, raw)
        return json.loads(raw)

    def fleet(self, token):
        status, headers, raw = self.get("/v1/account/fleet",
                                        token=token)
        self.assertEqual(status, 200, raw)
        return self.check_signature(headers, raw)

    # -- auth separation --------------------------------------------------

    def test_no_session_is_401(self):
        status, _h, _raw = self.get("/v1/account/fleet")
        self.assertEqual(status, 401)

    def test_api_key_does_not_authenticate_account_route(self):
        status, _h, _raw = self.get("/v1/account/fleet",
                                    key=self.verifier_key)
        self.assertEqual(status, 401)

    # -- the fleet --------------------------------------------------------

    def test_fresh_account_fleet_is_empty(self):
        token = self.sign_in("ada@example.com")
        body = self.fleet(token)
        self.assertEqual(body["counts"], {
            "total": 0, "with_declared_identity": 0,
            "with_attestations": 0})
        self.assertNotIn("verified", body["counts"])
        self.assertEqual(body["agents"], [])

    def test_agent_under_account_email_appears(self):
        token = self.sign_in("ada@example.com")
        rec = self.register_agent("ada@example.com")
        body = self.fleet(token)
        self.assertEqual(body["counts"], {
            "total": 1, "with_declared_identity": 0,
            "with_attestations": 0})
        self.assertEqual(len(body["agents"]), 1)
        entry = body["agents"][0]
        # The record is the full signed registration, exactly as
        # minted, and registration is not dressed as verification.
        self.assertEqual(entry["record"], rec)
        self.assertEqual(entry["record"]["kind"], "agent")
        self.assertEqual(entry["record"]["agent_name"],
                         "Harbor Helper")
        self.assertEqual(entry["record"]["owner_name"],
                         "Fleet Owner")
        self.assertEqual(entry["record"]["status"],
                         "registered_checks_pending")
        self.assertNotIn("verdict", entry["record"])
        self.assertIsNone(entry["attestation"])

    def test_second_agent_raises_total_to_two(self):
        token = self.sign_in("ada@example.com")
        first = self.register_agent("ada@example.com", "First Agent")
        second = self.register_agent("ada@example.com",
                                     "Second Agent")
        body = self.fleet(token)
        self.assertEqual(body["counts"]["total"], 2)
        self.assertEqual(len(body["agents"]), 2)
        # Newest first.
        self.assertEqual(
            [a["record"]["record_id"] for a in body["agents"]],
            [second["record_id"], first["record_id"]])

    def test_agent_under_different_email_never_appears(self):
        self.register_agent("grace@example.com", "Grace Agent")
        token = self.sign_in("ada@example.com")
        body = self.fleet(token)
        self.assertEqual(body["counts"]["total"], 0)
        self.assertEqual(body["agents"], [])
        # The other account does see its own agent.
        other = self.sign_in("grace@example.com")
        body = self.fleet(other)
        self.assertEqual(body["counts"]["total"], 1)
        self.assertEqual(body["agents"][0]["record"]["agent_name"],
                         "Grace Agent")

    def test_content_registration_does_not_appear(self):
        token = self.sign_in("ada@example.com")
        self.register_content("ada@example.com")
        body = self.fleet(token)
        self.assertEqual(body["counts"]["total"], 0)
        self.assertEqual(body["agents"], [])

    def test_attestation_summary_and_counts(self):
        token = self.sign_in("ada@example.com")
        self.app.store.insert_agent(
            "agent_fleet_scout", "verified",
            {"capabilities": ["test-navigation"]},
            "2026-09-20T12:00:00+00:00", "2027-09-20T12:00:00+00:00",
            "att_fleet_scout", "Test harness evaluation.")
        self.register_agent("ada@example.com", "Fleet Scout",
                            agent_id="agent_fleet_scout")
        body = self.fleet(token)
        self.assertEqual(body["counts"], {
            "total": 1, "with_declared_identity": 1,
            "with_attestations": 1})
        entry = body["agents"][0]
        self.assertEqual(entry["record"]["agent_id"],
                         "agent_fleet_scout")
        self.assertEqual(entry["attestation"], {
            "agent_id": "agent_fleet_scout",
            "verdict": "verified",
            "valid_from": "2026-09-20T12:00:00+00:00",
            "valid_until": "2027-09-20T12:00:00+00:00",
            "revoked": False})

    def test_declared_identity_without_attestation_row(self):
        token = self.sign_in("ada@example.com")
        self.register_agent("ada@example.com", "Unattested Agent",
                            agent_id="agent_fleet_unattested")
        body = self.fleet(token)
        self.assertEqual(body["counts"], {
            "total": 1, "with_declared_identity": 1,
            "with_attestations": 0})
        self.assertIsNone(body["agents"][0]["attestation"])

    def test_agent_without_declared_id_has_null_attestation(self):
        token = self.sign_in("ada@example.com")
        rec = self.register_agent("ada@example.com")
        self.assertNotIn("agent_id", rec)
        body = self.fleet(token)
        self.assertEqual(body["counts"], {
            "total": 1, "with_declared_identity": 0,
            "with_attestations": 0})
        self.assertIsNone(body["agents"][0]["attestation"])


def _ddb_record(record_id, kind, registered_at):
    return {"record_id": record_id, "kind": kind,
            "agent_name": "DD Agent", "owner_name": "Fleet Owner",
            "registered_at": registered_at,
            "status": "registered_checks_pending",
            "signature": "c2ln"}


class TestDynamoDBRegistrationsByEmail(unittest.TestCase):
    """DDB parity smoke test: registrations_by_email against the
    fake boto3 table, the test_ddb_store pattern."""

    def setUp(self):
        self.table = fake_boto3.FakeTable("npc-verify-store-test")
        self.store = DynamoDBStore(table=self.table)

    def test_filters_by_email_hash_and_kind_newest_first(self):
        older = _ddb_record("reg_dd_1", "agent",
                            "2026-10-14T01:00:00+00:00")
        newer = _ddb_record("reg_dd_2", "agent",
                            "2026-10-14T05:00:00+00:00")
        content = _ddb_record("reg_dd_3", "content",
                              "2026-10-14T06:00:00+00:00")
        other = _ddb_record("reg_dd_4", "agent",
                            "2026-10-14T07:00:00+00:00")
        self.store.add_registration(older, "a@example.com",
                                    "203.0.113.9")
        self.store.add_registration(newer, "a@example.com",
                                    "203.0.113.9")
        self.store.add_registration(content, "a@example.com",
                                    "203.0.113.9")
        self.store.add_registration(other, "b@example.com",
                                    "203.0.113.9")
        rows = self.store.registrations_by_email("a@example.com")
        self.assertEqual([r["record_id"] for r in rows],
                         ["reg_dd_2", "reg_dd_1"])
        self.assertEqual(rows[0], newer)
        rows = self.store.registrations_by_email(
            "a@example.com", kind="content")
        self.assertEqual([r["record_id"] for r in rows],
                         ["reg_dd_3"])
        self.assertEqual(
            self.store.registrations_by_email("nobody@example.com"),
            [])


if __name__ == "__main__":
    unittest.main()
