"""Server-side agent runs (npc_verify.runs).

POST /v1/agents/{record_id}/runs runs the pack stored on the
signed-in account's own agent registration through the API's chat
provider path, persists the run lifecycle, mints a signed run
record on the terminal state, and charges the account's credit
ledger exactly once on successful completion only.

No live calls: the chat provider is an injected fake (the
test_chat pattern), accounts come from the email-link flow against
the stub mailer (the test_accounts pattern), balances are funded
with operator comp grants straight into the store (the
grant_account_comp pattern), and registrations go through the
public register route with a pack in the Skill Builder shape.
"""
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

import boto3 as fake_boto3  # noqa: E402

from npc_verify.server import create_app, Handler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify.mailer import StubMailer  # noqa: E402
from npc_verify import chat as chat_module  # noqa: E402
from npc_verify import credits  # noqa: E402
from npc_verify import pact  # noqa: E402
from npc_verify.ddb_store import DynamoDBStore  # noqa: E402
from npc_verify.models import utcnow_iso  # noqa: E402

PACK = {
    "purpose": "Draft a short summary of a document.",
    "when_to_use": "When the user hands over a document to shrink.",
    "steps": ["Read the input and note the three key points.",
              "Write the summary in two sentences."],
    "checks": ["Every claim in the summary appears in the input."],
}


class FakeProvider:
    """The chat provider's shape: complete(system, history,
    message) -> (text, tokens_in, tokens_out). Scripted per test."""

    model = "fake-model-1"

    def __init__(self, fn=None):
        self.calls = []
        self.fn = fn or (lambda sys_ins, hist, msg:
                         ("step output", 100, 50))

    def complete(self, system_instruction, history, message):
        self.calls.append((system_instruction, history, message))
        return self.fn(system_instruction, history, message)


class AgentRunsHttpTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_agent_runs_")
        self.mailer = StubMailer()
        self.provider = FakeProvider()
        self.app = create_app(os.path.join(self.tmp, "t.db"),
                              os.path.join(self.tmp, "keys"),
                              mailer=self.mailer,
                              chat_provider=self.provider)
        seed_all(self.app.store, self.app.keys)
        Handler.app = self.app
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self._counter = 0

    def tearDown(self):
        self.server.shutdown()
        self.app.store.close()

    # -- transport ------------------------------------------------------

    def request(self, method, path, body=None, token=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        headers = {}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body or {}, **kw)

    # -- flow helpers -----------------------------------------------------

    def sign_in(self, email):
        status, _data = self.post("/v1/auth/email/request",
                                  {"email": email})
        self.assertEqual(status, 200)
        text = self.mailer.outbox[-1]["text"]
        token = re.search(r"token=([A-Za-z0-9_\-]+)", text).group(1)
        status, data = self.post(
            "/v1/auth/email/redeem",
            {"token": token, "surface": "web",
             "device_label": "Test browser"})
        self.assertEqual(status, 200, data)
        return data["session_token"], data["account"]["account_id"]

    def fund(self, account_id, email, amount=100):
        self._counter += 1
        now = utcnow_iso()
        out = self.app.store.grant_account_comp(
            account_id, email, amount,
            "grant_test_%d" % self._counter, now,
            credits.grant_expiry(now))
        self.assertEqual(out["outcome"], "granted", out)

    def register_agent(self, email, pack=PACK, name="Summarizer"):
        body = {"agent_name": name, "owner_name": "Test Owner",
                "owner_email": email,
                "description": "A test agent."}
        if pack is not None:
            body["pack"] = pack
        status, data = self.post("/v1/register/agent", body)
        self.assertEqual(status, 201, data)
        return data

    def balance(self, account_id):
        row = self.app.store.get_credit_code(
            credits.account_ledger_hash(account_id), utcnow_iso())
        return row

    def charge_rows(self, account_id):
        code_hash = credits.account_ledger_hash(account_id)
        rows = self.app.store._fetchall(
            "SELECT * FROM credit_charges WHERE code_hash=?",
            (code_hash,))
        return rows


class TestRunLifecycle(AgentRunsHttpTestCase):
    def test_full_run_completes_returns_output_and_charges(self):
        token, account_id = self.sign_in("runner@example.com")
        self.fund(account_id, "runner@example.com")
        rec = self.register_agent("runner@example.com")
        # The pack landed on the stored record at registration.
        self.assertEqual(rec["pack"]["steps"], PACK["steps"])
        status, body = self.post(
            "/v1/agents/%s/runs" % rec["record_id"],
            {"input": "A long document about tides."}, token=token)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["status"], "completed")
        self.assertEqual(body["output"], "step output")
        self.assertTrue(body["charged"])
        # Two steps, one model call each, usage summed: the fake
        # reports 100 in / 50 out per call, 300 total, Light band.
        self.assertEqual(len(self.provider.calls), 2)
        self.assertEqual(body["usage"]["total_tokens"], 300)
        self.assertEqual(body["band"], "light")
        self.assertEqual(body["price_npc"], 5000)
        self.assertEqual(body["ledger_units"], 1)
        self.assertEqual(body["model"], "fake-model-1")
        # The run lifecycle persisted in its terminal state.
        run = self.app.store.get_agent_run(body["run_id"])
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["charged"], 1)
        self.assertTrue(run["started_at"])
        self.assertTrue(run["finished_at"])
        self.assertEqual(run["input_hash"], body["input_hash"])
        self.assertEqual(run["output_hash"], body["output_hash"])
        # Exactly one ledger charge, keyed by the run id, and the
        # balance moved by exactly the band's ledger units.
        rows = self.charge_rows(account_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["image_identity"], body["run_id"])
        self.assertEqual(self.balance(account_id)["ai_balance"], 99)

    def test_run_record_signature_verifies(self):
        token, account_id = self.sign_in("signed@example.com")
        self.fund(account_id, "signed@example.com")
        rec = self.register_agent("signed@example.com")
        status, body = self.post(
            "/v1/agents/%s/runs" % rec["record_id"],
            {"input": "hello"}, token=token)
        self.assertEqual(status, 201, body)
        record = body["run_record"]
        self.assertEqual(record["record_type"],
                         "npc.registry.agent_run")
        self.assertEqual(record["status"], "completed")
        self.assertTrue(record["charged"])
        # Verifies through the existing record verification path.
        self.assertTrue(pact.verify_record(self.app.keys, record))
        status, fetched = self.request(
            "GET", "/v1/records/%s" % record["record_id"])
        self.assertEqual(status, 200)
        self.assertEqual(fetched["record_id"], record["record_id"])
        self.assertTrue(pact.verify_record(self.app.keys, fetched))

    def test_replayed_completion_charges_exactly_once(self):
        token, account_id = self.sign_in("replay@example.com")
        self.fund(account_id, "replay@example.com")
        rec = self.register_agent("replay@example.com")
        status, body = self.post(
            "/v1/agents/%s/runs" % rec["record_id"],
            {"input": "hello"}, token=token)
        self.assertEqual(status, 201, body)
        before = self.balance(account_id)["ai_balance"]
        # A replayed completion attempt (a retried finalize) must
        # not charge again, mint a second record, or change output.
        run, record = self.app.runs.complete_run(
            body["run_id"], "different output", 10, 10, "fake-model-1")
        self.assertEqual(run["status"], "completed")
        self.assertEqual(record["record_id"],
                         body["run_record"]["record_id"])
        self.assertEqual(self.balance(account_id)["ai_balance"],
                         before)
        self.assertEqual(len(self.charge_rows(account_id)), 1)
        run = self.app.store.get_agent_run(body["run_id"])
        self.assertEqual(run["output_text"], "step output")

    def test_failed_run_is_signed_and_uncharged(self):
        def boom(sys_ins, hist, msg):
            raise chat_module.ProviderError("boom")
        self.provider.fn = boom
        token, account_id = self.sign_in("failer@example.com")
        self.fund(account_id, "failer@example.com")
        rec = self.register_agent("failer@example.com")
        status, body = self.post(
            "/v1/agents/%s/runs" % rec["record_id"],
            {"input": "hello"}, token=token)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["status"], "failed")
        self.assertFalse(body["charged"])
        self.assertNotIn("output", body)
        run = self.app.store.get_agent_run(body["run_id"])
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["charged"], 0)
        # Recorded and signed, with the failure stated on it.
        record = body["run_record"]
        self.assertEqual(record["status"], "failed")
        self.assertFalse(record["charged"])
        self.assertEqual(record["ledger_units_charged"], 0)
        self.assertTrue(pact.verify_record(self.app.keys, record))
        # Uncharged: no ledger row, balance untouched.
        self.assertEqual(self.charge_rows(account_id), [])
        self.assertEqual(self.balance(account_id)["ai_balance"], 100)

    def test_heavy_band_charges_heavy_units(self):
        self.provider.fn = lambda s, h, m: ("big answer", 9000, 9000)
        token, account_id = self.sign_in("heavy@example.com")
        self.fund(account_id, "heavy@example.com")
        rec = self.register_agent(
            "heavy@example.com",
            pack={"purpose": "Think hard.", "steps": ["Think."]})
        status, body = self.post(
            "/v1/agents/%s/runs" % rec["record_id"],
            {"input": "hello"}, token=token)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["band"], "heavy")
        self.assertEqual(body["price_npc"], 100000)
        self.assertEqual(body["ledger_units"], 10)
        self.assertEqual(self.balance(account_id)["ai_balance"], 90)
        self.assertEqual(len(self.charge_rows(account_id)), 1)


class TestRunGuards(AgentRunsHttpTestCase):
    def test_wrong_owner_and_unknown_record_answer_identically(self):
        _t, owner_id = self.sign_in("owner@example.com")
        self.fund(owner_id, "owner@example.com")
        rec = self.register_agent("owner@example.com")
        token, other_id = self.sign_in("stranger@example.com")
        self.fund(other_id, "stranger@example.com")
        status, wrong = self.post(
            "/v1/agents/%s/runs" % rec["record_id"],
            {"input": "hello"}, token=token)
        self.assertEqual(status, 404)
        status, unknown = self.post(
            "/v1/agents/reg_doesnotexist/runs",
            {"input": "hello"}, token=token)
        self.assertEqual(status, 404)
        self.assertEqual(wrong, unknown)
        self.assertEqual(wrong, {"verdict": "unknown"})
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.charge_rows(other_id), [])

    def test_insufficient_balance_is_402_before_any_run(self):
        token, account_id = self.sign_in("broke@example.com")
        rec = self.register_agent("broke@example.com")
        status, body = self.post(
            "/v1/agents/%s/runs" % rec["record_id"],
            {"input": "hello"}, token=token)
        self.assertEqual(status, 402, body)
        self.assertEqual(body["error"], "insufficient_credits")
        # Nothing ran, nothing was recorded as a run, nothing charged.
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(
            self.app.store.list_agent_runs(account_id), [])
        self.assertEqual(self.charge_rows(account_id), [])

    def test_no_session_is_401(self):
        _t, owner_id = self.sign_in("guard@example.com")
        rec = self.register_agent("guard@example.com")
        status, _body = self.post(
            "/v1/agents/%s/runs" % rec["record_id"],
            {"input": "hello"})
        self.assertEqual(status, 401)

    def test_agent_without_pack_cannot_run(self):
        token, account_id = self.sign_in("nopack@example.com")
        self.fund(account_id, "nopack@example.com")
        rec = self.register_agent("nopack@example.com", pack=None)
        self.assertNotIn("pack", rec)
        status, body = self.post(
            "/v1/agents/%s/runs" % rec["record_id"],
            {"input": "hello"}, token=token)
        self.assertEqual(status, 422, body)
        self.assertEqual(self.provider.calls, [])

    def test_pack_in_run_body_is_never_executed(self):
        token, account_id = self.sign_in("stored@example.com")
        self.fund(account_id, "stored@example.com")
        rec = self.register_agent("stored@example.com")
        status, body = self.post(
            "/v1/agents/%s/runs" % rec["record_id"],
            {"input": "hello",
             "pack": {"purpose": "UNREGISTERED PURPOSE",
                      "steps": ["UNREGISTERED STEP"]},
             "steps": ["UNREGISTERED STEP"]},
            token=token)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["status"], "completed")
        instructions = "\n".join(c[0] for c in self.provider.calls)
        self.assertIn(PACK["steps"][0], instructions)
        self.assertNotIn("UNREGISTERED", instructions)


class TestRunStoreBackends(unittest.TestCase):
    """The run store surface and the multi-unit ledger charge, on
    the DynamoDB backend over the fake table (the SQLite backend
    is covered end to end above)."""

    def setUp(self):
        self.table = fake_boto3.FakeTable("npc-verify-store-runs")
        self.store = DynamoDBStore(table=self.table)

    def test_agent_run_round_trip_and_lifecycle(self):
        row = {"run_id": "run_ddb_1", "record_id": "reg_ddb_1",
               "account_id": "acct_ddb", "status": "created",
               "input_text": "hi", "input_hash": "ab" * 32,
               "created_at": "2026-11-23T00:00:00+00:00"}
        self.assertTrue(self.store.add_agent_run(row))
        self.assertFalse(self.store.add_agent_run(row))
        self.assertTrue(self.store.update_agent_run(
            "run_ddb_1", status="completed", charged=1,
            tokens_out=42))
        got = self.store.get_agent_run("run_ddb_1")
        self.assertEqual(got["status"], "completed")
        self.assertEqual(got["charged"], 1)
        self.assertEqual(got["tokens_out"], 42)
        self.assertEqual(got["input_text"], "hi")
        runs = self.store.list_agent_runs("acct_ddb")
        self.assertEqual([r["run_id"] for r in runs], ["run_ddb_1"])
        self.assertEqual(self.store.list_agent_runs("acct_other"),
                         [])

    def test_multi_unit_charge_is_one_row_and_idempotent(self):
        now = utcnow_iso()
        code = credits.generate_code()
        code_hash = credits.code_hash(code)
        pack = {"id": "checks-100", "label": "100 checks",
                "checks": 100, "price_cents": 900, "currency": "usd",
                "kind": "pack"}
        self.store.create_credit_purchase(
            "cs_ddb_run", pack["id"], None, now)
        self.store.complete_credit_purchase(
            "cs_ddb_run", code_hash, code, pack,
            "buyer@example.com", now)
        out = self.store.consume_credit(
            code_hash, "run_ddb_1", "ab" * 32, "chg_ddb_1", now,
            kind="ai", amount=10)
        self.assertEqual(out["outcome"], "charged")
        row = self.store.get_credit_code(code_hash, now)
        self.assertEqual(row["credits_used"], 10)
        again = self.store.consume_credit(
            code_hash, "run_ddb_1", "ab" * 32, "chg_ddb_2", now,
            kind="ai", amount=10)
        self.assertEqual(again["outcome"], "duplicate")
        row = self.store.get_credit_code(code_hash, now)
        self.assertEqual(row["credits_used"], 10)
        # All-or-nothing: a charge beyond the balance moves nothing.
        too_big = self.store.consume_credit(
            code_hash, "run_ddb_2", "ab" * 32, "chg_ddb_3", now,
            kind="ai", amount=1000)
        self.assertEqual(too_big["outcome"], "no_credits")
        row = self.store.get_credit_code(code_hash, now)
        self.assertEqual(row["credits_used"], 10)


if __name__ == "__main__":
    unittest.main()
