"""Paid check credits: ledger, checkout, webhook, redeem, consume.

Everything runs locally: Stripe is a fake transport plus the real
stdlib webhook verifier, the mailer is a recording stub, and no live
charge or network call exists anywhere in this file.
"""
import base64
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from http.server import ThreadingHTTPServer  # noqa: E402

from npc_verify import credits  # noqa: E402
from npc_verify.canonical import canonicalize  # noqa: E402
from npc_verify import ed25519  # noqa: E402
from npc_verify.server import create_app, Handler  # noqa: E402
from npc_verify.store import Store  # noqa: E402

WEBHOOK_SECRET = "whsec_test_only_not_a_real_secret"
PACKS_JSON = json.dumps([
    {"id": "starter", "label": "25 checks", "checks": 25,
     "price_cents": 900, "currency": "usd",
     "stripe_price_id": "price_test_starter"},
    {"id": "trio", "label": "3 checks", "checks": 3,
     "price_cents": 300, "currency": "usd",
     "stripe_price_id": "price_test_trio"},
])

IDENT_A = "sha256:" + "ab" * 32
IDENT_B = "sha256:" + "cd" * 32
IDENT_C = "url-sha256:" + "ef" * 32
IDENT_D = "sha256:" + "12" * 32


class FakePayments:
    """Injectable payments double: deterministic sessions, and the
    REAL webhook verifier (a StripePayments holding only the test
    webhook secret) so signature behavior is genuinely exercised."""

    configured = True

    def __init__(self):
        self.sessions = []
        self._verifier = credits.StripePayments(
            "sk_test_fake", WEBHOOK_SECRET,
            "https://verify.example/get-checks?session_id=x",
            "https://verify.example/get-checks",
            transport=self._no_transport)

    def _no_transport(self, *a, **k):
        raise AssertionError("webhook verifier must not call out")

    def create_checkout_session(self, pack, email=None):
        sid = "cs_test_%04d" % (len(self.sessions) + 1)
        self.sessions.append({"id": sid, "pack": pack, "email": email})
        return {"id": sid,
                "url": "https://checkout.stripe.test/pay/" + sid}

    def verify_webhook(self, raw_body, signature_header, now=None):
        return self._verifier.verify_webhook(
            raw_body, signature_header, now=now)


class StubMailer:
    enabled = True

    def __init__(self):
        self.sent = []

    def send(self, to, subject, text, html_body):
        self.sent.append({"to": to, "subject": subject,
                          "text": text, "html": html_body})
        return True


class CreditsHttpBase(unittest.TestCase):
    packs_env = PACKS_JSON
    payments_factory = FakePayments

    def setUp(self):
        self._old_packs = os.environ.get("NPC_CREDITS_PACKS_JSON")
        if self.packs_env is None:
            os.environ.pop("NPC_CREDITS_PACKS_JSON", None)
        else:
            os.environ["NPC_CREDITS_PACKS_JSON"] = self.packs_env
        self.tmp = tempfile.mkdtemp(prefix="npc_credits_test_")
        self.payments = self.payments_factory()
        self.mailer = StubMailer()
        self.app = create_app(
            os.path.join(self.tmp, "t.db"),
            os.path.join(self.tmp, "keys"),
            payments=self.payments, mailer=self.mailer)
        Handler.app = self.app
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.app.store.close()
        if self._old_packs is None:
            os.environ.pop("NPC_CREDITS_PACKS_JSON", None)
        else:
            os.environ["NPC_CREDITS_PACKS_JSON"] = self._old_packs

    # -- HTTP helpers ---------------------------------------------------
    def request(self, method, path, body=None, raw_body=None,
                headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        hdrs = dict(headers or {})
        payload = raw_body
        if body is not None:
            payload = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, dict(resp.getheaders()), data

    def post(self, path, body):
        return self.request("POST", path, body=body)

    def get(self, path):
        return self.request("GET", path)

    def check_signature(self, headers, body_bytes):
        sig = base64.b64decode(headers["X-NPC-Signature"])
        key_id = headers["X-NPC-Key-ID"]
        _s, _h, kdata = self.get("/v1/keys")
        keys_doc = json.loads(kdata)
        cur = keys_doc["api_signing"]["current"]
        pub = base64.b64decode(cur["public_key"])
        self.assertEqual(cur["key_id"], key_id)
        parsed = json.loads(body_bytes)
        self.assertEqual(canonicalize(parsed), body_bytes)
        self.assertTrue(ed25519.verify(pub, body_bytes, sig))

    # -- flow helpers -----------------------------------------------------
    def buy(self, pack_id="trio", email=None):
        body = {"pack_id": pack_id}
        if email:
            body["email"] = email
        status, _h, data = self.post("/v1/credits/checkout", body)
        self.assertEqual(status, 201, data)
        return json.loads(data)["session_id"]

    def fire_webhook(self, session_id, email="buyer@example.com",
                     event_type="checkout.session.completed"):
        event = {"id": "evt_test_1", "type": event_type,
                 "data": {"object": {
                     "id": session_id,
                     "customer_details": {"email": email}}}}
        raw = json.dumps(event).encode()
        header = credits.sign_webhook_payload(
            WEBHOOK_SECRET, raw, int(time.time()))
        return self.request("POST", "/v1/credits/stripe-webhook",
                            raw_body=raw,
                            headers={"Stripe-Signature": header,
                                     "Content-Type": "application/json"})

    def paid_code(self, pack_id="trio", email="buyer@example.com"):
        sid = self.buy(pack_id, email=email)
        status, _h, data = self.fire_webhook(sid, email=email)
        self.assertEqual(status, 200, data)
        status, _h, data = self.get(
            "/v1/credits/checkout-status?session_id=" + sid)
        self.assertEqual(status, 200, data)
        return json.loads(data)["code"]


class CreditsFlowTest(CreditsHttpBase):

    def test_packs_endpoint_shape(self):
        status, headers, data = self.get("/v1/credits/packs")
        self.assertEqual(status, 200)
        self.check_signature(headers, data)
        body = json.loads(data)
        self.assertEqual(body["packs_source"], "environment")
        self.assertTrue(body["checkout_available"])
        ids = [p["id"] for p in body["packs"]]
        self.assertEqual(ids, ["starter", "trio"])
        self.assertEqual(body["packs"][0]["price_cents"], 900)
        self.assertTrue(all(p["on_sale"] for p in body["packs"]))

    def test_checkout_creates_pending_purchase(self):
        sid = self.buy("trio")
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["status"], "pending")
        self.assertEqual(purchase["pack_id"], "trio")

    def test_checkout_unknown_pack_rejected(self):
        status, _h, _d = self.post("/v1/credits/checkout",
                                   {"pack_id": "nope"})
        self.assertEqual(status, 400)

    def test_webhook_grants_code_and_emails_it_once(self):
        sid = self.buy("trio", email="buyer@example.com")
        status, _h, _d = self.fire_webhook(sid)
        self.assertEqual(status, 200)
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["status"], "paid")
        self.assertIsNotNone(purchase["code_hash"])
        self.assertEqual(len(self.mailer.sent), 1)
        mail = self.mailer.sent[0]
        self.assertEqual(mail["to"], "buyer@example.com")
        self.assertEqual(mail["subject"],
                         "Your NPC Verify checks code")
        # replay: no second code, no second email
        first_hash = purchase["code_hash"]
        status, _h, _d = self.fire_webhook(sid)
        self.assertEqual(status, 200)
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["code_hash"], first_hash)
        self.assertEqual(len(self.mailer.sent), 1)

    def test_webhook_bad_signature_rejected(self):
        sid = self.buy("trio")
        event = {"id": "evt_x", "type": "checkout.session.completed",
                 "data": {"object": {"id": sid}}}
        raw = json.dumps(event).encode()
        status, _h, _d = self.request(
            "POST", "/v1/credits/stripe-webhook", raw_body=raw,
            headers={"Stripe-Signature": "t=1,v1=deadbeef",
                     "Content-Type": "application/json"})
        self.assertEqual(status, 400)
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["status"], "pending")

    def test_code_delivered_exactly_once(self):
        sid = self.buy("trio")
        self.fire_webhook(sid)
        status, _h, data = self.get(
            "/v1/credits/checkout-status?session_id=" + sid)
        body = json.loads(data)
        self.assertEqual(body["status"], "paid")
        self.assertEqual(body["checks"], 3)
        self.assertTrue(body["delivered_with_this_response"])
        code = body["code"]
        self.assertTrue(credits.valid_code_shape(code))
        # the emailed code is the delivered code
        self.assertIn(code, self.mailer.sent[0]["text"])
        status, _h, data = self.get(
            "/v1/credits/checkout-status?session_id=" + sid)
        body = json.loads(data)
        self.assertNotIn("code", body)
        self.assertFalse(body["delivered_with_this_response"])
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertIsNone(purchase["code_plaintext"])

    def test_checkout_status_unknown_session(self):
        status, _h, _d = self.get(
            "/v1/credits/checkout-status?session_id=cs_test_nope")
        self.assertEqual(status, 404)

    def test_redeem_balance_consume_duplicate_exhaust(self):
        code = self.paid_code("trio")
        status, headers, data = self.post("/v1/credits/redeem",
                                          {"code": code})
        self.assertEqual(status, 200)
        self.check_signature(headers, data)
        body = json.loads(data)
        self.assertEqual(body["balance"], 3)
        self.assertEqual(body["credits_total"], 3)

        status, _h, data = self.post(
            "/v1/credits/consume",
            {"code": code, "image_identity": IDENT_A,
             "claim_hash": "ab" * 32})
        body = json.loads(data)
        self.assertEqual(status, 200)
        self.assertTrue(body["charged"])
        self.assertFalse(body["duplicate"])
        self.assertEqual(body["balance"], 2)

        # the same image again: answered, never charged twice
        status, _h, data = self.post(
            "/v1/credits/consume",
            {"code": code, "image_identity": IDENT_A})
        body = json.loads(data)
        self.assertEqual(status, 200)
        self.assertFalse(body["charged"])
        self.assertTrue(body["duplicate"])
        self.assertEqual(body["balance"], 2)

        status, _h, data = self.post("/v1/credits/balance",
                                     {"code": code})
        self.assertEqual(json.loads(data)["balance"], 2)

        self.post("/v1/credits/consume",
                  {"code": code, "image_identity": IDENT_B})
        status, _h, data = self.post(
            "/v1/credits/consume",
            {"code": code, "image_identity": IDENT_C})
        body = json.loads(data)
        self.assertTrue(body["charged"])
        self.assertEqual(body["balance"], 0)
        self.assertEqual(body["status"], "exhausted")

        status, _h, data = self.post(
            "/v1/credits/consume",
            {"code": code, "image_identity": IDENT_D})
        body = json.loads(data)
        self.assertEqual(status, 402)
        self.assertEqual(body["error"], "no_credits")
        self.assertFalse(body["charged"])

    def test_consume_hourly_backstop_answers_429(self):
        code = self.paid_code("trio")
        old = credits.CONSUME_HOURLY_LIMIT
        credits.CONSUME_HOURLY_LIMIT = 2
        try:
            for ident in (IDENT_A, IDENT_B):
                status, _h, data = self.post(
                    "/v1/credits/consume",
                    {"code": code, "image_identity": ident})
                self.assertEqual(status, 200, data)
                self.assertTrue(json.loads(data)["charged"])
            # a third new image inside the hour trips the
            # backstop, though one check remains on the code
            status, _h, data = self.post(
                "/v1/credits/consume",
                {"code": code, "image_identity": IDENT_C})
            body = json.loads(data)
            self.assertEqual(status, 429)
            self.assertEqual(body["error"], "rate_limited")
            self.assertFalse(body["charged"])
            self.assertEqual(body["balance"], 1)
            # a duplicate is still answered, never refused by it
            status, _h, data = self.post(
                "/v1/credits/consume",
                {"code": code, "image_identity": IDENT_A})
            body = json.loads(data)
            self.assertEqual(status, 200)
            self.assertTrue(body["duplicate"])
        finally:
            credits.CONSUME_HOURLY_LIMIT = old

    def test_unknown_and_malformed_codes(self):
        ghost = credits.generate_code()  # well-formed, never granted
        for path, payload in (
                ("/v1/credits/redeem", {"code": ghost}),
                ("/v1/credits/balance", {"code": ghost}),
                ("/v1/credits/consume",
                 {"code": ghost, "image_identity": IDENT_A})):
            status, _h, _d = self.post(path, payload)
            self.assertEqual(status, 404, path)
        status, _h, _d = self.post("/v1/credits/balance",
                                   {"code": "not-a-code"})
        self.assertEqual(status, 400)

    def test_expired_session_marks_purchase(self):
        sid = self.buy("trio")
        status, _h, _d = self.fire_webhook(
            sid, event_type="checkout.session.expired")
        self.assertEqual(status, 200)
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["status"], "expired")


class DefaultPacksTest(CreditsHttpBase):
    packs_env = None  # no NPC_CREDITS_PACKS_JSON: decided defaults

    def test_decided_launch_packs_are_the_defaults(self):
        status, _h, data = self.get("/v1/credits/packs")
        body = json.loads(data)
        self.assertEqual(body["packs_source"], "default")
        self.assertTrue(body["checkout_available"])
        self.assertEqual(
            [(p["id"], p["checks"], p["price_cents"])
             for p in body["packs"]],
            [("verifier-pass", 1000, 2500), ("checks-100", 100, 900),
             ("checks-250", 250, 1900)])
        # The Pass leads the list, on sale, with its terms exposed
        # (Bayo switched it on 2026-10-28).
        lead = body["packs"][0]
        self.assertEqual(lead["kind"], "access")
        self.assertTrue(lead["on_sale"])
        self.assertEqual(lead["ai_checks"], 400)
        self.assertEqual(lead["interval"], "month")
        self.assertTrue(lead["registry_unlimited"])
        self.assertTrue(all(p["on_sale"] for p in body["packs"]))

    def test_headline_pack_buys_and_redeems_100(self):
        code = self.paid_code("checks-100")
        status, _h, data = self.post("/v1/credits/redeem",
                                     {"code": code})
        body = json.loads(data)
        self.assertEqual(status, 200)
        self.assertEqual(body["credits_total"], 100)
        self.assertEqual(body["balance"], 100)


class UnconfiguredPaymentsTest(CreditsHttpBase):
    payments_factory = credits.UnconfiguredPayments

    def test_checkout_refused_until_payments_configured(self):
        status, _h, data = self.get("/v1/credits/packs")
        self.assertFalse(json.loads(data)["checkout_available"])
        status, _h, data = self.post(
            "/v1/credits/checkout", {"pack_id": "starter"})
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(data)["error"],
                         "payments_not_configured")


class AccessKindOnSaleTest(CreditsHttpBase):
    """The access kind is the Verifier Pass, on sale since Bayo's
    2026-10-28 decision (this class replaces the earlier
    reserved/not-on-sale test, which encoded the pre-launch hold)."""
    packs_env = json.dumps([
        {"id": "pass-monthly", "label": "Verifier Pass",
         "checks": 1000, "price_cents": 2500, "currency": "usd",
         "kind": "access", "ai_checks": 200, "interval": "month",
         "stripe_price_id": "price_test_pass_monthly"},
        {"id": "starter", "label": "25 checks", "checks": 25,
         "price_cents": 900, "currency": "usd",
         "stripe_price_id": "price_test_starter"},
    ])

    def test_access_kind_is_listed_on_sale(self):
        status, _h, data = self.get("/v1/credits/packs")
        body = json.loads(data)
        kinds = {p["id"]: (p["kind"], p["on_sale"])
                 for p in body["packs"]}
        self.assertEqual(kinds["pass-monthly"], ("access", True))
        self.assertEqual(kinds["starter"], ("pack", True))
        lead = [p for p in body["packs"]
                if p["id"] == "pass-monthly"][0]
        self.assertEqual(lead["ai_checks"], 200)
        self.assertEqual(lead["interval"], "month")
        # checkout starts for the Pass like any other pack
        sid = self.buy("pass-monthly")
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["status"], "pending")
        self.assertEqual(purchase["pack_id"], "pass-monthly")
        self.assertEqual(self.payments.sessions[0]["pack"]["kind"],
                         "access")


class PassFlowBase(CreditsHttpBase):
    """Shared helpers for the Verifier Pass flows: signed webhooks
    for the subscription event family."""

    def fire_event(self, event_type, obj, event_id="evt_pass_1"):
        event = {"id": event_id, "type": event_type,
                 "data": {"object": obj}}
        raw = json.dumps(event).encode()
        header = credits.sign_webhook_payload(
            WEBHOOK_SECRET, raw, int(time.time()))
        return self.request("POST", "/v1/credits/stripe-webhook",
                            raw_body=raw,
                            headers={"Stripe-Signature": header,
                                     "Content-Type": "application/json"})

    def subscribe(self, pack_id="verifier-pass",
                  subscription="sub_test_1", invoice="in_test_1",
                  email="member@example.com"):
        sid = self.buy(pack_id, email=email)
        status, _h, data = self.fire_event(
            "checkout.session.completed",
            {"id": sid, "subscription": subscription,
             "customer": "cus_test_1", "invoice": invoice,
             "customer_details": {"email": email}})
        self.assertEqual(status, 200, data)
        status, _h, data = self.get(
            "/v1/credits/checkout-status?session_id=" + sid)
        self.assertEqual(status, 200, data)
        body = json.loads(data)
        self.assertEqual(body["status"], "paid")
        return body["code"]

    def balance_of(self, code):
        status, _h, data = self.post("/v1/credits/balance",
                                     {"code": code})
        self.assertEqual(status, 200, data)
        return json.loads(data)

    def consume(self, code, identity, kind=None):
        payload = {"code": code, "image_identity": identity}
        if kind:
            payload["kind"] = kind
        status, _h, data = self.post("/v1/credits/consume", payload)
        return status, json.loads(data)


class VerifierPassDefaultsTest(PassFlowBase):
    packs_env = None  # decided defaults: the real $25 / 1,000 / 400

    def test_subscription_webhook_grants_1000(self):
        code = self.subscribe()
        # the Pass email, not the pack email, carried the code
        self.assertEqual(len(self.mailer.sent), 1)
        mail = self.mailer.sent[0]
        self.assertEqual(mail["subject"],
                         "Your NPC Verify Verifier Pass")
        self.assertIn(code, mail["text"])
        body = self.balance_of(code)
        self.assertEqual(body["balance"], 1000)
        self.assertEqual(body["grant_balance"], 1000)
        self.assertEqual(body["ai_balance"], 400)
        self.assertEqual(body["subscription_status"], "active")
        self.assertTrue(body["registry_unlimited"])
        self.assertEqual(body["status"], "active")

    def test_duplicate_activation_grants_once(self):
        sid = self.buy("verifier-pass", email="member@example.com")
        obj = {"id": sid, "subscription": "sub_test_1",
               "customer": "cus_test_1", "invoice": "in_test_1",
               "customer_details": {"email": "member@example.com"}}
        self.fire_event("checkout.session.completed", obj)
        first = self.app.store.get_credit_purchase(sid)["code_hash"]
        # replayed delivery: no second code, grant, or email
        self.fire_event("checkout.session.completed", obj,
                        event_id="evt_pass_2")
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["code_hash"], first)
        self.assertEqual(len(self.mailer.sent), 1)
        status, _h, data = self.get(
            "/v1/credits/checkout-status?session_id=" + sid)
        code = json.loads(data)["code"]
        self.assertEqual(self.balance_of(code)["balance"], 1000)

    def test_renewal_grants_and_duplicate_invoice_grants_once(self):
        code = self.subscribe()
        status, _h, _d = self.fire_event(
            "invoice.paid",
            {"id": "in_test_2", "subscription": "sub_test_1"})
        self.assertEqual(status, 200)
        self.assertEqual(self.balance_of(code)["balance"], 2000)
        # the same invoice delivered again grants nothing more
        self.fire_event("invoice.paid",
                        {"id": "in_test_2",
                         "subscription": "sub_test_1"},
                        event_id="evt_pass_3")
        self.assertEqual(self.balance_of(code)["balance"], 2000)
        self.assertEqual(self.balance_of(code)["ai_balance"], 800)

    def test_cancellation_stops_the_next_grant(self):
        code = self.subscribe()
        self.fire_event("invoice.paid",
                        {"id": "in_test_2",
                         "subscription": "sub_test_1"})
        self.assertEqual(self.balance_of(code)["balance"], 2000)
        status, _h, _d = self.fire_event(
            "customer.subscription.deleted", {"id": "sub_test_1"})
        self.assertEqual(status, 200)
        body = self.balance_of(code)
        self.assertEqual(body["subscription_status"], "canceled")
        self.assertFalse(body["registry_unlimited"])
        # already-granted checks survive cancellation
        self.assertEqual(body["balance"], 2000)
        # and no further grant lands
        self.fire_event("invoice.paid",
                        {"id": "in_test_3",
                         "subscription": "sub_test_1"},
                        event_id="evt_pass_4")
        self.assertEqual(self.balance_of(code)["balance"], 2000)


class VerifierPassSmallTest(PassFlowBase):
    """Small Pass figures (5 checks, 2 AI) so the sub-allowance can
    be exhausted inside one test."""
    packs_env = json.dumps([
        {"id": "pass", "label": "Verifier Pass", "checks": 5,
         "price_cents": 2500, "currency": "usd", "kind": "access",
         "ai_checks": 2, "interval": "month",
         "stripe_price_id": "price_test_pass_small"},
        {"id": "trio", "label": "3 checks", "checks": 3,
         "price_cents": 300, "currency": "usd",
         "stripe_price_id": "price_test_trio"},
    ])

    def test_ai_sub_allowance_caps_ai_but_not_standard(self):
        code = self.subscribe(pack_id="pass")
        body = self.balance_of(code)
        self.assertEqual(body["balance"], 5)
        self.assertEqual(body["ai_balance"], 2)
        self.assertTrue(body["registry_unlimited"])

        status, body = self.consume(code, IDENT_A, kind="ai")
        self.assertEqual(status, 200)
        self.assertTrue(body["charged"])
        self.assertEqual(body["ai_balance"], 1)
        self.assertEqual(body["balance"], 4)
        status, body = self.consume(code, IDENT_B, kind="ai")
        self.assertTrue(body["charged"])
        self.assertEqual(body["ai_balance"], 0)
        self.assertEqual(body["balance"], 3)

        # the 3rd AI check is refused: the sub-allowance is spent,
        # even though checks remain
        status, body = self.consume(code, IDENT_C, kind="ai")
        self.assertEqual(status, 402)
        self.assertEqual(body["error"], "no_ai_credits")
        self.assertFalse(body["charged"])
        self.assertEqual(body["balance"], 3)

        # a standard check is covered by the Pass itself: charged,
        # and the finite balance does not move
        status, body = self.consume(code, IDENT_C)
        self.assertEqual(status, 200)
        self.assertTrue(body["charged"])
        self.assertEqual(body["balance"], 3)
        self.assertEqual(body["ai_balance"], 0)

    def test_standard_checks_unlimited_then_draw_after_cancel(self):
        code = self.subscribe(pack_id="pass")
        # the monthly grant holds 5 checks, yet standard checks
        # keep charging past it while the subscription runs, and
        # the finite pool is never touched
        for i in range(7):
            status, body = self.consume(code, "sha256:%064x" % i)
            self.assertEqual(status, 200)
            self.assertTrue(body["charged"])
            self.assertEqual(body["balance"], 5)
            self.assertTrue(body["registry_unlimited"])
        body = self.balance_of(code)
        self.assertEqual(body["grant_balance"], 5)
        # cancellation ends the coverage at once: standard checks
        # draw the finite pool again
        self.fire_event("customer.subscription.deleted",
                        {"id": "sub_test_1"})
        body = self.balance_of(code)
        self.assertEqual(body["subscription_status"], "canceled")
        self.assertFalse(body["registry_unlimited"])
        self.assertEqual(body["balance"], 5)
        status, body = self.consume(code, "sha256:%064x" % 99)
        self.assertEqual(status, 200)
        self.assertTrue(body["charged"])
        self.assertEqual(body["balance"], 4)

    def test_consume_kind_is_validated(self):
        code = self.subscribe(pack_id="pass")
        status, _h, data = self.post(
            "/v1/credits/consume",
            {"code": code, "image_identity": IDENT_A, "kind": "deep"})
        self.assertEqual(status, 400)

    def test_pack_credits_fund_ai_checks(self):
        # One-time pack credits fund AI generation checks at one
        # check per AI check, with no sub-cap (Bayo, 2026-10-28:
        # "Pack credits include the AI checks").
        code = self.paid_code("trio")
        status, body = self.consume(code, IDENT_A, kind="ai")
        self.assertEqual(status, 200)
        self.assertTrue(body["charged"])
        self.assertEqual(body["balance"], 2)
        self.assertEqual(body["ai_balance"], 2)
        status, body = self.consume(code, IDENT_B, kind="ai")
        self.assertEqual(status, 200)
        self.assertTrue(body["charged"])
        self.assertEqual(body["ai_balance"], 1)
        # standard checks spend the same pack pool
        status, body = self.consume(code, IDENT_C)
        self.assertEqual(status, 200)
        self.assertTrue(body["charged"])
        self.assertEqual(body["balance"], 0)
        # at zero the answer is no_credits, for either kind
        status, body = self.consume(code, IDENT_D, kind="ai")
        self.assertEqual(status, 402)
        self.assertEqual(body["error"], "no_credits")


class CatalogWiringTest(PassFlowBase):
    """The Stripe catalog wiring end to end (Bayo, 2026-10-29):
    webhook resolution by price id and renewal mapping, against
    the decided default packs and their live catalog price ids."""
    packs_env = None

    PASS_PRICE = "price_1UVmNkAmXrDzn7XPqeRHwIkZ"
    C100_PRICE = "price_1UVmMeAmXrDzn7XPOECPoeSR"
    C250_PRICE = "price_1UVmMeAmXrDzn7XP7lSWVGBR"

    @staticmethod
    def _lines(price_id):
        return {"object": "list", "data": [
            {"id": "li_test_1", "quantity": 1,
             "price": {"id": price_id, "object": "price"}}]}

    def _completed(self, sid, price_id=None, extra=None,
                   event_id="evt_cat_1"):
        obj = {"id": sid,
               "customer_details": {"email": "buyer@example.com"}}
        if price_id is not None:
            obj["line_items"] = self._lines(price_id)
        if extra:
            obj.update(extra)
        return self.fire_event("checkout.session.completed", obj,
                               event_id=event_id)

    def test_webhook_price_id_mints_pack_once_under_replay(self):
        sid = self.buy("checks-100", email="buyer@example.com")
        status, _h, _d = self._completed(sid, self.C100_PRICE)
        self.assertEqual(status, 200)
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["status"], "paid")
        self.assertEqual(len(self.mailer.sent), 1)
        # replay: the same charge reported again mints nothing
        self._completed(sid, self.C100_PRICE, event_id="evt_cat_2")
        self.assertEqual(len(self.mailer.sent), 1)
        status, _h, data = self.get(
            "/v1/credits/checkout-status?session_id=" + sid)
        body = json.loads(data)
        self.assertEqual(body["checks"], 100)
        body = self.balance_of(body["code"])
        self.assertEqual(body["credits_total"], 100)
        self.assertEqual(body["balance"], 100)

    def test_webhook_price_mismatch_refuses_the_mint(self):
        sid = self.buy("checks-100", email="buyer@example.com")
        # the event claims the 250 pack's price was charged for a
        # purchase recorded as the 100 pack: no code is granted
        status, _h, _d = self._completed(sid, self.C250_PRICE)
        self.assertEqual(status, 200)
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["status"], "pending")
        self.assertIsNone(purchase["code_hash"])
        self.assertEqual(len(self.mailer.sent), 0)
        # the refusal is not a wedge: the true price still mints
        self._completed(sid, self.C100_PRICE, event_id="evt_cat_2")
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["status"], "paid")

    def test_webhook_unknown_price_refuses_the_mint(self):
        sid = self.buy("checks-250", email="buyer@example.com")
        status, _h, _d = self._completed(sid, "price_not_a_pack")
        self.assertEqual(status, 200)
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["status"], "pending")
        self.assertIsNone(purchase["code_hash"])
        self.assertEqual(len(self.mailer.sent), 0)

    def test_webhook_metadata_names_the_pack_when_unpriced(self):
        # a payload naming no price resolves through the session
        # metadata the checkout set (metadata[pack_id])
        sid = self.buy("checks-250", email="buyer@example.com")
        status, _h, _d = self._completed(
            sid, None,
            extra={"metadata": {"pack_id": "checks-250"}})
        self.assertEqual(status, 200)
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["status"], "paid")

    def _subscribe_priced(self):
        sid = self.buy("verifier-pass", email="member@example.com")
        status, _h, data = self._completed(
            sid, self.PASS_PRICE,
            extra={"subscription": "sub_test_1",
                   "customer": "cus_test_1", "invoice": "in_test_1",
                   "customer_details":
                       {"email": "member@example.com"}})
        self.assertEqual(status, 200, data)
        status, _h, data = self.get(
            "/v1/credits/checkout-status?session_id=" + sid)
        body = json.loads(data)
        self.assertEqual(body["status"], "paid")
        return body["code"]

    def _invoice(self, invoice_id, price_id=None,
                 event_id="evt_cat_inv"):
        obj = {"id": invoice_id, "subscription": "sub_test_1"}
        if price_id is not None:
            obj["lines"] = self._lines(price_id)
        return self.fire_event("invoice.paid", obj,
                               event_id=event_id)

    def test_renewal_resolves_through_the_pass_price(self):
        code = self._subscribe_priced()
        self.assertEqual(self.balance_of(code)["balance"], 1000)
        # the renewal invoice names the Pass catalog price
        status, _h, _d = self._invoice("in_test_2", self.PASS_PRICE)
        self.assertEqual(status, 200)
        self.assertEqual(self.balance_of(code)["balance"], 2000)
        # replayed under a new event id, the invoice id still keys
        # the grant: nothing more lands
        self._invoice("in_test_2", self.PASS_PRICE,
                      event_id="evt_cat_inv2")
        self.assertEqual(self.balance_of(code)["balance"], 2000)
        # an invoice naming a one-time pack's price is not a Pass
        # renewal and grants nothing
        self._invoice("in_test_3", self.C100_PRICE,
                      event_id="evt_cat_inv3")
        self.assertEqual(self.balance_of(code)["balance"], 2000)
        # neither is an invoice naming a price no pack carries
        self._invoice("in_test_4", "price_not_a_pack",
                      event_id="evt_cat_inv4")
        self.assertEqual(self.balance_of(code)["balance"], 2000)
        # an invoice naming no price at all keeps the recorded
        # subscription as its authority and still grants
        self._invoice("in_test_5", None, event_id="evt_cat_inv5")
        self.assertEqual(self.balance_of(code)["balance"], 3000)


class UnpricedPackFailClosedTest(CreditsHttpBase):
    """An offer with no Stripe catalog price cannot check out
    (Bayo, 2026-10-29): it is listed with its configured price, it
    reports its own checkout as unavailable, and the checkout door
    refuses it with nothing created."""
    packs_env = json.dumps([
        {"id": "wired", "label": "10 checks", "checks": 10,
         "price_cents": 500, "currency": "usd",
         "stripe_price_id": "price_test_wired"},
        {"id": "stripped", "label": "10 checks (unwired)",
         "checks": 10, "price_cents": 500, "currency": "usd"},
    ])

    def test_stripped_pack_fails_closed(self):
        status, _h, data = self.get("/v1/credits/packs")
        body = json.loads(data)
        by_id = {p["id"]: p for p in body["packs"]}
        self.assertTrue(by_id["wired"]["checkout_available"])
        self.assertFalse(by_id["stripped"]["checkout_available"])
        self.assertTrue(body["checkout_available"])
        status, _h, data = self.post(
            "/v1/credits/checkout", {"pack_id": "stripped"})
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(data)["error"],
                         "checkout_not_configured")
        # nothing was created at the payments double for it
        self.assertEqual(self.payments.sessions, [])
        # the wired offer still checks out normally
        sid = self.buy("wired")
        purchase = self.app.store.get_credit_purchase(sid)
        self.assertEqual(purchase["pack_id"], "wired")
        self.assertEqual(purchase["status"], "pending")


class CreditsUnitTest(unittest.TestCase):

    def test_code_round_trip_and_normalization(self):
        code = credits.generate_code()
        self.assertTrue(credits.valid_code_shape(code))
        messy = "  " + code.lower().replace("-", " ") + " "
        self.assertEqual(credits.code_hash(messy),
                         credits.code_hash(code))
        self.assertFalse(credits.valid_code_shape("NPC-123"))
        self.assertFalse(credits.valid_code_shape(""))
        self.assertFalse(credits.valid_code_shape(None))

    def test_codes_are_unique(self):
        seen = {credits.generate_code() for _ in range(500)}
        self.assertEqual(len(seen), 500)

    def test_webhook_signature_verifies_and_tamper_fails(self):
        verifier = credits.StripePayments(
            "sk_test_fake", WEBHOOK_SECRET, "https://x.test/ok",
            "https://x.test/no", transport=lambda *a, **k: (0, {}))
        raw = json.dumps({"type": "ping", "data": {"object": {}}}).encode()
        now = int(time.time())
        header = credits.sign_webhook_payload(WEBHOOK_SECRET, raw, now)
        event = verifier.verify_webhook(raw, header, now=now)
        self.assertEqual(event["type"], "ping")
        with self.assertRaises(credits.WebhookSignatureError):
            verifier.verify_webhook(raw + b" ", header, now=now)
        with self.assertRaises(credits.WebhookSignatureError):
            verifier.verify_webhook(raw, header, now=now + 3600)
        with self.assertRaises(credits.WebhookSignatureError):
            verifier.verify_webhook(raw, None, now=now)

    def test_packs_env_parsing(self):
        packs, is_default = credits.packs_from_env(
            {"NPC_CREDITS_PACKS_JSON": PACKS_JSON})
        self.assertFalse(is_default)
        self.assertEqual(packs[1]["checks"], 3)
        self.assertEqual(packs[0]["kind"], "pack")
        # the catalog wiring survives the env round trip
        self.assertEqual(packs[0]["stripe_price_id"],
                         "price_test_starter")
        self.assertEqual(packs[1]["stripe_price_id"],
                         "price_test_trio")
        # missing or malformed config falls back to the decided
        # launch packs, never to an invented price
        for env in ({"NPC_CREDITS_PACKS_JSON": "{broken"}, {}):
            packs, is_default = credits.packs_from_env(env)
            self.assertTrue(is_default)
            self.assertEqual(packs[0]["id"], "verifier-pass")
            self.assertEqual(packs[0]["price_cents"], 2500)
            self.assertEqual(packs[1]["id"], "checks-100")
            self.assertEqual(packs[1]["price_cents"], 900)
            self.assertEqual(packs[2]["id"], "checks-250")
            self.assertEqual(packs[2]["price_cents"], 1900)
        # the shipped defaults carry the live catalog prices Bayo
        # created in the Stripe Dashboard (2026-10-28)
        defaults, _ = credits.packs_from_env({})
        by_id = {p["id"]: p.get("stripe_price_id")
                 for p in defaults}
        self.assertEqual(by_id, {
            "verifier-pass": "price_1UVmNkAmXrDzn7XPqeRHwIkZ",
            "checks-100": "price_1UVmMeAmXrDzn7XPOECPoeSR",
            "checks-250": "price_1UVmMeAmXrDzn7XP7lSWVGBR"})
        # a malformed price id poisons the whole override, so the
        # decided defaults (with their catalog wiring) stand
        bad = {"NPC_CREDITS_PACKS_JSON": json.dumps([
            {"id": "x", "label": "X", "checks": 1,
             "price_cents": 100, "currency": "usd",
             "stripe_price_id": ""}])}
        packs, is_default = credits.packs_from_env(bad)
        self.assertTrue(is_default)

    def test_packs_env_parsing_preserves_pass_fields(self):
        env = {"NPC_CREDITS_PACKS_JSON": json.dumps([
            {"id": "pass", "label": "Verifier Pass", "checks": 1000,
             "price_cents": 2500, "currency": "usd", "kind": "access",
             "ai_checks": 200, "interval": "month",
             "stripe_price_id": "price_test_pass_env"}])}
        packs, is_default = credits.packs_from_env(env)
        self.assertFalse(is_default)
        self.assertEqual(packs[0]["ai_checks"], 200)
        self.assertEqual(packs[0]["interval"], "month")
        self.assertEqual(packs[0]["stripe_price_id"],
                         "price_test_pass_env")
        public = credits.public_pack(packs[0])
        self.assertTrue(public["on_sale"])
        self.assertEqual(public["ai_checks"], 200)
        self.assertTrue(public["checkout_available"])
        # a pack with no catalog price is listed but reports that
        # it cannot check out
        bare = credits.public_pack(
            {"id": "bare", "label": "Bare", "checks": 1,
             "price_cents": 100, "currency": "usd", "kind": "pack"})
        self.assertTrue(bare["on_sale"])
        self.assertFalse(bare["checkout_available"])

    def test_grant_expiry_is_end_of_the_following_month(self):
        # granted in October: spendable through the end of November
        self.assertEqual(
            credits.grant_expiry("2026-10-28T22:14:00+00:00"),
            "2026-12-01T00:00:00+00:00")
        # granted on the first of November: through end of December
        self.assertEqual(
            credits.grant_expiry("2026-11-01T00:00:00+00:00"),
            "2027-01-01T00:00:00+00:00")
        # granted mid-December: through the end of January
        self.assertEqual(
            credits.grant_expiry("2026-12-15T09:30:00+00:00"),
            "2027-02-01T00:00:00+00:00")

    def test_catalog_checkout_uses_price_ids(self):
        # Session creation charges the Stripe catalog (Bayo,
        # 2026-10-29): every offer's session names its exact live
        # catalog price id as the line item, and no inline
        # price_data rides along for any of them.
        calls = []

        def recording(method, url, headers, body):
            calls.append(urllib.parse.parse_qs(
                body.decode("utf-8")))
            return 200, {"id": "cs_cat_%d" % len(calls),
                         "url": "https://checkout.stripe.test/cat"}

        stripe = credits.StripePayments(
            "sk_test_fake", WEBHOOK_SECRET, "https://x.test/ok",
            "https://x.test/no", transport=recording)
        defaults, _ = credits.packs_from_env({})
        by_id = {p["id"]: p for p in defaults}

        session = stripe.create_checkout_session(
            by_id["verifier-pass"])
        self.assertEqual(session["id"], "cs_cat_1")
        fields = calls[0]
        self.assertEqual(fields["mode"], ["subscription"])
        self.assertEqual(fields["line_items[0][price]"],
                         ["price_1UVmNkAmXrDzn7XPqeRHwIkZ"])
        self.assertEqual(fields["line_items[0][quantity]"], ["1"])
        self.assertEqual(fields["metadata[pack_id]"],
                         ["verifier-pass"])
        self.assertEqual(
            fields["subscription_data[metadata][pack_id]"],
            ["verifier-pass"])

        stripe.create_checkout_session(by_id["checks-100"])
        fields = calls[1]
        self.assertEqual(fields["mode"], ["payment"])
        self.assertEqual(fields["line_items[0][price]"],
                         ["price_1UVmMeAmXrDzn7XPOECPoeSR"])
        self.assertEqual(fields["metadata[pack_id]"],
                         ["checks-100"])
        self.assertNotIn("subscription_data[metadata][pack_id]",
                         fields)

        stripe.create_checkout_session(by_id["checks-250"])
        fields = calls[2]
        self.assertEqual(fields["mode"], ["payment"])
        self.assertEqual(fields["line_items[0][price]"],
                         ["price_1UVmMeAmXrDzn7XP7lSWVGBR"])

        # no offer falls back to an inline price, ever
        for fields in calls:
            self.assertFalse(
                any(k.startswith("line_items[0][price_data]")
                    for k in fields), fields)

    def test_checkout_without_price_id_fails_closed(self):
        # A pack stripped of its catalog price cannot check out:
        # the payments layer raises before any transport call, so
        # no session exists anywhere for it.
        calls = []

        def recording(method, url, headers, body):
            calls.append(body)
            return 200, {"id": "cs_never", "url": "https://x.test"}

        stripe = credits.StripePayments(
            "sk_test_fake", WEBHOOK_SECRET, "https://x.test/ok",
            "https://x.test/no", transport=recording)
        bare = {"id": "bare", "label": "Bare", "checks": 1,
                "price_cents": 100, "currency": "usd", "kind": "pack"}
        with self.assertRaises(credits.PaymentsError):
            stripe.create_checkout_session(bare)
        self.assertEqual(calls, [])


class CreditsStoreTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_credits_store_")
        self.store = Store(os.path.join(self.tmp, "s.db"))
        self.pack = {"id": "trio", "label": "3 checks", "checks": 3,
                     "price_cents": 300, "currency": "usd"}
        self.now = "2026-10-28T00:00:00+00:00"

    def tearDown(self):
        self.store.close()

    def _grant(self, session="cs_1"):
        code = credits.generate_code()
        self.store.create_credit_purchase(session, "trio", None,
                                          self.now)
        row = self.store.complete_credit_purchase(
            session, credits.code_hash(code), code, self.pack,
            "b@example.com", self.now)
        return code, row

    def test_grant_redeem_consume_cycle(self):
        code, row = self._grant()
        self.assertEqual(row["credits_total"], 3)
        again = self.store.complete_credit_purchase(
            "cs_1", credits.code_hash(credits.generate_code()),
            "whatever", self.pack, "b@example.com", self.now)
        self.assertEqual(again["code_hash"], row["code_hash"])
        got = self.store.redeem_credit_code(
            credits.code_hash(code), self.now)
        self.assertEqual(got["redeemed_at"], self.now)
        out = self.store.consume_credit(
            credits.code_hash(code), IDENT_A, None, "chg_1", self.now)
        self.assertEqual(out["outcome"], "charged")
        out = self.store.consume_credit(
            credits.code_hash(code), IDENT_A, None, "chg_2", self.now)
        self.assertEqual(out["outcome"], "duplicate")
        self.assertEqual(out["code"]["credits_used"], 1)
        out = self.store.consume_credit(
            credits.code_hash("NPC-" + "0" * 20), IDENT_A, None,
            "chg_3", self.now)
        self.assertEqual(out["outcome"], "not_found")

    def test_delivery_once_and_wipe(self):
        code, _row = self._grant()
        got, _p = self.store.take_credit_code_delivery("cs_1")
        self.assertEqual(got, code)
        got, _p = self.store.take_credit_code_delivery("cs_1")
        self.assertIsNone(got)
        purchase = self.store.get_credit_purchase("cs_1")
        self.assertIsNone(purchase["code_plaintext"])
        self.assertEqual(purchase["code_delivered"], 1)

    # -- Verifier Pass: grants, rollover, AI cap, cancellation ---------

    pass_pack = {"id": "verifier-pass", "label": "Verifier Pass",
                 "checks": 5, "price_cents": 2500, "currency": "usd",
                 "kind": "access", "ai_checks": 2,
                 "interval": "month"}

    def _activate_pass(self, granted_at="2026-10-28T00:00:00+00:00"):
        code = credits.generate_code()
        code_hash = credits.code_hash(code)
        self.store.create_credit_purchase(
            "cs_pass", "verifier-pass", None, granted_at)
        row = self.store.activate_pass_subscription(
            "cs_pass", code_hash, code, self.pass_pack,
            "m@example.com", "sub_1", "cus_1", "in_1", granted_at,
            credits.grant_expiry(granted_at))
        return code, code_hash, row

    def test_pass_activation_grants_first_month(self):
        code, code_hash, row = self._activate_pass()
        self.assertEqual(row["grant_balance"], 5)
        self.assertEqual(row["ai_balance"], 2)
        self.assertEqual(row["subscription_status"], "active")
        # replayed activation returns the same code, grants nothing
        again = self.store.activate_pass_subscription(
            "cs_pass", credits.code_hash(credits.generate_code()),
            "other", self.pass_pack, "m@example.com", "sub_1",
            "cus_1", "in_1", "2026-10-28T00:00:00+00:00",
            "2026-12-01T00:00:00+00:00")
        self.assertEqual(again["code_hash"], code_hash)
        view = self.store.get_credit_code(
            code_hash, "2026-10-29T00:00:00+00:00")
        self.assertEqual(view["grant_balance"], 5)
        self.assertEqual(len(view["grants"]), 1)

    def test_rollover_expiry_after_the_second_month(self):
        _code, code_hash, _row = self._activate_pass(
            "2026-10-28T00:00:00+00:00")
        # while the subscription runs, a standard check is covered
        # by the Pass: charged even at the grant's edge of life,
        # and the October grant is untouched
        out = self.store.consume_credit(
            code_hash, IDENT_A, None, "chg_oct",
            "2026-11-30T23:59:00+00:00")
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 5)
        # a November renewal lands while the first grant still lives
        res = self.store.grant_subscription_allowance(
            "sub_1", "in_2", "2026-11-05T00:00:00+00:00",
            credits.grant_expiry("2026-11-05T00:00:00+00:00"))
        self.assertEqual(res["outcome"], "granted")
        view = self.store.get_credit_code(
            code_hash, "2026-11-15T00:00:00+00:00")
        self.assertEqual(view["grant_balance"], 5 + 5)
        # December: the October grant has expired, November's lives,
        # and a standard check is still Pass-covered
        view = self.store.get_credit_code(
            code_hash, "2026-12-15T00:00:00+00:00")
        self.assertEqual(view["grant_balance"], 5)
        out = self.store.consume_credit(
            code_hash, IDENT_B, None, "chg_dec",
            "2026-12-15T00:00:00+00:00")
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 5)
        grants = {g["grant_id"]: g
                  for g in out["code"]["grants"]}
        self.assertEqual(grants["in_2"]["used"], 0)
        # cancellation ends the coverage: the next standard check
        # draws the finite pool again, oldest live grant first
        self.store.cancel_subscription(
            "sub_1", "2026-12-15T00:00:00+00:00")
        out = self.store.consume_credit(
            code_hash, IDENT_C, None, "chg_dec2",
            "2026-12-15T00:00:00+00:00")
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 4)
        grants = {g["grant_id"]: g
                  for g in out["code"]["grants"]}
        self.assertEqual(grants["in_2"]["used"], 1)
        # January: both grants expired, nothing spendable
        view = self.store.get_credit_code(
            code_hash, "2027-01-02T00:00:00+00:00")
        self.assertEqual(view["grant_balance"], 0)
        out = self.store.consume_credit(
            code_hash, IDENT_D, None, "chg_jan",
            "2027-01-02T00:00:00+00:00")
        self.assertEqual(out["outcome"], "no_credits")

    def test_grant_outcomes_duplicate_and_inactive(self):
        _code, code_hash, _row = self._activate_pass()
        res = self.store.grant_subscription_allowance(
            "sub_1", "in_2", "2026-11-28T00:00:00+00:00",
            credits.grant_expiry("2026-11-28T00:00:00+00:00"))
        self.assertEqual(res["outcome"], "granted")
        res = self.store.grant_subscription_allowance(
            "sub_1", "in_2", "2026-11-28T00:00:00+00:00",
            credits.grant_expiry("2026-11-28T00:00:00+00:00"))
        self.assertEqual(res["outcome"], "duplicate")
        res = self.store.grant_subscription_allowance(
            "sub_nope", "in_9", "2026-11-28T00:00:00+00:00",
            credits.grant_expiry("2026-11-28T00:00:00+00:00"))
        self.assertEqual(res["outcome"], "not_found")
        sub = self.store.cancel_subscription(
            "sub_1", "2026-12-01T00:00:00+00:00")
        self.assertEqual(sub["status"], "canceled")
        res = self.store.grant_subscription_allowance(
            "sub_1", "in_3", "2026-12-28T00:00:00+00:00",
            credits.grant_expiry("2026-12-28T00:00:00+00:00"))
        self.assertEqual(res["outcome"], "inactive")
        # granted checks survive cancellation until their expiry
        view = self.store.get_credit_code(
            code_hash, "2026-11-15T00:00:00+00:00")
        self.assertEqual(view["grant_balance"], 10)
        self.assertEqual(view["subscription_status"], "canceled")

    def test_store_level_ai_cap(self):
        _code, code_hash, _row = self._activate_pass()
        now = "2026-10-29T00:00:00+00:00"
        for i, ident in enumerate((IDENT_A, IDENT_B)):
            out = self.store.consume_credit(
                code_hash, ident, None, "chg_ai_%d" % i, now,
                kind="ai")
            self.assertEqual(out["outcome"], "charged")
        out = self.store.consume_credit(
            code_hash, IDENT_C, None, "chg_ai_3", now, kind="ai")
        self.assertEqual(out["outcome"], "no_ai_credits")
        # a standard check is Pass-covered while subscribed: it
        # charges and the grant (5 minus the 2 AI draws) stands
        out = self.store.consume_credit(
            code_hash, IDENT_C, None, "chg_std_3", now)
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 3)

    def test_default_pass_ai_cap_is_400(self):
        # Bayo's structure (2026-10-28): the Pass's monthly grant
        # of 1,000 carries 400 AI generation checks. Standard
        # registry checks are unlimited while the subscription
        # runs, so what the AI cap leaves standing is the finite
        # balance, not a registry budget.
        pack = credits.DEFAULT_PACKS[0]
        self.assertEqual(pack["id"], "verifier-pass")
        self.assertEqual(pack["checks"], 1000)
        self.assertEqual(pack["ai_checks"], 400)
        code = credits.generate_code()
        code_hash = credits.code_hash(code)
        granted_at = "2026-10-28T00:00:00+00:00"
        self.store.create_credit_purchase(
            "cs_big", "verifier-pass", None, granted_at)
        row = self.store.activate_pass_subscription(
            "cs_big", code_hash, code, pack, "m@example.com",
            "sub_big", "cus_1", "in_1", granted_at,
            credits.grant_expiry(granted_at))
        self.assertEqual(row["grant_balance"], 1000)
        self.assertEqual(row["ai_balance"], 400)
        now = "2026-10-29T00:00:00+00:00"
        for i in range(400):
            # all inside one hour: the anti-scripting backstop
            # (1,000 an hour, Bayo 2026-10-28) stays clear; it is
            # not what this test measures
            out = self.store.consume_credit(
                code_hash, "sha256:%064x" % i, None,
                "chg_ai_%d" % i, now, kind="ai")
            self.assertEqual(out["outcome"], "charged")
        # the 401st AI check in the month is refused, even though
        # 600 checks remain (probed in a later, empty hour)
        later = "2026-10-29T05:00:00+00:00"
        out = self.store.consume_credit(
            code_hash, IDENT_D, None, "chg_ai_401", later, kind="ai")
        self.assertEqual(out["outcome"], "no_ai_credits")
        self.assertEqual(out["code"]["ai_balance"], 0)
        self.assertEqual(out["code"]["grant_balance"], 600)
        # and a standard check is covered by the Pass itself
        # while the subscription runs: charged, grant untouched
        out = self.store.consume_credit(
            code_hash, IDENT_D, None, "chg_std_401", later)
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 600)

    def _refer_to(self, referee_hash, granted_at):
        """Attribute a code as another buyer's referee, landing
        the 10-check referee bonus grant on it."""
        ref_code, _row = self._grant("cs_referrer_" + referee_hash[:8])
        ref_hash = credits.code_hash(ref_code)
        plain = credits.generate_code()
        self.store.ensure_referral_code(
            ref_hash, credits.code_hash(plain), plain, granted_at)
        res = self.store.attribute_referral(
            referee_hash, credits.code_hash(plain),
            "referee:" + referee_hash, "referrer:" + referee_hash,
            granted_at, credits.grant_expiry(granted_at),
            credits.REFEREE_BONUS_CHECKS,
            credits.REFERRER_BONUS_CHECKS,
            credits.REFERRAL_MONTHLY_CAP_CHECKS,
            referrer_link_bonus=credits.REFERRER_LINK_BONUS_CHECKS,
            referrer_link_grant_id="referrer-link:" + referee_hash)
        self.assertEqual(res["outcome"], "linked")
        return res

    def test_pack_only_code_funds_ai(self):
        # Pack counters fund AI checks (Bayo, 2026-10-28: "Pack
        # credits include the AI checks"): the charge lands
        # against the counters, marked funded_by "pack", and the
        # pack's ai_balance is its whole remaining balance.
        code, _row = self._grant()
        code_hash = credits.code_hash(code)
        view = self.store.get_credit_code(code_hash, self.now)
        self.assertEqual(view["ai_balance"], 3)
        out = self.store.consume_credit(
            code_hash, IDENT_A, None, "chg_pk_ai", self.now,
            kind="ai")
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["credits_used"], 1)
        self.assertEqual(out["code"]["ai_balance"], 2)
        charge = self.store._fetchone(
            "SELECT * FROM credit_charges WHERE code_hash=?"
            " AND image_identity=?", (code_hash, IDENT_A))
        self.assertEqual(charge["kind"], "ai")
        self.assertEqual(charge["funded_by"], "pack")
        # the same pool funds standard checks, unmarked
        out = self.store.consume_credit(
            code_hash, IDENT_B, None, "chg_pk_std", self.now)
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["credits_used"], 2)
        charge = self.store._fetchone(
            "SELECT * FROM credit_charges WHERE code_hash=?"
            " AND image_identity=?", (code_hash, IDENT_B))
        self.assertEqual(charge["funded_by"], "")
        # the last pack check funds one more AI check; then the
        # pool is empty and the answer is no_credits
        out = self.store.consume_credit(
            code_hash, IDENT_C, None, "chg_pk_ai2", self.now,
            kind="ai")
        self.assertEqual(out["outcome"], "charged")
        out = self.store.consume_credit(
            code_hash, IDENT_D, None, "chg_pk_ai3", self.now,
            kind="ai")
        self.assertEqual(out["outcome"], "no_credits")

    def test_ai_draw_order_pass_then_bonus_then_pack(self):
        # The full AI draw order on one code holding all three
        # sources (Bayo, 2026-10-28): a Pass grant's AI
        # sub-allowance first, then bonus grants, then the code's
        # pack counters. The hybrid is assembled directly at the
        # store: a pack code (3 counters) that also carries a
        # referral bonus grant (+10) and a Pass-shaped grant
        # (2 checks, AI sub-allowance 2). The pack code is minted
        # under its own buyer email: _grant's shared default
        # would trip the same-email self-referral guard inside
        # _refer_to.
        code = credits.generate_code()
        code_hash = credits.code_hash(code)
        self.store.create_credit_purchase(
            "cs_hybrid", "trio", None, self.now)
        self.store.complete_credit_purchase(
            "cs_hybrid", code_hash, code, self.pack,
            "hybrid@example.com", self.now)
        self._refer_to(code_hash, "2026-10-28T01:00:00+00:00")
        granted_at = "2026-10-28T02:00:00+00:00"
        self.store.db.execute(
            "INSERT INTO credit_grants (grant_id, code_hash,"
            " amount, used, ai_cap, ai_used, source, granted_at,"
            " expires_at) VALUES (?,?,2,0,2,0,'pass',?,?)",
            ("hybrid_pass", code_hash, granted_at,
             credits.grant_expiry(granted_at)))
        self.store.db.commit()
        now = "2026-10-29T00:00:00+00:00"
        bonus_id = "referee:" + code_hash

        def view():
            return self.store.get_credit_code(code_hash, now)

        def grants():
            return {g["grant_id"]: g for g in view()["grants"]}

        def ai(i):
            return self.store.consume_credit(
                code_hash, "sha256:%064x" % i, None,
                "chg_3p_%d" % i, now, kind="ai")

        def funded_by(i):
            row = self.store._fetchone(
                "SELECT * FROM credit_charges WHERE code_hash=?"
                " AND image_identity=?",
                (code_hash, "sha256:%064x" % i))
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

    def test_ai_draw_order_pass_allowance_before_bonus(self):
        # Draw order (Bayo, 2026-10-28): a Pass grant's AI
        # sub-allowance is spent before bonus grants, even when
        # the bonus grant is older than the Pass grant that pays.
        _code, code_hash, _row = self._activate_pass()
        self._refer_to(code_hash, "2026-10-28T01:00:00+00:00")
        res = self.store.grant_subscription_allowance(
            "sub_1", "in_2", "2026-10-29T00:00:00+00:00",
            credits.grant_expiry("2026-10-29T00:00:00+00:00"))
        self.assertEqual(res["outcome"], "granted")
        now = "2026-10-29T12:00:00+00:00"
        bonus_id = "referee:" + code_hash

        def grants():
            view = self.store.get_credit_code(code_hash, now)
            return ({g["grant_id"]: g for g in view["grants"]},
                    view)

        def ai(i):
            return self.store.consume_credit(
                code_hash, "sha256:%064x" % i, None,
                "chg_ord_%d" % i, now, kind="ai")

        # the first Pass grant's two AI checks go first
        for i in range(2):
            self.assertEqual(ai(i)["outcome"], "charged")
        g, view = grants()
        self.assertEqual(g["in_1"]["ai_used"], 2)
        self.assertEqual(g[bonus_id]["used"], 0)
        self.assertEqual(g["in_2"]["ai_used"], 0)
        self.assertEqual(view["ai_balance"], 2 + 10)
        # the renewal grant (younger than the bonus) pays next,
        # before the bonus is touched
        self.assertEqual(ai(2)["outcome"], "charged")
        g, _view = grants()
        self.assertEqual(g["in_2"]["ai_used"], 1)
        self.assertEqual(g[bonus_id]["used"], 0)
        self.assertEqual(ai(3)["outcome"], "charged")
        g, view = grants()
        self.assertEqual(g["in_2"]["ai_used"], 2)
        self.assertEqual(view["ai_balance"], 10)
        # only now does an AI check draw the bonus, marked as such
        self.assertEqual(ai(4)["outcome"], "charged")
        g, view = grants()
        self.assertEqual(g[bonus_id]["used"], 1)
        self.assertEqual(g[bonus_id]["ai_used"], 1)
        self.assertEqual(view["ai_balance"], 9)
        charge = self.store._fetchone(
            "SELECT * FROM credit_charges WHERE code_hash=?"
            " AND image_identity=?",
            (code_hash, "sha256:%064x" % 4))
        self.assertEqual(charge["funded_by"], "bonus")
        # the rest of the bonus drains the same way, and then an
        # AI check is refused even though standard checks remain
        for i in range(5, 14):
            self.assertEqual(ai(i)["outcome"], "charged")
        g, view = grants()
        self.assertEqual(g[bonus_id]["used"], 10)
        out = ai(14)
        self.assertEqual(out["outcome"], "no_ai_credits")
        self.assertEqual(out["code"]["ai_balance"], 0)
        self.assertEqual(out["code"]["grant_balance"], 3 + 3)

    def test_default_pass_401st_ai_draws_bonus(self):
        # The real 400 structure with a bonus standing behind it
        # (Bayo, 2026-10-28): the sub-allowance is spent first,
        # and the 401st AI check charges against the bonus.
        pack = credits.DEFAULT_PACKS[0]
        code = credits.generate_code()
        code_hash = credits.code_hash(code)
        granted_at = "2026-10-28T00:00:00+00:00"
        self.store.create_credit_purchase(
            "cs_big2", "verifier-pass", None, granted_at)
        self.store.activate_pass_subscription(
            "cs_big2", code_hash, code, pack, "m@example.com",
            "sub_big2", "cus_1", "in_1", granted_at,
            credits.grant_expiry(granted_at))
        self._refer_to(code_hash, granted_at)
        for i in range(400):
            # all inside one hour, as in the cap test: the
            # 1,000-an-hour backstop stays clear of what is
            # measured here
            out = self.store.consume_credit(
                code_hash, "sha256:%064x" % i, None,
                "chg_big_%d" % i, "2026-10-29T00:00:00+00:00",
                kind="ai")
            self.assertEqual(out["outcome"], "charged")
        view = self.store.get_credit_code(
            code_hash, "2026-10-29T04:00:00+00:00")
        grants = {g["grant_id"]: g for g in view["grants"]}
        self.assertEqual(grants["in_1"]["ai_used"], 400)
        self.assertEqual(grants["referee:" + code_hash]["used"], 0)
        # the balance a client shows: 600 grant checks stand, and
        # 10 of them (the bonus) can still fund an AI check
        self.assertEqual(view["grant_balance"], 600 + 10)
        self.assertEqual(view["ai_balance"], 10)
        # the 401st AI check charges, drawn from the bonus grant
        later = "2026-10-29T05:00:00+00:00"
        out = self.store.consume_credit(
            code_hash, IDENT_D, None, "chg_big_401", later,
            kind="ai")
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["ai_balance"], 9)
        grants = {g["grant_id"]: g for g in out["code"]["grants"]}
        self.assertEqual(grants["referee:" + code_hash]["used"], 1)
        charge = self.store._fetchone(
            "SELECT * FROM credit_charges WHERE code_hash=?"
            " AND image_identity=?", (code_hash, IDENT_D))
        self.assertEqual(charge["kind"], "ai")
        self.assertEqual(charge["funded_by"], "bonus")

    def test_pass_covered_charge_is_marked_and_moves_nothing(self):
        _code, code_hash, _row = self._activate_pass()
        out = self.store.consume_credit(
            code_hash, IDENT_A, None, "chg_pass_1", self.now)
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["credits_used"], 0)
        self.assertEqual(out["code"]["grant_balance"], 5)
        self.assertEqual(out["code"]["grants"][0]["used"], 0)
        # the charge row is the usage record, marked as Pass-drawn
        charge = self.store._fetchone(
            "SELECT * FROM credit_charges WHERE code_hash=?"
            " AND image_identity=?", (code_hash, IDENT_A))
        self.assertEqual(charge["funded_by"], "pass")
        self.assertEqual(charge["kind"], "standard")
        # after cancellation the same kind of charge draws the
        # pool and carries no Pass mark
        self.store.cancel_subscription("sub_1", self.now)
        out = self.store.consume_credit(
            code_hash, IDENT_B, None, "chg_pass_2", self.now)
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 4)
        charge = self.store._fetchone(
            "SELECT * FROM credit_charges WHERE code_hash=?"
            " AND image_identity=?", (code_hash, IDENT_B))
        self.assertEqual(charge["funded_by"], "")

    def test_consume_hourly_backstop(self):
        # the shipped default is generous: a few hundred an hour,
        # an anti-scripting guard and not a usage cap
        self.assertGreaterEqual(credits.CONSUME_HOURLY_LIMIT, 200)
        self.assertLessEqual(credits.CONSUME_HOURLY_LIMIT, 1000)
        code, _row = self._grant()
        code_hash = credits.code_hash(code)
        out = self.store.consume_credit(
            code_hash, IDENT_A, None, "chg_l1", self.now,
            hourly_limit=2)
        self.assertEqual(out["outcome"], "charged")
        out = self.store.consume_credit(
            code_hash, IDENT_B, None, "chg_l2", self.now,
            hourly_limit=2)
        self.assertEqual(out["outcome"], "charged")
        # a third new image inside the hour trips the backstop,
        # though one check remains on the code
        out = self.store.consume_credit(
            code_hash, IDENT_C, None, "chg_l3", self.now,
            hourly_limit=2)
        self.assertEqual(out["outcome"], "rate_limited")
        # duplicates are answered, never refused by the backstop
        out = self.store.consume_credit(
            code_hash, IDENT_A, None, "chg_l4", self.now,
            hourly_limit=2)
        self.assertEqual(out["outcome"], "duplicate")
        # an hour later the window has moved on and it charges
        later = "2026-10-28T02:00:01+00:00"
        out = self.store.consume_credit(
            code_hash, IDENT_C, None, "chg_l5", later,
            hourly_limit=2)
        self.assertEqual(out["outcome"], "charged")
        # and the pool really is spent now
        out = self.store.consume_credit(
            code_hash, IDENT_D, None, "chg_l6", later,
            hourly_limit=2)
        self.assertEqual(out["outcome"], "no_credits")


class ReferralStoreTest(unittest.TestCase):
    """Referral mechanics at the store level (SQLite): referral
    code delivery, attribution, both bonuses, the self-referral
    guards, the monthly cap, and bonus expiry."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_referral_store_")
        self.store = Store(os.path.join(self.tmp, "s.db"))
        self.pack = {"id": "trio", "label": "3 checks", "checks": 3,
                     "price_cents": 300, "currency": "usd"}
        self.now = "2026-10-28T12:00:00+00:00"
        self.expiry = credits.grant_expiry(self.now)

    def tearDown(self):
        self.store.close()

    def _mint(self, session, email):
        code = credits.generate_code()
        code_hash = credits.code_hash(code)
        self.store.create_credit_purchase(session, "trio", email,
                                          self.now)
        self.store.complete_credit_purchase(
            session, code_hash, code, self.pack, email, self.now)
        return code, code_hash

    def _referral_code(self, code_hash):
        plain = credits.generate_code()
        self.store.ensure_referral_code(
            code_hash, credits.code_hash(plain), plain, self.now)
        got, _row = self.store.take_referral_code_delivery(
            code_hash)
        self.assertEqual(got, plain)
        return plain

    def _attribute(self, referee_hash, referral_plain, now=None):
        now = now or self.now
        return self.store.attribute_referral(
            referee_hash, credits.code_hash(referral_plain),
            "referee:" + referee_hash, "referrer:" + referee_hash,
            now, credits.grant_expiry(now),
            credits.REFEREE_BONUS_CHECKS,
            credits.REFERRER_BONUS_CHECKS,
            credits.REFERRAL_MONTHLY_CAP_CHECKS,
            referrer_link_bonus=credits.REFERRER_LINK_BONUS_CHECKS,
            referrer_link_grant_id="referrer-link:" + referee_hash)

    def _balance(self, code_hash, now=None):
        view = self.store.get_credit_code(code_hash, now or self.now)
        return (view["credits_total"] - view["credits_used"]
                + view["grant_balance"])

    def test_referral_code_delivery_once(self):
        _code, code_hash = self._mint("cs_a", "a@example.com")
        plain = credits.generate_code()
        row = self.store.ensure_referral_code(
            code_hash, credits.code_hash(plain), plain, self.now)
        self.assertEqual(row["code_hash"], code_hash)
        # a second ensure keeps the first code
        other = credits.generate_code()
        row = self.store.ensure_referral_code(
            code_hash, credits.code_hash(other), other, self.now)
        self.assertEqual(row["referral_hash"],
                         credits.code_hash(plain))
        # the owner is findable by hash, and delivery happens once
        owner = self.store.get_referral_owner(
            credits.code_hash(plain))
        self.assertEqual(owner["code_hash"], code_hash)
        got, row = self.store.take_referral_code_delivery(code_hash)
        self.assertEqual(got, plain)
        self.assertIsNone(row["code_plaintext"])
        got, _row = self.store.take_referral_code_delivery(code_hash)
        self.assertIsNone(got)

    def test_link_grants_the_bonuses_exactly_once(self):
        _a, a_hash = self._mint("cs_a", "a@example.com")
        _b, b_hash = self._mint("cs_b", "b@example.com")
        ref = self._referral_code(a_hash)
        res = self._attribute(b_hash, ref)
        self.assertEqual(res["outcome"], "linked")
        # both sides are rewarded at the link (+10 each), and the
        # referrer earns +100 more for the first paid purchase
        self.assertEqual(res["referee_bonus"], 10)
        self.assertEqual(res["referrer_link_bonus"], 10)
        self.assertEqual(res["referrer_bonus"], 100)
        # referee: 3 pack checks + 10 bonus; referrer: 3 + 110
        self.assertEqual(self._balance(b_hash), 13)
        self.assertEqual(self._balance(a_hash), 113)
        b_view = self.store.get_credit_code(b_hash, self.now)
        self.assertEqual(b_view["grant_balance"], 10)
        # ai_balance counts the bonus in full, on both sides, and
        # each side's own 3 pack checks too: pack balances fund
        # AI checks as well (Bayo, 2026-10-28)
        self.assertEqual(b_view["ai_balance"], 10 + 3)
        a_view = self.store.get_credit_code(a_hash, self.now)
        self.assertEqual(a_view["ai_balance"], 110 + 3)
        # a second attribution (either path) grants nothing more
        res = self._attribute(b_hash, ref)
        self.assertEqual(res["outcome"], "already_referred")
        self.assertEqual(self._balance(b_hash), 13)
        self.assertEqual(self._balance(a_hash), 113)
        stats = self.store.referral_stats(a_hash, self.now)
        self.assertEqual(stats["referred_count"], 1)
        self.assertEqual(stats["referral_bonus_this_month"], 110)
        self.assertTrue(
            self.store.referral_stats(b_hash, self.now)
            ["referred_by"])

    def test_self_referral_same_code_grants_nothing(self):
        _a, a_hash = self._mint("cs_a", "a@example.com")
        ref = self._referral_code(a_hash)
        res = self._attribute(a_hash, ref)
        self.assertEqual(res["outcome"], "self_referral")
        self.assertIsNone(self.store.get_referral(a_hash))
        self.assertEqual(self._balance(a_hash), 3)

    def test_self_referral_same_email_grants_nothing(self):
        _a, a_hash = self._mint("cs_a", "same@example.com")
        _b, b_hash = self._mint("cs_b", "Same@Example.com")
        ref = self._referral_code(a_hash)
        res = self._attribute(b_hash, ref)
        self.assertEqual(res["outcome"], "self_referral")
        self.assertIsNone(self.store.get_referral(b_hash))
        self.assertEqual(self._balance(a_hash), 3)
        self.assertEqual(self._balance(b_hash), 3)

    def test_unknown_referral_code(self):
        _b, b_hash = self._mint("cs_b", "b@example.com")
        res = self._attribute(b_hash, credits.generate_code())
        self.assertEqual(res["outcome"], "referral_not_found")
        self.assertEqual(self._balance(b_hash), 3)

    def test_monthly_cap_holds_at_500(self):
        _a, a_hash = self._mint("cs_a", "a@example.com")
        ref = self._referral_code(a_hash)
        amounts = []
        link_amounts = []
        for i in range(6):
            _b, b_hash = self._mint(
                "cs_b%d" % i, "b%d@example.com" % i)
            res = self._attribute(b_hash, ref)
            self.assertEqual(res["outcome"], "linked")
            amounts.append(res["referrer_bonus"])
            link_amounts.append(res["referrer_link_bonus"])
            # every referee still receives the full +10
            self.assertEqual(self._balance(b_hash), 13)
        # each referral pays the referrer 10 at link + 100 at the
        # first purchase until the month's 500 is reached: the
        # fifth link bonus lands in full, its purchase bonus is
        # trimmed to the last 50, and the sixth referral pays the
        # referrer nothing (the referee is never trimmed)
        self.assertEqual(link_amounts, [10, 10, 10, 10, 10, 0])
        self.assertEqual(amounts, [100, 100, 100, 100, 50, 0])
        stats = self.store.referral_stats(a_hash, self.now)
        self.assertEqual(stats["referred_count"], 6)
        self.assertEqual(stats["referral_bonus_this_month"], 500)
        self.assertEqual(self._balance(a_hash), 3 + 500)
        # a referral in the next month earns again
        _b, b_hash = self._mint("cs_b6", "b6@example.com")
        res = self._attribute(
            b_hash, ref, now="2026-11-02T12:00:00+00:00")
        self.assertEqual(res["referrer_link_bonus"], 10)
        self.assertEqual(res["referrer_bonus"], 100)

    def test_bonus_funds_ai_and_standard_from_one_pool(self):
        _a, a_hash = self._mint("cs_a", "a@example.com")
        _b, b_hash = self._mint("cs_b", "b@example.com")
        ref = self._referral_code(a_hash)
        self._attribute(b_hash, ref)
        # the referee's whole bonus balance is AI-usable, and so
        # is the code's own 3-check pack balance behind it
        view = self.store.get_credit_code(b_hash, self.now)
        self.assertEqual(view["ai_balance"], 10 + 3)
        # an AI check spends the bonus first (Bayo, 2026-10-28:
        # the referral cap includes all AI checks; draw order is
        # bonus before pack), and the charge row records that a
        # bonus paid for it
        out = self.store.consume_credit(
            b_hash, IDENT_A, None, "chg_r1", self.now, kind="ai")
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 9)
        self.assertEqual(out["code"]["ai_balance"], 9 + 3)
        self.assertEqual(out["code"]["credits_used"], 0)
        charge = self.store._fetchone(
            "SELECT * FROM credit_charges WHERE code_hash=?"
            " AND image_identity=?", (b_hash, IDENT_A))
        self.assertEqual(charge["kind"], "ai")
        self.assertEqual(charge["funded_by"], "bonus")
        # a standard check draws the same pool: the bonus grant
        # now stands at 2 used (one AI draw, one standard draw)
        out = self.store.consume_credit(
            b_hash, IDENT_B, None, "chg_r2", self.now)
        self.assertEqual(out["outcome"], "charged")
        self.assertEqual(out["code"]["grant_balance"], 8)
        self.assertEqual(out["code"]["ai_balance"], 8 + 3)
        grants = {g["source"]: g for g in out["code"]["grants"]}
        self.assertEqual(grants["referral_referee"]["used"], 2)
        self.assertEqual(grants["referral_referee"]["ai_used"], 1)
        # the bonus expires under the one-month rollover rule: the
        # October grant is dead in December; the pack checks
        # remain, and they still fund AI checks on their own
        view = self.store.get_credit_code(
            b_hash, "2026-12-15T00:00:00+00:00")
        self.assertEqual(view["grant_balance"], 0)
        self.assertEqual(view["ai_balance"], 3)
        self.assertEqual(
            view["credits_total"] - view["credits_used"], 3)


class ReferralFlowTest(CreditsHttpBase):
    """Referrals over HTTP: lookup delivery, the link route, and
    checkout-carried attribution through the Stripe webhook."""

    def lookup(self, code):
        status, _h, data = self.post(
            "/v1/credits/referral/lookup", {"code": code})
        return status, json.loads(data)

    def link(self, code, referral_code):
        status, _h, data = self.post(
            "/v1/credits/referral/link",
            {"code": code, "referral_code": referral_code})
        return status, json.loads(data)

    def balance_of(self, code):
        status, _h, data = self.post("/v1/credits/balance",
                                     {"code": code})
        self.assertEqual(status, 200, data)
        return json.loads(data)["balance"]

    def test_lookup_delivers_referral_code_once(self):
        code = self.paid_code("trio", email="a@example.com")
        status, body = self.lookup(code)
        self.assertEqual(status, 200)
        self.assertTrue(body["referral_code_included"])
        self.assertTrue(
            credits.valid_code_shape(body["referral_code"]))
        self.assertEqual(body["referred_count"], 0)
        self.assertEqual(body["referral_bonus_this_month"], 0)
        self.assertFalse(body["referred_by"])
        # later lookups report the record without the code
        status, body = self.lookup(code)
        self.assertEqual(status, 200)
        self.assertIsNone(body["referral_code"])
        self.assertFalse(body["referral_code_included"])

    def test_link_flow_grants_once(self):
        a_code = self.paid_code("trio", email="a@example.com")
        _s, a_lookup = self.lookup(a_code)
        ref = a_lookup["referral_code"]
        b_code = self.paid_code("trio", email="b@example.com")
        status, body = self.link(b_code, ref)
        self.assertEqual(status, 200)
        self.assertEqual(body["outcome"], "linked")
        self.assertTrue(body["granted"])
        self.assertEqual(body["referee_bonus_checks"], 10)
        self.assertEqual(body["referrer_link_bonus_checks"], 10)
        self.assertEqual(body["referrer_bonus_checks"], 100)
        self.assertEqual(body["balance"], 13)
        self.assertEqual(self.balance_of(a_code), 113)
        # linking again grants nothing
        status, body = self.link(b_code, ref)
        self.assertEqual(status, 200)
        self.assertEqual(body["outcome"], "already_referred")
        self.assertFalse(body["granted"])
        self.assertEqual(self.balance_of(b_code), 13)
        self.assertEqual(self.balance_of(a_code), 113)
        # a later purchase by the referee fires nothing more
        self.paid_code("trio", email="b@example.com")
        self.assertEqual(self.balance_of(a_code), 113)
        _s, a_lookup = self.lookup(a_code)
        self.assertEqual(a_lookup["referred_count"], 1)
        self.assertEqual(a_lookup["referral_bonus_this_month"], 110)
        _s, b_lookup = self.lookup(b_code)
        self.assertTrue(b_lookup["referred_by"])

    def test_checkout_carried_referral_and_webhook_replay(self):
        a_code = self.paid_code("trio", email="a@example.com")
        _s, a_lookup = self.lookup(a_code)
        ref = a_lookup["referral_code"]
        status, _h, data = self.post(
            "/v1/credits/checkout",
            {"pack_id": "trio", "email": "c@example.com",
             "referral_code": ref})
        self.assertEqual(status, 201, data)
        sid = json.loads(data)["session_id"]
        status, _h, data = self.fire_webhook(
            sid, email="c@example.com")
        self.assertEqual(status, 200, data)
        status, _h, data = self.get(
            "/v1/credits/checkout-status?session_id=" + sid)
        c_code = json.loads(data)["code"]
        # the bonuses landed with the first paid purchase
        self.assertEqual(self.balance_of(c_code), 13)
        self.assertEqual(self.balance_of(a_code), 113)
        # a replayed webhook grants nothing twice
        status, _h, data = self.fire_webhook(
            sid, email="c@example.com")
        self.assertEqual(status, 200, data)
        self.assertEqual(self.balance_of(c_code), 13)
        self.assertEqual(self.balance_of(a_code), 113)
        # and the new buyer carries a referral code of their own
        status, body = self.lookup(c_code)
        self.assertEqual(status, 200)
        self.assertTrue(body["referral_code_included"])
        self.assertTrue(body["referred_by"])

    def test_self_referral_and_bad_codes(self):
        a_code = self.paid_code("trio", email="a@example.com")
        _s, a_lookup = self.lookup(a_code)
        ref = a_lookup["referral_code"]
        status, body = self.link(a_code, ref)
        self.assertEqual(status, 200)
        self.assertEqual(body["outcome"], "self_referral")
        self.assertFalse(body["granted"])
        self.assertEqual(self.balance_of(a_code), 3)
        # an unregistered referral code is a clean 404
        b_code = self.paid_code("trio", email="b@example.com")
        status, body = self.link(b_code, credits.generate_code())
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "referral_not_found")
        # an unknown referee code is a clean 404
        status, body = self.link(credits.generate_code(), ref)
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "code_not_found")
        # malformed input is a 400, at link and at checkout alike
        status, _body = self.link(b_code, "NPC-123")
        self.assertEqual(status, 400)
        status, _h, _d = self.post(
            "/v1/credits/checkout",
            {"pack_id": "trio", "referral_code": "NPC-123"})
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
