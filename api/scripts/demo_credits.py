"""End-to-end local demo of the NPC Verify credit tool.

Runs the whole purchase and spend cycle against a loopback copy of
the real API, with Stripe simulated in test mode: checkout sessions
come from a fake transport, and the payment-completion webhook is
an honestly HMAC-signed fixture pushed through the API's real
signature verifier. No live key, no live charge, no network beyond
loopback. With a real Stripe test key configured in the environment
instead, the same API endpoints run against Stripe test mode
unchanged; only this script's fake would be out of the loop.

Proves, in order:
  packs listed -> checkout started -> webhook grants a code ->
  code delivered once on the success page and once by email ->
  a failed check consumes nothing (no consume call, no movement) ->
  redeem shows the balance -> first check of an image charges 1 ->
  re-check of the same image charges 0 -> balance reaches zero ->
  the next new image is refused with no_credits -> a forged
  webhook is rejected and mints nothing.

Then the Verifier Pass (switched on 2026-10-28; registry checks
made unlimited for subscribers later that day):
  pass checkout -> activation webhook mints the subscriber code
  and grants the first 1,000 -> the Pass email carries the code ->
  redeem shows 1,000 with 400 AI and registry checks unlimited ->
  a standard check is covered by the Pass and draws nothing, an
  AI check charges 1 -> a renewal invoice.paid grants the next
  1,000 -> the same invoice replayed grants nothing more ->
  cancellation stops the following grant, granted checks survive.

Run: python3 scripts/demo_credits.py   (exit 0 = every step passed)
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.environ.setdefault("NPC_ALLOW_LOOPBACK_FETCH", "1")
os.environ["NPC_CREDITS_PACKS_JSON"] = json.dumps([
    {"id": "demo3", "label": "3 checks (demo pack)", "checks": 3,
     "price_cents": 300, "currency": "usd",
     "stripe_price_id": "price_demo_3"},
    {"id": "demopass", "label": "Verifier Pass (demo)",
     "checks": 1000, "price_cents": 2500, "currency": "usd",
     "kind": "access", "ai_checks": 400, "interval": "month",
     "stripe_price_id": "price_demo_pass"},
])

from http.server import ThreadingHTTPServer  # noqa: E402

from npc_verify import credits  # noqa: E402
from npc_verify.server import create_app, Handler  # noqa: E402

WEBHOOK_SECRET = "whsec_demo_only_not_a_real_secret"
CHECKS = []


def step(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print("%s %s%s" % ("PASS" if cond else "FAIL", name,
                       (" :: " + detail) if detail else ""))
    if not cond:
        raise SystemExit("demo failed at: " + name)


class FakePayments:
    configured = True

    def __init__(self):
        self._count = 0
        self._verifier = credits.StripePayments(
            "sk_test_demo", WEBHOOK_SECRET,
            "http://127.0.0.1/get-checks?session_id={CHECKOUT_SESSION_ID}",
            "http://127.0.0.1/get-checks",
            transport=lambda *a, **k: (0, {}))

    def create_checkout_session(self, pack, email=None):
        self._count += 1
        sid = "cs_test_demo_%d" % self._count
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
        self.sent.append({"to": to, "subject": subject, "text": text})
        return True


def main():
    tmp = tempfile.mkdtemp(prefix="npc_credits_demo_")
    mailer = StubMailer()
    app = create_app(os.path.join(tmp, "demo.db"),
                     os.path.join(tmp, "keys"),
                     payments=FakePayments(), mailer=mailer)
    Handler.app = app
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def call(method, path, body=None, raw=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        hdrs = dict(headers or {})
        payload = raw
        if body is not None:
            payload = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data) if data else {}

    try:
        status, body = call("GET", "/v1/credits/packs")
        step("packs listed, checkout available",
             status == 200 and body["checkout_available"]
             and body["packs"][0]["id"] == "demo3",
             json.dumps(body["packs"]))

        status, body = call("POST", "/v1/credits/checkout",
                            {"pack_id": "demo3",
                             "email": "demo@example.com"})
        step("checkout session created (test mode)",
             status == 201 and body["session_id"] == "cs_test_demo_1",
             body.get("checkout_url", ""))
        sid = body["session_id"]

        event = {"id": "evt_demo_1",
                 "type": "checkout.session.completed",
                 "data": {"object": {
                     "id": sid,
                     "customer_details": {"email": "demo@example.com"}}}}
        raw = json.dumps(event).encode()
        header = credits.sign_webhook_payload(
            WEBHOOK_SECRET, raw, int(time.time()))
        status, body = call("POST", "/v1/credits/stripe-webhook",
                            raw=raw,
                            headers={"Stripe-Signature": header,
                                     "Content-Type": "application/json"})
        step("signed webhook accepted", status == 200
             and body.get("received") is True)

        status, body = call(
            "GET", "/v1/credits/checkout-status?session_id=" + sid)
        code = body.get("code")
        step("success page delivers the code once",
             status == 200 and body["status"] == "paid"
             and credits.valid_code_shape(code or ""), code or "")
        step("the same code arrived by email",
             len(mailer.sent) == 1 and code in mailer.sent[0]["text"],
             mailer.sent[0]["subject"] if mailer.sent else "")
        status, body = call(
            "GET", "/v1/credits/checkout-status?session_id=" + sid)
        step("second delivery attempt returns no code",
             status == 200 and "code" not in body)

        status, body = call("POST", "/v1/credits/redeem",
                            {"code": code})
        step("redeem shows the full balance",
             status == 200 and body["balance"] == 3,
             "balance=%s" % body.get("balance"))

        # A check that fails (API down, bad signature) never reaches
        # the consume call in the client, so the ledger cannot move.
        status, body = call("POST", "/v1/credits/balance",
                            {"code": code})
        step("a failed check consumed nothing",
             status == 200 and body["balance"] == 3,
             "balance still %s" % body.get("balance"))

        ident_a = "sha256:" + "ab" * 32
        status, body = call("POST", "/v1/credits/consume",
                            {"code": code, "image_identity": ident_a})
        step("first check of a new image charges 1",
             status == 200 and body["charged"]
             and body["balance"] == 2)
        status, body = call("POST", "/v1/credits/consume",
                            {"code": code, "image_identity": ident_a})
        step("re-check of the same image charges 0",
             status == 200 and body["duplicate"]
             and not body["charged"] and body["balance"] == 2)
        call("POST", "/v1/credits/consume",
             {"code": code, "image_identity": "sha256:" + "cd" * 32})
        status, body = call(
            "POST", "/v1/credits/consume",
            {"code": code, "image_identity": "sha256:" + "ef" * 32})
        step("balance reaches zero and the code is exhausted",
             status == 200 and body["balance"] == 0
             and body["status"] == "exhausted")
        status, body = call(
            "POST", "/v1/credits/consume",
            {"code": code, "image_identity": "sha256:" + "12" * 32})
        step("a new image at zero balance is refused, not charged",
             status == 402 and body["error"] == "no_credits")

        # -- the Verifier Pass --------------------------------------
        def fire(event_type, obj, event_id):
            event = {"id": event_id, "type": event_type,
                     "data": {"object": obj}}
            raw = json.dumps(event).encode()
            header = credits.sign_webhook_payload(
                WEBHOOK_SECRET, raw, int(time.time()))
            return call("POST", "/v1/credits/stripe-webhook", raw=raw,
                        headers={"Stripe-Signature": header,
                                 "Content-Type": "application/json"})

        status, body = call("GET", "/v1/credits/packs")
        demo_pass = [p for p in body["packs"]
                     if p["id"] == "demopass"][0]
        step("verifier pass listed on sale with its terms",
             demo_pass["kind"] == "access" and demo_pass["on_sale"]
             and demo_pass["checks"] == 1000
             and demo_pass["ai_checks"] == 400
             and demo_pass["registry_unlimited"] is True
             and demo_pass["price_cents"] == 2500,
             json.dumps(demo_pass))

        status, body = call("POST", "/v1/credits/checkout",
                            {"pack_id": "demopass",
                             "email": "member@example.com"})
        step("pass checkout session created (test mode)",
             status == 201 and body["pack_id"] == "demopass",
             body.get("checkout_url", ""))
        pass_sid = body["session_id"]

        status, body = fire(
            "checkout.session.completed",
            {"id": pass_sid, "subscription": "sub_demo_1",
             "customer": "cus_demo_1", "invoice": "in_demo_1",
             "customer_details": {"email": "member@example.com"}},
            "evt_demo_pass_1")
        step("activation webhook accepted", status == 200
             and body.get("received") is True)

        status, body = call(
            "GET", "/v1/credits/checkout-status?session_id=" + pass_sid)
        pass_code = body.get("code")
        step("success page delivers the pass code once",
             status == 200 and body["status"] == "paid"
             and credits.valid_code_shape(pass_code or ""),
             pass_code or "")
        step("the pass code arrived by pass email",
             len(mailer.sent) == 2
             and mailer.sent[1]["subject"]
             == "Your NPC Verify Verifier Pass"
             and pass_code in mailer.sent[1]["text"],
             mailer.sent[1]["subject"] if len(mailer.sent) > 1 else "")

        status, body = call("POST", "/v1/credits/redeem",
                            {"code": pass_code})
        step("redeem shows 1,000 checks and 400 AI checks",
             status == 200 and body["balance"] == 1000
             and body["ai_balance"] == 400
             and body["registry_unlimited"] is True
             and body["subscription_status"] == "active",
             "balance=%s ai=%s" % (body.get("balance"),
                                   body.get("ai_balance")))

        status, body = call(
            "POST", "/v1/credits/consume",
            {"code": pass_code, "image_identity": "sha256:" + "34" * 32})
        step("a standard check is covered by the pass, draws nothing",
             status == 200 and body["charged"]
             and body["balance"] == 1000
             and body["ai_balance"] == 400)
        status, body = call(
            "POST", "/v1/credits/consume",
            {"code": pass_code, "image_identity": "sha256:" + "56" * 32,
             "kind": "ai"})
        step("an AI check charges the grant and its AI allowance",
             status == 200 and body["charged"]
             and body["balance"] == 999
             and body["ai_balance"] == 399)

        status, _b = fire("invoice.paid",
                          {"id": "in_demo_2",
                           "subscription": "sub_demo_1"},
                          "evt_demo_pass_2")
        status, body = call("POST", "/v1/credits/balance",
                            {"code": pass_code})
        step("renewal invoice grants the next 1,000",
             status == 200 and body["balance"] == 1999
             and body["ai_balance"] == 799,
             "balance=%s" % body.get("balance"))
        fire("invoice.paid",
             {"id": "in_demo_2", "subscription": "sub_demo_1"},
             "evt_demo_pass_3")
        status, body = call("POST", "/v1/credits/balance",
                            {"code": pass_code})
        step("the same invoice replayed grants nothing more",
             status == 200 and body["balance"] == 1999)

        fire("customer.subscription.deleted", {"id": "sub_demo_1"},
             "evt_demo_pass_4")
        fire("invoice.paid",
             {"id": "in_demo_3", "subscription": "sub_demo_1"},
             "evt_demo_pass_5")
        status, body = call("POST", "/v1/credits/balance",
                            {"code": pass_code})
        step("cancellation stops future grants, granted checks stay",
             status == 200 and body["balance"] == 1999
             and body["registry_unlimited"] is False
             and body["subscription_status"] == "canceled")

        forged = json.dumps(
            {"id": "evt_forged", "type": "checkout.session.completed",
             "data": {"object": {"id": sid}}}).encode()
        status, _body = call(
            "POST", "/v1/credits/stripe-webhook", raw=forged,
            headers={"Stripe-Signature": "t=1,v1=forged",
                     "Content-Type": "application/json"})
        purchase = app.store.get_credit_purchase(sid)
        step("a forged webhook is rejected and mints nothing",
             status == 400 and purchase["status"] == "paid"
             and len(mailer.sent) == 2)
    finally:
        server.shutdown()
        app.store.close()

    failed = [n for n, ok in CHECKS if not ok]
    print("\n%d steps, %d passed" % (len(CHECKS),
                                     len(CHECKS) - len(failed)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
