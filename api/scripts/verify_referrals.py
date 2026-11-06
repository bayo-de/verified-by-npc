"""End-to-end verification walk of the NPC Verify referral scheme.

Bayo's instruction (2026-10-28): "make sure the referral scheme
works technically." This script proves it against the real API,
run on loopback with Stripe simulated in test mode exactly the
way scripts/demo_credits.py does: checkout sessions come from a
fake transport, and every payment-completion webhook is an
honestly HMAC-signed fixture pushed through the API's real
signature verifier. No live key, no live charge.

The walk (balances are read back through the API after each
step):

  A buys a pack and takes delivery of a personal referral code
  (exactly once; a second lookup returns no code).
  B buys a pack, then links A's referral code: B +10, A +10 for
  the link and +100 for B's first paid purchase. A code exists
  only because a purchase minted it, so the link attributes that
  first purchase in the same atomic step; the walk confirms the
  +100 is part of the link outcome, not a later event.
  The link call is replayed, and B's purchase webhook is
  replayed: nothing grants twice.
  C buys with A's referral code carried into checkout: the
  webhook attributes at completion (C +10, A +10 and +100), and
  replaying that webhook grants nothing twice.
  B tries to link a second referrer: already_referred, nothing
  moves. A links A's own code, and a second code bought under
  A's email links A's code: self_referral both times, nothing
  granted or recorded.
  A fresh referrer R takes six referrals in one month: the
  at-link bonuses land 10, 10, 10, 10, 10, 0 and the
  first-purchase bonuses 100, 100, 100, 100, 50, 0, trimming at
  the shared 500 monthly cap, while every referee keeps the
  full +10.
  B spends one AI generation check against the bonus (the
  2026-10-28 extension of bonus checks to the AI layer): the
  charge draws the bonus grant, not the pack counters.

Two steps are store-level, and are labeled as such when they
print: the API's clock is wall time, so "a referral next month
earns again" and "the bonus dies at its rollover expiry" are
proven by calling the store with a later `now` against codes
the API minted. Everything else goes through HTTP.

Run: python3 scripts/verify_referrals.py
(exit 0 = every step passed)
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
    {"id": "walk3", "label": "3 checks (walk pack)", "checks": 3,
     "price_cents": 300, "currency": "usd",
     "stripe_price_id": "price_walk_3"},
])

from http.server import ThreadingHTTPServer  # noqa: E402

from npc_verify import credits  # noqa: E402
from npc_verify.server import create_app, Handler  # noqa: E402

WEBHOOK_SECRET = "whsec_walk_only_not_a_real_secret"
CHECKS = []


def step(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print("%s %s%s" % ("PASS" if cond else "FAIL", name,
                       (" :: " + detail) if detail else ""))
    if not cond:
        raise SystemExit("referral walk failed at: " + name)


class FakePayments:
    configured = True

    def __init__(self):
        self._count = 0
        self._verifier = credits.StripePayments(
            "sk_test_walk", WEBHOOK_SECRET,
            "http://127.0.0.1/get-checks?session_id={CHECKOUT_SESSION_ID}",
            "http://127.0.0.1/get-checks",
            transport=lambda *a, **k: (0, {}))

    def create_checkout_session(self, pack, email=None):
        self._count += 1
        sid = "cs_test_walk_%d" % self._count
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
    tmp = tempfile.mkdtemp(prefix="npc_referral_walk_")
    mailer = StubMailer()
    app = create_app(os.path.join(tmp, "walk.db"),
                     os.path.join(tmp, "keys"),
                     payments=FakePayments(), mailer=mailer)
    Handler.app = app
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    store = app.store
    event_counter = [0]

    def call(method, path, body=None, raw=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port,
                                          timeout=10)
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

    def fire_completed(sid, email):
        event_counter[0] += 1
        event = {"id": "evt_walk_%d" % event_counter[0],
                 "type": "checkout.session.completed",
                 "data": {"object": {
                     "id": sid,
                     "customer_details": {"email": email}}}}
        raw = json.dumps(event).encode()
        header = credits.sign_webhook_payload(
            WEBHOOK_SECRET, raw, int(time.time()))
        return call("POST", "/v1/credits/stripe-webhook", raw=raw,
                    headers={"Stripe-Signature": header,
                             "Content-Type": "application/json"})

    def buy(email, referral_code=None):
        """The purchase path: checkout, signed webhook, delivery.
        Returns (code, session_id)."""
        payload = {"pack_id": "walk3", "email": email}
        if referral_code is not None:
            payload["referral_code"] = referral_code
        status, body = call("POST", "/v1/credits/checkout", payload)
        assert status == 201, body
        sid = body["session_id"]
        status, body = fire_completed(sid, email)
        assert status == 200 and body.get("received") is True, body
        status, body = call(
            "GET", "/v1/credits/checkout-status?session_id=" + sid)
        assert status == 200 and body["status"] == "paid", body
        return body["code"], sid

    def balance(code):
        status, body = call("POST", "/v1/credits/balance",
                            {"code": code})
        assert status == 200, body
        return body

    def lookup(code):
        status, body = call("POST", "/v1/credits/referral/lookup",
                            {"code": code})
        assert status == 200, body
        return body

    def link(code, referral_code):
        return call("POST", "/v1/credits/referral/link",
                    {"code": code, "referral_code": referral_code})

    try:
        # -- A: the referrer --------------------------------------
        a_code, _a_sid = buy("a@walk.test")
        body = balance(a_code)
        step("A buys a 3-check pack through the purchase path",
             body["balance"] == 3 and body["grant_balance"] == 0,
             "A balance=%s" % body["balance"])
        first = lookup(a_code)
        step("A's referral code is delivered on first lookup",
             first["referral_code_included"]
             and credits.valid_code_shape(
                 first["referral_code"] or "")
             and first["referred_count"] == 0
             and first["referral_bonus_this_month"] == 0
             and first["referred_by"] is False)
        ref_a = first["referral_code"]
        second = lookup(a_code)
        step("second lookup returns no code (delivered once)",
             second["referral_code"] is None
             and second["referral_code_included"] is False)

        # -- B: link after purchase --------------------------------
        b_code, b_sid = buy("b@walk.test")
        step("B buys a pack with no referral in play",
             balance(b_code)["balance"] == 3, "B balance=3")
        status, body = link(b_code, ref_a)
        step("B links A's code: +10 referee, +10 link, +100 "
             "first purchase, all in the link outcome",
             status == 200 and body["outcome"] == "linked"
             and body["granted"]
             and body["referee_bonus_checks"] == 10
             and body["referrer_link_bonus_checks"] == 10
             and body["referrer_bonus_checks"] == 100
             and body["balance"] == 13,
             "referee=%s link=%s purchase=%s" % (
                 body.get("referee_bonus_checks"),
                 body.get("referrer_link_bonus_checks"),
                 body.get("referrer_bonus_checks")))
        a_bal, b_bal = balance(a_code), balance(b_code)
        stats_a, stats_b = lookup(a_code), lookup(b_code)
        step("balances after the link: A=113, B=13 (B's "
             "ai_balance counts the 10 bonus checks and the 3 "
             "pack checks behind them)",
             a_bal["balance"] == 113 and b_bal["balance"] == 13
             and b_bal["ai_balance"] == 13
             and stats_a["referred_count"] == 1
             and stats_a["referral_bonus_this_month"] == 110
             and stats_b["referred_by"] is True,
             "A=%s B=%s B ai=%s A month bonus=%s" % (
                 a_bal["balance"], b_bal["balance"],
                 b_bal["ai_balance"],
                 stats_a["referral_bonus_this_month"]))
        status, body = link(b_code, ref_a)
        step("replaying the link grants nothing twice",
             status == 200 and body["outcome"] == "already_referred"
             and body["granted"] is False
             and balance(a_code)["balance"] == 113
             and balance(b_code)["balance"] == 13)
        status, body = fire_completed(b_sid, "b@walk.test")
        step("replaying B's purchase webhook grants nothing twice",
             status == 200 and body.get("received") is True
             and balance(a_code)["balance"] == 113
             and balance(b_code)["balance"] == 13)

        # -- C: referral carried into checkout ----------------------
        c_code, c_sid = buy("c@walk.test", referral_code=ref_a)
        stats_a = lookup(a_code)
        step("C buys with A's code at checkout: attributed at "
             "completion, A gains another 10 + 100",
             balance(c_code)["balance"] == 13
             and lookup(c_code)["referred_by"] is True
             and balance(a_code)["balance"] == 223
             and stats_a["referred_count"] == 2
             and stats_a["referral_bonus_this_month"] == 220,
             "A=%s C=%s" % (balance(a_code)["balance"],
                            balance(c_code)["balance"]))
        status, body = fire_completed(c_sid, "c@walk.test")
        step("replaying C's webhook grants nothing twice",
             status == 200 and body.get("received") is True
             and balance(a_code)["balance"] == 223
             and balance(c_code)["balance"] == 13)

        # -- one referral per user, ever ----------------------------
        other_code, _o_sid = buy("other@walk.test")
        ref_other = lookup(other_code)["referral_code"]
        status, body = link(b_code, ref_other)
        step("B links a second referrer: refused as "
             "already_referred, nothing moves",
             status == 200 and body["outcome"] == "already_referred"
             and body["granted"] is False
             and balance(other_code)["balance"] == 3
             and balance(b_code)["balance"] == 13)

        # -- self-referral, both guards ------------------------------
        status, body = link(a_code, ref_a)
        step("A links A's own code: self_referral, nothing granted",
             status == 200 and body["outcome"] == "self_referral"
             and body["granted"] is False
             and balance(a_code)["balance"] == 223)
        d_code, _d_sid = buy("a@walk.test")
        status, body = link(d_code, ref_a)
        step("a code bought under A's email links A's code: "
             "self_referral, nothing granted or recorded",
             status == 200 and body["outcome"] == "self_referral"
             and balance(d_code)["balance"] == 3
             and balance(a_code)["balance"] == 223
             and lookup(d_code)["referred_by"] is False)

        # -- the monthly cap -----------------------------------------
        r_code, _r_sid = buy("r@walk.test")
        ref_r = lookup(r_code)["referral_code"]
        link_amounts, purchase_amounts = [], []
        referees_ok = True
        for i in range(6):
            f_code, _f_sid = buy("f%d@walk.test" % (i + 1))
            status, body = link(f_code, ref_r)
            referees_ok = referees_ok and status == 200 \
                and body["outcome"] == "linked" \
                and body["referee_bonus_checks"] == 10 \
                and balance(f_code)["balance"] == 13
            link_amounts.append(body["referrer_link_bonus_checks"])
            purchase_amounts.append(body["referrer_bonus_checks"])
        stats_r = lookup(r_code)
        step("six referrals trim at the shared 500 monthly cap "
             "(link 10,10,10,10,10,0; purchase 100,100,100,100,50,0) "
             "while every referee keeps the full +10",
             referees_ok
             and link_amounts == [10, 10, 10, 10, 10, 0]
             and purchase_amounts == [100, 100, 100, 100, 50, 0]
             and stats_r["referral_bonus_this_month"] == 500
             and stats_r["referred_count"] == 6
             and balance(r_code)["balance"] == 503,
             "R month bonus=%s R balance=%s" % (
                 stats_r["referral_bonus_this_month"],
                 balance(r_code)["balance"]))

        # -- store-level: next month earns again ----------------------
        # The API's clock is wall time, so this step calls the
        # store directly, on a code the API minted, with a `now`
        # in the following month.
        g_code, _g_sid = buy("g@walk.test")
        r_hash = credits.code_hash(r_code)
        r_view = store.get_credit_code(
            r_hash, store.get_credit_code(r_hash)["created_at"])
        grant_month = r_view["grants"][0]["granted_at"][:7]
        year, month = int(grant_month[:4]), int(grant_month[5:7])
        month += 1
        if month == 13:
            year, month = year + 1, 1
        next_now = "%04d-%02d-02T12:00:00+00:00" % (year, month)
        g_hash = credits.code_hash(g_code)
        res = store.attribute_referral(
            g_hash, credits.code_hash(ref_r),
            "referee:" + g_hash, "referrer:" + g_hash, next_now,
            credits.grant_expiry(next_now),
            credits.REFEREE_BONUS_CHECKS,
            credits.REFERRER_BONUS_CHECKS,
            credits.REFERRAL_MONTHLY_CAP_CHECKS,
            referrer_link_bonus=credits.REFERRER_LINK_BONUS_CHECKS,
            referrer_link_grant_id="referrer-link:" + g_hash)
        step("(store) a referral in the next month earns in full "
             "again: +10 at link, +100 at first purchase",
             res["outcome"] == "linked"
             and res["referrer_link_bonus"] == 10
             and res["referrer_bonus"] == 100
             and store.referral_stats(r_hash, next_now)
             ["referral_bonus_this_month"] == 110,
             "next month=%s" % next_now[:7])

        # -- B spends an AI check against the bonus -------------------
        status, body = call("POST", "/v1/credits/consume",
                            {"code": b_code,
                             "image_identity": "sha256:" + "ab" * 32,
                             "kind": "ai"})
        step("B spends one AI check: charged against the bonus "
             "grant (draw order puts bonus before pack), pack "
             "counters untouched",
             status == 200 and body["charged"]
             and body["balance"] == 12
             and body["ai_balance"] == 12
             and body["credits_used"] == 0,
             "B balance=%s ai=%s" % (body["balance"],
                                     body["ai_balance"]))

        # -- store-level: the bonus dies at its rollover expiry -------
        b_hash = credits.code_hash(b_code)
        bonus = [g for g in store._credit_grants(b_hash)
                 if g["source"] == "referral_referee"][0]
        step("(store) the bonus grant's expiry is the one-month "
             "rollover of its grant date",
             bonus["expires_at"]
             == credits.grant_expiry(bonus["granted_at"]),
             "granted=%s expires=%s" % (bonus["granted_at"],
                                        bonus["expires_at"]))
        dead = store.get_credit_code(b_hash, bonus["expires_at"])
        step("(store) at the expiry instant the bonus counts for "
             "nothing; the 3 pack checks remain and fund AI "
             "checks on their own",
             dead["grant_balance"] == 0
             and dead["ai_balance"] == 3
             and dead["credits_total"] - dead["credits_used"] == 3,
             "balance at expiry=%s" % (
                 dead["credits_total"] - dead["credits_used"]
                 + dead["grant_balance"]))
    finally:
        server.shutdown()
        store.close()

    failed = [n for n, ok in CHECKS if not ok]
    print("\n%d steps, %d passed" % (len(CHECKS),
                                     len(CHECKS) - len(failed)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
