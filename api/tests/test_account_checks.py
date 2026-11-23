"""Account session checks + check history (Biblo tab, 2026-11-21).

POST /v1/account/checks/image and /v1/account/checks/video run the
verifier routes' check cores under the account session, charge the
account's own balance on the credit ledger (a body code is still
honored for older clients), and record the check in the account's
history; GET /v1/account/checks serves that history, newest first,
to the session's account only, and GET /v1/account/balance serves
the account's balance.

No live calls: detectors and the media fetcher are injected fakes
(the test_detector / test_av pattern), accounts come from the
email-link flow against the stub mailer (the test_accounts
pattern), and funded codes are minted straight into the store
(the test_credits pattern).
"""
import base64
import hashlib
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

os.environ["NPC_AUTH_RP_ID"] = "localhost"
os.environ["NPC_AUTH_ORIGINS"] = "http://127.0.0.1"
os.environ["NPC_AUTH_SITE_BASE"] = "http://127.0.0.1"

from npc_verify.server import create_app, Handler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify.mailer import StubMailer  # noqa: E402
from npc_verify import credits  # noqa: E402
from npc_verify import ed25519  # noqa: E402
from npc_verify.av_detector import VideoCheckResult  # noqa: E402
from npc_verify.canonical import canonicalize  # noqa: E402
from npc_verify.detector import DetectorError  # noqa: E402
from npc_verify.models import utcnow_iso  # noqa: E402

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"npc-account-check" * 8
PNG_B64 = base64.b64encode(PNG_BYTES).decode()
VIDEO_BYTES = b"\x00\x00\x00\x18ftypmp42" + b"npc-account-video" * 8
IMAGE_URL = "https://example.com/pic.jpg"
VIDEO_URL = "https://example.com/clip.mp4"

PACK = {"id": "trio", "label": "3 checks", "checks": 3,
        "price_cents": 300, "currency": "usd"}


class FakeImageDetector:
    provider = "sightengine"
    model = "genai"
    configured = True

    def __init__(self, prob=0.99, error=None):
        self.prob = prob
        self.error = error
        self.calls = []

    def check_ai(self, image_bytes=None, image_url=None):
        self.calls.append((image_bytes, image_url))
        if self.error is not None:
            raise self.error
        return self.prob


class FakeVideoDetector:
    provider = "sightengine"
    model = "genai"
    configured = True

    def __init__(self, scores=(0.99, 0.10, 0.60), error=None):
        self.scores = scores
        self.error = error
        self.calls = []

    def check_ai_video(self, video_bytes=None, interval_seconds=2):
        self.calls.append((video_bytes, interval_seconds))
        if self.error is not None:
            raise self.error
        frames = [(i * int(interval_seconds * 1000), s)
                  for i, s in enumerate(self.scores)]
        return VideoCheckResult(frames, operations=40)


class FakeFetcher:
    def __init__(self, data=VIDEO_BYTES):
        self.data = data
        self.calls = []

    def __call__(self, url, max_bytes):
        self.calls.append((url, max_bytes))
        return self.data


class AccountChecksTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_acct_checks_")
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
        self.fake_image = FakeImageDetector()
        self.fake_video = FakeVideoDetector()
        self.fake_fetch = FakeFetcher()
        self.app.detector = self.fake_image
        self.app.video_detector = self.fake_video
        self.app.media_fetcher = self.fake_fetch
        self._mint_counter = 0

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

    def mint_code(self, pack=PACK, email="buyer@example.com"):
        self._mint_counter += 1
        session = "cs_acct_%d" % self._mint_counter
        code = credits.generate_code()
        now = utcnow_iso()
        self.app.store.create_credit_purchase(session, pack["id"],
                                              None, now)
        self.app.store.complete_credit_purchase(
            session, credits.code_hash(code), code, pack, email, now)
        return code

    def history(self, token):
        status, headers, raw = self.get("/v1/account/checks",
                                        token=token)
        self.assertEqual(status, 200, raw)
        return self.check_signature(headers, raw)["checks"]

    # -- auth separation --------------------------------------------------

    def test_no_session_is_401(self):
        status, _h, _raw = self.post(
            "/v1/account/checks/image",
            {"code": "whatever", "image_url": IMAGE_URL})
        self.assertEqual(status, 401)
        status, _h, _raw = self.post(
            "/v1/account/checks/video",
            {"code": "whatever", "video_url": VIDEO_URL})
        self.assertEqual(status, 401)
        status, _h, _raw = self.get("/v1/account/checks")
        self.assertEqual(status, 401)

    def test_api_key_does_not_authenticate_account_routes(self):
        status, _h, _raw = self.post(
            "/v1/account/checks/image",
            {"code": "whatever", "image_url": IMAGE_URL},
            key=self.verifier_key)
        self.assertEqual(status, 401)
        status, _h, _raw = self.get("/v1/account/checks",
                                    key=self.verifier_key)
        self.assertEqual(status, 401)

    # -- image checks -------------------------------------------------------

    def test_history_starts_empty(self):
        token = self.sign_in("ada@example.com")
        self.assertEqual(self.history(token), [])

    def test_image_check_charges_once_and_lands_in_history(self):
        token = self.sign_in("ada@example.com")
        code = self.mint_code()
        status, headers, raw = self.post(
            "/v1/account/checks/image",
            {"code": code, "image_base64": PNG_B64}, token=token)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertEqual(body["check"], "ai_generation")
        self.assertEqual(body["ai_generated_percent"], 99)
        self.assertEqual(body["image_sha256"],
                         hashlib.sha256(PNG_BYTES).hexdigest())
        self.assertTrue(body["check_id"].startswith("chk_"))
        self.assertTrue(body["charged"])
        self.assertFalse(body["duplicate"])
        self.assertEqual(body["balance"], 2)
        self.assertEqual(body["ai_balance"], 2)

        checks = self.history(token)
        self.assertEqual(len(checks), 1)
        entry = checks[0]
        self.assertEqual(entry["check_id"], body["check_id"])
        self.assertEqual(entry["check"], "ai_generation")
        self.assertEqual(entry["media_ref"],
                         "sha256:" + hashlib.sha256(
                             PNG_BYTES).hexdigest())
        self.assertEqual(entry["media_sha256"],
                         hashlib.sha256(PNG_BYTES).hexdigest())
        self.assertTrue(entry["charged"])
        self.assertFalse(entry["duplicate"])
        self.assertEqual(entry["result"]["ai_generated_percent"], 99)
        # The recorded result is the check body itself; the
        # response-only fields (check_id, charged, ...) are not in it.
        self.assertNotIn("check_id", entry["result"])
        self.assertIn("created_at", entry)

    def test_repeat_image_check_is_duplicate_and_charges_nothing(self):
        token = self.sign_in("ada@example.com")
        code = self.mint_code()
        status, _h, raw = self.post(
            "/v1/account/checks/image",
            {"code": code, "image_url": IMAGE_URL}, token=token)
        self.assertEqual(status, 200, raw)
        first = json.loads(raw)
        self.assertTrue(first["charged"])
        self.assertEqual(first["ai_balance"], 2)

        status, headers, raw = self.post(
            "/v1/account/checks/image",
            {"code": code, "image_url": IMAGE_URL}, token=token)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertFalse(body["charged"])
        self.assertTrue(body["duplicate"])
        self.assertEqual(body["balance"], 2)
        self.assertEqual(body["ai_balance"], 2)
        self.assertNotEqual(body["check_id"], first["check_id"])

        checks = self.history(token)
        self.assertEqual(len(checks), 2)
        self.assertTrue(checks[0]["duplicate"])
        self.assertFalse(checks[0]["charged"])
        self.assertTrue(checks[1]["charged"])

    def test_no_ai_balance_is_402_and_detector_never_runs(self):
        token = self.sign_in("ada@example.com")
        code = self.mint_code()
        code_hash = credits.code_hash(code)
        now = utcnow_iso()
        for i in range(3):
            out = self.app.store.consume_credit(
                code_hash, "drain-%d" % i, None, "chg_drain_%d" % i,
                now, kind="ai")
            self.assertEqual(out["outcome"], "charged")
        status, _h, raw = self.post(
            "/v1/account/checks/image",
            {"code": code, "image_url": IMAGE_URL}, token=token)
        self.assertEqual(status, 402, raw)
        self.assertEqual(json.loads(raw)["error"], "no_ai_credits")
        self.assertEqual(self.fake_image.calls, [])
        self.assertEqual(self.history(token), [])

    def test_unknown_code_is_404(self):
        token = self.sign_in("ada@example.com")
        ghost = credits.generate_code()
        status, _h, raw = self.post(
            "/v1/account/checks/image",
            {"code": ghost, "image_url": IMAGE_URL}, token=token)
        self.assertEqual(status, 404, raw)
        self.assertEqual(json.loads(raw)["error"], "code_not_found")
        self.assertEqual(self.fake_image.calls, [])

    def test_revoked_code_is_403(self):
        token = self.sign_in("ada@example.com")
        code = self.mint_code()
        store = self.app.store
        with store.db_lock:
            store.db.execute(
                "UPDATE credit_codes SET status='revoked'"
                " WHERE code_hash=?",
                (credits.code_hash(code),))
            store.db.commit()
        status, _h, raw = self.post(
            "/v1/account/checks/image",
            {"code": code, "image_url": IMAGE_URL}, token=token)
        self.assertEqual(status, 403, raw)
        self.assertEqual(json.loads(raw)["error"], "code_revoked")
        self.assertEqual(self.fake_image.calls, [])

    def test_detector_unavailable_is_503_no_charge_no_record(self):
        token = self.sign_in("ada@example.com")
        code = self.mint_code()
        self.fake_image.error = DetectorError("vendor down")
        status, headers, raw = self.post(
            "/v1/account/checks/image",
            {"code": code, "image_url": IMAGE_URL}, token=token)
        self.assertEqual(status, 503, raw)
        body = self.check_signature(headers, raw)
        self.assertEqual(body["error"], "detector_unavailable")
        row = self.app.store.get_credit_code(
            credits.code_hash(code), utcnow_iso())
        self.assertEqual(row["credits_used"], 0)
        self.assertEqual(self.history(token), [])

    # -- account balance funding (no code, 2026-11-22) -------------------
    # Bayo's ruling: desktop checks draw on the signed-in account's
    # own balance; no code is presented or needed. Funding here
    # lands through the store's account purchase completion, the
    # same call the Stripe webhook makes for a signed-in purchase.

    def account_id_of(self, sess):
        status, _h, raw = self.get("/v1/auth/me", token=sess)
        self.assertEqual(status, 200, raw)
        return json.loads(raw)["account"]["account_id"]

    def fund_account(self, sess, checks=3):
        acct = self.account_id_of(sess)
        self._mint_counter += 1
        session = "cs_acct_bal_%d" % self._mint_counter
        now = utcnow_iso()
        self.app.store.create_credit_purchase(
            session, PACK["id"], None, now, account_id=acct)
        row = self.app.store.complete_account_purchase(
            session, credits.account_ledger_hash(acct), PACK,
            "buyer@example.com", now)
        self.assertIsNotNone(row)
        return acct

    def account_balance_of(self, sess):
        status, headers, raw = self.get("/v1/account/balance",
                                        token=sess)
        self.assertEqual(status, 200, raw)
        return self.check_signature(headers, raw)

    def test_balance_route_needs_session_and_starts_at_zero(self):
        status, _h, _raw = self.get("/v1/account/balance")
        self.assertEqual(status, 401)
        status, _h, _raw = self.get("/v1/account/balance",
                                    key=self.verifier_key)
        self.assertEqual(status, 401)
        sess = self.sign_in("owner@example.com")
        body = self.account_balance_of(sess)
        self.assertEqual(body["balance"], 0)
        self.assertEqual(body["ai_balance"], 0)
        self.assertEqual(body["status"], "active")

    def test_no_code_check_at_zero_balance_is_402(self):
        sess = self.sign_in("owner@example.com")
        status, _h, raw = self.post(
            "/v1/account/checks/image",
            {"image_url": IMAGE_URL}, token=sess)
        self.assertEqual(status, 402, raw)
        self.assertEqual(json.loads(raw)["error"], "no_ai_credits")
        self.assertEqual(self.fake_image.calls, [])
        self.assertEqual(self.history(sess), [])

    def test_no_code_check_charges_account_once_duplicate_free(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        status, headers, raw = self.post(
            "/v1/account/checks/image",
            {"image_base64": PNG_B64}, token=sess)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertTrue(body["charged"])
        self.assertFalse(body["duplicate"])
        self.assertEqual(body["balance"], 2)
        self.assertEqual(body["ai_balance"], 2)
        self.assertEqual(self.account_balance_of(sess)["ai_balance"], 2)

        status, headers, raw = self.post(
            "/v1/account/checks/image",
            {"image_base64": PNG_B64}, token=sess)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertFalse(body["charged"])
        self.assertTrue(body["duplicate"])
        self.assertEqual(body["ai_balance"], 2)
        self.assertEqual(self.account_balance_of(sess)["balance"], 2)

        checks = self.history(sess)
        self.assertEqual(len(checks), 2)
        # Order-insensitive: two checks inside one second can list
        # in either order (the history sort ties on created_at).
        self.assertEqual(
            sorted((c["charged"], c["duplicate"]) for c in checks),
            [(False, True), (True, False)])

    def test_no_code_video_check_charges_account(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        status, headers, raw = self.post(
            "/v1/account/checks/video",
            {"video_url": VIDEO_URL}, token=sess)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertTrue(body["charged"])
        self.assertEqual(body["ai_balance"], 2)

    def test_no_code_detector_failure_charges_nothing(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        self.fake_image.error = DetectorError("vendor down")
        status, _h, raw = self.post(
            "/v1/account/checks/image",
            {"image_url": IMAGE_URL}, token=sess)
        self.assertEqual(status, 503, raw)
        self.assertEqual(self.account_balance_of(sess)["balance"], 3)
        self.assertEqual(self.history(sess), [])

    def test_account_balances_are_per_account(self):
        sess_a = self.sign_in("a@example.com")
        sess_b = self.sign_in("b@example.com")
        self.fund_account(sess_a)
        self.assertEqual(self.account_balance_of(sess_a)["balance"], 3)
        self.assertEqual(self.account_balance_of(sess_b)["balance"], 0)
        status, _h, raw = self.post(
            "/v1/account/checks/image",
            {"image_url": IMAGE_URL}, token=sess_b)
        self.assertEqual(status, 402, raw)

    def test_operator_comp_funds_checks_and_is_marked_in_ledger(self):
        sess = self.sign_in("owner@example.com")
        acct = self.account_id_of(sess)
        now = utcnow_iso()
        outcome = self.app.store.grant_account_comp(
            acct, "owner@example.com", 25,
            "operator-comp:test", now, credits.grant_expiry(now))
        self.assertEqual(outcome["outcome"], "granted")
        body = self.account_balance_of(sess)
        self.assertEqual(body["balance"], 25)
        self.assertEqual(body["ai_balance"], 25)
        # The ledger tells a comp apart from a purchase: the grant
        # carries the operator_comp source, and no pack counters
        # moved.
        row = outcome["code"]
        self.assertEqual(row["credits_total"], 0)
        self.assertEqual(len(row["grants"]), 1)
        self.assertEqual(row["grants"][0]["source"], "operator_comp")
        self.assertEqual(row["grants"][0]["amount"], 25)
        # A replay under the same grant id lands nothing twice.
        outcome = self.app.store.grant_account_comp(
            acct, "owner@example.com", 25,
            "operator-comp:test", now, credits.grant_expiry(now))
        self.assertEqual(outcome["outcome"], "duplicate")
        self.assertEqual(self.account_balance_of(sess)["balance"], 25)
        # The round trip draws exactly one check from the comp.
        status, headers, raw = self.post(
            "/v1/account/checks/image",
            {"image_base64": PNG_B64}, token=sess)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertTrue(body["charged"])
        self.assertEqual(body["balance"], 24)
        self.assertEqual(body["ai_balance"], 24)
        self.assertEqual(self.account_balance_of(sess)["balance"], 24)

    def test_operator_comp_unknown_account_grants_nothing(self):
        now = utcnow_iso()
        outcome = self.app.store.grant_account_comp(
            "acct_ghost", "ghost@example.com", 25,
            "operator-comp:ghost", now, credits.grant_expiry(now))
        self.assertEqual(outcome["outcome"], "not_found")
        self.assertIsNone(outcome["code"])

    # -- video checks -------------------------------------------------------

    def test_video_check_succeeds_and_is_recorded(self):
        token = self.sign_in("ada@example.com")
        code = self.mint_code()
        status, headers, raw = self.post(
            "/v1/account/checks/video",
            {"code": code, "video_url": VIDEO_URL}, token=token)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertEqual(body["check"], "ai_generation_video")
        self.assertEqual(body["ai_generated_percent"], 56)
        self.assertEqual(body["ai_generated_percent_peak"], 99)
        self.assertEqual(body["video_sha256"],
                         hashlib.sha256(VIDEO_BYTES).hexdigest())
        self.assertTrue(body["charged"])
        self.assertFalse(body["duplicate"])
        self.assertEqual(body["ai_balance"], 2)
        self.assertEqual(self.fake_fetch.calls[0][0], VIDEO_URL)

        checks = self.history(token)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["check"], "ai_generation_video")
        self.assertEqual(checks[0]["media_ref"], VIDEO_URL)
        self.assertEqual(checks[0]["media_sha256"],
                         hashlib.sha256(VIDEO_BYTES).hexdigest())
        self.assertEqual(checks[0]["result"]["frames_analyzed"], 3)

    # -- isolation + tamper evidence ----------------------------------------

    def test_second_account_history_is_separate(self):
        token_a = self.sign_in("ada@example.com")
        code = self.mint_code()
        status, _h, _raw = self.post(
            "/v1/account/checks/image",
            {"code": code, "image_url": IMAGE_URL}, token=token_a)
        self.assertEqual(status, 200)
        self.assertEqual(len(self.history(token_a)), 1)

        token_b = self.sign_in("grace@example.com")
        self.assertEqual(self.history(token_b), [])

    def test_history_signature_fails_on_tampered_body(self):
        token = self.sign_in("ada@example.com")
        code = self.mint_code()
        status, _h, _raw = self.post(
            "/v1/account/checks/image",
            {"code": code, "image_url": IMAGE_URL}, token=token)
        self.assertEqual(status, 200)

        status, headers, raw = self.get("/v1/account/checks",
                                        token=token)
        self.assertEqual(status, 200)
        self.check_signature(headers, raw)  # untampered verifies
        sig = base64.b64decode(headers["X-NPC-Signature"])
        _s, _h, kdata = self.get("/v1/keys")
        pub = base64.b64decode(
            json.loads(kdata)["api_signing"]["current"]["public_key"])
        tampered = raw.replace(b"ai_generation", b"ai_generatioX", 1)
        self.assertNotEqual(tampered, raw)
        self.assertFalse(ed25519.verify(pub, tampered, sig))


if __name__ == "__main__":
    unittest.main()
