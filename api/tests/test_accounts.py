"""Gate G1: the unified NPC account, end to end over loopback HTTP.

Covers the decided login shape (2026-10-24): passkeys first, the
one-time email link as anchor and fallback, recovery codes issued
at first passkey enrollment, revocable device sessions visible on
every surface, the desktop browser handoff, and the separation
between session tokens and API keys.

The app under test is built with the stub mailer, so the email
link flow runs without SES: the link is read out of the mailer's
outbox exactly as a local developer would read it from the stub
file.
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

os.environ["NPC_AUTH_RP_ID"] = "localhost"
os.environ["NPC_AUTH_ORIGINS"] = "http://127.0.0.1"
os.environ["NPC_AUTH_SITE_BASE"] = "http://127.0.0.1"

from npc_verify.server import create_app, Handler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify.mailer import StubMailer  # noqa: E402
from npc_verify import accounts as accounts_module  # noqa: E402
from tests.helpers import SoftAuthenticator  # noqa: E402

RP_ID = "localhost"
ORIGIN = "http://127.0.0.1"
EMAIL = "ada@example.com"


class AccountHttpTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_accounts_test_")
        cls.mailer = StubMailer()
        cls.app = create_app(os.path.join(cls.tmp, "t.db"),
                             os.path.join(cls.tmp, "keys"),
                             mailer=cls.mailer)
        seeded = seed_all(cls.app.store, cls.app.keys)
        cls.verifier_key = seeded["verifier_key"]
        Handler.app = cls.app
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.app.store.close()

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
        try:
            data = json.loads(raw)
        except ValueError:
            data = {"_raw": raw.decode("utf-8", "replace")}
        return resp.status, dict(resp.getheaders()), data

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body or {}, **kw)

    # -- flow helpers -----------------------------------------------------

    def request_link(self, email=EMAIL, handoff_id=None):
        body = {"email": email}
        if handoff_id:
            body["handoff_id"] = handoff_id
        status, _h, data = self.post("/v1/auth/email/request", body)
        self.assertEqual(status, 200, data)
        return data

    def link_token_from_outbox(self):
        self.assertTrue(self.mailer.outbox, "no mail was sent")
        text = self.mailer.outbox[-1]["text"]
        match = re.search(r"token=([A-Za-z0-9_\-]+)", text)
        self.assertIsNotNone(match, text)
        return match.group(1)

    def redeem_link(self, email=EMAIL, **kw):
        self.request_link(email, **kw)
        token = self.link_token_from_outbox()
        status, _h, data = self.post(
            "/v1/auth/email/redeem",
            {"token": token, "surface": "web",
             "device_label": "Test browser"})
        self.assertEqual(status, 200, data)
        return data

    def enroll_passkey(self, session_token, authenticator=None):
        authenticator = authenticator or SoftAuthenticator(RP_ID, ORIGIN)
        status, _h, begin = self.post(
            "/v1/auth/passkeys/register/begin", {},
            token=session_token)
        self.assertEqual(status, 200, begin)
        payload = authenticator.create(begin["publicKey"])
        payload["challenge_id"] = begin["challenge_id"]
        status, _h, done = self.post(
            "/v1/auth/passkeys/register/finish", payload,
            token=session_token)
        self.assertEqual(status, 200, done)
        return authenticator, done

    def sign_in_with_passkey(self, authenticator, email=EMAIL, **extra):
        body = {"email": email}
        status, _h, begin = self.post(
            "/v1/auth/passkeys/authenticate/begin", body)
        self.assertEqual(status, 200, begin)
        payload = authenticator.get(begin["publicKey"])
        payload["challenge_id"] = begin["challenge_id"]
        payload.update(extra)
        status, _h, data = self.post(
            "/v1/auth/passkeys/authenticate/finish", payload)
        self.assertEqual(status, 200, data)
        return data


class TestEmailLink(AccountHttpTestCase):
    def test_full_flow_and_single_use(self):
        data = self.redeem_link("grace@example.com")
        self.assertTrue(data["session_token"].startswith("npc_sess_"))
        self.assertTrue(data["passkey_enrollment_recommended"])
        self.assertEqual(data["account"]["email"], "grace@example.com")
        status, _h, me = self.get("/v1/auth/me",
                                  token=data["session_token"])
        self.assertEqual(status, 200, me)
        self.assertEqual(me["account"]["email"], "grace@example.com")
        self.assertEqual(me["session"]["surface"], "web")
        # The same link cannot be redeemed twice.
        token = self.link_token_from_outbox()
        status, _h, again = self.post("/v1/auth/email/redeem",
                                      {"token": token})
        self.assertEqual(status, 400, again)

    def test_new_link_retires_the_old_one(self):
        self.request_link("hopper@example.com")
        old = self.link_token_from_outbox()
        self.request_link("hopper@example.com")
        new = self.link_token_from_outbox()
        self.assertNotEqual(old, new)
        status, _h, data = self.post("/v1/auth/email/redeem",
                                     {"token": old})
        self.assertEqual(status, 400, data)
        status, _h, data = self.post("/v1/auth/email/redeem",
                                     {"token": new})
        self.assertEqual(status, 200, data)

    def test_bad_email_and_unknown_token(self):
        status, _h, data = self.post("/v1/auth/email/request",
                                     {"email": "not-an-email"})
        self.assertEqual(status, 400, data)
        status, _h, data = self.post(
            "/v1/auth/email/redeem", {"token": "npc_link_nope"})
        self.assertEqual(status, 400, data)

    def test_expired_link(self):
        config = accounts_module.config_from_env()
        config["email_ttl"] = accounts_module.timedelta(0)
        service = accounts_module.AccountService(
            self.app.store, self.mailer, config)
        service.request_email_link("expired@example.com")
        token = self.link_token_from_outbox()
        with self.assertRaises(accounts_module.AccountError) as ctx:
            service.redeem_email_link(token)
        self.assertIn("expired", ctx.exception.body["detail"])


class TestPasskeys(AccountHttpTestCase):
    def test_enroll_then_sign_in(self):
        data = self.redeem_link("passkey@example.com")
        _auth, done = self.enroll_passkey(data["session_token"])
        self.assertEqual(len(done["recovery_codes"]), 10)
        self.assertTrue(done["recovery_codes_shown_once"])
        self.assertEqual(done["passkeys_on_file"], 1)

    def test_registration_requires_a_session(self):
        status, _h, data = self.post("/v1/auth/passkeys/register/begin",
                                     {})
        self.assertEqual(status, 401, data)

    def test_second_passkey_issues_no_new_codes(self):
        data = self.redeem_link("two@example.com")
        first = SoftAuthenticator(RP_ID, ORIGIN)
        self.enroll_passkey(data["session_token"], first)
        second = SoftAuthenticator(RP_ID, ORIGIN)
        _a, done = self.enroll_passkey(data["session_token"], second)
        self.assertNotIn("recovery_codes", done)
        self.assertEqual(done["passkeys_on_file"], 2)
        # Either passkey signs in.
        self.sign_in_with_passkey(first, "two@example.com")
        self.sign_in_with_passkey(second, "two@example.com")

    def test_es256_passkey(self):
        data = self.redeem_link("es@example.com")
        auth = SoftAuthenticator(RP_ID, ORIGIN, alg=-7)
        self.enroll_passkey(data["session_token"], auth)
        self.sign_in_with_passkey(auth, "es@example.com")

    def test_wrong_challenge_and_replay_fail(self):
        data = self.redeem_link("challenge@example.com")
        auth, _done = self.enroll_passkey(data["session_token"])
        status, _h, begin = self.post(
            "/v1/auth/passkeys/authenticate/begin",
            {"email": "challenge@example.com"})
        payload = auth.get(begin["publicKey"])
        payload["challenge_id"] = "chal_does_not_exist"
        status, _h, data = self.post(
            "/v1/auth/passkeys/authenticate/finish", payload)
        self.assertEqual(status, 400, data)
        # A real ceremony answers once; its replay fails.
        payload = auth.get(begin["publicKey"])
        payload["challenge_id"] = begin["challenge_id"]
        status, _h, data = self.post(
            "/v1/auth/passkeys/authenticate/finish", payload)
        self.assertEqual(status, 200, data)
        status, _h, data = self.post(
            "/v1/auth/passkeys/authenticate/finish", payload)
        self.assertEqual(status, 400, data)

    def test_counter_regression_fails(self):
        data = self.redeem_link("counter@example.com")
        auth, _done = self.enroll_passkey(data["session_token"])
        self.sign_in_with_passkey(auth, "counter@example.com")
        status, _h, begin = self.post(
            "/v1/auth/passkeys/authenticate/begin",
            {"email": "counter@example.com"})
        payload = auth.get(begin["publicKey"], count=1)
        payload["challenge_id"] = begin["challenge_id"]
        status, _h, data = self.post(
            "/v1/auth/passkeys/authenticate/finish", payload)
        self.assertEqual(status, 400, data)
        self.assertIn("could not be verified", data["detail"])

    def test_unknown_passkey_rejected(self):
        stranger = SoftAuthenticator(RP_ID, ORIGIN)
        status, _h, begin = self.post(
            "/v1/auth/passkeys/authenticate/begin", {})
        payload = stranger.get(begin["publicKey"])
        payload["challenge_id"] = begin["challenge_id"]
        status, _h, data = self.post(
            "/v1/auth/passkeys/authenticate/finish", payload)
        self.assertEqual(status, 400, data)


class TestRecoveryCodes(AccountHttpTestCase):
    def test_code_signs_in_once(self):
        data = self.redeem_link("recovery@example.com")
        _auth, done = self.enroll_passkey(data["session_token"])
        code = done["recovery_codes"][0]
        status, _h, back = self.post(
            "/v1/auth/recovery/redeem",
            {"email": "recovery@example.com", "code": code,
             "surface": "web", "device_label": "New browser"})
        self.assertEqual(status, 200, back)
        self.assertTrue(back["passkey_enrollment_recommended"])
        self.assertEqual(back["recovery_codes_remaining"], 9)
        status, _h, again = self.post(
            "/v1/auth/recovery/redeem",
            {"email": "recovery@example.com", "code": code})
        self.assertEqual(status, 400, again)

    def test_failures_do_not_enumerate(self):
        data = self.redeem_link("enum@example.com")
        self.enroll_passkey(data["session_token"])
        _s, _h, wrong_code = self.post(
            "/v1/auth/recovery/redeem",
            {"email": "enum@example.com", "code": "AAAA-BBBB-CCCC"})
        _s, _h, wrong_email = self.post(
            "/v1/auth/recovery/redeem",
            {"email": "ghost@example.com", "code": "AAAA-BBBB-CCCC"})
        self.assertEqual(wrong_code["detail"], wrong_email["detail"])


class TestSessions(AccountHttpTestCase):
    def test_list_and_revoke(self):
        first = self.redeem_link("devices@example.com")
        auth, _done = self.enroll_passkey(first["session_token"])
        second = self.sign_in_with_passkey(auth, "devices@example.com")
        status, _h, listing = self.get(
            "/v1/auth/sessions", token=second["session_token"])
        self.assertEqual(status, 200, listing)
        self.assertEqual(len(listing["sessions"]), 2)
        currents = [s for s in listing["sessions"] if s["current"]]
        self.assertEqual(len(currents), 1)
        other = [s for s in listing["sessions"]
                 if not s["current"]][0]
        status, _h, data = self.post(
            "/v1/auth/sessions/revoke",
            {"session_id": other["session_id"]},
            token=second["session_token"])
        self.assertEqual(status, 200, data)
        status, _h, me = self.get("/v1/auth/me",
                                  token=first["session_token"])
        self.assertEqual(status, 401, me)

    def test_sign_out_revokes_current(self):
        data = self.redeem_link("bye@example.com")
        status, _h, out = self.post("/v1/auth/sign-out", {},
                                    token=data["session_token"])
        self.assertEqual(status, 200, out)
        self.assertTrue(out["revoked_current"])
        status, _h, me = self.get("/v1/auth/me",
                                  token=data["session_token"])
        self.assertEqual(status, 401, me)

    def test_cannot_revoke_another_accounts_session(self):
        mine = self.redeem_link("mine@example.com")
        theirs = self.redeem_link("theirs@example.com")
        status, _h, data = self.post(
            "/v1/auth/sessions/revoke",
            {"session_id": theirs["session"]["session_id"]},
            token=mine["session_token"])
        self.assertEqual(status, 404, data)
        status, _h, me = self.get("/v1/auth/me",
                                  token=theirs["session_token"])
        self.assertEqual(status, 200, me)


class TestSeparationFromApiKeys(AccountHttpTestCase):
    def test_session_token_is_not_an_api_key(self):
        data = self.redeem_link("separate@example.com")
        status, _h, body = self.get(
            "/v1/credentials/cred_whatever",
            token=data["session_token"])
        self.assertEqual(status, 401, body)

    def test_api_key_is_not_a_session(self):
        status, _h, body = self.get("/v1/auth/me",
                                    key=self.verifier_key)
        self.assertEqual(status, 401, body)


class TestHandoff(AccountHttpTestCase):
    def _create_handoff(self):
        status, _h, data = self.post(
            "/v1/auth/handoff", {"device_label": "Bayo's Mac"})
        self.assertEqual(status, 200, data)
        self.assertIn("handoff=" + data["handoff_id"],
                      data["authorize_url"])
        return data

    def test_email_completion_cycle(self):
        handoff = self._create_handoff()
        status, _h, poll = self.post(
            "/v1/auth/handoff/poll",
            {"handoff_id": handoff["handoff_id"],
             "secret": handoff["secret"]})
        self.assertEqual(poll["status"], "pending")
        self.redeem_link("desk@example.com",
                         handoff_id=handoff["handoff_id"])
        status, _h, poll = self.post(
            "/v1/auth/handoff/poll",
            {"handoff_id": handoff["handoff_id"],
             "secret": handoff["secret"]})
        self.assertEqual(poll["status"], "ready")
        status, _h, exchanged = self.post(
            "/v1/auth/handoff/exchange",
            {"handoff_id": handoff["handoff_id"],
             "secret": handoff["secret"]})
        self.assertEqual(status, 200, exchanged)
        self.assertEqual(exchanged["session"]["surface"], "desktop")
        self.assertEqual(exchanged["session"]["device_label"],
                         "Bayo's Mac")
        status, _h, me = self.get("/v1/auth/me",
                                  token=exchanged["session_token"])
        self.assertEqual(status, 200, me)
        status, _h, again = self.post(
            "/v1/auth/handoff/exchange",
            {"handoff_id": handoff["handoff_id"],
             "secret": handoff["secret"]})
        self.assertEqual(status, 400, again)
        status, _h, poll = self.post(
            "/v1/auth/handoff/poll",
            {"handoff_id": handoff["handoff_id"],
             "secret": handoff["secret"]})
        self.assertEqual(poll["status"], "consumed")

    def test_passkey_completion_cycle(self):
        data = self.redeem_link("desktwo@example.com")
        auth, _done = self.enroll_passkey(data["session_token"])
        handoff = self._create_handoff()
        self.sign_in_with_passkey(
            auth, "desktwo@example.com", surface="web",
            device_label="Browser", handoff_id=handoff["handoff_id"])
        status, _h, poll = self.post(
            "/v1/auth/handoff/poll",
            {"handoff_id": handoff["handoff_id"],
             "secret": handoff["secret"]})
        self.assertEqual(poll["status"], "ready")

    def test_wrong_secret_rejected(self):
        handoff = self._create_handoff()
        status, _h, poll = self.post(
            "/v1/auth/handoff/poll",
            {"handoff_id": handoff["handoff_id"],
             "secret": "npc_hoff_wrong"})
        self.assertEqual(status, 400, poll)


class TestSignInPage(AccountHttpTestCase):
    def test_page_is_served(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        conn.request("GET", "/auth/sign-in?handoff=hoff_test")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        headers = dict(resp.getheaders())
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn("Sign in to", body)
        self.assertNotIn("X-NPC-Signature", headers)


if __name__ == "__main__":
    unittest.main()
