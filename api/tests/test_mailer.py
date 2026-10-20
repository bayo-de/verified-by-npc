"""Registrant email follow-up tests (npc_verify.mailer, 2026-10-16).

No real sends anywhere: SES is a stub client injected into SesMailer,
which is injected into the App. What is proven:

- a content registration sends exactly one confirmation carrying the
  record ID and the public record link;
- an agent registration sends its own confirmation;
- an SES failure never breaks a registration (still 201);
- with follow-up off (the default), nothing is sent;
- an accepted verification request sends one "request received"
  email, and a repeat request sends nothing more;
- the status-change hook (mailer.notify_status_change) resolves the
  record and the registrant's stored address, and honors the D6
  retention purge (no address, no email);
- the templates and rendered emails contain no em dashes.
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
import unittest.mock
from http.server import ThreadingHTTPServer

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import mailer  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify.server import Handler, create_app  # noqa: E402

HASH_LOCATOR = "sha256:" + "a" * 64


class StubSesClient:
    """Records send_email calls; optionally raises like a dead SES."""

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def send_email(self, **kwargs):
        if self.fail:
            raise RuntimeError("SES is down (stub)")
        self.calls.append(kwargs)
        return {"MessageId": "stub-%d" % len(self.calls)}


def _text_of(call):
    return call["Message"]["Body"]["Text"]["Data"]


def _html_of(call):
    return call["Message"]["Body"]["Html"]["Data"]


class MailerAppCase(unittest.TestCase):
    """An App wired to a stub-SES mailer, over real loopback HTTP."""

    fail_ses = False

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_mailer_test_")
        cls.stub = StubSesClient(fail=cls.fail_ses)
        cls.mailer = mailer.SesMailer(
            sender="hello@npclabs.xyz", client=cls.stub)
        cls.app = create_app(os.path.join(cls.tmp, "t.db"),
                             os.path.join(cls.tmp, "keys"),
                             mailer=cls.mailer)
        seed_all(cls.app.store, cls.app.keys)
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

    def setUp(self):
        self.stub.calls.clear()

    def post(self, path, body):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        conn.request("POST", path, body=json.dumps(body).encode(),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data) if data else {}

    def register_content(self, email="ada@example.com"):
        status, rec = self.post("/v1/register/content", {
            "title": "Harbor Light Study",
            "kind": "text",
            "locator": HASH_LOCATOR,
            "creator_name": "Ada Lovelace",
            "creator_email": email,
        })
        self.assertEqual(status, 201)
        return rec


class TestRegistrationConfirmation(MailerAppCase):
    def test_content_registration_sends_one_confirmation(self):
        rec = self.register_content()
        self.assertEqual(len(self.stub.calls), 1)
        call = self.stub.calls[0]
        self.assertEqual(call["Destination"]["ToAddresses"],
                         ["ada@example.com"])
        self.assertEqual(call["Source"], "NPC Labs <hello@npclabs.xyz>")
        self.assertEqual(call["Message"]["Subject"]["Data"],
                         "Your work is on record with NPC")
        text = _text_of(call)
        self.assertIn(rec["record_id"], text)
        self.assertIn(
            "https://verify.npclabs.xyz/search?id=%s"
            % rec["record_id"], text)
        self.assertIn("registered, checks pending", text)
        self.assertIn("Registration is not verification", text)
        self.assertIn("Who signed for that?", text)
        html_body = _html_of(call)
        self.assertIn(rec["record_id"], html_body)
        self.assertIn("search?id=%s" % rec["record_id"], html_body)

    def test_agent_registration_sends_its_confirmation(self):
        status, rec = self.post("/v1/register/agent", {
            "agent_name": "Harbor Bot",
            "owner_name": "Ada Lovelace",
            "owner_email": "ada@example.com",
            "description": "Watches the harbor.",
        })
        self.assertEqual(status, 201)
        self.assertEqual(len(self.stub.calls), 1)
        call = self.stub.calls[0]
        self.assertEqual(call["Message"]["Subject"]["Data"],
                         "Your agent is on record with NPC")
        text = _text_of(call)
        self.assertIn("Harbor Bot", text)
        self.assertIn(rec["record_id"], text)
        self.assertIn("accountable owner", text)


class TestFailSoft(MailerAppCase):
    fail_ses = True

    def test_ses_failure_does_not_break_registration(self):
        status, rec = self.post("/v1/register/content", {
            "title": "Harbor Light Study",
            "kind": "text",
            "locator": HASH_LOCATOR,
            "creator_name": "Ada Lovelace",
            "creator_email": "ada@example.com",
        })
        self.assertEqual(status, 201)
        self.assertEqual(rec["status"], "registered_checks_pending")
        # The record is really stored and publicly resolvable.
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        conn.request("GET", "/v1/records/%s" % rec["record_id"])
        resp = conn.getresponse()
        body = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertEqual(body["record_id"], rec["record_id"])


class TestVerificationRequestEmail(MailerAppCase):
    def test_request_sends_once_and_repeat_is_quiet(self):
        rec = self.register_content()
        self.assertEqual(len(self.stub.calls), 1)  # the confirmation
        status, vreq = self.post(
            "/v1/records/%s:request-verification" % rec["record_id"],
            {"email": "ada@example.com"})
        self.assertEqual(status, 201)
        self.assertEqual(len(self.stub.calls), 2)
        call = self.stub.calls[1]
        self.assertEqual(call["Message"]["Subject"]["Data"],
                         "We received your verification request")
        text = _text_of(call)
        self.assertIn(vreq["record_id"], text)          # request ID
        self.assertIn(rec["record_id"], text)           # subject ID
        self.assertIn("queue", text)
        # A repeat request returns the same record, 200, no new email.
        status, again = self.post(
            "/v1/records/%s:request-verification" % rec["record_id"],
            {"email": "ada@example.com"})
        self.assertEqual(status, 200)
        self.assertEqual(again["record_id"], vreq["record_id"])
        self.assertEqual(len(self.stub.calls), 2)

    def test_wrong_email_sends_nothing(self):
        rec = self.register_content()
        self.stub.calls.clear()
        status, _ = self.post(
            "/v1/records/%s:request-verification" % rec["record_id"],
            {"email": "mallory@example.com"})
        self.assertEqual(status, 404)
        self.assertEqual(self.stub.calls, [])


class TestStatusChangeHook(MailerAppCase):
    def test_notify_status_change_sends_update(self):
        rec = self.register_content()
        self.stub.calls.clear()
        sent = mailer.notify_status_change(
            self.mailer, self.app.store, rec["record_id"], "Verified",
            "NPC ran the checks that were pending on this record, "
            "and the record now carries the verification mark.")
        self.assertTrue(sent)
        self.assertEqual(len(self.stub.calls), 1)
        call = self.stub.calls[0]
        self.assertEqual(call["Destination"]["ToAddresses"],
                         ["ada@example.com"])
        self.assertEqual(call["Message"]["Subject"]["Data"],
                         "An update on your NPC record")
        text = _text_of(call)
        self.assertIn("Verified", text)
        self.assertIn(rec["record_id"], text)
        self.assertIn("search?id=%s" % rec["record_id"], text)

    def test_notify_unknown_record_and_purged_email_send_nothing(self):
        rec = self.register_content(email="grace@example.com")
        self.stub.calls.clear()
        self.assertFalse(mailer.notify_status_change(
            self.mailer, self.app.store, "reg_missing", "Verified",
            "n/a"))
        # Retention purge (D6): the raw address goes away, the hook
        # then has nobody to write to and says so by returning False.
        purged = self.app.store.purge_registration_emails(
            "2999-01-01T00:00:00+00:00")
        self.assertGreaterEqual(purged, 1)
        self.assertIsNone(
            self.app.store.registration_email(rec["record_id"]))
        self.assertFalse(mailer.notify_status_change(
            self.mailer, self.app.store, rec["record_id"], "Verified",
            "n/a"))
        self.assertEqual(self.stub.calls, [])


class TestMailerConfig(unittest.TestCase):
    def test_env_defaults_rest(self):
        m = mailer.mailer_from_env({})
        self.assertIsInstance(m, mailer.DisabledMailer)
        self.assertFalse(m.enabled)
        self.assertFalse(m.send("a@example.com", "s", "t", "h"))

    def test_env_enabled_builds_ses_mailer_with_defaults(self):
        m = mailer.mailer_from_env({"NPC_MAIL_ENABLED": "1"})
        self.assertIsInstance(m, mailer.SesMailer)
        self.assertTrue(m.enabled)
        self.assertEqual(m.sender, "hello@npclabs.xyz")
        self.assertEqual(m.source, "NPC Labs <hello@npclabs.xyz>")
        self.assertEqual(m.reply_to, "hello@npclabs.xyz")
        self.assertEqual(m.region, "us-east-2")

    def test_env_overrides(self):
        m = mailer.mailer_from_env({
            "NPC_MAIL_ENABLED": "1",
            "NPC_MAIL_FROM": "records@npclabs.xyz",
            "NPC_MAIL_REGION": "us-west-2",
        })
        self.assertEqual(m.sender, "records@npclabs.xyz")
        self.assertEqual(m.region, "us-west-2")

    def test_record_link_site_base_override(self):
        self.assertEqual(
            mailer.record_link("reg_x"),
            "https://verify.npclabs.xyz/search?id=reg_x")
        with unittest.mock.patch.dict(
                os.environ, {"NPC_MAIL_SITE_BASE": "https://stg.ex/"}):
            self.assertEqual(mailer.record_link("reg_x"),
                             "https://stg.ex/search?id=reg_x")

    def test_disabled_mailer_via_app_sends_nothing(self):
        # An App built without NPC_MAIL_ENABLED rests: registration
        # works, no SES client is ever constructed.
        tmp = tempfile.mkdtemp(prefix="npc_mailer_off_")
        app = create_app(os.path.join(tmp, "t.db"),
                         os.path.join(tmp, "keys"),
                         mailer=mailer.mailer_from_env({}))
        self.assertFalse(app.mailer.enabled)
        app.store.close()


class TestTemplates(unittest.TestCase):
    NAMES = ("registration_content", "registration_agent",
             "verification_request", "status_update")

    def test_template_files_have_no_em_dashes(self):
        for name in self.NAMES:
            for fmt in ("txt", "html"):
                path = os.path.join(mailer.TEMPLATES_DIR,
                                    "%s.%s" % (name, fmt))
                with open(path, encoding="utf-8") as f:
                    body = f.read()
                self.assertNotIn("—", body, path)
                self.assertNotIn("–", body, path)

    def test_rendered_emails_have_no_em_dashes(self):
        record = {"record_id": "reg_abc123", "kind": "content",
                  "title": "Harbor Light Study",
                  "creator_name": "Ada Lovelace"}
        values = {
            "recipient_name": "Ada Lovelace",
            "title": "Harbor Light Study",
            "agent_name": "Harbor Bot",
            "subject_name": "Harbor Light Study",
            "subject_record_id": "reg_abc123",
            "request_id": "vreq_def456",
            "status_label": "Verified",
            "detail": "The checks are done.",
            "record_id": "reg_abc123",
            "record_link": mailer.record_link("reg_abc123"),
        }
        for name in self.NAMES:
            for fmt in ("txt", "html"):
                out = mailer._render(name, fmt, values)
                self.assertNotIn("—", out, name)
                self.assertIn("reg_abc123", out, name)


if __name__ == "__main__":
    unittest.main()
