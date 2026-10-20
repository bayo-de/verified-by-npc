"""Public registration layer tests (verification-start).

POST /v1/register/content and /v1/register/agent are PUBLIC: they mint
signed registration records whose status is honestly "registered,
checks pending". Registration is not verification: no verdict, no
mark. GET /v1/records/{id} resolves any API-issued ID.

The C2PA fixture is a hand-built JPEG: a JUMBF manifest store in an
APP11 (JPEG XT) packet carrying a CBOR claim, built with the tiny
encoder below so the structural parse is tested deterministically.
"""
import hashlib
import http.server
import json
import os
import struct
import sys
import tempfile
import threading
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import pact, registry  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify.server import Handler, create_app  # noqa: E402
from tests.helpers import ApiTestCase  # noqa: E402


# -- tiny CBOR / JUMBF builders for the C2PA fixture -------------------------
def _cbor_text(s):
    b = s.encode("utf-8")
    if len(b) < 24:
        return bytes([0x60 + len(b)]) + b
    return bytes([0x78, len(b)]) + b


def _cbor_map(pairs):
    out = bytes([0xA0 + len(pairs)])
    for key, value_bytes in pairs:
        out += _cbor_text(key) + value_bytes
    return out


def _cbor_array(items):
    return bytes([0x80 + len(items)]) + b"".join(items)


def _box(btype, payload):
    return struct.pack(">I", len(payload) + 8) + btype + payload


def _jumd(label):
    return _box(b"jumd", b"\x00" * 16 + b"\x00" + label.encode() + b"\x00")


def _jumb(children):
    return _box(b"jumb", b"".join(children))


def build_c2pa_jpeg():
    """A minimal JPEG whose APP11 packet carries a C2PA claim."""
    claim = _cbor_map([
        ("claim_generator", _cbor_text("TestGen 1.0")),
        ("instanceID", _cbor_text("xmp:iid:test-0001")),
    ])
    actions = _cbor_map([
        ("actions", _cbor_array([
            _cbor_map([
                ("action", _cbor_text("c2pa.created")),
                ("digitalSourceType", _cbor_text(
                    "http://cv.iptc.org/newscodes/digitalsourcetype/"
                    "trainedAlgorithmicMedia")),
            ]),
        ])),
    ])
    assertions = _jumb([
        _jumd("c2pa.assertions"),
        _jumb([_jumd("c2pa.actions"), _box(b"cbor", actions)]),
    ])
    manifest = _jumb([
        _jumd("urn:c2pa:test-manifest"),
        _box(b"c2cl", claim),
        assertions,
    ])
    jumbf = _jumb([_jumd("c2pa"), manifest])
    payload = b"JUMB" + struct.pack(">H", 1) + jumbf
    app11 = b"\xff\xeb" + struct.pack(">H", len(payload) + 2) + payload
    return b"\xff\xd8" + app11 + b"\xff\xd9"


def build_plain_jpeg():
    return (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 32
            + b"\xff\xd9")


C2PA_JPEG = build_c2pa_jpeg()
PLAIN_JPEG = build_plain_jpeg()
SHA_LOCATOR = "sha256:" + "ab" * 32


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = {"/c2pa.jpg": C2PA_JPEG, "/plain.jpg": PLAIN_JPEG}.get(
            self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def _checks(rec, name):
    return [c for c in rec["checks_run"] + rec["checks_not_run"]
            if c["check"] == name]


class RegisterContentTest(ApiTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.files = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _FixtureHandler)
        cls.file_port = cls.files.server_address[1]
        threading.Thread(target=cls.files.serve_forever,
                         daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.files.shutdown()
        super().tearDownClass()

    def url(self, name):
        return "http://127.0.0.1:%d/%s" % (self.file_port, name)

    def register_text(self, email="maker@example.com", **over):
        body = {
            "title": "A short story about a lighthouse",
            "kind": "text",
            "locator": SHA_LOCATOR,
            "creator_name": "Test Maker",
            "creator_email": email,
        }
        body.update(over)
        return self.post("/v1/register/content", body=body)

    def test_public_no_key_required(self):
        status, headers, data = self.register_text()
        self.assertEqual(status, 201)
        rec = self.check_signature(headers, data)
        self.assertEqual(rec["record_type"],
                         "npc.registry.content_registration")
        self.assertEqual(rec["status"], "registered_checks_pending")
        self.assertEqual(rec["status_label"], "registered, checks pending")
        self.assertTrue(rec["record_id"].startswith("reg_"))
        # the record itself is issuer-signed and verifies offline
        self.assertTrue(pact.verify_record(self.app.keys, rec))
        # registration is not verification: no verdict anywhere
        self.assertNotIn("verdict", rec)

    def test_email_never_in_public_record(self):
        status, _, data = self.register_text()
        self.assertEqual(status, 201)
        self.assertNotIn(b"maker@example.com", data)
        self.assertNotIn(b"creator_email", data)

    def test_hash_locator_records_provided_hash(self):
        status, _, data = self.register_text()
        rec = json.loads(data)
        entries = _checks(rec, "content_hash")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "provided_by_creator")
        pending = {c["check"] for c in rec["checks_not_run"]}
        self.assertIn("verification_decision", pending)
        self.assertIn("human_review", pending)

    def test_image_url_c2pa_structural_parse_runs(self):
        status, _, data = self.register_text(
            email="img@example.com", kind="image",
            locator=self.url("c2pa.jpg"), title="A generated harbor")
        self.assertEqual(status, 201)
        rec = json.loads(data)
        fetch = _checks(rec, "content_fetch")
        self.assertEqual(fetch[0]["status"], "fetched")
        self.assertEqual(fetch[0]["sha256"],
                         hashlib.sha256(C2PA_JPEG).hexdigest())
        creds = _checks(rec, "c2pa_credentials")
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["status"],
                         "present_not_cryptographically_validated")
        self.assertEqual(creds[0]["validated"], False)
        self.assertEqual(creds[0]["generator"], "TestGen 1.0")
        self.assertEqual(creds[0]["digital_source_type"], "AI-generated")
        self.assertIn("c2pa.actions", creds[0]["assertions"])
        # the AI check honestly did not run: no detector configured here
        ai = [c for c in rec["checks_not_run"]
              if c["check"] == "ai_generation_signal"]
        self.assertEqual(len(ai), 1)
        self.assertIn("not configured", ai[0]["reason"])
        # Cryptographic validation RUNS now (v5.5): this hand-built
        # manifest carries no signature box, so the honest outcome is
        # a run entry reporting not_validated, never a pending entry
        # and never a pass. (Reconciled 2026-10-15: the pre-v5.5
        # assertion here expected the check to stay pending.)
        crypto = [c for c in rec["checks_run"]
                  if c["check"] == "c2pa_cryptographic_validation"]
        self.assertEqual(len(crypto), 1)
        self.assertEqual(crypto[0]["status"], "not_validated")
        pending = {c["check"] for c in rec["checks_not_run"]}
        self.assertNotIn("c2pa_cryptographic_validation", pending)
        self.assertEqual(creds[0]["validation"]["status"],
                         "not_validated")
        self.assertEqual(creds[0]["validation"]["signature"], "not_run")

    def test_image_url_without_credentials(self):
        status, _, data = self.register_text(
            email="plain@example.com", kind="image",
            locator=self.url("plain.jpg"), title="A plain photo")
        self.assertEqual(status, 201)
        rec = json.loads(data)
        creds = _checks(rec, "c2pa_credentials")
        self.assertEqual(creds[0]["status"], "not_present")
        # No manifest means validation has nothing to run on: it
        # stays honestly pending with that reason (v5.5).
        crypto = [c for c in rec["checks_not_run"]
                  if c["check"] == "c2pa_cryptographic_validation"]
        self.assertEqual(len(crypto), 1)
        self.assertIn("nothing to validate", crypto[0]["reason"])

    def test_image_url_unreachable_still_registers(self):
        status, _, data = self.register_text(
            email="down@example.com", kind="image",
            locator="http://127.0.0.1:1/img.jpg", title="Unreachable")
        self.assertEqual(status, 201)
        rec = json.loads(data)
        fetch = _checks(rec, "content_fetch")
        self.assertEqual(fetch[0]["status"], "not_fetched")
        not_run = {c["check"] for c in rec["checks_not_run"]}
        self.assertIn("c2pa_credentials", not_run)
        self.assertIn("c2pa_cryptographic_validation", not_run)
        self.assertIn("ai_generation_signal", not_run)

    def test_validation(self):
        base = {
            "title": "T", "kind": "text", "locator": SHA_LOCATOR,
            "creator_name": "Maker", "creator_email": "m@example.com",
        }
        for drop in ("title", "creator_name", "creator_email"):
            body = {k: v for k, v in base.items() if k != drop}
            status, _, _ = self.post("/v1/register/content", body=body)
            self.assertEqual(status, 422, drop)
        status, _, _ = self.post(
            "/v1/register/content", body=dict(base, kind="bogus"))
        self.assertEqual(status, 422)
        status, _, _ = self.post(
            "/v1/register/content",
            body=dict(base, locator="not a url or hash"))
        self.assertEqual(status, 422)
        status, _, _ = self.post(
            "/v1/register/content",
            body=dict(base, creator_email="not-an-email"))
        self.assertEqual(status, 422)
        status, _, _ = self.post("/v1/register/content",
                                 raw_body=b"[1,2]")
        self.assertEqual(status, 400)


class RegisterAgentTest(ApiTestCase):
    def test_agent_registration_claim(self):
        status, headers, data = self.post("/v1/register/agent", body={
            "agent_name": "Harbor Helper",
            "owner_name": "Test Owner",
            "owner_email": "owner@example.com",
            "homepage": "https://example.com/harbor-helper",
        })
        self.assertEqual(status, 201)
        rec = self.check_signature(headers, data)
        self.assertEqual(rec["record_type"],
                         "npc.registry.agent_registration")
        self.assertEqual(rec["kind"], "agent")
        self.assertEqual(rec["status_label"], "registered, checks pending")
        self.assertTrue(pact.verify_record(self.app.keys, rec))
        run = {c["check"] for c in rec["checks_run"]}
        self.assertIn("named_owner", run)
        self.assertIn("registration_claim", run)
        claim = [c for c in rec["checks_run"]
                 if c["check"] == "registration_claim"][0]
        self.assertIn("Registration is not verification",
                      claim["detail"])
        self.assertNotIn(b"owner@example.com", data)
        self.assertNotIn("verdict", rec)

    def test_agent_validation(self):
        base = {
            "agent_name": "Helper", "owner_name": "Owner",
            "owner_email": "o@example.com",
            "description": "Answers harbor questions.",
        }
        for drop in ("agent_name", "owner_name", "owner_email"):
            body = {k: v for k, v in base.items() if k != drop}
            status, _, _ = self.post("/v1/register/agent", body=body)
            self.assertEqual(status, 422, drop)
        body = {k: v for k, v in base.items() if k != "description"}
        status, _, _ = self.post("/v1/register/agent", body=body)
        self.assertEqual(status, 422)  # homepage or description required
        status, _, _ = self.post(
            "/v1/register/agent", body=dict(base, homepage="ftp://x"))
        self.assertEqual(status, 422)


class RecordsResolutionTest(ApiTestCase):
    def test_registration_resolves_by_id(self):
        status, _, data = self.post("/v1/register/content", body={
            "title": "Resolvable", "kind": "text", "locator": SHA_LOCATOR,
            "creator_name": "Maker", "creator_email": "r@example.com",
        })
        self.assertEqual(status, 201)
        rec = json.loads(data)
        status, headers, data2 = self.get(
            "/v1/records/" + rec["record_id"])
        self.assertEqual(status, 200)
        got = self.check_signature(headers, data2)
        self.assertEqual(got, rec)

    def test_existing_record_types_resolve(self):
        status, _, data = self.get("/v1/records/cred_test_001")
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertEqual(body["title"], "Test Artisan Certificate")
        self.assertIn("verification_url", body)

        status, _, data = self.get("/v1/records/tag_test_authentic")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["verdict"], "verified")

        status, _, data = self.get("/v1/records/agent_test_scout")
        self.assertEqual(status, 200)
        self.assertIn("attestation_id", json.loads(data))

        # an attestation ID, found through the claims endpoint
        status, _, data = self.post(
            "/v1/claims/verify",
            body={"claim_text": "The test widget passes drop testing"},
            key=self.verifier_key)
        self.assertEqual(status, 200)
        att_id = json.loads(data)["attestation"]["id"]
        status, _, data = self.get("/v1/records/" + att_id)
        self.assertEqual(status, 200)
        body = json.loads(data)
        self.assertEqual(body["id"], att_id)
        self.assertEqual(body["verdict"], "verified")

    def test_unknown_id_fails_closed(self):
        status, headers, data = self.get("/v1/records/reg_doesnotexist")
        self.assertEqual(status, 404)
        body = self.check_signature(headers, data)
        self.assertEqual(body, {"verdict": "unknown"})


class RegisterEmailCapTest(ApiTestCase):
    def test_per_email_cap(self):
        old = registry.EMAIL_DAILY_CAP
        registry.EMAIL_DAILY_CAP = 3
        try:
            for i in range(3):
                status, _, _ = self.post("/v1/register/content", body={
                    "title": "Piece %d" % i, "kind": "text",
                    "locator": "sha256:" + ("%02x" % i) * 32,
                    "creator_name": "Maker",
                    "creator_email": "capped@example.com",
                })
                self.assertEqual(status, 201)
            status, _, data = self.post("/v1/register/content", body={
                "title": "One too many", "kind": "text",
                "locator": SHA_LOCATOR, "creator_name": "Maker",
                "creator_email": "capped@example.com",
            })
            self.assertEqual(status, 429)
            self.assertEqual(json.loads(data)["error"], "rate_limited")
            # a different email is unaffected
            status, _, _ = self.post("/v1/register/content", body={
                "title": "Someone else", "kind": "text",
                "locator": SHA_LOCATOR, "creator_name": "Other",
                "creator_email": "other@example.com",
            })
            self.assertEqual(status, 201)
        finally:
            registry.EMAIL_DAILY_CAP = old


class RegisterIpCapTest(ApiTestCase):
    def test_per_ip_cap(self):
        old = registry.IP_DAILY_CAP
        registry.IP_DAILY_CAP = 3
        try:
            for i in range(3):
                status, _, _ = self.post("/v1/register/agent", body={
                    "agent_name": "Agent %d" % i,
                    "owner_name": "Owner",
                    "owner_email": "owner%d@example.com" % i,
                    "description": "Does test things.",
                })
                self.assertEqual(status, 201)
            status, _, _ = self.post("/v1/register/agent", body={
                "agent_name": "One too many", "owner_name": "Owner",
                "owner_email": "fresh@example.com",
                "description": "Does test things.",
            })
            self.assertEqual(status, 429)
        finally:
            registry.IP_DAILY_CAP = old


class _FakeDetector:
    provider = "fake-detector"
    model = "fake-v1"
    configured = True

    def check_ai(self, image_bytes=None, image_url=None):
        return 0.42


class RegisterDetectorTest(unittest.TestCase):
    """Intake with a configured detector and a stub fetcher: the AI
    signal is recorded as a percent with its uncertainty stated."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_register_det_")
        cls.app = create_app(
            os.path.join(cls.tmp, "t.db"), os.path.join(cls.tmp, "keys"),
            detector=_FakeDetector(), fetcher=lambda url: C2PA_JPEG)
        seed_all(cls.app.store, cls.app.keys)
        Handler.app = cls.app
        cls.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever,
                         daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.app.store.close()

    def test_ai_signal_and_c2pa_recorded(self):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        body = json.dumps({
            "title": "Signal test", "kind": "image",
            "locator": "https://images.example.com/harbor.jpg",
            "creator_name": "Maker", "creator_email": "sig@example.com",
        }).encode()
        conn.request("POST", "/v1/register/content", body=body,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        self.assertEqual(resp.status, 201)
        rec = json.loads(data)
        ai = [c for c in rec["checks_run"]
              if c["check"] == "ai_generation_signal"]
        self.assertEqual(len(ai), 1)
        self.assertEqual(ai[0]["ai_generated_percent"], 42)
        self.assertEqual(ai[0]["provider"], "fake-detector")
        self.assertIn("not a verdict", ai[0]["detail"])
        creds = [c for c in rec["checks_run"]
                 if c["check"] == "c2pa_credentials"]
        self.assertEqual(creds[0]["status"],
                         "present_not_cryptographically_validated")


if __name__ == "__main__":
    unittest.main()
