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
from npc_verify.store import Store  # noqa: E402
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


def build_plain_jpeg_2():
    return (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 48
            + b"\xff\xd9")


C2PA_JPEG = build_c2pa_jpeg()
PLAIN_JPEG = build_plain_jpeg()
PLAIN_JPEG_2 = build_plain_jpeg_2()
SHA_LOCATOR = "sha256:" + "ab" * 32


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = {"/c2pa.jpg": C2PA_JPEG, "/plain.jpg": PLAIN_JPEG,
                "/plain2.jpg": PLAIN_JPEG_2}.get(self.path)
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


class ClaimsVerifyRegistrationTest(ApiTestCase):
    """The claims/verify registration bridge.

    Registrations mint registry records, never attestations, so the
    attestation-only lookup could never find a registered work: the
    browser extension hashes the address of the image it is checking
    and asks claims/verify, and a registered cover answered 404
    unknown. The endpoint now also consults registrations, indexed
    by locator-address hash and by the content hash from intake,
    and presents a match as what it is: a registration, standing
    "registered, checks pending", never a verification.
    """

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

    def register_cover(self, email="bridge@example.com"):
        status, _, data = self.post("/v1/register/content", body={
            "title": "A plain photo", "kind": "image",
            "locator": self.url("plain.jpg"),
            "creator_name": "Bridge Maker", "creator_email": email,
        })
        self.assertEqual(status, 201)
        return json.loads(data)

    def verify(self, claim_hash):
        return self.post("/v1/claims/verify",
                         body={"claim_hash": claim_hash},
                         key=self.verifier_key)

    def test_match_by_locator_address_hash(self):
        rec = self.register_cover()
        address_hash = hashlib.sha256(
            self.url("plain.jpg").encode("utf-8")).hexdigest()
        status, headers, data = self.verify(address_hash)
        self.assertEqual(status, 200)
        body = self.check_signature(headers, data)
        self.assertTrue(body["matched"])
        self.assertEqual(body["match_type"], "registration")
        reg = body["registration"]
        self.assertEqual(reg["id"], rec["record_id"])
        self.assertEqual(reg["matched_by"], "locator_address")
        self.assertEqual(reg["status"], "registered_checks_pending")
        self.assertEqual(reg["status_label"],
                         "registered, checks pending")
        self.assertEqual(reg["title"], "A plain photo")
        self.assertEqual(reg["creator_name"], "Bridge Maker")
        self.assertEqual(reg["registered_at"], rec["registered_at"])
        # The attestation-shaped summary states the honest standing;
        # it is never "verified" and never omitted (clients default
        # a missing verdict to "verified", so omission would lie).
        att = body["attestation"]
        self.assertEqual(att["id"], rec["record_id"])
        self.assertEqual(att["verdict"], "registered, checks pending")
        self.assertNotEqual(att["verdict"], "verified")
        self.assertEqual(att["creator_name"], "Bridge Maker")
        self.assertEqual(att["created_at"], rec["registered_at"])
        self.assertEqual(att["signature"], rec["signature"])
        self.assertEqual(att["key_id"], rec["key_id"])
        self.assertIn("not verification", att["findings_summary"])

    def test_match_by_content_bytes_hash(self):
        status, _, data = self.post("/v1/register/content", body={
            "title": "A second plain photo", "kind": "image",
            "locator": self.url("plain2.jpg"),
            "creator_name": "Bridge Maker",
            "creator_email": "bytes@example.com",
        })
        self.assertEqual(status, 201)
        rec = json.loads(data)
        content_hash = hashlib.sha256(PLAIN_JPEG_2).hexdigest()
        status, headers, data = self.verify(content_hash)
        self.assertEqual(status, 200)
        body = self.check_signature(headers, data)
        self.assertTrue(body["matched"])
        self.assertEqual(body["match_type"], "registration")
        self.assertEqual(body["registration"]["id"],
                         rec["record_id"])
        self.assertEqual(body["registration"]["matched_by"],
                         "content_bytes")

    def test_match_by_provided_content_hash_locator(self):
        status, _, data = self.post("/v1/register/content", body={
            "title": "Hash-addressed text", "kind": "text",
            "locator": SHA_LOCATOR, "creator_name": "Hash Maker",
            "creator_email": "hash@example.com",
        })
        self.assertEqual(status, 201)
        rec = json.loads(data)
        status, headers, data = self.verify("ab" * 32)
        self.assertEqual(status, 200)
        body = self.check_signature(headers, data)
        self.assertEqual(body["registration"]["id"],
                         rec["record_id"])
        self.assertEqual(body["registration"]["matched_by"],
                         "content_bytes")

    def test_unregistered_hash_still_unknown(self):
        self.register_cover(email="solo@example.com")
        unknown_hash = hashlib.sha256(
            b"https://example.com/never-registered.png").hexdigest()
        status, headers, data = self.verify(unknown_hash)
        self.assertEqual(status, 404)
        body = self.check_signature(headers, data)
        self.assertEqual(body["verdict"], "unknown")
        self.assertFalse(body["matched"])

    def test_agent_registration_is_not_a_claim_match(self):
        status, _, _ = self.post("/v1/register/agent", body={
            "agent_name": "Bridge Agent",
            "owner_name": "Bridge Owner",
            "owner_email": "agentbridge@example.com",
            "homepage": "https://example.com/bridge-agent",
        })
        self.assertEqual(status, 201)
        homepage_hash = hashlib.sha256(
            b"https://example.com/bridge-agent").hexdigest()
        status, _, data = self.verify(homepage_hash)
        self.assertEqual(status, 404)
        self.assertFalse(json.loads(data)["matched"])


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


class RegisterContentLanesTest(ApiTestCase):
    """Content-registration cap lanes (Bayo's directive, 2026-11-01):
    the operator lane (a valid issuer-role key skips the public caps
    entirely), the tiered public lane, and an honest retry_after on
    a cap 429. The agent lane keeps the flat caps (RegisterEmailCap-
    Test / RegisterIpCapTest above cover the shared constants)."""

    def _piece(self, i, email, key=None):
        return self.post("/v1/register/content", body={
            "title": "Lane piece %d" % i, "kind": "text",
            "locator": "sha256:" + ("%02x" % (i % 256)) * 32,
            "creator_name": "Maker", "creator_email": email,
        }, key=key)

    def test_operator_issuer_key_skips_caps(self):
        old = registry.EMAIL_DAILY_CAP
        registry.EMAIL_DAILY_CAP = 2
        try:
            for i in range(2):
                status, _, _ = self._piece(i, "op@example.com")
                self.assertEqual(status, 201)
            status, _, _ = self._piece(2, "op@example.com")
            self.assertEqual(status, 429)
            # The same email, carrying NPC's issuer key, is the
            # operator lane: uncapped, well past the public limit.
            for i in range(3, 7):
                status, _, _ = self._piece(
                    i, "op@example.com", key=self.issuer_key)
                self.assertEqual(status, 201)
        finally:
            registry.EMAIL_DAILY_CAP = old

    def test_verifier_and_invalid_keys_stay_public(self):
        old = registry.EMAIL_DAILY_CAP
        registry.EMAIL_DAILY_CAP = 2
        try:
            for i in range(2):
                status, _, _ = self._piece(i, "pub@example.com")
                self.assertEqual(status, 201)
            # A verifier key is a real key but not the operator
            # credential: the public lane still applies.
            status, _, _ = self._piece(
                2, "pub@example.com", key=self.verifier_key)
            self.assertEqual(status, 429)
            # A garbage key is not an error on a public endpoint;
            # it simply stays on the public lane too.
            status, _, _ = self._piece(
                3, "pub@example.com", key="npc_test_not_a_real_key")
            self.assertEqual(status, 429)
        finally:
            registry.EMAIL_DAILY_CAP = old

    def test_retry_after_is_the_real_wait(self):
        old = registry.EMAIL_DAILY_CAP
        registry.EMAIL_DAILY_CAP = 1
        try:
            status, _, _ = self._piece(0, "wait@example.com")
            self.assertEqual(status, 201)
            status, _, data = self._piece(1, "wait@example.com")
            self.assertEqual(status, 429)
            retry = json.loads(data)["retry_after_seconds"]
            self.assertIsInstance(retry, int)
            # The one counted registration landed seconds ago, so
            # the honest wait is close to the full 24h window —
            # never the old flat 3600 that understated it.
            self.assertGreater(retry, 3600)
            self.assertLessEqual(retry, 86400)
        finally:
            registry.EMAIL_DAILY_CAP = old

    def test_paid_tier_raises_the_email_cap(self):
        old_free = registry.EMAIL_DAILY_CAP
        old_starter = registry.REGISTRATION_TIER_PAID_EMAIL_CAPS[
            "starter"]
        old_resolver = registry.registration_tier_for_email
        registry.EMAIL_DAILY_CAP = 2
        registry.REGISTRATION_TIER_PAID_EMAIL_CAPS["starter"] = 3
        registry.registration_tier_for_email = (
            lambda store, email: "starter")
        try:
            # Free would cap at 2; the starter tier governs at 3.
            for i in range(3):
                status, _, _ = self._piece(i, "tiered@example.com")
                self.assertEqual(status, 201)
            status, _, _ = self._piece(3, "tiered@example.com")
            self.assertEqual(status, 429)
        finally:
            registry.EMAIL_DAILY_CAP = old_free
            registry.REGISTRATION_TIER_PAID_EMAIL_CAPS[
                "starter"] = old_starter
            registry.registration_tier_for_email = old_resolver

    def test_tier_cap_table(self):
        self.assertEqual(registry.registration_tier_cap("free"),
                         registry.EMAIL_DAILY_CAP)
        self.assertEqual(registry.registration_tier_cap("starter"),
                         100)
        self.assertEqual(registry.registration_tier_cap("growth"),
                         500)
        self.assertEqual(registry.registration_tier_cap("scale"),
                         2500)
        # An unrecognized tier fails closed to the free cap.
        self.assertEqual(registry.registration_tier_cap("platinum"),
                         registry.EMAIL_DAILY_CAP)

    def test_tier_resolver_returns_free_today(self):
        # Paid state is keyed to redeem codes, not emails, so no
        # public email resolves above free until an account/tier
        # source is wired into the resolver seam.
        self.assertEqual(
            registry.registration_tier_for_email(
                self.app.store, "anyone@example.com"), "free")


class ContentCapStatusTest(unittest.TestCase):
    """registry.content_cap_status against a bare store: per-tier
    email caps, the max(IP_DAILY_CAP, tier cap) IP floor, and the
    retry_after computed from the oldest counted registration."""

    def setUp(self):
        from datetime import datetime, timezone
        self.tmp = tempfile.mkdtemp(prefix="npc_cap_status_")
        self.store = Store(os.path.join(self.tmp, "t.db"))
        self.now = datetime(2026, 11, 1, 12, 0, 0,
                            tzinfo=timezone.utc)

    def tearDown(self):
        self.store.close()

    def _add(self, rid, email, ip, when):
        rec = {"record_id": rid, "kind": "content",
               "registered_at": when.isoformat(timespec="seconds")}
        self.store.add_registration(rec, email, ip)

    def _now_iso(self):
        return self.now.isoformat(timespec="seconds")

    def test_retry_after_from_oldest_in_window(self):
        from datetime import timedelta
        old = registry.EMAIL_DAILY_CAP
        registry.EMAIL_DAILY_CAP = 1
        try:
            self._add("reg_old", "a@example.com", "203.0.113.9",
                      self.now - timedelta(hours=23))
            capped = registry.content_cap_status(
                self.store, "a@example.com", "203.0.113.9",
                self._now_iso(), "free")
            self.assertEqual(capped["dimension"], "email")
            # The oldest (only) counted registration ages out one
            # hour from now: the hint is that hour, not a flat one.
            self.assertGreaterEqual(capped["retry_after_seconds"],
                                    3500)
            self.assertLessEqual(capped["retry_after_seconds"],
                                 3600)
        finally:
            registry.EMAIL_DAILY_CAP = old

    def test_ip_floor_scales_with_tier(self):
        from datetime import timedelta
        old_ip = registry.IP_DAILY_CAP
        old_starter = registry.REGISTRATION_TIER_PAID_EMAIL_CAPS[
            "starter"]
        registry.IP_DAILY_CAP = 2
        registry.REGISTRATION_TIER_PAID_EMAIL_CAPS["starter"] = 3
        try:
            for i in range(3):
                self._add("reg_ip_%d" % i,
                          "person%d@example.com" % i, "203.0.113.9",
                          self.now - timedelta(hours=1))
            # Free floor is max(2, free cap 10) = 10: not capped.
            self.assertIsNone(registry.content_cap_status(
                self.store, "fresh@example.com", "203.0.113.9",
                self._now_iso(), "free"))
            # Starter floor is max(2, 3) = 3: the IP caps here,
            # even though this email itself is fresh.
            capped = registry.content_cap_status(
                self.store, "fresh@example.com", "203.0.113.9",
                self._now_iso(), "starter")
            self.assertEqual(capped["dimension"], "ip")
        finally:
            registry.IP_DAILY_CAP = old_ip
            registry.REGISTRATION_TIER_PAID_EMAIL_CAPS[
                "starter"] = old_starter

    def test_paid_tier_email_cap_counts(self):
        from datetime import timedelta
        old_starter = registry.REGISTRATION_TIER_PAID_EMAIL_CAPS[
            "starter"]
        old_growth = registry.REGISTRATION_TIER_PAID_EMAIL_CAPS[
            "growth"]
        registry.REGISTRATION_TIER_PAID_EMAIL_CAPS["starter"] = 3
        registry.REGISTRATION_TIER_PAID_EMAIL_CAPS["growth"] = 5
        try:
            for i in range(3):
                self._add("reg_t_%d" % i, "busy@example.com",
                          "203.0.113.9", self.now - timedelta(hours=1))
            self.assertEqual(
                registry.content_cap_status(
                    self.store, "busy@example.com", "203.0.113.9",
                    self._now_iso(), "starter")["dimension"],
                "email")
            self.assertIsNone(registry.content_cap_status(
                self.store, "busy@example.com", "203.0.113.9",
                self._now_iso(), "growth"))
        finally:
            registry.REGISTRATION_TIER_PAID_EMAIL_CAPS[
                "starter"] = old_starter
            registry.REGISTRATION_TIER_PAID_EMAIL_CAPS[
                "growth"] = old_growth


if __name__ == "__main__":
    unittest.main()
