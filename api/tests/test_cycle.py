"""Cycle completion (v5.5): the three workstreams end to end.

WS1: a genuinely C2PA-signed image registers as validated, a
tampered one as validation-failed, through the public endpoint.
WS2: audio and video registrations carry the media probe and the
honest pending set (frame checks, AI audio) in their records.
WS3: POST /v1/records/{id}:request-verification and its state read:
email-hash match mints a signed request record once, mismatches and
unknown IDs share one signed 404, attempts are capped.

Fixtures are real files in tests/fixtures/ (see test_c2pa_validate
for their provenance), served over loopback like test_register does.
"""
import http.server
import json
import os
import sys
import tempfile
import threading
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "serverless", "lambda_v3",
                                 "fake_boto3"))

import boto3 as fake_boto3  # noqa: E402  (the fake; tests only)

from npc_verify import pact  # noqa: E402
from npc_verify.ddb_store import DynamoDBStore  # noqa: E402
from npc_verify.store import Store  # noqa: E402
from tests.helpers import ApiTestCase  # noqa: E402

FIXTURES = os.path.join(BASE, "tests", "fixtures")
SERVED = ("signed-es256.jpg", "tampered-signature.jpg",
          "signed-es256.mp4", "plain.mp4", "plain.jpg", "tone.wav",
          "tone.mp3")


def _fixture_bytes(name):
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        name = self.path.lstrip("/")
        if name == "big.bin":
            body = b"\x00" * (9 * 1024 * 1024)
        elif name in SERVED:
            body = _fixture_bytes(name)
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def _checks(rec, name, where="checks_run"):
    return [c for c in rec[where] if c["check"] == name]


class _FileServerCase(ApiTestCase):
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

    def register(self, kind, name, email, title="Cycle test"):
        status, _, data = self.post("/v1/register/content", body={
            "title": title, "kind": kind, "locator": self.url(name),
            "creator_name": "Cycle Maker", "creator_email": email})
        self.assertEqual(status, 201)
        return json.loads(data)


class CycleIntakeTest(_FileServerCase):
    def test_signed_image_registers_validated(self):
        rec = self.register("image", "signed-es256.jpg",
                            "valid@example.com")
        creds = _checks(rec, "c2pa_credentials")
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["status"], "validated")
        self.assertEqual(creds[0]["validated"], True)
        validation = creds[0]["validation"]
        self.assertEqual(validation["status"], "valid")
        self.assertEqual(validation["signature"], "valid")
        self.assertEqual(validation["signature_algorithm"], "ES256")
        self.assertEqual(validation["asset_binding"], "verified")
        self.assertIn("NPC Test Signer",
                      validation["signer_subject"])
        self.assertEqual(validation["signer_trust"],
                         "as_presented_not_rated")
        crypto = _checks(rec, "c2pa_cryptographic_validation")
        self.assertEqual(len(crypto), 1)
        self.assertEqual(crypto[0]["status"], "valid")
        pending = {c["check"] for c in rec["checks_not_run"]}
        self.assertNotIn("c2pa_cryptographic_validation", pending)
        # validation changes the credential label only: registration
        # is still not verification.
        self.assertEqual(rec["status"], "registered_checks_pending")

    def test_tampered_image_registers_validation_failed(self):
        rec = self.register("image", "tampered-signature.jpg",
                            "tamper@example.com")
        creds = _checks(rec, "c2pa_credentials")[0]
        self.assertEqual(creds["status"],
                         "present_cryptographic_validation_failed")
        self.assertEqual(creds["validated"], False)
        self.assertEqual(creds["validation"]["status"], "invalid")
        self.assertEqual(creds["validation"]["signature"], "invalid")
        crypto = _checks(rec, "c2pa_cryptographic_validation")[0]
        self.assertEqual(crypto["status"], "invalid")

    def test_video_registration_probe_c2pa_and_pending_frames(self):
        rec = self.register("video", "signed-es256.mp4",
                            "video@example.com")
        probe = _checks(rec, "media_probe")
        self.assertEqual(len(probe), 1)
        self.assertEqual(probe[0]["duration_ms"], 1000)
        self.assertEqual(probe[0]["video_codec"], "H.264")
        self.assertEqual(probe[0]["width"], 64)
        self.assertTrue(probe[0]["kind_match"])
        creds = _checks(rec, "c2pa_credentials")[0]
        self.assertEqual(creds["validation"]["signature"], "valid")
        self.assertEqual(creds["validation"]["asset_binding"],
                         "not_run")
        pending = {c["check"]: c for c in rec["checks_not_run"]}
        self.assertIn("video_frame_checks", pending)
        self.assertIn("decoder", pending["video_frame_checks"]
                      ["reason"])
        self.assertIn("ai_generation_signal", pending)
        self.assertIn("frames", pending["ai_generation_signal"]
                      ["reason"])

    def test_video_wrong_kind_bytes_probe_reports_mismatch(self):
        rec = self.register("video", "tone.wav", "mismatch@e.com")
        probe = _checks(rec, "media_probe")
        self.assertEqual(len(probe), 1)
        self.assertEqual(probe[0]["detected_kind"], "audio")
        self.assertFalse(probe[0]["kind_match"])

    def test_video_non_media_bytes_probe_pending(self):
        rec = self.register("video", "plain.jpg", "notmedia@e.com")
        self.assertEqual(_checks(rec, "media_probe"), [])
        pending = {c["check"] for c in rec["checks_not_run"]}
        self.assertIn("media_probe", pending)

    def test_audio_registration_probe_and_honest_pending(self):
        rec = self.register("audio", "tone.wav", "audio@e.com")
        probe = _checks(rec, "media_probe")[0]
        self.assertEqual(probe["container"], "wav")
        self.assertEqual(probe["sample_rate"], 44100)
        self.assertEqual(probe["duration_ms"], 2000)
        pending = {c["check"]: c for c in rec["checks_not_run"]}
        self.assertIn("c2pa_credentials", pending)
        self.assertIn("carriage", pending["c2pa_credentials"]
                      ["reason"])
        self.assertIn("ai_generation_signal", pending)
        self.assertIn("not been cleared",
                      pending["ai_generation_signal"]["reason"])

    def test_audio_mp3_registration(self):
        rec = self.register("audio", "tone.mp3", "mp3@e.com")
        probe = _checks(rec, "media_probe")[0]
        self.assertEqual(probe["container"], "mp3")
        self.assertEqual(probe["sample_rate"], 44100)

    def test_oversized_video_registers_with_pending_checks(self):
        # The intake fetch caps at 8 MiB: an oversized file is a
        # not_fetched registration, never a partial probe.
        status, _, data = self.post("/v1/register/content", body={
            "title": "Too big", "kind": "video",
            "locator": self.url("big.bin"),
            "creator_name": "Cycle Maker",
            "creator_email": "big@e.com"})
        self.assertEqual(status, 201)
        rec = json.loads(data)
        fetch = _checks(rec, "content_fetch")[0]
        self.assertEqual(fetch["status"], "not_fetched")
        pending = {c["check"] for c in rec["checks_not_run"]}
        for check in ("media_probe", "c2pa_credentials",
                      "c2pa_cryptographic_validation",
                      "video_frame_checks", "ai_generation_signal"):
            self.assertIn(check, pending)


class VerificationRequestTest(ApiTestCase):
    def _register_content(self, email):
        status, _, data = self.post("/v1/register/content", body={
            "title": "Ask for step two", "kind": "text",
            "locator": "sha256:" + "ef" * 32,
            "creator_name": "Asker", "creator_email": email})
        self.assertEqual(status, 201)
        return json.loads(data)

    def test_full_flow_and_idempotency(self):
        reg = self._register_content("asker@example.com")
        rid = reg["record_id"]
        # before: state reads not requested
        status, headers, data = self.get(
            "/v1/records/%s/verification-request" % rid)
        self.assertEqual(status, 200)
        state = self.check_signature(headers, data)
        self.assertEqual(state["verification_requested"], False)
        self.assertIsNone(state["requested_at"])
        self.assertIsNone(state["request"])
        # wrong email: the same signed unknown as a missing ID
        status, headers, data = self.post(
            "/v1/records/%s:request-verification" % rid,
            body={"email": "someone-else@example.com"})
        self.assertEqual(status, 404)
        body = self.check_signature(headers, data)
        self.assertEqual(body, {"verdict": "unknown"})
        # the right email: 201 + a signed request record
        status, headers, data = self.post(
            "/v1/records/%s:request-verification" % rid,
            body={"email": "asker@example.com"})
        self.assertEqual(status, 201)
        req_rec = self.check_signature(headers, data)
        self.assertEqual(req_rec["record_type"],
                         "npc.registry.verification_request")
        self.assertEqual(req_rec["subject_record_id"], rid)
        self.assertEqual(req_rec["status"], "verification_requested")
        self.assertEqual(req_rec["status_label"],
                         "Verification requested")
        self.assertTrue(req_rec["record_id"].startswith("vreq_"))
        self.assertTrue(pact.verify_record(self.app.keys, req_rec))
        self.assertNotIn(b"asker@example.com", data)
        # repeat: 200, same record, no duplicate
        status, _, data = self.post(
            "/v1/records/%s:request-verification" % rid,
            body={"email": "asker@example.com"})
        self.assertEqual(status, 200)
        again = json.loads(data)
        self.assertEqual(again["record_id"], req_rec["record_id"])
        # state now reads requested, with the request record
        status, _, data = self.get(
            "/v1/records/%s/verification-request" % rid)
        state = json.loads(data)
        self.assertEqual(state["verification_requested"], True)
        self.assertEqual(state["requested_at"],
                         req_rec["requested_at"])
        self.assertEqual(state["request"]["record_id"],
                         req_rec["record_id"])
        # the queue NPC works holds exactly one request for this
        # subject (the class store is shared across tests)
        queue = [q for q in self.app.store.list_verification_requests()
                 if q["subject_record_id"] == rid]
        self.assertEqual([q["record_id"] for q in queue],
                         [req_rec["record_id"]])
        # and the request record itself resolves by ID... nowhere:
        # it is a queue artifact, and the subject record is unchanged
        status, _, data = self.get("/v1/records/%s" % rid)
        self.assertEqual(json.loads(data)["status"],
                         "registered_checks_pending")

    def test_unknown_id_and_non_registration_fail_closed(self):
        status, headers, data = self.post(
            "/v1/records/reg_missing:request-verification",
            body={"email": "asker@example.com"})
        self.assertEqual(status, 404)
        self.assertEqual(self.check_signature(headers, data),
                         {"verdict": "unknown"})
        status, _, _ = self.get(
            "/v1/records/reg_missing/verification-request")
        self.assertEqual(status, 404)
        status, _, _ = self.get(
            "/v1/records/demo-tag-001/verification-request")
        self.assertEqual(status, 404)

    def test_agent_registration_can_request(self):
        status, _, data = self.post("/v1/register/agent", body={
            "agent_name": "Asker Agent", "owner_name": "Asker",
            "owner_email": "agent-asker@example.com",
            "description": "An agent whose owner asks for step two."})
        self.assertEqual(status, 201)
        rid = json.loads(data)["record_id"]
        status, _, data = self.post(
            "/v1/records/%s:request-verification" % rid,
            body={"email": "agent-asker@example.com"})
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(data)["subject_kind"], "agent")

    def test_invalid_body_is_422(self):
        reg = self._register_content("shapes@example.com")
        status, _, _ = self.post(
            "/v1/records/%s:request-verification" % reg["record_id"],
            body={"email": "not-an-email"})
        self.assertEqual(status, 422)
        status, _, _ = self.post(
            "/v1/records/%s:request-verification" % reg["record_id"],
            body={})
        self.assertEqual(status, 422)

    def test_attempts_are_capped_like_registration(self):
        # Ten unmatched attempts from one email are answered; the
        # eleventh is rate limited, mirroring the register caps.
        for i in range(10):
            status, _, _ = self.post(
                "/v1/records/reg_probe%d:request-verification" % i,
                body={"email": "probe@example.com"})
            self.assertEqual(status, 404)
        status, _, _ = self.post(
            "/v1/records/reg_probeX:request-verification",
            body={"email": "probe@example.com"})
        self.assertEqual(status, 429)


class VerificationRequestStoreParityTest(unittest.TestCase):
    """The new store methods behave identically on both backends."""

    def _exercise(self, store):
        rec = {"record_id": "reg_parity", "kind": "content",
               "registered_at": "2026-10-15T00:00:00+00:00"}
        store.add_registration(rec, "owner@example.com", "203.0.113.5")
        from npc_verify.store import registration_email_hash
        self.assertEqual(store.registration_email_hash("reg_parity"),
                         registration_email_hash("owner@example.com"))
        self.assertIsNone(store.registration_email_hash("reg_none"))
        req = {"record_id": "vreq_parity",
               "requested_at": "2026-10-15T01:00:00+00:00"}
        self.assertTrue(store.add_verification_request(
            req, "reg_parity", "owner@example.com", "203.0.113.5"))
        # put-if-absent: a second request for the same subject loses
        self.assertFalse(store.add_verification_request(
            req, "reg_parity", "owner@example.com", "203.0.113.5"))
        self.assertEqual(
            store.get_verification_request("reg_parity"), req)
        self.assertEqual(store.list_verification_requests(), [req])
        store.record_verification_request_attempt(
            "reg_parity", "owner@example.com", "203.0.113.5", True,
            "2026-10-15T01:00:00+00:00")
        store.record_verification_request_attempt(
            "reg_other", "owner@example.com", "203.0.113.5", False,
            "2026-10-15T01:01:00+00:00")
        since = "2026-10-15T00:00:00+00:00"
        self.assertEqual(
            store.count_verification_request_attempts_since(
                "email", "owner@example.com", since), 2)
        self.assertEqual(
            store.count_verification_request_attempts_since(
                "ip", "203.0.113.5", since), 2)
        self.assertEqual(
            store.count_verification_request_attempts_since(
                "email", "other@example.com", since), 0)

    def test_sqlite(self):
        tmp = tempfile.mkdtemp(prefix="npc_vreq_sqlite_")
        store = Store(os.path.join(tmp, "t.db"))
        try:
            self._exercise(store)
        finally:
            store.close()

    def test_dynamodb(self):
        table = fake_boto3.FakeTable("npc-verify-store-test")
        self._exercise(DynamoDBStore(table=table))


if __name__ == "__main__":
    unittest.main()
