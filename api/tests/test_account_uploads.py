"""Staged media uploads (v6.11): POST /v1/account/uploads plus
upload_id on the account check routes.

One staging path serves every oversized file: an image above the
750 KB inline cap, a video, an audio file. The account asks for an
upload slot (session only), the file lands in the staging store,
and the check runs by upload id: the API reads the bytes itself,
charges the account exactly once under the v6.10 balance rules,
records the signed result, and deletes the staged object whether
the check completed or failed. A replayed upload id is refused
and charged nothing; a balance that cannot fund the check leaves
the upload staged and usable.

No live calls and no AWS: detectors are injected fakes (the
test_account_checks pattern), the staging store is the in-memory
store from npc_verify.uploads, accounts come from the email-link
flow against the stub mailer, and balances are funded through a
signed-in purchase straight into the store. The DynamoDB upload
record methods are proven against the fake boto3 table (the
test_ddb_store pattern).
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
from npc_verify import uploads as uploads_module  # noqa: E402
from npc_verify.av_detector import VideoCheckResult  # noqa: E402
from npc_verify.canonical import canonicalize  # noqa: E402
from npc_verify.detector import DetectorError  # noqa: E402
from npc_verify.models import utcnow_iso  # noqa: E402

# 800 KB of image: above the 750 KB inline cap, so only the staged
# path can carry it.
BIG_IMAGE_BYTES = b"\x89PNG\r\n\x1a\n" + b"npc-big-image" * 61530
VIDEO_BYTES = b"\x00\x00\x00\x18ftypmp42" + b"npc-account-video" * 8
AUDIO_BYTES = b"ID3" + b"npc-account-audio" * 16

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


class FakeAudioDetector:
    provider = "sightengine"
    model = "ai_music"
    configured = True

    def __init__(self, prob=0.42, error=None):
        self.prob = prob
        self.error = error
        self.calls = []

    def check_ai_music(self, audio_bytes=None):
        self.calls.append(audio_bytes)
        if self.error is not None:
            raise self.error
        return self.prob


class AccountUploadsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_acct_uploads_")
        self.mailer = StubMailer()
        self.staging = uploads_module.MemoryStagingStore()
        self.app = create_app(os.path.join(self.tmp, "t.db"),
                              os.path.join(self.tmp, "keys"),
                              mailer=self.mailer,
                              staging_store=self.staging)
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
        self.fake_audio = FakeAudioDetector()
        self.app.detector = self.fake_image
        self.app.video_detector = self.fake_video
        self.app.audio_detector = self.fake_audio
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

    def account_id_of(self, sess):
        status, _h, raw = self.get("/v1/auth/me", token=sess)
        self.assertEqual(status, 200, raw)
        return json.loads(raw)["account"]["account_id"]

    def fund_account(self, sess, checks=3):
        acct = self.account_id_of(sess)
        self._mint_counter += 1
        session = "cs_upl_bal_%d" % self._mint_counter
        now = utcnow_iso()
        pack = dict(PACK, checks=checks)
        self.app.store.create_credit_purchase(
            session, pack["id"], None, now, account_id=acct)
        row = self.app.store.complete_account_purchase(
            session, credits.account_ledger_hash(acct), pack,
            "buyer@example.com", now)
        self.assertIsNotNone(row)
        return acct

    def account_balance_of(self, sess):
        status, headers, raw = self.get("/v1/account/balance",
                                        token=sess)
        self.assertEqual(status, 200, raw)
        return self.check_signature(headers, raw)

    def history(self, token):
        status, headers, raw = self.get("/v1/account/checks",
                                        token=token)
        self.assertEqual(status, 200, raw)
        return self.check_signature(headers, raw)["checks"]

    def presign(self, sess, media_type, data, filename):
        status, headers, raw = self.post(
            "/v1/account/uploads",
            {"media_type": media_type, "size_bytes": len(data),
             "filename": filename}, token=sess)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        # Stand in for the client's presigned PUT: the store now
        # holds exactly the bytes a completed PUT would leave.
        acct = self.account_id_of(sess)
        key = uploads_module.object_key(acct, body["upload_id"])
        self.staging.put_bytes(key, data)
        return body

    # -- presign: session gate and validation ----------------------------

    def test_presign_requires_a_session(self):
        status, _h, _raw = self.post(
            "/v1/account/uploads",
            {"media_type": "video", "size_bytes": 10,
             "filename": "clip.mp4"})
        self.assertEqual(status, 401)
        status, _h, _raw = self.post(
            "/v1/account/uploads",
            {"media_type": "video", "size_bytes": 10,
             "filename": "clip.mp4"}, key=self.verifier_key)
        self.assertEqual(status, 401)

    def test_presign_shape_and_caps(self):
        sess = self.sign_in("owner@example.com")
        body = self.presign(sess, "video", VIDEO_BYTES, "clip.mp4")
        self.assertTrue(body["upload_id"].startswith("upl_"))
        self.assertTrue(body["upload_url"])
        self.assertEqual(body["expires_in_seconds"], 900)
        self.assertEqual(body["max_bytes"], 50 * 1000 * 1000)
        self.assertEqual(body["media_type"], "video")

    def test_presign_refuses_oversize_declaration(self):
        sess = self.sign_in("owner@example.com")
        status, _h, raw = self.post(
            "/v1/account/uploads",
            {"media_type": "video",
             "size_bytes": 50 * 1000 * 1000 + 1,
             "filename": "clip.mp4"}, token=sess)
        self.assertEqual(status, 400, raw)
        status, _h, raw = self.post(
            "/v1/account/uploads",
            {"media_type": "image",
             "size_bytes": 10 * 1000 * 1000 + 1,
             "filename": "photo.jpg"}, token=sess)
        self.assertEqual(status, 400, raw)

    def test_presign_refuses_bad_kind_and_file_type(self):
        sess = self.sign_in("owner@example.com")
        status, _h, _raw = self.post(
            "/v1/account/uploads",
            {"media_type": "document", "size_bytes": 10,
             "filename": "clip.mp4"}, token=sess)
        self.assertEqual(status, 400)
        status, _h, _raw = self.post(
            "/v1/account/uploads",
            {"media_type": "video", "size_bytes": 10,
             "filename": "notes.txt"}, token=sess)
        self.assertEqual(status, 400)

    def test_uploads_unconfigured_answers_503(self):
        self.app.staging = None
        sess = self.sign_in("owner@example.com")
        status, _h, _raw = self.post(
            "/v1/account/uploads",
            {"media_type": "video", "size_bytes": 10,
             "filename": "clip.mp4"}, token=sess)
        self.assertEqual(status, 503)

    # -- staged checks -----------------------------------------------------

    def test_oversized_image_via_upload_id(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        up = self.presign(sess, "image", BIG_IMAGE_BYTES, "photo.png")
        status, headers, raw = self.post(
            "/v1/account/checks/image",
            {"upload_id": up["upload_id"]}, token=sess)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertEqual(body["check"], "ai_generation")
        self.assertEqual(body["source"], "upload")
        self.assertEqual(body["image_sha256"],
                         hashlib.sha256(BIG_IMAGE_BYTES).hexdigest())
        self.assertTrue(body["charged"])
        self.assertEqual(body["ai_balance"], 2)
        # The detector saw the staged bytes themselves.
        self.assertEqual(self.fake_image.calls[-1][0], BIG_IMAGE_BYTES)
        # The staged object is deleted once the check completes.
        acct = self.account_id_of(sess)
        key = uploads_module.object_key(acct, up["upload_id"])
        self.assertNotIn(key, self.staging.objects)
        # History carries the digest reference, never a file or URL.
        checks = self.history(sess)
        self.assertEqual(len(checks), 1)
        self.assertEqual(
            checks[0]["media_ref"],
            "sha256:" + hashlib.sha256(BIG_IMAGE_BYTES).hexdigest())

    def test_video_via_upload_id_charged_exactly_once(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        up = self.presign(sess, "video", VIDEO_BYTES, "clip.mp4")
        status, headers, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up["upload_id"]}, token=sess)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertEqual(body["check"], "ai_generation_video")
        self.assertEqual(body["source"], "upload")
        self.assertTrue(body["charged"])
        self.assertEqual(body["ai_balance"], 2)
        acct = self.account_id_of(sess)
        key = uploads_module.object_key(acct, up["upload_id"])
        self.assertNotIn(key, self.staging.objects)
        # Replay of the same upload id: refused, charged nothing,
        # and the detector does not run again.
        calls = len(self.fake_video.calls)
        status, _h, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up["upload_id"]}, token=sess)
        self.assertEqual(status, 409, raw)
        self.assertEqual(len(self.fake_video.calls), calls)
        self.assertEqual(self.account_balance_of(sess)["ai_balance"], 2)

    def test_same_video_staged_twice_second_is_duplicate(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        up1 = self.presign(sess, "video", VIDEO_BYTES, "clip.mp4")
        status, _h, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up1["upload_id"]}, token=sess)
        self.assertEqual(status, 200, raw)
        self.assertTrue(json.loads(raw)["charged"])
        up2 = self.presign(sess, "video", VIDEO_BYTES, "clip.mp4")
        status, headers, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up2["upload_id"]}, token=sess)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertFalse(body["charged"])
        self.assertTrue(body["duplicate"])
        self.assertEqual(body["ai_balance"], 2)

    def test_audio_via_upload_id(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        up = self.presign(sess, "audio", AUDIO_BYTES, "song.mp3")
        status, headers, raw = self.post(
            "/v1/account/checks/audio",
            {"upload_id": up["upload_id"]}, token=sess)
        self.assertEqual(status, 200, raw)
        body = self.check_signature(headers, raw)
        self.assertEqual(body["check"], "ai_generation_music")
        self.assertEqual(body["ai_generated_percent"], 42)
        self.assertEqual(body["source"], "upload")
        self.assertTrue(body["charged"])
        acct = self.account_id_of(sess)
        key = uploads_module.object_key(acct, up["upload_id"])
        self.assertNotIn(key, self.staging.objects)

    def test_failed_check_deletes_object_and_charges_nothing(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        self.fake_video.error = DetectorError("vendor down")
        up = self.presign(sess, "video", VIDEO_BYTES, "clip.mp4")
        status, _h, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up["upload_id"]}, token=sess)
        self.assertEqual(status, 503, raw)
        self.assertEqual(self.account_balance_of(sess)["ai_balance"], 3)
        self.assertEqual(self.history(sess), [])
        acct = self.account_id_of(sess)
        key = uploads_module.object_key(acct, up["upload_id"])
        self.assertNotIn(key, self.staging.objects)
        # The upload is consumed even though the check failed: a
        # replay is refused, not silently retried against the
        # (now deleted) file.
        status, _h, _raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up["upload_id"]}, token=sess)
        self.assertEqual(status, 409)

    def test_size_mismatch_at_check_time_is_refused(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        # Declare the real size, then stage different bytes (more
        # of them) than declared: the check refuses, charges
        # nothing, and deletes the object.
        status, _h, raw = self.post(
            "/v1/account/uploads",
            {"media_type": "video", "size_bytes": len(VIDEO_BYTES),
             "filename": "clip.mp4"}, token=sess)
        self.assertEqual(status, 200, raw)
        upload_id = json.loads(raw)["upload_id"]
        acct = self.account_id_of(sess)
        key = uploads_module.object_key(acct, upload_id)
        self.staging.put_bytes(key, VIDEO_BYTES + b"x" * 64)
        status, _h, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": upload_id}, token=sess)
        self.assertEqual(status, 400, raw)
        self.assertEqual(self.account_balance_of(sess)["ai_balance"], 3)
        self.assertNotIn(key, self.staging.objects)

    def test_no_balance_leaves_upload_usable(self):
        sess = self.sign_in("owner@example.com")
        up = self.presign(sess, "video", VIDEO_BYTES, "clip.mp4")
        status, _h, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up["upload_id"]}, token=sess)
        self.assertEqual(status, 402, raw)
        # Nothing claimed, nothing deleted: fund the account and
        # the same upload id runs.
        acct = self.account_id_of(sess)
        key = uploads_module.object_key(acct, up["upload_id"])
        self.assertIn(key, self.staging.objects)
        self.fund_account(sess)
        status, headers, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up["upload_id"]}, token=sess)
        self.assertEqual(status, 200, raw)
        self.assertTrue(self.check_signature(headers, raw)["charged"])

    def test_upload_id_is_namespaced_to_its_account(self):
        sess_a = self.sign_in("a@example.com")
        sess_b = self.sign_in("b@example.com")
        self.fund_account(sess_a)
        self.fund_account(sess_b)
        up = self.presign(sess_a, "video", VIDEO_BYTES, "clip.mp4")
        status, _h, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up["upload_id"]}, token=sess_b)
        self.assertEqual(status, 400, raw)
        # B's attempt touched nothing: A can still run the check.
        status, _h, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up["upload_id"]}, token=sess_a)
        self.assertEqual(status, 200, raw)

    def test_upload_id_kind_must_match_the_route(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        up = self.presign(sess, "video", VIDEO_BYTES, "clip.mp4")
        status, _h, raw = self.post(
            "/v1/account/checks/image",
            {"upload_id": up["upload_id"]}, token=sess)
        self.assertEqual(status, 400, raw)

    def test_upload_id_and_url_together_are_refused(self):
        sess = self.sign_in("owner@example.com")
        self.fund_account(sess)
        up = self.presign(sess, "video", VIDEO_BYTES, "clip.mp4")
        status, _h, raw = self.post(
            "/v1/account/checks/video",
            {"upload_id": up["upload_id"],
             "video_url": "https://example.com/clip.mp4"}, token=sess)
        self.assertEqual(status, 400, raw)


class TestDynamoUploadRecords(unittest.TestCase):
    """The DynamoDB backend's upload records, against the fake
    boto3 table: create, resolve under the owning account only,
    claim exactly once, release back to pending."""

    def setUp(self):
        fake_dir = os.path.join(BASE, "serverless", "lambda_v3",
                                "fake_boto3")
        if fake_dir not in sys.path:
            sys.path.insert(0, fake_dir)
        import boto3 as fake_boto3
        from npc_verify.ddb_store import DynamoDBStore
        self.store = DynamoDBStore(
            table=fake_boto3.FakeTable("npc-verify-store-test"))

    def test_claim_is_exactly_once(self):
        row = self.store.create_account_upload(
            "upl_1", "acct_a", "video", 10, "video/mp4",
            "staging/acct_a/upl_1", utcnow_iso())
        self.assertEqual(row["state"], "pending")
        got = self.store.get_account_upload("acct_a", "upl_1")
        self.assertEqual(got["media_type"], "video")
        # Another account cannot resolve the id at all.
        self.assertIsNone(self.store.get_account_upload("acct_b",
                                                        "upl_1"))
        self.assertTrue(self.store.claim_account_upload("acct_a",
                                                        "upl_1"))
        self.assertFalse(self.store.claim_account_upload("acct_a",
                                                         "upl_1"))
        self.store.release_account_upload("acct_a", "upl_1")
        self.assertTrue(self.store.claim_account_upload("acct_a",
                                                        "upl_1"))


if __name__ == "__main__":
    unittest.main()
