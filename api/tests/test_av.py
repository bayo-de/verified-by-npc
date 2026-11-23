"""Tests for the AV detection lane (video + music).

No live calls and no credentials: the vendor clients are tested
with injected fake transports replaying the response shapes in
Sightengine's official docs (video: data.frames[].type.ai_generated
with info.position in ms; music: type.ai_music), the endpoints are
tested against the production App with fake detectors and a fake
media fetcher, and the SSRF-guarded fetcher is tested with a fake
resolver and a fake opener.

Run from the api/ directory:
    python3 -m unittest tests.test_av -v
"""
import hashlib
import ipaddress
import unittest
import urllib.request

from tests.helpers import ApiTestCase
from npc_verify import av_detector
from npc_verify.av_detector import (SightengineAudioDetector,
                                    SightengineVideoDetector,
                                    UnconfiguredAudioDetector,
                                    UnconfiguredVideoDetector,
                                    VideoCheckResult,
                                    av_detectors_from_env,
                                    parse_video_callback)
from npc_verify.detector import DetectorError, DetectorNotConfigured
from npc_verify.media_fetch import (FetchError, fetch_media_bytes,
                                    host_permitted, url_permitted)

VIDEO_BYTES = b"\x00\x00\x00\x18ftypmp42" + b"npc-test-video" * 16
AUDIO_BYTES = b"ID3" + b"npc-test-audio" * 16

PUBLIC_IP = ipaddress.ip_address("93.184.216.34")
PRIVATE_IP = ipaddress.ip_address("10.0.0.7")
LOOPBACK_IP = ipaddress.ip_address("127.0.0.1")


def video_payload(scores, operations=40):
    return {
        "status": "success",
        "request": {"id": "req_test", "operations": operations},
        "data": {"frames": [
            {"info": {"id": f"med_{i}", "position": i * 2000},
             "type": {"ai_generated": s}}
            for i, s in enumerate(scores)]},
        "media": {"id": "med_x", "uri": "video.mp4"},
    }


def fake_transport(payload, status=200, capture=None):
    def transport(endpoint, fields, file_field, filename, file_bytes,
                  timeout):
        if capture is not None:
            capture.update(endpoint=endpoint, fields=fields,
                           file_field=file_field, filename=filename,
                           file_bytes=file_bytes)
        return status, payload
    return transport


class TestVideoClient(unittest.TestCase):
    def test_aggregates_frames(self):
        cap = {}
        det = SightengineVideoDetector(
            "u", "s", transport=fake_transport(
                video_payload([0.99, 0.10, 0.60]), capture=cap))
        result = det.check_ai_video(video_bytes=VIDEO_BYTES,
                                    interval_seconds=2)
        self.assertIsInstance(result, VideoCheckResult)
        self.assertEqual(len(result.frames), 3)
        self.assertEqual(result.frames[0], (0, 0.99))
        self.assertEqual(result.frames[2], (4000, 0.60))
        self.assertAlmostEqual(result.mean, (0.99 + 0.10 + 0.60) / 3)
        self.assertEqual(result.peak, 0.99)
        self.assertEqual(result.flagged, 2)
        self.assertEqual(result.operations, 40)
        # Request shape matches the vendor docs.
        self.assertEqual(cap["endpoint"], av_detector
                         .SIGHTENGINE_VIDEO_SYNC_ENDPOINT)
        self.assertEqual(cap["fields"]["models"], "genai")
        self.assertEqual(cap["fields"]["interval"], 2)
        self.assertEqual(cap["file_field"], "media")
        self.assertEqual(cap["file_bytes"], VIDEO_BYTES)

    def test_empty_frames_is_error(self):
        det = SightengineVideoDetector(
            "u", "s", transport=fake_transport(video_payload([])))
        with self.assertRaises(DetectorError):
            det.check_ai_video(video_bytes=VIDEO_BYTES)

    def test_vendor_failure_status(self):
        det = SightengineVideoDetector(
            "u", "s", transport=fake_transport(
                {"status": "failure"}, status=200))
        with self.assertRaises(DetectorError):
            det.check_ai_video(video_bytes=VIDEO_BYTES)

    def test_http_error(self):
        det = SightengineVideoDetector(
            "u", "s", transport=fake_transport({}, status=500))
        with self.assertRaises(DetectorError):
            det.check_ai_video(video_bytes=VIDEO_BYTES)

    def test_bad_interval(self):
        det = SightengineVideoDetector(
            "u", "s", transport=fake_transport(video_payload([0.1])))
        with self.assertRaises(DetectorError):
            det.check_ai_video(video_bytes=VIDEO_BYTES,
                               interval_seconds=7)

    def test_missing_bytes(self):
        det = SightengineVideoDetector(
            "u", "s", transport=fake_transport(video_payload([0.1])))
        with self.assertRaises(DetectorError):
            det.check_ai_video(video_bytes=b"")

    def test_async_submit_returns_request_id(self):
        cap = {}
        payload = {"status": "success", "request": {"id": "req_abc"}}
        det = SightengineVideoDetector(
            "u", "s", transport=fake_transport(payload, capture=cap))
        rid = det.submit_ai_video_async(
            video_bytes=VIDEO_BYTES,
            callback_url="https://api.example.test/cb")
        self.assertEqual(rid, "req_abc")
        self.assertEqual(cap["endpoint"], av_detector
                         .SIGHTENGINE_VIDEO_ASYNC_ENDPOINT)
        self.assertEqual(cap["fields"]["callback_url"],
                         "https://api.example.test/cb")

    def test_parse_callback(self):
        result = parse_video_callback(video_payload([0.2, 0.9]))
        self.assertEqual(result.peak, 0.9)
        self.assertEqual(result.flagged, 1)
        with self.assertRaises(DetectorError):
            parse_video_callback({"status": "failure"})


class TestAudioClient(unittest.TestCase):
    def test_score(self):
        cap = {}
        payload = {"status": "success",
                   "request": {"id": "req_1", "operations": 15},
                   "type": {"ai_music": 0.01},
                   "media": {"id": "med_1", "uri": "music.mp3"}}
        det = SightengineAudioDetector(
            "u", "s", transport=fake_transport(payload, capture=cap))
        prob = det.check_ai_music(audio_bytes=AUDIO_BYTES)
        self.assertEqual(prob, 0.01)
        self.assertEqual(cap["endpoint"], av_detector
                         .SIGHTENGINE_AUDIO_ENDPOINT)
        self.assertEqual(cap["fields"]["models"], "ai_music")
        self.assertEqual(cap["file_field"], "audio")

    def test_missing_score_is_error(self):
        det = SightengineAudioDetector(
            "u", "s", transport=fake_transport(
                {"status": "success", "type": {}}))
        with self.assertRaises(DetectorError):
            det.check_ai_music(audio_bytes=AUDIO_BYTES)

    def test_out_of_range_is_error(self):
        det = SightengineAudioDetector(
            "u", "s", transport=fake_transport(
                {"status": "success", "type": {"ai_music": 1.7}}))
        with self.assertRaises(DetectorError):
            det.check_ai_music(audio_bytes=AUDIO_BYTES)


class TestEnvFactory(unittest.TestCase):
    def test_unconfigured_without_env(self):
        video, audio = av_detectors_from_env({})
        self.assertIsInstance(video, UnconfiguredVideoDetector)
        self.assertIsInstance(audio, UnconfiguredAudioDetector)
        self.assertFalse(video.configured)
        with self.assertRaises(DetectorNotConfigured):
            video.check_ai_video(video_bytes=VIDEO_BYTES)
        with self.assertRaises(DetectorNotConfigured):
            audio.check_ai_music(audio_bytes=AUDIO_BYTES)

    def test_configured_with_env(self):
        video, audio = av_detectors_from_env(
            {"SIGHTENGINE_API_USER": "u", "SIGHTENGINE_API_SECRET": "s"})
        self.assertIsInstance(video, SightengineVideoDetector)
        self.assertIsInstance(audio, SightengineAudioDetector)
        self.assertTrue(video.configured and audio.configured)


class TestMediaFetchGuard(unittest.TestCase):
    def test_private_literal_refused(self):
        self.assertFalse(host_permitted("10.0.0.7"))
        self.assertFalse(host_permitted("192.168.1.1"))
        self.assertFalse(host_permitted("169.254.169.254"))
        self.assertFalse(host_permitted("0x7f000001"))

    def test_loopback_refused_by_default(self):
        self.assertFalse(host_permitted("127.0.0.1"))
        self.assertFalse(host_permitted("localhost"))
        self.assertTrue(host_permitted("127.0.0.1", allow_loopback=True))

    def test_public_literal_allowed(self):
        self.assertTrue(host_permitted("93.184.216.34"))

    def test_dns_name_resolving_private_refused(self):
        resolver = lambda host: [PRIVATE_IP]  # noqa: E731
        self.assertFalse(host_permitted("evil.example", resolver=resolver))

    def test_dns_name_resolving_mixed_refused(self):
        resolver = lambda host: [PUBLIC_IP, PRIVATE_IP]  # noqa: E731
        self.assertFalse(host_permitted("evil.example", resolver=resolver))

    def test_dns_name_resolving_public_allowed(self):
        resolver = lambda host: [PUBLIC_IP]  # noqa: E731
        self.assertTrue(host_permitted("cdn.example", resolver=resolver))

    def test_dns_failure_refused(self):
        def resolver(host):
            raise OSError("no such host")
        self.assertFalse(host_permitted("gone.example", resolver=resolver))

    def test_url_scheme_screen(self):
        resolver = lambda host: [PUBLIC_IP]  # noqa: E731
        self.assertFalse(url_permitted("ftp://cdn.example/x.mp4",
                                       resolver=resolver))
        self.assertTrue(url_permitted("https://cdn.example/x.mp4",
                                      resolver=resolver))

    def test_redirect_hop_to_private_refused(self):
        from npc_verify.media_fetch import _GuardedRedirectHandler
        handler = _GuardedRedirectHandler(
            resolver=lambda host: [PUBLIC_IP])
        req = urllib.request.Request("https://cdn.example/clip.mp4")
        out = handler.redirect_request(
            req, None, 302, "Found", {},
            "https://169.254.169.254/latest/meta-data")
        self.assertIsNone(out)

    def test_redirect_hop_to_public_allowed(self):
        from npc_verify.media_fetch import _GuardedRedirectHandler
        handler = _GuardedRedirectHandler(
            resolver=lambda host: [PUBLIC_IP])
        req = urllib.request.Request("https://cdn.example/clip.mp4")
        out = handler.redirect_request(
            req, None, 302, "Found", {}, "https://cdn.example/final.mp4")
        self.assertIsNotNone(out)
        self.assertEqual(out.get_full_url(),
                         "https://cdn.example/final.mp4")


class _FakeResponse:
    def __init__(self, data):
        self._data = data
        self._pos = 0

    def read(self, n=-1):
        if self._pos >= len(self._data):
            return b""
        end = self._pos + (len(self._data) if n < 0 else n)
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeOpener:
    def __init__(self, data=b"", error=None):
        self.data = data
        self.error = error
        self.calls = []

    def open(self, req, timeout=None):
        self.calls.append(req.get_full_url())
        if self.error is not None:
            raise self.error
        return _FakeResponse(self.data)


class TestMediaFetch(unittest.TestCase):
    def setUp(self):
        self.resolver = lambda host: [PUBLIC_IP]  # noqa: E731

    def test_fetch_success(self):
        opener = _FakeOpener(VIDEO_BYTES)
        data = fetch_media_bytes("https://cdn.example/clip.mp4", 1000,
                                 resolver=self.resolver, opener=opener)
        self.assertEqual(data, VIDEO_BYTES)

    def test_fetch_oversize(self):
        opener = _FakeOpener(b"x" * 5000)
        with self.assertRaises(FetchError) as ctx:
            fetch_media_bytes("https://cdn.example/clip.mp4", 1000,
                              resolver=self.resolver, opener=opener)
        self.assertIn("size cap", str(ctx.exception))

    def test_fetch_empty(self):
        opener = _FakeOpener(b"")
        with self.assertRaises(FetchError):
            fetch_media_bytes("https://cdn.example/clip.mp4", 1000,
                              resolver=self.resolver, opener=opener)

    def test_fetch_transport_error(self):
        opener = _FakeOpener(error=OSError("boom"))
        with self.assertRaises(FetchError):
            fetch_media_bytes("https://cdn.example/clip.mp4", 1000,
                              resolver=self.resolver, opener=opener)

    def test_fetch_private_url_refused_before_open(self):
        opener = _FakeOpener(VIDEO_BYTES)
        with self.assertRaises(FetchError):
            fetch_media_bytes("https://10.0.0.7/clip.mp4", 1000,
                              resolver=self.resolver, opener=opener)
        self.assertEqual(opener.calls, [])


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

    def __init__(self, prob=0.87, error=None):
        self.prob = prob
        self.error = error
        self.calls = []

    def check_ai_music(self, audio_bytes=None):
        self.calls.append(audio_bytes)
        if self.error is not None:
            raise self.error
        return self.prob


class FakeFetcher:
    def __init__(self, data=VIDEO_BYTES, error=None):
        self.data = data
        self.error = error
        self.calls = []

    def __call__(self, url, max_bytes):
        self.calls.append((url, max_bytes))
        if self.error is not None:
            raise self.error
        return self.data


class TestAvEndpoints(ApiTestCase):
    def setUp(self):
        self.fake_video = FakeVideoDetector()
        self.fake_audio = FakeAudioDetector()
        self.fake_fetch = FakeFetcher()
        self.app.video_detector = self.fake_video
        self.app.audio_detector = self.fake_audio
        self.app.media_fetcher = self.fake_fetch

    def test_video_success_signed(self):
        s, h, d = self.post(
            "/v1/videos/ai-check",
            {"video_url": "https://example.com/clip.mp4"},
            key=self.verifier_key)
        self.assertEqual(s, 200)
        body = self.check_signature(h, d)
        self.assertEqual(body["check"], "ai_generation_video")
        self.assertEqual(body["provider"], "sightengine")
        self.assertEqual(body["model"], "genai")
        self.assertEqual(body["ai_generated_percent"], 56)
        self.assertEqual(body["ai_generated_percent_peak"], 99)
        self.assertEqual(body["frames_analyzed"], 3)
        self.assertEqual(body["frames_flagged"], 2)
        self.assertEqual(body["interval_ms"], 2000)
        self.assertEqual(body["video_sha256"],
                         hashlib.sha256(VIDEO_BYTES).hexdigest())
        self.assertEqual(body["vendor_operations"], 40)
        self.assertIn("checked_at", body)

    def test_video_interval_passthrough(self):
        s, h, d = self.post(
            "/v1/videos/ai-check",
            {"video_url": "https://example.com/clip.mp4",
             "interval_seconds": 0.5},
            key=self.verifier_key)
        self.assertEqual(s, 200)
        body = self.check_signature(h, d)
        self.assertEqual(body["interval_ms"], 500)
        self.assertEqual(self.fake_video.calls[-1][1], 0.5)

    def test_video_bad_interval_400(self):
        s, _, _ = self.post(
            "/v1/videos/ai-check",
            {"video_url": "https://example.com/clip.mp4",
             "interval_seconds": 7},
            key=self.verifier_key)
        self.assertEqual(s, 400)

    def test_video_no_auth_401(self):
        s, _, _ = self.post(
            "/v1/videos/ai-check",
            {"video_url": "https://example.com/clip.mp4"})
        self.assertEqual(s, 401)
        self.assertEqual(self.fake_fetch.calls, [])

    def test_video_missing_url_400(self):
        s, _, _ = self.post("/v1/videos/ai-check", {},
                            key=self.verifier_key)
        self.assertEqual(s, 400)

    def test_video_bad_url_400(self):
        s, _, _ = self.post("/v1/videos/ai-check",
                            {"video_url": "ftp://example.com/x.mp4"},
                            key=self.verifier_key)
        self.assertEqual(s, 400)

    def test_video_fetch_failure_422(self):
        self.fake_fetch.error = FetchError("media could not be fetched")
        s, _, _ = self.post(
            "/v1/videos/ai-check",
            {"video_url": "https://example.com/clip.mp4"},
            key=self.verifier_key)
        self.assertEqual(s, 422)

    def test_video_detector_error_503(self):
        self.fake_video.error = DetectorError("boom")
        s, _, d = self.post(
            "/v1/videos/ai-check",
            {"video_url": "https://example.com/clip.mp4"},
            key=self.verifier_key)
        self.assertEqual(s, 503)
        self.assertIn(b"detector_unavailable", d)

    def test_video_unconfigured_503(self):
        self.app.video_detector = UnconfiguredVideoDetector()
        s, _, _ = self.post(
            "/v1/videos/ai-check",
            {"video_url": "https://example.com/clip.mp4"},
            key=self.verifier_key)
        self.assertEqual(s, 503)

    def test_audio_success_signed(self):
        self.fake_fetch.data = AUDIO_BYTES
        s, h, d = self.post(
            "/v1/audio/ai-check",
            {"audio_url": "https://example.com/song.mp3"},
            key=self.verifier_key)
        self.assertEqual(s, 200)
        body = self.check_signature(h, d)
        self.assertEqual(body["check"], "ai_generation_music")
        self.assertEqual(body["model"], "ai_music")
        self.assertEqual(body["ai_generated_percent"], 87)
        self.assertEqual(body["audio_sha256"],
                         hashlib.sha256(AUDIO_BYTES).hexdigest())
        self.assertIn("checked_at", body)

    def test_audio_no_auth_401(self):
        s, _, _ = self.post(
            "/v1/audio/ai-check",
            {"audio_url": "https://example.com/song.mp3"})
        self.assertEqual(s, 401)

    def test_audio_detector_error_503(self):
        self.fake_audio.error = DetectorError("boom")
        s, _, _ = self.post(
            "/v1/audio/ai-check",
            {"audio_url": "https://example.com/song.mp3"},
            key=self.verifier_key)
        self.assertEqual(s, 503)

    def test_audio_unexpected_field_400(self):
        s, _, _ = self.post(
            "/v1/audio/ai-check",
            {"audio_url": "https://example.com/song.mp3",
             "video_url": "https://example.com/x.mp4"},
            key=self.verifier_key)
        self.assertEqual(s, 400)


if __name__ == "__main__":
    unittest.main()
