"""Tests for POST /v1/images/ai-check and the Sightengine client.

No live calls and no credentials: the endpoint is tested with an
injected fake detector, and the real Sightengine client is tested
with an injected fake transport replaying the response shape the
Oct 13 trial recorded (status / type.ai_generated).
"""
import base64
import hashlib
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from tests.helpers import ApiTestCase  # noqa: E402
from npc_verify.detector import (DetectorError, DetectorNotConfigured,  # noqa: E402
                                 SightengineDetector, UnconfiguredDetector,
                                 detector_from_env)

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"npc-test-image" * 8
PNG_B64 = base64.b64encode(PNG_BYTES).decode()


class FakeDetector:
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


class TestAiCheckEndpoint(ApiTestCase):
    def setUp(self):
        self._saved_detector = self.app.detector
        self.fake = FakeDetector()
        self.app.detector = self.fake

    def tearDown(self):
        self.app.detector = self._saved_detector

    def test_bytes_success_signed(self):
        s, h, d = self.post("/v1/images/ai-check",
                            {"image_base64": PNG_B64},
                            key=self.verifier_key)
        self.assertEqual(s, 200)
        body = self.check_signature(h, d)
        self.assertEqual(body["check"], "ai_generation")
        self.assertEqual(body["provider"], "sightengine")
        self.assertEqual(body["model"], "genai")
        self.assertEqual(body["ai_generated_percent"], 99)
        self.assertIsInstance(body["ai_generated_percent"], int)
        self.assertEqual(body["source"], "bytes")
        self.assertEqual(body["image_sha256"],
                         hashlib.sha256(PNG_BYTES).hexdigest())
        self.assertIn("checked_at", body)
        self.assertEqual(self.fake.calls, [(PNG_BYTES, None)])

    def test_url_success_signed(self):
        self.fake.prob = 0.02
        s, h, d = self.post(
            "/v1/images/ai-check",
            {"image_url": "https://example.com/pic.jpg"},
            key=self.verifier_key)
        self.assertEqual(s, 200)
        body = self.check_signature(h, d)
        self.assertEqual(body["ai_generated_percent"], 2)
        self.assertEqual(body["source"], "url")
        self.assertIsNone(body["image_sha256"])
        self.assertEqual(self.fake.calls,
                         [(None, "https://example.com/pic.jpg")])

    def test_percent_rounding_and_clamp(self):
        for prob, want in ((0.5, 50), (0.995, 100), (0.0, 0), (1.0, 100)):
            self.fake.prob = prob
            s, h, d = self.post("/v1/images/ai-check",
                                {"image_base64": PNG_B64},
                                key=self.verifier_key)
            self.assertEqual(s, 200)
            body = self.check_signature(h, d)
            self.assertEqual(body["ai_generated_percent"], want)

    def test_no_auth_401(self):
        s, _, _ = self.post("/v1/images/ai-check",
                            {"image_base64": PNG_B64})
        self.assertEqual(s, 401)
        self.assertEqual(self.fake.calls, [])

    def test_both_fields_400(self):
        s, _, _ = self.post("/v1/images/ai-check",
                            {"image_base64": PNG_B64,
                             "image_url": "https://example.com/x.jpg"},
                            key=self.verifier_key)
        self.assertEqual(s, 400)

    def test_neither_field_400(self):
        s, _, _ = self.post("/v1/images/ai-check", {},
                            key=self.verifier_key)
        self.assertEqual(s, 400)

    def test_bad_base64_400(self):
        s, _, _ = self.post("/v1/images/ai-check",
                            {"image_base64": "!!!not-base64!!!"},
                            key=self.verifier_key)
        self.assertEqual(s, 400)

    def test_empty_image_400(self):
        s, _, _ = self.post("/v1/images/ai-check",
                            {"image_base64": ""},
                            key=self.verifier_key)
        self.assertEqual(s, 400)

    def test_oversized_image_400(self):
        big = base64.b64encode(b"x" * 750_001).decode()
        s, _, _ = self.post("/v1/images/ai-check",
                            {"image_base64": big},
                            key=self.verifier_key)
        self.assertEqual(s, 400)
        self.assertEqual(self.fake.calls, [])

    def test_bad_url_400(self):
        s, _, _ = self.post("/v1/images/ai-check",
                            {"image_url": "ftp://example.com/x.jpg"},
                            key=self.verifier_key)
        self.assertEqual(s, 400)

    def test_detector_error_503_signed(self):
        self.fake.error = DetectorError("upstream down")
        s, h, d = self.post("/v1/images/ai-check",
                            {"image_base64": PNG_B64},
                            key=self.verifier_key)
        self.assertEqual(s, 503)
        body = self.check_signature(h, d)
        self.assertEqual(body["error"], "detector_unavailable")
        self.assertNotIn("ai_generated_percent", body)

    def test_not_configured_503_signed(self):
        self.app.detector = UnconfiguredDetector()
        s, h, d = self.post("/v1/images/ai-check",
                            {"image_base64": PNG_B64},
                            key=self.verifier_key)
        self.assertEqual(s, 503)
        body = self.check_signature(h, d)
        self.assertEqual(body["error"], "detector_unavailable")


class TestSightengineClient(unittest.TestCase):
    def _detector(self, transport):
        return SightengineDetector("test-user", "test-secret",
                                   transport=transport)

    def test_success_url_mode_and_fields(self):
        seen = {}

        def transport(endpoint, fields, file_field, filename,
                      file_bytes, timeout):
            seen.update(fields)
            seen["file_bytes"] = file_bytes
            return 200, {"status": "success",
                         "type": {"ai_generated": 0.99}}

        det = self._detector(transport)
        prob = det.check_ai(image_url="https://example.com/a.jpg")
        self.assertEqual(prob, 0.99)
        self.assertEqual(seen["models"], "genai")
        self.assertEqual(seen["api_user"], "test-user")
        self.assertEqual(seen["url"], "https://example.com/a.jpg")
        self.assertIsNone(seen["file_bytes"])

    def test_success_bytes_mode(self):
        def transport(endpoint, fields, file_field, filename,
                      file_bytes, timeout):
            self.assertEqual(file_field, "media")
            self.assertEqual(file_bytes, PNG_BYTES)
            return 200, {"status": "success",
                         "type": {"ai_generated": 0.03}}

        det = self._detector(transport)
        self.assertEqual(det.check_ai(image_bytes=PNG_BYTES), 0.03)

    def test_failure_status_raises(self):
        def transport(*a):
            return 200, {"status": "failure",
                         "error": {"type": "usage_error"}}

        with self.assertRaises(DetectorError):
            self._detector(transport).check_ai(image_bytes=PNG_BYTES)

    def test_http_error_raises(self):
        def transport(*a):
            return 400, {"status": "failure"}

        with self.assertRaises(DetectorError):
            self._detector(transport).check_ai(image_bytes=PNG_BYTES)

    def test_missing_score_raises(self):
        def transport(*a):
            return 200, {"status": "success", "type": {}}

        with self.assertRaises(DetectorError):
            self._detector(transport).check_ai(image_bytes=PNG_BYTES)

    def test_out_of_range_score_raises(self):
        def transport(*a):
            return 200, {"status": "success",
                         "type": {"ai_generated": 1.5}}

        with self.assertRaises(DetectorError):
            self._detector(transport).check_ai(image_bytes=PNG_BYTES)

    def test_transport_failure_raises(self):
        def transport(*a):
            raise DetectorError("detection service could not be reached")

        with self.assertRaises(DetectorError):
            self._detector(transport).check_ai(image_bytes=PNG_BYTES)

    def test_from_env(self):
        self.assertFalse(detector_from_env({}).configured)
        self.assertFalse(
            detector_from_env({"SIGHTENGINE_API_USER": "u"}).configured)
        det = detector_from_env({"SIGHTENGINE_API_USER": "u",
                                 "SIGHTENGINE_API_SECRET": "s"})
        self.assertTrue(det.configured)
        self.assertIsInstance(det, SightengineDetector)

    def test_unconfigured_raises_not_configured(self):
        det = UnconfiguredDetector()
        with self.assertRaises(DetectorNotConfigured):
            det.check_ai(image_bytes=PNG_BYTES)


if __name__ == "__main__":
    unittest.main()
