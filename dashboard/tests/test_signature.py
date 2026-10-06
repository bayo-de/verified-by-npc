"""Signature verification integration: valid passes, tampered fails."""
import base64
import json
import os
import sys

try:
    from tests.helpers import DashTestCase
except ImportError:  # pragma: no cover - direct invocation
    from helpers import DashTestCase

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.normpath(os.path.join(BASE, "..", "api")))

from dashboard.client import ApiError, VerifiedClient  # noqa: E402
from npc_verify.canonical import canonicalize  # noqa: E402


class SignatureTest(DashTestCase):
    def _client(self):
        return VerifiedClient(base_url=self.api_url,
                              api_key=self.verifier_key, timeout=10)

    def test_valid_response_verifies(self):
        client = self._client()
        # keys() and health() are unauthenticated; both are verified.
        doc = client.keys()
        self.assertIn("api_signing", doc)
        health = client.health()
        self.assertEqual(health["status"], "ok")

    def test_tampered_body_rejected(self):
        client = self._client()
        status, headers, data = client._http("GET", "/v1/health")
        parsed = json.loads(data)
        parsed["status"] = "tampered"
        forged = canonicalize(parsed)
        with self.assertRaises(ApiError):
            client._verify_response(status, headers, forged)

    def test_swapped_signature_rejected(self):
        client = self._client()
        status, headers, data = client._http("GET", "/v1/health")
        bad = dict(headers)
        bad["X-NPC-Signature"] = base64.b64encode(b"\x00" * 64).decode()
        with self.assertRaises(ApiError):
            client._verify_response(status, bad, data)

    def test_missing_signature_headers_rejected(self):
        client = self._client()
        status, headers, data = client._http("GET", "/v1/health")
        bad = {k: v for k, v in headers.items()
               if k not in ("X-NPC-Signature", "X-NPC-Key-ID")}
        with self.assertRaises(ApiError):
            client._verify_response(status, bad, data)

    def test_unknown_key_id_rejected(self):
        client = self._client()
        status, headers, data = client._http("GET", "/v1/health")
        bad = dict(headers)
        bad["X-NPC-Key-ID"] = "npc-api_signing-20990101-deadbeef"
        with self.assertRaises(ApiError):
            client._verify_response(status, bad, data)

    def test_noncanonical_body_rejected(self):
        client = self._client()
        status, headers, data = client._http("GET", "/v1/health")
        # same JSON, non-canonical whitespace: must be refused
        pretty = json.dumps(json.loads(data), indent=2).encode()
        with self.assertRaises(ApiError):
            client._verify_response(status, headers, pretty)
