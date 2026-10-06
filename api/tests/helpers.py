"""Shared fixtures: temp app + live loopback server for API tests."""
import base64
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify.server import create_app, Handler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify.canonical import canonicalize  # noqa: E402
from npc_verify import ed25519  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402


class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_verify_test_")
        cls.app = create_app(os.path.join(cls.tmp, "t.db"),
                             os.path.join(cls.tmp, "keys"))
        seeded = seed_all(cls.app.store, cls.app.keys)
        cls.verifier_key = seeded["verifier_key"]
        cls.issuer_key = seeded["issuer_key"]
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

    # -- helpers ---------------------------------------------------------
    def request(self, method, path, body=None, key=None, raw_body=None,
                headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = dict(headers or {})
        payload = None
        if raw_body is not None:
            payload = raw_body
        elif body is not None:
            payload = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        if key:
            hdrs["Authorization"] = f"Bearer {key}"
        conn.request(method, path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, dict(resp.getheaders()), data

    def get(self, path, key=None, headers=None):
        return self.request("GET", path, key=key, headers=headers)

    def post(self, path, body=None, key=None, raw_body=None):
        return self.request("POST", path, body=body, key=key,
                            raw_body=raw_body)

    def check_signature(self, headers, body_bytes):
        """Verify X-NPC-Signature against the published keys. Returns body."""
        sig_b64 = headers.get("X-NPC-Signature")
        key_id = headers.get("X-NPC-Key-ID")
        self.assertIsNotNone(sig_b64, "missing X-NPC-Signature")
        self.assertIsNotNone(key_id, "missing X-NPC-Key-ID")
        # fetch the public key from /v1/keys
        status, _, kdata = self.get("/v1/keys")
        self.assertEqual(status, 200)
        keys_doc = json.loads(kdata)
        pub = None
        cur = keys_doc["api_signing"]["current"]
        if cur and cur["key_id"] == key_id:
            pub = base64.b64decode(cur["public_key"])
        else:
            for h in keys_doc["api_signing"]["history"]:
                if h["key_id"] == key_id:
                    pub = base64.b64decode(h["public_key"])
        self.assertIsNotNone(pub, f"key {key_id} not published")
        sig = base64.b64decode(sig_b64)
        # body must be byte-identical to canonical form of parsed JSON
        parsed = json.loads(body_bytes)
        self.assertEqual(canonicalize(parsed), body_bytes,
                         "body is not canonical JSON")
        self.assertTrue(ed25519.verify(pub, body_bytes, sig),
                        "signature verification failed")
        return parsed
