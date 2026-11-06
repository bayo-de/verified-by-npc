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

# Test-harness path for the intake-fetch SSRF guard (audit D3): the
# registration fixtures serve content over loopback, so the harness
# opts in to loopback fetches. Production never sets this; the guard
# still refuses private/link-local ranges and all redirect hops.
os.environ.setdefault("NPC_ALLOW_LOOPBACK_FETCH", "1")

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


# -- Gate G1 test support: a software passkey --------------------------------
#
# A minimal WebAuthn authenticator that speaks just enough of the
# protocol to drive the account ceremonies in tests: it builds real
# attestation objects and real assertions, signed with keys the
# verifier accepts (Ed25519 by default, ES256 for one test), using
# the package's own primitives the same way npc_verify.webauthn
# verifies them.

import hashlib as _hashlib  # noqa: E402

from npc_verify import ed25519 as _ed25519  # noqa: E402
from npc_verify.c2pa import _cbor_encode as _cbor_enc  # noqa: E402
from npc_verify.webauthn import b64url_encode as _b64e  # noqa: E402


class SoftAuthenticator:
    def __init__(self, rp_id, origin, alg=-8):
        self.rp_id = rp_id
        self.origin = origin
        self.alg = alg
        self.credential_id = os.urandom(16)
        self.sign_count = 0
        if alg == -8:
            self._seed = os.urandom(32)
            self._cose_key = {1: 1, 3: -8, -1: 6,
                              -2: _ed25519.publickey(self._seed)}
        elif alg == -7:
            from npc_verify import cose as _cose
            self._cose = _cose
            params = _cose._curve_params("P-256")
            self._n = params[5]
            self._priv = int.from_bytes(os.urandom(32), "big") % self._n
            x, y = _cose._ec_mul(params, self._priv,
                                 (params[3], params[4]))
            self._cose_key = {
                1: 2, 3: -7, -1: 1,
                -2: x.to_bytes(32, "big"), -3: y.to_bytes(32, "big")}
        else:
            raise ValueError("unsupported test alg %r" % (alg,))

    def _sign(self, message):
        if self.alg == -8:
            return _ed25519.sign(self._seed, message)
        cose = self._cose
        params = cose._curve_params("P-256")
        z = int.from_bytes(_hashlib.sha256(message).digest(), "big")
        while True:
            k = int.from_bytes(os.urandom(32), "big") % self._n
            if not k:
                continue
            point = cose._ec_mul(params, k, (params[3], params[4]))
            r = point[0] % self._n
            if not r:
                continue
            s = (cose._inv(k, self._n)
                 * (z + r * self._priv)) % self._n
            if s:
                return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def _client_data(self, ceremony, challenge_b64):
        return json.dumps({
            "type": ceremony, "challenge": challenge_b64,
            "origin": self.origin, "crossOrigin": False,
        }, separators=(",", ":")).encode()

    def _auth_data(self, flags, attested=None):
        out = _hashlib.sha256(self.rp_id.encode()).digest()
        out += bytes([flags])
        out += self.sign_count.to_bytes(4, "big")
        if attested is not None:
            out += b"\x00" * 16
            out += len(self.credential_id).to_bytes(2, "big")
            out += self.credential_id
            out += _cbor_enc(self._cose_key)
        return out

    def create(self, options, fmt="none"):
        """Answer a registration ceremony. Returns the payload the
        sign-in page would POST to register/finish."""
        client_data = self._client_data("webauthn.create",
                                        options["challenge"])
        auth_data = self._auth_data(0x01 | 0x04 | 0x40, attested=True)
        att_stmt = {}
        if fmt == "packed":
            signed = auth_data + _hashlib.sha256(client_data).digest()
            att_stmt = {"alg": self.alg, "sig": self._sign(signed)}
        att_obj = _cbor_enc({"fmt": fmt, "attStmt": att_stmt,
                             "authData": auth_data})
        return {
            "id": _b64e(self.credential_id),
            "rawId": _b64e(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64e(client_data),
                "attestationObject": _b64e(att_obj),
            },
        }

    def get(self, options, count=None):
        """Answer an authentication ceremony."""
        if count is None:
            self.sign_count += 1
        else:
            self.sign_count = count
        client_data = self._client_data("webauthn.get",
                                        options["challenge"])
        auth_data = self._auth_data(0x01 | 0x04)
        signed = auth_data + _hashlib.sha256(client_data).digest()
        return {
            "id": _b64e(self.credential_id),
            "rawId": _b64e(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64e(client_data),
                "authenticatorData": _b64e(auth_data),
                "signature": _b64e(self._sign(signed)),
            },
        }
