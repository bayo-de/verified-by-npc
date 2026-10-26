"""Federated identity linking tests (phase 1).

The linking service behind the registry's `identity_signals` block
(design: integrations/federated-identity-signals-DESIGN-2026-10-19.md).
These tests pin the phase 1 contract:

- SIWE wallet control: a server-issued nonce challenge, verified
  against the signature, the domain, the chain, and the expiry,
  fail closed on any mismatch, single use;
- GitHub and Google linking through NPC's own OAuth apps: the
  authorization URL carries the exact redirect URI and the minimum
  scopes, the callback consumes its state before the exchange, the
  attached signal's subject is the provider's opaque id, and no
  provider email ever lands in a record;
- with no OAuth app configured, the flow refuses with a clear
  not-configured 503, never a fake success;
- Coinbase Verifications: a valid public attestation for a proven
  wallet mints the kyc_backed_account link; a revoked, expired, or
  vanished attestation stops producing the signal on the panel;
- the panel endpoint serves the design's drafted labels and
  boundary line, with signals grouped by assurance class at their
  current observed state;
- everything stays behind NPC_IDENTITY_SIGNALS=1.

All external calls are fakes injected into the app. No test touches
the network.
"""
import base64
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

os.environ.setdefault("NPC_ALLOW_LOOPBACK_FETCH", "1")

from npc_verify import ethkeys, linking, pact, registry  # noqa: E402
from npc_verify.canonical import canonicalize  # noqa: E402
from npc_verify import ed25519  # noqa: E402
from npc_verify.server import Handler, create_app  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402

FLAG = registry.IDENTITY_SIGNALS_ENV
WALLET_KEY = 1
WALLET = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
OTHER_KEY = 2

ENV_KEYS = (FLAG, "NPC_GITHUB_CLIENT_ID", "NPC_GITHUB_CLIENT_SECRET",
            "NPC_GOOGLE_CLIENT_ID", "NPC_GOOGLE_CLIENT_SECRET",
            "NPC_PUBLIC_BASE_URL")


class FakeHttp:
    """Stands in for GitHub and Google. Records every call."""

    def __init__(self):
        self.calls = []
        self.google_aud = "test-google-client-id"

    def __call__(self, method, url, headers=None, form=None,
                 json_body=None, timeout=10):
        self.calls.append((method, url))
        if url == "https://github.com/login/oauth/access_token":
            assert form and form["code"], "missing oauth code"
            assert form["redirect_uri"] == \
                "https://api.npclabs.xyz/v1/link/github/callback"
            return 200, {"access_token": "gho_test_token"}, ""
        if url == "https://api.github.com/user":
            assert (headers or {}).get("Authorization") == \
                "Bearer gho_test_token"
            return 200, {"id": 88342117, "login": "octo-test",
                         "email": "octo@example.com"}, ""
        if url == "https://oauth2.googleapis.com/token":
            assert form and form["grant_type"] == \
                "authorization_code"
            assert form["redirect_uri"] == \
                "https://api.npclabs.xyz/v1/link/google/callback"
            return 200, {"access_token": "ya29.test",
                         "id_token": "fake-id-token"}, ""
        if url.startswith(
                "https://oauth2.googleapis.com/tokeninfo"):
            assert "id_token=fake-id-token" in url
            return 200, {
                "aud": self.google_aud,
                "iss": "https://accounts.google.com",
                "sub": "109887766554433221100",
                "exp": str(int(time.time()) + 3600),
                "email": "person@example.com",
                "email_verified": "true",
            }, ""
        raise AssertionError("unexpected external call: %s %s"
                             % (method, url))


class FakeCoinbaseReader:
    """Stands in for the EAS read path."""

    def __init__(self):
        self.attestations = []

    def schemas(self):
        return [("verified_account", "0x" + "5c" * 32)]

    def attestations_for(self, wallet):
        return list(self.attestations)


def valid_attestation(**overrides):
    att = {
        "signal": "verified_account",
        "uid": "0x" + "ab" * 32,
        "attester": "0x" + "00" * 20,
        "recipient": WALLET,
        "time": int(time.time()),
        "expiration_time": 0,
        "revoked": False,
        "data": "0x" + "00" * 31 + "01",
    }
    att.update(overrides)
    return att


class LinkTestCase(unittest.TestCase):
    """An app with the linking fakes injected, over real HTTP."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_link_test_")
        cls.fake_http = FakeHttp()
        cls.coinbase = FakeCoinbaseReader()
        cls.app = create_app(
            os.path.join(cls.tmp, "t.db"),
            os.path.join(cls.tmp, "keys"),
            link_http=cls.fake_http, coinbase_reader=cls.coinbase)
        seed_all(cls.app.store, cls.app.keys)
        Handler.app = cls.app
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.app.store.close()

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ENV_KEYS}
        os.environ[FLAG] = "1"
        os.environ["NPC_GITHUB_CLIENT_ID"] = "test-github-client-id"
        os.environ["NPC_GITHUB_CLIENT_SECRET"] = "test-gh-secret"
        os.environ["NPC_GOOGLE_CLIENT_ID"] = \
            "test-google-client-id"
        os.environ["NPC_GOOGLE_CLIENT_SECRET"] = "test-go-secret"
        os.environ["NPC_PUBLIC_BASE_URL"] = "https://api.npclabs.xyz"
        self.coinbase.attestations = []
        self.fake_http.google_aud = "test-google-client-id"

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # -- HTTP plumbing (mirrors tests/helpers.py) ---------------------
    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        payload = None
        headers = {}
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        out = (resp.status, dict(resp.getheaders()), data)
        conn.close()
        return out

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None):
        return self.request("POST", path, body=body)

    def check_signature(self, headers, body_bytes):
        sig_b64 = headers.get("X-NPC-Signature")
        key_id = headers.get("X-NPC-Key-ID")
        self.assertIsNotNone(sig_b64)
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
        parsed = json.loads(body_bytes)
        self.assertEqual(canonicalize(parsed), body_bytes)
        self.assertTrue(ed25519.verify(
            pub, body_bytes, base64.b64decode(sig_b64)))
        return parsed

    # -- domain helpers -------------------------------------------------
    _counter = [0]

    def fresh_email(self, tag):
        LinkTestCase._counter[0] += 1
        return "%s-%d@example.com" % (tag, LinkTestCase._counter[0])

    def register_agent(self, email, signals=None):
        body = {
            "agent_name": "Harbor Helper",
            "owner_name": "Test Owner",
            "owner_email": email,
            "homepage": "https://example.com/harbor-helper",
        }
        if signals is not None:
            body["identity_signals"] = signals
        status, _, data = self.post("/v1/register/agent", body=body)
        self.assertEqual(status, 201, data)
        return json.loads(data)

    def link_wallet(self, record_id, email):
        """Run one full SIWE link; returns the verify response."""
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/challenge"
            % record_id,
            body={"email": email, "wallet_address": WALLET})
        self.assertEqual(status, 201, data)
        challenge = json.loads(data)["challenge"]
        signature = "0x" + ethkeys.sign_personal(
            WALLET_KEY, challenge["message"].encode()).hex()
        status, headers, data = self.post(
            "/v1/records/%s/identity-links/siwe/verify" % record_id,
            body={"email": email,
                  "challenge_id": challenge["challenge_id"],
                  "message": challenge["message"],
                  "signature": signature})
        self.assertEqual(status, 201, data)
        return self.check_signature(headers, data)

    def panel(self, record_id):
        status, _, data = self.get(
            "/v1/records/%s/identity-panel" % record_id)
        self.assertEqual(status, 200, data)
        return json.loads(data)

    def panel_signals(self, panel, state="current"):
        out = []
        if state == "current":
            for group in panel["panel"]["groups"]:
                out.extend(group["signals"])
        else:
            out = panel["panel"]["not_current"]
        return out


class EthKeysTests(unittest.TestCase):

    def test_keccak_vectors(self):
        self.assertEqual(
            ethkeys.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad"
            "8045d85a470")
        self.assertEqual(
            ethkeys.keccak256(b"hello world").hex(),
            "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bb"
            "fa254cb01fad")

    def test_address_of_private_key_1(self):
        self.assertEqual(ethkeys.address_from_private_key(1), WALLET)

    def test_sign_and_recover(self):
        message = b"sign in with ethereum, test vector"
        sig = ethkeys.sign_personal(WALLET_KEY, message)
        self.assertEqual(
            ethkeys.verify_personal_signature(message, sig), WALLET)
        self.assertNotEqual(
            ethkeys.verify_personal_signature(b"tampered", sig),
            WALLET)
        self.assertIsNone(
            ethkeys.verify_personal_signature(message, b"\x00" * 10))

    def test_address_validation(self):
        self.assertTrue(ethkeys.is_valid_address(WALLET))
        self.assertTrue(ethkeys.is_valid_address(WALLET.lower()))
        self.assertFalse(ethkeys.is_valid_address(
            "0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf"))  # bad sum
        self.assertFalse(ethkeys.is_valid_address("0x1234"))


class SiweFlowTests(LinkTestCase):

    def test_challenge_verify_and_panel(self):
        email = self.fresh_email("siwe-ok")
        rec = self.register_agent(email)
        out = self.link_wallet(rec["record_id"], email)
        link = out["link"]
        self.assertTrue(pact.verify_record(self.app.keys, link))
        self.assertEqual(link["record_type"],
                         "npc.identity.signal_link")
        self.assertEqual(link["subject_record_id"], rec["record_id"])
        signal = link["signal"]
        self.assertEqual(signal["provider"], "siwe")
        self.assertEqual(signal["signal"], "wallet_control")
        self.assertEqual(signal["assurance_class"], "account_control")
        self.assertEqual(signal["subject_ref"], WALLET)
        # the registration itself is untouched, and its status too
        status, _, data = self.get("/v1/records/" + rec["record_id"])
        self.assertEqual(status, 200)
        got = json.loads(data)
        self.assertEqual(got["status"], "registered_checks_pending")
        self.assertNotIn("identity_signals", got)
        # the panel shows the link, labeled, inside the boundary
        panel = self.panel(rec["record_id"])
        self.assertEqual(panel["panel"]["heading"],
                         "Identity the owner has linked")
        self.assertEqual(
            panel["panel"]["boundary"],
            "Linked checks show what the services named confirmed "
            "about the owner. They are not an identity check by NPC, "
            "and they do not change what this record's status says.")
        signals = self.panel_signals(panel)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["state"], "current")
        self.assertEqual(signals[0]["label"],
                         linking.SIGNAL_LABELS[("siwe",
                                                "wallet_control")])
        group = panel["panel"]["groups"][0]
        self.assertEqual(group["assurance_class"], "account_control")
        self.assertEqual(group["heading"],
                         "Accounts the owner controls")

    def test_wrong_signer_fails_closed(self):
        email = self.fresh_email("siwe-wrong-key")
        rec = self.register_agent(email)
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/challenge"
            % rec["record_id"],
            body={"email": email, "wallet_address": WALLET})
        challenge = json.loads(data)["challenge"]
        signature = "0x" + ethkeys.sign_personal(
            OTHER_KEY, challenge["message"].encode()).hex()
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/verify"
            % rec["record_id"],
            body={"email": email,
                  "challenge_id": challenge["challenge_id"],
                  "message": challenge["message"],
                  "signature": signature})
        self.assertEqual(status, 422, data)
        self.assertEqual(self.panel_signals(self.panel(
            rec["record_id"])), [])

    def test_wrong_domain_fails_closed(self):
        email = self.fresh_email("siwe-domain")
        rec = self.register_agent(email)
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/challenge"
            % rec["record_id"],
            body={"email": email, "wallet_address": WALLET})
        challenge = json.loads(data)["challenge"]
        evil = linking.build_siwe_message(
            "evil.example", WALLET, "https://api.npclabs.xyz", 1,
            challenge["nonce"], "2026-10-19T00:00:00+00:00",
            challenge["expires_at"])
        signature = "0x" + ethkeys.sign_personal(
            WALLET_KEY, evil.encode()).hex()
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/verify"
            % rec["record_id"],
            body={"email": email,
                  "challenge_id": challenge["challenge_id"],
                  "message": evil, "signature": signature})
        self.assertEqual(status, 422, data)
        self.assertIn("domain", json.loads(data)["detail"])

    def test_expired_challenge_and_replay_fail_closed(self):
        email = self.fresh_email("siwe-expire")
        rec = self.register_agent(email)
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/challenge"
            % rec["record_id"],
            body={"email": email, "wallet_address": WALLET})
        challenge = json.loads(data)["challenge"]
        self.app.store._write(
            "UPDATE identity_link_challenges SET expires_at=?"
            " WHERE challenge_id=?",
            ("2020-01-01T00:00:00+00:00", challenge["challenge_id"]))
        signature = "0x" + ethkeys.sign_personal(
            WALLET_KEY, challenge["message"].encode()).hex()
        body = {"email": email,
                "challenge_id": challenge["challenge_id"],
                "message": challenge["message"],
                "signature": signature}
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/verify"
            % rec["record_id"], body=body)
        self.assertEqual(status, 422, data)
        # a fresh challenge completes once, and only once
        out = self.link_wallet(rec["record_id"], email)
        self.assertEqual(out["link"]["signal"]["provider"], "siwe")
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/challenge"
            % rec["record_id"],
            body={"email": email, "wallet_address": WALLET})
        challenge2 = json.loads(data)["challenge"]
        signature2 = "0x" + ethkeys.sign_personal(
            WALLET_KEY, challenge2["message"].encode()).hex()
        body2 = {"email": email,
                 "challenge_id": challenge2["challenge_id"],
                 "message": challenge2["message"],
                 "signature": signature2}
        status, _, _ = self.post(
            "/v1/records/%s/identity-links/siwe/verify"
            % rec["record_id"], body=body2)
        self.assertEqual(status, 201)
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/verify"
            % rec["record_id"], body=body2)
        self.assertEqual(status, 422, data)

    def test_ownership_gate_hides_everything(self):
        email = self.fresh_email("siwe-gate")
        rec = self.register_agent(email)
        for rid, em in ((rec["record_id"], "intruder@example.com"),
                        ("reg_0000000000000000", email)):
            status, _, data = self.post(
                "/v1/records/%s/identity-links/siwe/challenge" % rid,
                body={"email": em, "wallet_address": WALLET})
            self.assertEqual(status, 404, data)
            self.assertEqual(json.loads(data),
                             {"verdict": "unknown"})

    def test_bad_wallet_is_422(self):
        email = self.fresh_email("siwe-badwallet")
        rec = self.register_agent(email)
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/challenge"
            % rec["record_id"],
            body={"email": email, "wallet_address": "0x1234"})
        self.assertEqual(status, 422, data)

    def test_flag_off_fails_closed(self):
        os.environ.pop(FLAG, None)
        email = self.fresh_email("siwe-flagoff")
        rec = self.register_agent(email)  # plain record, no signals
        status, _, data = self.post(
            "/v1/records/%s/identity-links/siwe/challenge"
            % rec["record_id"],
            body={"email": email, "wallet_address": WALLET})
        self.assertEqual(status, 503, data)
        self.assertEqual(json.loads(data)["error"],
                         "identity_linking_not_enabled")
        status, _, data = self.get(
            "/v1/records/%s/identity-panel" % rec["record_id"])
        self.assertEqual(status, 503, data)


class OAuthFlowTests(LinkTestCase):

    def start(self, record_id, email, provider):
        status, _, data = self.post(
            "/v1/records/%s/identity-links/%s/start"
            % (record_id, provider),
            body={"email": email})
        self.assertEqual(status, 201, data)
        return json.loads(data)

    def test_github_flow(self):
        email = self.fresh_email("gh")
        rec = self.register_agent(email)
        out = self.start(rec["record_id"], email, "github")
        self.assertEqual(
            out["redirect_uri"],
            "https://api.npclabs.xyz/v1/link/github/callback")
        url = out["authorization_url"]
        self.assertTrue(url.startswith(
            "https://github.com/login/oauth/authorize?"))
        self.assertIn("client_id=test-github-client-id", url)
        self.assertIn("scope=read%3Auser", url)
        self.assertIn("redirect_uri=https%3A%2F%2Fapi.npclabs.xyz"
                      "%2Fv1%2Flink%2Fgithub%2Fcallback", url)
        status, headers, data = self.get(
            "/v1/link/github/callback?code=abc123&state="
            + out["state"])
        self.assertEqual(status, 200, data)
        body = self.check_signature(headers, data)
        self.assertTrue(body["linked"])
        self.assertEqual(body["signal"]["provider"], "github")
        self.assertEqual(body["signal"]["assurance_class"],
                         "account_control")
        self.assertEqual(body["signal"]["subject_ref"], "88342117")
        # the GitHub email and login never land in the record
        stored = self.app.store.get_identity_link(
            body["link_record_id"])
        self.assertTrue(pact.verify_record(self.app.keys, stored))
        blob = json.dumps(stored)
        self.assertNotIn("octo@example.com", blob)
        self.assertNotIn("octo-test", blob)
        # a replayed callback fails closed (the state was consumed)
        status, _, data = self.get(
            "/v1/link/github/callback?code=abc123&state="
            + out["state"])
        self.assertEqual(status, 422, data)
        # the panel carries the link
        signals = self.panel_signals(self.panel(rec["record_id"]))
        self.assertEqual([s["provider"] for s in signals],
                         ["github"])

    def test_google_flow(self):
        email = self.fresh_email("go")
        rec = self.register_agent(email)
        out = self.start(rec["record_id"], email, "google")
        self.assertEqual(
            out["redirect_uri"],
            "https://api.npclabs.xyz/v1/link/google/callback")
        url = out["authorization_url"]
        self.assertTrue(url.startswith(
            "https://accounts.google.com/o/oauth2/v2/auth?"))
        self.assertIn("scope=openid+email", url)
        self.assertIn("response_type=code", url)
        status, _, data = self.get(
            "/v1/link/google/callback?code=xyz&state="
            + out["state"])
        self.assertEqual(status, 200, data)
        body = json.loads(data)
        self.assertEqual(body["signal"]["provider"], "google")
        self.assertEqual(body["signal"]["subject_ref"],
                         "109887766554433221100")
        stored = self.app.store.get_identity_link(
            body["link_record_id"])
        self.assertNotIn("person@example.com",
                         json.dumps(stored))

    def test_google_wrong_audience_fails_closed(self):
        email = self.fresh_email("go-aud")
        rec = self.register_agent(email)
        out = self.start(rec["record_id"], email, "google")
        self.fake_http.google_aud = "someone-elses-client-id"
        status, _, data = self.get(
            "/v1/link/google/callback?code=xyz&state="
            + out["state"])
        self.assertEqual(status, 422, data)
        self.assertEqual(self.panel_signals(self.panel(
            rec["record_id"])), [])

    def test_unknown_state_fails_closed(self):
        status, _, data = self.get(
            "/v1/link/github/callback?code=abc&state=nope")
        self.assertEqual(status, 422, data)

    def test_not_configured_fails_closed(self):
        email = self.fresh_email("gh-noconfig")
        rec = self.register_agent(email)
        os.environ.pop("NPC_GITHUB_CLIENT_ID", None)
        os.environ.pop("NPC_GITHUB_CLIENT_SECRET", None)
        status, _, data = self.post(
            "/v1/records/%s/identity-links/github/start"
            % rec["record_id"], body={"email": email})
        self.assertEqual(status, 503, data)
        self.assertEqual(json.loads(data)["error"],
                         "identity_linking_not_configured")


class CoinbaseFlowTests(LinkTestCase):

    def refresh(self, record_id, email):
        status, _, data = self.post(
            "/v1/records/%s/identity-links/coinbase/refresh"
            % record_id, body={"email": email})
        self.assertEqual(status, 200, data)
        return json.loads(data)

    def test_valid_attestation_links_and_shows_current(self):
        email = self.fresh_email("cb-valid")
        rec = self.register_agent(email)
        self.link_wallet(rec["record_id"], email)
        self.coinbase.attestations = [valid_attestation()]
        out = self.refresh(rec["record_id"], email)
        obs = out["observations"][0]
        self.assertEqual(obs["state"], "valid")
        self.assertIsNotNone(obs["link_record_id"])
        link = self.app.store.get_identity_link(
            obs["link_record_id"])
        self.assertTrue(pact.verify_record(self.app.keys, link))
        self.assertEqual(link["signal"]["assurance_class"],
                         "kyc_backed_account")
        self.assertEqual(link["signal"]["evidence_ref"],
                         "0x" + "ab" * 32)
        panel = self.panel(rec["record_id"])
        signals = self.panel_signals(panel)
        coinbase = [s for s in signals
                    if s["provider"] == "coinbase"]
        self.assertEqual(len(coinbase), 1)
        self.assertEqual(coinbase[0]["state"], "current")
        self.assertEqual(
            coinbase[0]["label"],
            "Coinbase: this wallet belongs to a Coinbase customer "
            "whose identity Coinbase has checked.")
        groups = {g["assurance_class"]: g
                  for g in panel["panel"]["groups"]}
        self.assertEqual(groups["kyc_backed_account"]["heading"],
                         "Accounts backed by an identity check")
        self.assertIn("account_control", groups)

    def test_revoked_attestation_stops_the_signal(self):
        email = self.fresh_email("cb-revoked")
        rec = self.register_agent(email)
        self.link_wallet(rec["record_id"], email)
        self.coinbase.attestations = [valid_attestation()]
        self.refresh(rec["record_id"], email)
        self.assertEqual(len([s for s in self.panel_signals(
            self.panel(rec["record_id"]))
            if s["provider"] == "coinbase"]), 1)
        self.coinbase.attestations = [valid_attestation(
            revoked=True)]
        self.refresh(rec["record_id"], email)
        panel = self.panel(rec["record_id"])
        self.assertEqual([s for s in self.panel_signals(panel)
                          if s["provider"] == "coinbase"], [])
        gone = [s for s in self.panel_signals(panel, "not_current")
                if s["provider"] == "coinbase"]
        self.assertEqual(len(gone), 1)
        self.assertEqual(gone[0]["state"], "revoked")
        self.assertEqual(gone[0]["reason"],
                         "The service withdrew this confirmation.")
        # the link record itself is untouched (append-only history)
        links = self.app.store.list_identity_links(rec["record_id"])
        self.assertEqual(len([r for r in links
                              if r["signal"]["provider"]
                              == "coinbase"]), 1)

    def test_expired_attestation_stops_the_signal(self):
        email = self.fresh_email("cb-expired")
        rec = self.register_agent(email)
        self.link_wallet(rec["record_id"], email)
        self.coinbase.attestations = [valid_attestation(
            expiration_time=int(time.time()) - 3600)]
        out = self.refresh(rec["record_id"], email)
        self.assertEqual(out["observations"][0]["state"],
                         "expired")
        self.assertIsNone(out["observations"][0]
                          ["link_record_id"])

    def test_expiry_is_evaluated_at_read_time(self):
        email = self.fresh_email("cb-readexpiry")
        rec = self.register_agent(email)
        self.link_wallet(rec["record_id"], email)
        self.coinbase.attestations = [valid_attestation(
            expiration_time=int(time.time()) + 3600)]
        self.refresh(rec["record_id"], email)
        self.assertEqual(len([s for s in self.panel_signals(
            self.panel(rec["record_id"]))
            if s["provider"] == "coinbase"]), 1)
        # time passes: the stored expiry is now in the past, and the
        # panel drops the signal without any new refresh
        self.app.store._write(
            "UPDATE identity_observations SET expires_at=?"
            " WHERE subject_record_id=?",
            ("2020-01-01T00:00:00+00:00", rec["record_id"]))
        panel = self.panel(rec["record_id"])
        gone = [s for s in self.panel_signals(panel, "not_current")
                if s["provider"] == "coinbase"]
        self.assertEqual(len(gone), 1)
        self.assertEqual(gone[0]["state"], "expired")

    def test_carried_signal_drops_when_attestation_vanishes(self):
        email = self.fresh_email("cb-vanish")
        signals = [
            {"provider": "siwe", "signal": "wallet_control",
             "subject_ref": WALLET,
             "linked_at": "2026-10-17T20:15:00+00:00"},
            {"provider": "coinbase", "signal": "verified_account",
             "subject_ref": WALLET,
             "linked_at": "2026-10-17T20:15:00+00:00"},
        ]
        body = {
            "title": "A work with a carried coinbase link",
            "kind": "text",
            "locator": "sha256:" + "ef" * 32,
            "creator_name": "Test Maker",
            "creator_email": email,
            "identity_signals": signals,
        }
        status, _, data = self.post("/v1/register/content", body=body)
        self.assertEqual(status, 201, data)
        rec = json.loads(data)
        # before any observation the carried link stands as recorded
        panel = self.panel(rec["record_id"])
        carried = [s for s in self.panel_signals(panel)
                   if s["provider"] == "coinbase"]
        self.assertEqual(len(carried), 1)
        self.assertEqual(carried[0]["state"], "recorded")
        # the indexer now shows nothing for the wallet
        out = self.refresh(rec["record_id"], email)
        self.assertEqual(out["observations"][0]["state"],
                         "not_seen")
        panel = self.panel(rec["record_id"])
        gone = [s for s in self.panel_signals(panel, "not_current")
                if s["provider"] == "coinbase"]
        self.assertEqual(len(gone), 1)
        self.assertEqual(gone[0]["state"],
                         "not_seen_at_last_check")

    def test_refresh_without_proven_wallet_is_empty(self):
        email = self.fresh_email("cb-nowallet")
        rec = self.register_agent(email)
        out = self.refresh(rec["record_id"], email)
        self.assertEqual(out["observations"], [])


class PanelTests(LinkTestCase):

    def test_panel_empty_for_plain_record(self):
        email = self.fresh_email("panel-empty")
        rec = self.register_agent(email)
        panel = self.panel(rec["record_id"])
        self.assertEqual(panel["panel"]["groups"], [])
        self.assertEqual(panel["panel"]["not_current"], [])
        self.assertEqual(panel["panel"]["signals_current"], 0)
        self.assertEqual(panel["record_status"],
                         "registered_checks_pending")

    def test_panel_unknown_record_is_404(self):
        status, _, data = self.get(
            "/v1/records/reg_0000000000000000/identity-panel")
        self.assertEqual(status, 404, data)
        self.assertEqual(json.loads(data), {"verdict": "unknown"})

    def test_panel_groups_carried_signals_by_class(self):
        email = self.fresh_email("panel-groups")
        signals = [
            {"provider": "world_id", "signal": "proof_of_human",
             "subject_ref": "0x" + "12" * 20,
             "linked_at": "2026-10-19T15:04:05+00:00"},
            {"provider": "github", "signal": "account",
             "subject_ref": "88342117",
             "linked_at": "2026-10-18T09:30:00+00:00"},
            {"provider": "stripe_identity",
             "signal": "document_check",
             "subject_ref": "vs_1J2e3K4l5M6n7O8p",
             "linked_at": "2026-10-18T10:00:00+00:00"},
        ]
        body = {
            "title": "A work with several carried links",
            "kind": "text",
            "locator": "sha256:" + "ab" * 32,
            "creator_name": "Test Maker",
            "creator_email": email,
            "identity_signals": signals,
        }
        status, _, data = self.post("/v1/register/content", body=body)
        self.assertEqual(status, 201, data)
        rec = json.loads(data)
        panel = self.panel(rec["record_id"])
        classes = [g["assurance_class"]
                   for g in panel["panel"]["groups"]]
        self.assertEqual(classes, ["account_control",
                                   "unique_human", "document_check"])
        world = [s for g in panel["panel"]["groups"]
                 for s in g["signals"]
                 if s["provider"] == "world_id"][0]
        self.assertEqual(
            world["label"],
            "World ID: the owner proved they are one unique "
            "person. This proof does not include a name.")
        self.assertEqual(panel["panel"]["signals_current"], 3)


if __name__ == "__main__":
    unittest.main()
