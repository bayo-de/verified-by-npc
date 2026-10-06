"""Proofline-style contract suite for the Verification API v1.

Each contract pins one behavioral guarantee:
  - correct endpoint: the request reaches the intended handler
  - well-formed args: valid inputs produce the documented shape
  - fail-closed errors: invalid/unknown inputs never fabricate data
  - signature integrity: every response verifies against published keys

Contracts are declarative (name, request, assertions) so the dashboard and
plugin workstreams can reuse them as integration checks.
"""
import base64
import json
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from tests.helpers import ApiTestCase  # noqa: E402
from npc_verify.canonical import canonicalize, claim_hash_for_text  # noqa: E402
from npc_verify import ed25519  # noqa: E402


class Contract:
    def __init__(self, name, kind, run):
        self.name = name
        self.kind = kind  # endpoint | args | fail_closed | signature
        self.run = run


class TestContracts(ApiTestCase):
    def contracts(self):
        C = []

        def c(name, kind, run):
            C.append(Contract(name, kind, run))

        # -- correct endpoint ------------------------------------------------
        c("health answers without auth", "endpoint", lambda: self._eq(
            self.get("/v1/health")[0], 200))
        c("keys answers without auth", "endpoint", lambda: self._eq(
            self.get("/v1/keys")[0], 200))
        c("credential lookup routes by id", "endpoint", lambda: self._eq(
            self.get("/v1/credentials/cred_test_001",
                     key=self.verifier_key)[0], 200))
        c("product lookup routes by tag", "endpoint", lambda: self._eq(
            self.get("/v1/products/tag_test_authentic",
                     key=self.verifier_key)[0], 200))
        c("agent attestation routes by agent id", "endpoint", lambda: self._eq(
            self.get("/v1/agents/agent_test_scout/attestation",
                     key=self.verifier_key)[0], 200))

        # -- well-formed args -------------------------------------------------
        def claim_shape():
            s, h, d = self.post("/v1/claims/verify",
                                {"claim_text": "The test widget passes drop testing"},
                                key=self.verifier_key)
            body = self.check_signature(h, d)
            assert s == 200 and body["matched"] is True
            att = body["attestation"]
            for f in ("id", "verdict", "scope", "tested_at",
                      "findings_summary", "signature", "key_id",
                      "onchain_anchor"):
                assert f in att, f"missing {f}"
        c("claim verify returns documented shape", "args", claim_shape)

        def issuance_shape():
            s, h, d = self.post("/v1/attestations", {
                "subject_type": "product", "subject_id": "tag_contract_1",
                "verdict": "verified", "scope": {},
                "tested_at": "2026-10-05T00:00:00+00:00",
                "findings_summary": "Contract issuance."},
                key=self.issuer_key)
            body = self.check_signature(h, d)
            assert s == 201 and body["id"].startswith("att_")
            assert body["onchain_anchor"]["status"] == "not_anchored"
        c("attestation issuance returns documented shape", "args",
          issuance_shape)

        # -- fail-closed errors ------------------------------------------------
        def unknown_credential():
            s, h, d = self.get("/v1/credentials/does-not-exist",
                               key=self.verifier_key)
            body = self.check_signature(h, d)
            assert s == 404 and body == {"verdict": "unknown"}, body
        c("unknown credential -> 404 unknown, nothing fabricated",
          "fail_closed", unknown_credential)

        def unknown_product():
            s, h, d = self.get("/v1/products/tag-does-not-exist",
                               key=self.verifier_key)
            body = self.check_signature(h, d)
            assert s == 404 and body == {"verdict": "unknown"}, body
        c("unknown product tag -> 404 unknown, nothing fabricated",
          "fail_closed", unknown_product)

        def unknown_agent():
            s, h, d = self.get("/v1/agents/ghost/attestation",
                               key=self.verifier_key)
            body = self.check_signature(h, d)
            assert s == 404 and body == {"verdict": "unknown"}, body
        c("unknown agent -> 404 unknown, nothing fabricated",
          "fail_closed", unknown_agent)

        def unknown_claim():
            s, h, d = self.post("/v1/claims/verify",
                                {"claim_text": "a claim nobody attested"},
                                key=self.verifier_key)
            body = self.check_signature(h, d)
            assert s == 404 and body["verdict"] == "unknown"
            assert body["matched"] is False
        c("unmatched claim -> 404 unknown, matched=false",
          "fail_closed", unknown_claim)

        def verifier_cannot_issue():
            s, h, d = self.post("/v1/attestations", {
                "subject_type": "claim", "subject_id": "x",
                "verdict": "verified", "scope": {},
                "tested_at": "2026-10-05T00:00:00+00:00",
                "findings_summary": "nope"}, key=self.verifier_key)
            assert s == 403, s
        c("verifier role cannot issue attestations",
          "fail_closed", verifier_cannot_issue)

        def bad_json_never_500():
            for raw in (b"{", b"\xff\xfe", b"\"just a string\""):
                s, _, _ = self.post("/v1/claims/verify",
                                    key=self.verifier_key, raw_body=raw)
                assert s in (400, 422), (raw, s)
        c("malformed bodies -> 4xx, never 500", "fail_closed",
          bad_json_never_500)

        def no_pii_leak():
            s, h, d = self.get("/v1/credentials/cred_test_003",
                               key=self.verifier_key)
            body = self.check_signature(h, d)
            assert body["holder_name"] is None  # private holder stays hidden
        c("private holder name never leaks", "fail_closed", no_pii_leak)

        # -- signature integrity ----------------------------------------------
        def every_response_signed():
            probes = [
                ("GET", "/v1/health", None, None),
                ("GET", "/v1/keys", None, None),
                ("GET", "/v1/credentials/cred_test_001", None,
                 self.verifier_key),
                ("POST", "/v1/claims/verify",
                 {"claim_text": "x"}, self.verifier_key),
            ]
            for method, path, body, key in probes:
                s, h, d = self.request(method, path, body=body, key=key)
                self.check_signature(h, d)
        c("every response carries a valid signature", "signature",
          every_response_signed)

        def tampered_body_rejected():
            s, h, d = self.get("/v1/health")
            sig = base64.b64decode(h["X-NPC-Signature"])
            key_id = h["X-NPC-Key-ID"]
            s2, _, kd = self.get("/v1/keys")
            pub = base64.b64decode(
                json.loads(kd)["api_signing"]["current"]["public_key"])
            assert ed25519.verify(pub, d, sig)
            tampered = d.replace(b'"ok"', b'"pwned"')
            assert not ed25519.verify(pub, tampered, sig)
        c("tampered body fails signature check", "signature",
          tampered_body_rejected)

        def key_rotation_keeps_old_verifiable():
            kid_before = self.app.keys.active_key_id("api_signing")
            s, h, d = self.get("/v1/health")
            sig_before = h["X-NPC-Signature"]
            self.app.keys.rotate("api_signing")
            # old response still verifies via rotation history
            s2, _, kd = self.get("/v1/keys")
            keys_doc = json.loads(kd)
            pubs = {keys_doc["api_signing"]["current"]["key_id"]:
                    keys_doc["api_signing"]["current"]["public_key"]}
            for e in keys_doc["api_signing"]["history"]:
                pubs[e["key_id"]] = e["public_key"]
            pub = base64.b64decode(pubs[kid_before])
            assert ed25519.verify(pub, d, base64.b64decode(sig_before))
            # new responses use the new key
            s3, h3, d3 = self.get("/v1/health")
            assert h3["X-NPC-Key-ID"] != kid_before
            self.check_signature(h3, d3)
        c("rotation retires keys without breaking old signatures",
          "signature", key_rotation_keeps_old_verifiable)

        return C

    def _eq(self, a, b):
        assert a == b, f"{a} != {b}"

    def test_contracts(self):
        failures = []
        for contract in self.contracts():
            try:
                contract.run()
            except Exception as e:  # noqa: BLE001
                failures.append(f"[{contract.kind}] {contract.name}: {e!r}")
        self.assertEqual(failures, [],
                         "\n".join(["contract failures:"] + failures))


if __name__ == "__main__":
    unittest.main()
