"""End-to-end API tests over loopback HTTP: all 7 endpoints.

Every response is signature-checked client-side against the published keys,
and every body is asserted byte-identical to its canonical form.
"""
import base64
import json
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from tests.helpers import ApiTestCase  # noqa: E402


class TestHealthAndKeys(ApiTestCase):
    def test_health_no_auth(self):
        status, headers, data = self.get("/v1/health")
        self.assertEqual(status, 200)
        body = self.check_signature(headers, data)
        self.assertEqual(body["status"], "ok")
        self.assertIn("key_id", body)
        self.assertEqual(body["chain"]["mode"], "local-first")

    def test_keys_no_auth(self):
        status, headers, data = self.get("/v1/keys")
        self.assertEqual(status, 200)
        body = self.check_signature(headers, data)
        cur = body["api_signing"]["current"]
        self.assertIsNotNone(cur)
        self.assertEqual(cur["algorithm"], "Ed25519")
        self.assertTrue(len(body["issuers"]) >= 1)


class TestCredentials(ApiTestCase):
    def test_valid_credential(self):
        s, h, d = self.get("/v1/credentials/cred_test_001",
                           key=self.verifier_key)
        self.assertEqual(s, 200)
        body = self.check_signature(h, d)
        self.assertEqual(body["status"], "valid")
        self.assertEqual(body["holder_name"], "Test Holder")

    def test_revoked_credential(self):
        s, h, d = self.get("/v1/credentials/cred_test_002",
                           key=self.verifier_key)
        body = self.check_signature(h, d)
        self.assertEqual(body["status"], "revoked")

    def test_private_holder_hidden(self):
        s, h, d = self.get("/v1/credentials/cred_test_003",
                           key=self.verifier_key)
        body = self.check_signature(h, d)
        self.assertEqual(body["status"], "expired")
        self.assertIsNone(body["holder_name"])

    def test_unknown_credential_fail_closed(self):
        s, h, d = self.get("/v1/credentials/cred_nope",
                           key=self.verifier_key)
        self.assertEqual(s, 404)
        body = self.check_signature(h, d)
        self.assertEqual(body, {"verdict": "unknown"})

    def test_no_auth_401(self):
        s, h, d = self.get("/v1/credentials/cred_test_001")
        self.assertEqual(s, 401)

    def test_bad_key_401(self):
        s, h, d = self.get("/v1/credentials/cred_test_001",
                           key="npc_test_wrong")
        self.assertEqual(s, 401)


class TestClaims(ApiTestCase):
    def test_verify_by_text(self):
        s, h, d = self.post("/v1/claims/verify",
                            {"claim_text": "The test widget passes drop testing"},
                            key=self.verifier_key)
        self.assertEqual(s, 200)
        body = self.check_signature(h, d)
        self.assertTrue(body["matched"])
        self.assertEqual(body["attestation"]["verdict"], "verified")
        self.assertIn("findings_summary", body["attestation"])
        self.assertNotIn("methodology", json.dumps(body).lower())

    def test_verify_case_insensitive(self):
        s, h, d = self.post("/v1/claims/verify",
                            {"claim_text": "  THE TEST widget PASSES drop TESTING "},
                            key=self.verifier_key)
        body = self.check_signature(h, d)
        self.assertTrue(body["matched"])

    def test_verify_by_hash(self):
        from npc_verify.canonical import claim_hash_for_text
        ch = claim_hash_for_text("Test Farms honey is single-origin")
        s, h, d = self.post("/v1/claims/verify", {"claim_hash": ch},
                            key=self.verifier_key)
        body = self.check_signature(h, d)
        self.assertTrue(body["matched"])
        self.assertEqual(body["attestation"]["verdict"],
                         "verified_with_caveats")

    def test_unmatched_claim_fail_closed(self):
        s, h, d = self.post("/v1/claims/verify",
                            {"claim_text": "the moon is made of cheese"},
                            key=self.verifier_key)
        self.assertEqual(s, 404)
        body = self.check_signature(h, d)
        self.assertEqual(body["verdict"], "unknown")
        self.assertFalse(body["matched"])

    def test_missing_input_400(self):
        s, h, d = self.post("/v1/claims/verify", {},
                            key=self.verifier_key)
        self.assertEqual(s, 400)

    def test_bad_hash_400(self):
        s, h, d = self.post("/v1/claims/verify", {"claim_hash": "zzz"},
                            key=self.verifier_key)
        self.assertEqual(s, 400)

    def test_invalid_json_400(self):
        s, h, d = self.post("/v1/claims/verify", key=self.verifier_key,
                            raw_body=b"{not json")
        self.assertEqual(s, 400)


class TestProducts(ApiTestCase):
    def test_authentic(self):
        s, h, d = self.get("/v1/products/tag_test_authentic",
                           key=self.verifier_key)
        body = self.check_signature(h, d)
        self.assertEqual(body["status"], "authentic")
        self.assertEqual(body["verdict"], "verified")
        self.assertTrue(len(body["provenance"]) >= 1)

    def test_counterfeit(self):
        s, h, d = self.get("/v1/products/tag_test_counterfeit",
                           key=self.verifier_key)
        body = self.check_signature(h, d)
        self.assertEqual(body["status"], "counterfeit")
        self.assertEqual(body["verdict"], "not_verified")

    def test_unknown_tag_fail_closed(self):
        s, h, d = self.get("/v1/products/tag_nope", key=self.verifier_key)
        self.assertEqual(s, 404)
        body = self.check_signature(h, d)
        self.assertEqual(body, {"verdict": "unknown"})


class TestAgents(ApiTestCase):
    def test_verified_agent(self):
        s, h, d = self.get("/v1/agents/agent_test_scout/attestation",
                           key=self.verifier_key)
        body = self.check_signature(h, d)
        self.assertEqual(body["verdict"], "verified")
        self.assertEqual(body["valid_until"], "2027-09-20T12:00:00+00:00")
        self.assertIn("onchain_anchor", body)

    def test_caveats_agent(self):
        s, h, d = self.get("/v1/agents/agent_test_herald/attestation",
                           key=self.verifier_key)
        body = self.check_signature(h, d)
        self.assertEqual(body["verdict"], "verified_with_caveats")

    def test_unknown_agent_fail_closed(self):
        s, h, d = self.get("/v1/agents/agent_nope/attestation",
                           key=self.verifier_key)
        self.assertEqual(s, 404)
        body = self.check_signature(h, d)
        self.assertEqual(body, {"verdict": "unknown"})


class TestAttestationIssuance(ApiTestCase):
    def _payload(self):
        return {
            "subject_type": "claim",
            "subject_id": "claim:e2e-1",
            "verdict": "verified",
            "scope": {"domain": "e2e"},
            "tested_at": "2026-10-05T00:00:00+00:00",
            "findings_summary": "End-to-end issuance test.",
        }

    def test_issuer_can_record(self):
        s, h, d = self.post("/v1/attestations", self._payload(),
                            key=self.issuer_key)
        self.assertEqual(s, 201)
        body = self.check_signature(h, d)
        self.assertTrue(body["id"].startswith("att_"))
        self.assertIn("signature", body)
        anchor = body["onchain_anchor"]
        self.assertEqual(anchor["status"], "not_anchored")
        self.assertIsNone(anchor["tx"])
        self.assertRegex(anchor["hash"], r"^[0-9a-f]{64}$")

    def test_verifier_cannot_issue_403(self):
        s, h, d = self.post("/v1/attestations", self._payload(),
                            key=self.verifier_key)
        self.assertEqual(s, 403)

    def test_no_auth_401(self):
        s, h, d = self.post("/v1/attestations", self._payload())
        self.assertEqual(s, 401)

    def test_invalid_attestation_422(self):
        bad = self._payload()
        bad["verdict"] = "maybe"
        s, h, d = self.post("/v1/attestations", bad, key=self.issuer_key)
        self.assertEqual(s, 422)
        body = self.check_signature(h, d)
        self.assertEqual(body["error"], "unprocessable")

    def test_missing_fields_422(self):
        s, h, d = self.post("/v1/attestations", {"subject_type": "claim"},
                            key=self.issuer_key)
        self.assertEqual(s, 422)

    def test_issued_attestation_verifiable(self):
        s, h, d = self.post("/v1/attestations", self._payload(),
                            key=self.issuer_key)
        body = self.check_signature(h, d)
        # the NPC issuer signature on the attestation verifies against /v1/keys
        s2, _, kd = self.get("/v1/keys")
        keys_doc = json.loads(kd)
        issuers = {k["key_id"]: base64.b64decode(k["public_key"])
                   for k in keys_doc["issuers"]}
        pub = issuers[body["key_id"]]
        from npc_verify.canonical import canonicalize
        from npc_verify import ed25519
        core = {
            "id": body["id"],
            "subject_type": "claim",
            "subject_id": "claim:e2e-1",
            "verdict": "verified",
            "scope": {"domain": "e2e"},
            "tested_at": "2026-10-05T00:00:00+00:00",
            "findings_summary": "End-to-end issuance test.",
        }
        sig = base64.b64decode(body["signature"])
        self.assertTrue(ed25519.verify(pub, canonicalize(core), sig))


class TestMisc(ApiTestCase):
    def test_unknown_route_404(self):
        s, h, d = self.get("/v1/nope", key=self.verifier_key)
        self.assertEqual(s, 404)

    def test_rate_limit_429_shape(self):
        # shrink a key's limit to 1/min via a fresh key
        from npc_verify.auth import Auth
        auth = Auth(self.app.store)
        tiny = auth.create_key("tiny", "verifier", per_minute=1)
        s, _, _ = self.get("/v1/credentials/cred_test_001", key=tiny)
        self.assertEqual(s, 200)
        s, h, d = self.get("/v1/credentials/cred_test_001", key=tiny)
        self.assertEqual(s, 429)
        body = self.check_signature(h, d)
        self.assertEqual(body["error"], "rate_limited")
        self.assertIn("retry_after_seconds", body)


if __name__ == "__main__":
    unittest.main()
