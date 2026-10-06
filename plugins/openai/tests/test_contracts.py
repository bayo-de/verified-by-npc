"""Proofline-style contracts for the OpenAI plugin helper.

Contracts per tool: correct endpoint routing, well-formed argument
validation, fail-closed error shapes, and no fabricated verdicts.
Everything runs against the live in-process API fixture (fictional data).
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import OpenAITestCase  # noqa: E402
from npc_verify_openai.client import (  # noqa: E402
    run_operation, verify_product, verify_credential, verify_claim,
    verify_agent, explain_verification, OPERATIONS, EXPLAINER)


class TestOperationContracts(OpenAITestCase):
    def test_five_operations_exposed(self):
        self.assertEqual(sorted(OPERATIONS),
                         ["explain_verification", "verify_agent",
                          "verify_claim", "verify_credential",
                          "verify_product"])

    def test_unknown_operation_rejected(self):
        with self.assertRaises(KeyError):
            run_operation(self.client, "mint_money", {})

    def test_verify_product_authentic(self):
        is_err, text = verify_product(self.client, "tag_test_authentic")
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertEqual(body["status"], "authentic")

    def test_verify_product_counterfeit(self):
        is_err, text = verify_product(self.client, "tag_test_counterfeit")
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertEqual(body["status"], "counterfeit")

    def test_verify_credential_valid(self):
        is_err, text = verify_credential(self.client, "cred_test_001")
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertEqual(body["status"], "valid")

    def test_verify_credential_revoked(self):
        is_err, text = verify_credential(self.client, "cred_test_002")
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertEqual(body["status"], "revoked")

    def test_verify_claim_matched(self):
        is_err, text = verify_claim(
            self.client, claim_text="The test widget passes drop testing")
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertTrue(body["matched"])
        self.assertEqual(body["attestation"]["verdict"], "verified")

    def test_verify_claim_by_hash(self):
        from npc_verify.canonical import claim_hash_for_text
        h = claim_hash_for_text("Test Farms honey is single-origin")
        is_err, text = verify_claim(self.client, claim_hash=h)
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertTrue(body["matched"])
        self.assertEqual(body["attestation"]["verdict"],
                         "verified_with_caveats")

    def test_verify_agent(self):
        is_err, text = verify_agent(self.client, "agent_test_scout")
        self.assertFalse(is_err)
        body = json.loads(text)
        self.assertEqual(body["verdict"], "verified")

    def test_no_fabricated_verdicts(self):
        # unknown inputs must surface exactly "unknown", and the envelope
        # must not invent a positive status or verdict.
        for op, args in [
                ("verify_claim",
                 {"claim_text": "nothing like this was ever attested"}),
                ("verify_credential", {"credential_id": "cred_nope"}),
                ("verify_product", {"tag_id": "tag_nope"}),
                ("verify_agent", {"agent_id": "agent_nope"})]:
            is_err, text = run_operation(self.client, op, args)
            self.assertFalse(is_err, f"{op} marked unknown as an error")
            body = json.loads(text)
            self.assertEqual(body["verdict"], "unknown")
            self.assertNotIn("valid", text)
            self.assertNotIn("authentic", text)
            self.assertNotIn("verified", text.replace('"verdict": "unknown"',
                                                      ""))

    def test_missing_args_fail_closed_not_fabricated(self):
        # empty args are rejected with guidance, never with a verdict.
        for op, args in [
                ("verify_claim", {}),
                ("verify_credential", {"credential_id": ""}),
                ("verify_product", {"tag_id": ""}),
                ("verify_agent", {"agent_id": ""})]:
            is_err, text = run_operation(self.client, op, args)
            self.assertTrue(is_err)
            self.assertNotIn('"verdict"', text)

    def test_explain_verification_is_static(self):
        text = explain_verification()
        self.assertEqual(text, EXPLAINER)
        self.assertIn("unknown", text.lower())
        # the why, never the how
        self.assertNotIn("Ed25519", text)

    def test_run_operation_matches_convenience_helpers(self):
        a = run_operation(self.client, "verify_agent",
                          {"agent_id": "agent_test_herald"})
        b = verify_agent(self.client, "agent_test_herald")
        self.assertEqual(a, b)
        self.assertEqual(json.loads(a[1])["verdict"],
                         "verified_with_caveats")


class TestExplainerCopy(unittest.TestCase):
    def test_no_em_dashes(self):
        self.assertNotIn("—", EXPLAINER)

    def test_explainer_names_unknown_not_false(self):
        self.assertIn("not a claim", EXPLAINER)
