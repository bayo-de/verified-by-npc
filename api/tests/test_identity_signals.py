"""Federated identity signal tests (the `identity_signals` block).

A registration (content or agent) may carry `identity_signals`: the
outside identity checks the owner linked (World ID, Google, GitHub,
a Coinbase attestation, a hosted document check). The design lives
in integrations/federated-identity-signals-DESIGN-2026-10-19.md.
These tests pin the contract:

- the block is flag-gated (NPC_IDENTITY_SIGNALS=1): a deployment
  that has not enabled it refuses the block with 422 rather than
  signing claims it cannot stand behind;
- with the flag on, valid signals are normalized (known fields
  only, assurance class derived server-side, canonical order) and
  signed into the record, which still verifies offline;
- signals change nothing else: the status stays "registered,
  checks pending", there is no verdict, and the verification
  decision stays in checks_not_run;
- a record without the block has no `identity_signals` key at all,
  exactly the records this API has always minted;
- malformed blocks fail validation with 422.
"""
import json
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import pact, registry  # noqa: E402
from tests.helpers import ApiTestCase  # noqa: E402

ENV = registry.IDENTITY_SIGNALS_ENV

WORLD_SIGNAL = {
    "provider": "world_id",
    "signal": "proof_of_human",
    "subject_ref": "0x9f2c1ab47d3e5f8091a2b3c4d5e6f708192a3b4c",
    "linked_at": "2026-10-19T15:04:05+00:00",
}

GITHUB_SIGNAL = {
    "provider": "github",
    "signal": "account",
    "subject_ref": "88342117",
    "linked_at": "2026-10-18T09:30:00+00:00",
    "observed_at": "2026-10-19T15:04:05+00:00",
}

COINBASE_SIGNAL = {
    "provider": "coinbase",
    "signal": "verified_account",
    "subject_ref": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
    "linked_at": "2026-10-17T20:15:00+00:00",
    "evidence_ref": "0x9ab5c1d2e3f4051627384950a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4",
}


def _checks(rec, name, bucket="checks_run"):
    return [c for c in rec[bucket] if c["check"] == name]


class IdentitySignalsFlagMixin:
    """Turn the flag on for a test, restore the environment after."""

    def setUp(self):
        self._saved = os.environ.get(ENV)
        os.environ[ENV] = "1"

    def tearDown(self):
        if self._saved is None:
            os.environ.pop(ENV, None)
        else:
            os.environ[ENV] = self._saved


class ContentIdentitySignalTests(IdentitySignalsFlagMixin, ApiTestCase):

    def register_with_signals(self, signals, email, kind="text"):
        body = {
            "title": "A registration with linked identity",
            "kind": kind,
            "locator": "sha256:" + "cd" * 32,
            "creator_name": "Test Maker",
            "creator_email": email,
            "identity_signals": signals,
        }
        return self.post("/v1/register/content", body=body)

    def test_signals_are_signed_normalized_and_change_no_status(self):
        signals = [dict(GITHUB_SIGNAL, unexpected="must not survive"),
                   dict(WORLD_SIGNAL, assurance_class="document_check"),
                   dict(COINBASE_SIGNAL)]
        status, headers, data = self.register_with_signals(
            signals, "signals-ok@example.com")
        self.assertEqual(status, 201)
        rec = self.check_signature(headers, data)
        self.assertTrue(pact.verify_record(self.app.keys, rec))
        # status and the pending decision are untouched by signals
        self.assertEqual(rec["status"], "registered_checks_pending")
        self.assertNotIn("verdict", rec)
        self.assertIn("verification_decision",
                      {c["check"] for c in rec["checks_not_run"]})
        kept = rec["identity_signals"]
        self.assertEqual(len(kept), 3)
        # canonical order: provider, then signal
        self.assertEqual([s["provider"] for s in kept],
                         ["coinbase", "github", "world_id"])
        by_provider = {s["provider"]: s for s in kept}
        # unknown fields are stripped
        self.assertNotIn("unexpected", by_provider["github"])
        # the assurance class is derived, never caller-supplied: the
        # caller tried to upgrade World ID to document_check and the
        # record still carries the derived unique_human
        self.assertEqual(by_provider["world_id"]["assurance_class"],
                         "unique_human")
        self.assertEqual(by_provider["github"]["assurance_class"],
                         "account_control")
        self.assertEqual(by_provider["coinbase"]["assurance_class"],
                         "kyc_backed_account")
        self.assertEqual(by_provider["coinbase"]["evidence_ref"],
                         COINBASE_SIGNAL["evidence_ref"])
        # exactly one honest checks entry rides along
        entries = _checks(rec, "identity_signals")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "recorded")
        self.assertEqual(entries[0]["signals"], 3)
        self.assertIn("not an identity check by NPC",
                      entries[0]["detail"])

    def test_record_without_signals_has_no_signals_key(self):
        body = {
            "title": "A plain registration",
            "kind": "text",
            "locator": "sha256:" + "ab" * 32,
            "creator_name": "Test Maker",
            "creator_email": "plain-signals@example.com",
        }
        status, _, data = self.post("/v1/register/content", body=body)
        self.assertEqual(status, 201)
        rec = json.loads(data)
        self.assertNotIn("identity_signals", rec)
        self.assertEqual(_checks(rec, "identity_signals"), [])
        self.assertTrue(pact.verify_record(self.app.keys, rec))

    def test_signals_record_resolves_by_id(self):
        status, _, data = self.register_with_signals(
            [dict(WORLD_SIGNAL)], "signals-resolve@example.com")
        self.assertEqual(status, 201)
        rec = json.loads(data)
        status, _, data = self.get("/v1/records/" + rec["record_id"])
        self.assertEqual(status, 200)
        got = json.loads(data)
        self.assertEqual(got["identity_signals"][0]["provider"],
                         "world_id")

    def test_invalid_signal_blocks_are_422(self):
        bad_blocks = [
            "not-a-list",
            [],
            [dict(WORLD_SIGNAL) for _ in range(9)],
            ["not-an-object"],
            [dict(WORLD_SIGNAL, provider="myspace")],
            [dict(WORLD_SIGNAL, signal="account")],
            [dict(GITHUB_SIGNAL, signal="proof_of_human")],
            [{k: v for k, v in WORLD_SIGNAL.items()
              if k != "subject_ref"}],
            [dict(WORLD_SIGNAL, subject_ref="owner@example.com")],
            [dict(WORLD_SIGNAL, subject_ref="has spaces in it")],
            [{k: v for k, v in WORLD_SIGNAL.items()
              if k != "linked_at"}],
            [dict(WORLD_SIGNAL, linked_at="last Tuesday")],
            [dict(WORLD_SIGNAL, observed_at="2026-13-40T99:99:99Z")],
            [dict(WORLD_SIGNAL, evidence_ref="has spaces")],
            [dict(WORLD_SIGNAL), dict(WORLD_SIGNAL)],
        ]
        for i, block in enumerate(bad_blocks):
            status, _, data = self.register_with_signals(
                block, "bad-signals-%d@example.com" % i)
            self.assertEqual(status, 422, data)


class AgentIdentitySignalTests(IdentitySignalsFlagMixin, ApiTestCase):

    def register_agent(self, signals, email):
        body = {
            "agent_name": "Harbor Helper",
            "owner_name": "Test Owner",
            "owner_email": email,
            "homepage": "https://example.com/harbor-helper",
            "identity_signals": signals,
        }
        return self.post("/v1/register/agent", body=body)

    def test_agent_record_carries_signals(self):
        status, headers, data = self.register_agent(
            [dict(WORLD_SIGNAL)], "agent-signals@example.com")
        self.assertEqual(status, 201)
        rec = self.check_signature(headers, data)
        self.assertTrue(pact.verify_record(self.app.keys, rec))
        self.assertEqual(rec["kind"], "agent")
        self.assertEqual(rec["status_label"],
                         "registered, checks pending")
        kept = rec["identity_signals"]
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["assurance_class"], "unique_human")
        entries = _checks(rec, "identity_signals")
        self.assertEqual(len(entries), 1)
        self.assertIn("verification_decision",
                      {c["check"] for c in rec["checks_not_run"]})

    def test_agent_invalid_signals_are_422(self):
        status, _, data = self.register_agent(
            [dict(WORLD_SIGNAL, provider="myspace")],
            "agent-bad-signals@example.com")
        self.assertEqual(status, 422, data)


class IdentitySignalsFlagOffTests(ApiTestCase):
    """No mixin: the flag stays unset, as in production today."""

    def setUp(self):
        self._saved = os.environ.pop(ENV, None)

    def tearDown(self):
        if self._saved is not None:
            os.environ[ENV] = self._saved

    def test_content_signals_refused_when_flag_off(self):
        body = {
            "title": "Signals before their time",
            "kind": "text",
            "locator": "sha256:" + "ef" * 32,
            "creator_name": "Test Maker",
            "creator_email": "flag-off@example.com",
            "identity_signals": [dict(WORLD_SIGNAL)],
        }
        status, _, data = self.post("/v1/register/content", body=body)
        self.assertEqual(status, 422, data)

    def test_agent_signals_refused_when_flag_off(self):
        body = {
            "agent_name": "Harbor Helper",
            "owner_name": "Test Owner",
            "owner_email": "flag-off-agent@example.com",
            "homepage": "https://example.com/harbor-helper",
            "identity_signals": [dict(WORLD_SIGNAL)],
        }
        status, _, data = self.post("/v1/register/agent", body=body)
        self.assertEqual(status, 422, data)

    def test_normalize_returns_none_when_flag_off(self):
        self.assertIsNone(
            registry.normalize_identity_signals([dict(WORLD_SIGNAL)]))


class IdentitySignalUnitTests(unittest.TestCase):

    def setUp(self):
        self._saved = os.environ.get(ENV)
        os.environ[ENV] = "1"

    def tearDown(self):
        if self._saved is None:
            os.environ.pop(ENV, None)
        else:
            os.environ[ENV] = self._saved

    def test_validate_accepts_minimal(self):
        self.assertEqual(
            registry.validate_identity_signals([dict(GITHUB_SIGNAL)]),
            [])

    def test_normalize_derives_class_and_dedupes(self):
        out = registry.normalize_identity_signals([
            dict(WORLD_SIGNAL, assurance_class="document_check"),
            dict(WORLD_SIGNAL),
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["assurance_class"], "unique_human")

    def test_normalize_rejects_unusable(self):
        self.assertIsNone(registry.normalize_identity_signals(None))
        self.assertIsNone(registry.normalize_identity_signals("nope"))
        self.assertIsNone(registry.normalize_identity_signals([
            dict(WORLD_SIGNAL, provider="myspace")]))
        self.assertIsNone(registry.normalize_identity_signals([
            dict(WORLD_SIGNAL, subject_ref="owner@example.com")]))


if __name__ == "__main__":
    unittest.main()
