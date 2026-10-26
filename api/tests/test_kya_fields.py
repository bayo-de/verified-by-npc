"""KYA (Know Your Agent) field tests.

a16z crypto's KYA shape names four fields on an agent credential:
principal, permissions, constraints, reputation. NPC's records
carried most of that data under other names. These tests pin the
additive, flag-gated alignment (npc_verify.kya, NPC_KYA_FIELDS=1):

- with the flag off, existing records are byte-identical in shape:
  the same stored record read with the flag on differs only by the
  added `kya` key, model dicts with the flag off equal the exact
  pre-KYA shape, and signed records carry no `kya` key at all;
- with the flag on, agent records carry a `kya` block with exactly
  the four named fields, populated only from data the underlying
  record already holds (owner_name on a registration, scope
  capabilities and limits on an attestation, scopes_granted and
  expires_at on a PACT grant);
- a field whose data does not exist on that record is null, never
  invented: a registration without a declared scope has no
  permissions or constraints; an attestation whose agent no
  registration names has no principal;
- reputation is NPC's own definition (Bayo, Oct 21, 2026): a
  rating computed mathematically from the agent's attestation
  history, proof and effectiveness, under the published rule in
  npc_verify.kya. A new agent has no rating and therefore no
  reputation: never a fabricated score, never a neutral zero. The
  standing-facts entry (score null, state not_computed) survives
  exactly where it always lived: surfaces that see a record's own
  standing but no history behind it.
- the gaps close where the data honestly exists: a registration
  may declare the agent_id its attestations will use and a scope
  of authority, which links attestations back to the accountable
  owner and fills the registration's permissions and constraints
  from birth.
"""
import json
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import kya, models, pact  # noqa: E402
from npc_verify.canonical import canonicalize  # noqa: E402
from tests.helpers import ApiTestCase  # noqa: E402

ENV = kya.KYA_FIELDS_ENV
SIGNALS_ENV = "NPC_IDENTITY_SIGNALS"

AGENT_BODY_KEYS = {"agent_id", "verdict", "scope", "valid_from",
                   "valid_until", "attestation_id", "onchain_anchor",
                   "notes"}
ATTESTATION_BODY_KEYS = {"id", "subject_type", "subject_id",
                         "verdict", "scope", "tested_at",
                         "expires_at", "findings_summary",
                         "signature", "key_id", "onchain_anchor",
                         "revoked", "created_at"}
REGISTRATION_KEYS = {"record_type", "record_id", "kind", "status",
                     "status_label", "agent_name", "owner_name",
                     "homepage", "description", "registered_at",
                     "checks_run", "checks_not_run", "key_id",
                     "signature"}


class KyaFlagMixin:
    """Set NPC_KYA_FIELDS per test, restore the environment after."""

    def set_kya(self, value):
        if value is None:
            os.environ.pop(ENV, None)
        else:
            os.environ[ENV] = value

    def setUp(self):
        self._saved_kya = os.environ.get(ENV)
        self._saved_signals = os.environ.get(SIGNALS_ENV)
        os.environ.pop(ENV, None)

    def tearDown(self):
        for name, saved in ((ENV, self._saved_kya),
                            (SIGNALS_ENV, self._saved_signals)):
            if saved is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = saved


class KyaBuilderUnitTests(unittest.TestCase):

    def test_scope_splits_into_permissions_and_constraints(self):
        block = kya.build_kya_block(scope={
            "capabilities": ["navigate"],
            "limits": ["no-payments"],
            "domain": "test-fixture",
        }, expires_at="2027-01-01T00:00:00+00:00", revoked=False,
            reputation_basis={"verdict": "verified",
                              "revoked": False})
        self.assertEqual(list(block), ["principal", "permissions",
                                       "constraints", "reputation"])
        self.assertIsNone(block["principal"])
        self.assertEqual(block["permissions"]["capabilities"],
                         ["navigate"])
        # residual scope keys ride verbatim, renamed into nothing
        self.assertEqual(block["permissions"]["scope"],
                         {"domain": "test-fixture"})
        self.assertEqual(block["constraints"]["limits"],
                         ["no-payments"])
        self.assertEqual(block["constraints"]["expires_at"],
                         "2027-01-01T00:00:00+00:00")
        self.assertIs(block["constraints"]["revoked"], False)

    def test_empty_inputs_are_all_null(self):
        block = kya.build_kya_block()
        self.assertEqual(block, {"principal": None,
                                 "permissions": None,
                                 "constraints": None,
                                 "reputation": None})

    def test_reputation_never_carries_a_score(self):
        block = kya.build_kya_block(
            reputation_basis={"verdict": "not_verified",
                              "revoked": True})
        rep = block["reputation"]
        self.assertIsNone(rep["score"])
        self.assertIs(rep["computed"], False)
        self.assertEqual(rep["state"], "not_computed")
        self.assertEqual(rep["based_on"],
                         {"verdict": "not_verified", "revoked": True})

    def test_block_does_not_alias_the_source_scope(self):
        scope = {"capabilities": ["read"]}
        block = kya.build_kya_block(scope=scope)
        scope["capabilities"].append("write")
        self.assertEqual(block["permissions"]["capabilities"],
                         ["read"])


class KyaModelUnitTests(KyaFlagMixin, unittest.TestCase):

    def _agent_attestation(self):
        return models.Attestation(
            id="att_test_kya", subject_type="agent",
            subject_id="agent_test_kya", verdict="verified",
            scope={"capabilities": ["test-navigation"],
                   "limits": ["no-payments"]},
            tested_at="2026-09-20T12:00:00+00:00",
            expires_at="2027-09-20T12:00:00+00:00",
            findings_summary="Passed.")

    def test_flag_off_public_dict_is_the_pre_kya_shape(self):
        out = self._agent_attestation().public_dict()
        self.assertEqual(set(out), ATTESTATION_BODY_KEYS)
        self.assertNotIn("kya", out)

    def test_flag_off_serialization_byte_identical(self):
        att = self._agent_attestation()
        expected = {
            "id": "att_test_kya", "subject_type": "agent",
            "subject_id": "agent_test_kya", "verdict": "verified",
            "scope": {"capabilities": ["test-navigation"],
                      "limits": ["no-payments"]},
            "tested_at": "2026-09-20T12:00:00+00:00",
            "expires_at": "2027-09-20T12:00:00+00:00",
            "findings_summary": "Passed.", "signature": "",
            "key_id": "",
            "onchain_anchor": {"chain": "base", "tx": None,
                               "hash": "", "status": "not_anchored"},
            "revoked": False,
            "created_at": att.created_at,
        }
        self.assertEqual(canonicalize(att.public_dict()),
                         canonicalize(expected))

    def test_flag_on_agent_attestation_carries_kya(self):
        self.set_kya("1")
        block = self._agent_attestation().public_dict()["kya"]
        # no principal is stored on an attestation: honestly null
        self.assertIsNone(block["principal"])
        self.assertEqual(block["permissions"],
                         {"capabilities": ["test-navigation"]})
        self.assertEqual(block["constraints"]["limits"],
                         ["no-payments"])
        self.assertEqual(block["constraints"]["expires_at"],
                         "2027-09-20T12:00:00+00:00")
        self.assertIsNone(block["reputation"]["score"])
        self.assertEqual(block["reputation"]["based_on"],
                         {"verdict": "verified", "revoked": False})

    def test_flag_on_non_agent_attestation_has_no_kya(self):
        self.set_kya("1")
        att = models.Attestation(
            id="att_test_kya2", subject_type="claim",
            subject_id="claim:x", verdict="verified", scope={},
            tested_at="2026-09-20T12:00:00+00:00", expires_at=None,
            findings_summary="Passed.")
        self.assertNotIn("kya", att.public_dict())

    def test_agent_attestation_dataclass(self):
        agent = models.AgentAttestation(
            agent_id="agent_test_kya", verdict="verified",
            scope={"capabilities": ["test-cataloging"],
                   "limits": ["read-only"]},
            valid_from="2026-09-25T12:00:00+00:00",
            valid_until="2027-09-25T12:00:00+00:00",
            attestation_id="att_test_kya", anchor={})
        self.assertNotIn("kya", agent.public_dict())
        self.set_kya("1")
        block = agent.public_dict()["kya"]
        self.assertIsNone(block["principal"])
        self.assertEqual(block["permissions"]["capabilities"],
                         ["test-cataloging"])
        self.assertEqual(block["constraints"]["valid_until"],
                         "2027-09-25T12:00:00+00:00")
        self.assertEqual(block["reputation"]["based_on"],
                         {"verdict": "verified"})


class AgentReadKyaTests(KyaFlagMixin, ApiTestCase):
    """GET /v1/agents/{id}/attestation and GET /v1/records/{id}
    over the seeded agent_test_scout fixture."""

    def test_flag_off_agent_body_has_no_kya(self):
        status, _, data = self.get(
            "/v1/agents/agent_test_scout/attestation",
            key=self.verifier_key)
        self.assertEqual(status, 200)
        self.assertEqual(set(json.loads(data)), AGENT_BODY_KEYS)

    def test_flag_on_differs_from_flag_off_only_by_kya(self):
        status, _, data = self.get(
            "/v1/agents/agent_test_scout/attestation",
            key=self.verifier_key)
        self.assertEqual(status, 200)
        off = json.loads(data)
        self.set_kya("1")
        status, _, data = self.get(
            "/v1/agents/agent_test_scout/attestation",
            key=self.verifier_key)
        self.assertEqual(status, 200)
        on = json.loads(data)
        block = on.pop("kya")
        # the same stored record, byte-identical apart from kya
        self.assertEqual(on, off)
        self.assertEqual(canonicalize(on), canonicalize(off))
        # no registration names agent_test_scout: the chain is not
        # recorded, so the principal stays honestly null
        self.assertIsNone(block["principal"])
        self.assertEqual(block["permissions"],
                         {"capabilities": ["test-navigation"]})
        self.assertEqual(block["constraints"]["limits"],
                         ["no-payments"])
        self.assertEqual(block["constraints"]["valid_until"],
                         "2027-09-20T12:00:00+00:00")
        self.assertIs(block["constraints"]["revoked"], False)
        # reputation is the rating computed from the agent's
        # attestation history: one live verified attestation
        rep = block["reputation"]
        self.assertEqual(rep["state"], "rated")
        self.assertIs(rep["computed"], True)
        self.assertEqual(rep["rating"], 100.0)
        self.assertEqual(rep["rule"], "npc-agent-rating")
        self.assertEqual(rep["rule_version"], "1.0.0")
        self.assertEqual(rep["based_on"]["attestations"], 1)
        self.assertEqual(rep["based_on"]["by_verdict"],
                         {"verified": 1})
        self.assertEqual(rep["based_on"]["revocations"], 0)
        self.assertEqual(rep["based_on"]["latest_verdict"],
                         "verified")
        self.assertIs(rep["based_on"]["latest_revoked"], False)
        self.assertIs(rep["based_on"]["latest_expired"], False)

    def test_flag_on_attestation_record_via_records_endpoint(self):
        status, _, data = self.get(
            "/v1/agents/agent_test_scout/attestation",
            key=self.verifier_key)
        att_id = json.loads(data)["attestation_id"]
        self.set_kya("1")
        status, _, data = self.get("/v1/records/" + att_id)
        self.assertEqual(status, 200)
        rec = json.loads(data)
        self.assertEqual(rec["subject_type"], "agent")
        self.assertIn("kya", rec)
        self.assertEqual(rec["kya"]["permissions"],
                         {"capabilities": ["test-navigation"]})
        # and with the flag off the same record is the old shape
        self.set_kya(None)
        status, _, data = self.get("/v1/records/" + att_id)
        self.assertEqual(status, 200)
        self.assertEqual(set(json.loads(data)),
                         ATTESTATION_BODY_KEYS)

    def test_flag_on_non_agent_attestation_has_no_kya(self):
        body = {"subject_type": "claim", "subject_id": "claim:kya",
                "verdict": "verified", "scope": {"domain": "x"},
                "tested_at": "2026-10-20T00:00:00+00:00",
                "expires_at": None, "findings_summary": "Checked."}
        status, _, data = self.post("/v1/attestations", body=body,
                                    key=self.issuer_key)
        self.assertEqual(status, 201)
        att_id = json.loads(data)["id"]
        self.set_kya("1")
        status, _, data = self.get("/v1/records/" + att_id)
        self.assertEqual(status, 200)
        self.assertNotIn("kya", json.loads(data))


class AgentRegistrationKyaTests(KyaFlagMixin, ApiTestCase):

    def _register_agent(self, email, extra=None):
        body = {"agent_name": "Harbor Helper",
                "owner_name": "Test Owner",
                "owner_email": email,
                "homepage": "https://example.com/harbor-helper"}
        body.update(extra or {})
        return self.post("/v1/register/agent", body=body)

    def test_flag_off_registration_has_no_kya(self):
        status, _, data = self._register_agent("kya-off@example.com")
        self.assertEqual(status, 201)
        rec = json.loads(data)
        self.assertEqual(set(rec), REGISTRATION_KEYS)
        self.assertTrue(pact.verify_record(self.app.keys, rec))

    def test_flag_on_registration_carries_principal_only(self):
        self.set_kya("1")
        status, headers, data = self._register_agent(
            "kya-on@example.com")
        self.assertEqual(status, 201)
        rec = self.check_signature(headers, data)
        # the block is inside the signed record, not an envelope add-on
        self.assertTrue(pact.verify_record(self.app.keys, rec))
        self.assertEqual(set(rec), REGISTRATION_KEYS | {"kya"})
        block = rec["kya"]
        self.assertEqual(block["principal"],
                         {"name": "Test Owner",
                          "role": "accountable_owner"})
        # a registration carries no declared scope, no expiry or
        # limits, and no verdict: all three are honestly null
        self.assertIsNone(block["permissions"])
        self.assertIsNone(block["constraints"])
        self.assertIsNone(block["reputation"])

    def test_flag_on_content_registration_has_no_kya(self):
        self.set_kya("1")
        body = {"title": "A plain work", "kind": "text",
                "locator": "sha256:" + "ab" * 32,
                "creator_name": "Test Maker",
                "creator_email": "kya-content@example.com"}
        status, _, data = self.post("/v1/register/content", body=body)
        self.assertEqual(status, 201)
        self.assertNotIn("kya", json.loads(data))

    def test_flag_on_principal_carries_linked_identity_signals(self):
        os.environ[SIGNALS_ENV] = "1"
        self.set_kya("1")
        signal = {"provider": "github", "signal": "account",
                  "subject_ref": "88342117",
                  "linked_at": "2026-10-18T09:30:00+00:00"}
        status, _, data = self._register_agent(
            "kya-signals@example.com",
            extra={"identity_signals": [signal]})
        self.assertEqual(status, 201)
        rec = json.loads(data)
        principal = rec["kya"]["principal"]
        self.assertEqual(principal["name"], "Test Owner")
        self.assertEqual(len(principal["identity_signals"]), 1)
        self.assertEqual(
            principal["identity_signals"][0]["provider"], "github")
        self.assertEqual(
            principal["identity_signals"][0]["assurance_class"],
            "account_control")


class PactGrantKyaTests(KyaFlagMixin, ApiTestCase):

    GRANT = {"pa_iss": "pa.example", "pa_sub": "user-123",
             "brand_id": "brand.example",
             "user_id_at_brand": "u-42",
             "scopes_requested": ["read", "pay", "admin"],
             "scopes_granted": ["read", "pay"],
             "expires_at": "2027-01-01T00:00:00+00:00"}

    def _create_grant(self, grant_id):
        body = dict(self.GRANT, grant_id=grant_id)
        return self.post("/v1/pact/grants", body=body,
                         key=self.issuer_key)

    def test_flag_off_consent_and_status_have_no_kya(self):
        status, _, data = self._create_grant("grant_kya_off")
        self.assertEqual(status, 201)
        self.assertNotIn("kya", json.loads(data))
        status, _, data = self.get(
            "/v1/pact/grants/grant_kya_off/status",
            key=self.verifier_key)
        self.assertEqual(status, 200)
        self.assertNotIn("kya", json.loads(data))

    def test_flag_on_status_differs_only_by_kya_and_signature(self):
        store, keys = self.app.store, self.app.keys
        body = dict(self.GRANT, grant_id="grant_kya_det")
        rec = pact.mint_consent_record(store, keys, body)
        self.assertIsNotNone(rec)
        at = "2026-10-20T00:00:00+00:00"
        off = pact.grant_status_record(store, keys, "grant_kya_det",
                                       at=at)
        self.set_kya("1")
        on = pact.grant_status_record(store, keys, "grant_kya_det",
                                      at=at)
        self.assertIn("kya", on)
        on_core = {k: v for k, v in on.items()
                   if k not in ("kya", "signature")}
        off_core = {k: v for k, v in off.items() if k != "signature"}
        self.assertEqual(on_core, off_core)

    def test_flag_on_consent_carries_kya(self):
        self.set_kya("1")
        status, _, data = self._create_grant("grant_kya_on")
        self.assertEqual(status, 201)
        rec = json.loads(data)
        self.assertTrue(pact.verify_record(self.app.keys, rec))
        block = rec["kya"]
        self.assertEqual(block["principal"],
                         {"user_id_at_brand": "u-42",
                          "pa_sub": "user-123"})
        self.assertEqual(block["permissions"],
                         {"scopes_granted": ["read", "pay"]})
        self.assertEqual(block["constraints"]["scopes_withheld"],
                         ["admin"])
        self.assertEqual(block["constraints"]["expires_at"],
                         "2027-01-01T00:00:00+00:00")
        # nothing has happened under this grant yet: no reputation
        self.assertIsNone(block["reputation"])

    def test_flag_on_status_reputation_is_standing_not_a_score(self):
        self.set_kya("1")
        status, _, _ = self._create_grant("grant_kya_status")
        self.assertEqual(status, 201)
        status, _, data = self.get(
            "/v1/pact/grants/grant_kya_status/status",
            key=self.verifier_key)
        self.assertEqual(status, 200)
        rec = json.loads(data)
        self.assertTrue(pact.verify_status_record(self.app.keys,
                                                  rec))
        rep = rec["kya"]["reputation"]
        self.assertIsNone(rep["score"])
        self.assertIs(rep["computed"], False)
        self.assertEqual(rep["based_on"],
                         {"grant_status": "active",
                          "revocation_recorded": False,
                          "audit_entries": 0})
        # revoke, then the same read states the revocation exactly
        status, _, _ = self.post(
            "/v1/pact/grants/grant_kya_status:revoke",
            body={"revoked_by": "user", "reason": "no longer needed"},
            key=self.issuer_key)
        self.assertEqual(status, 201)
        status, _, data = self.get(
            "/v1/pact/grants/grant_kya_status/status",
            key=self.verifier_key)
        self.assertEqual(status, 200)
        rep = json.loads(data)["kya"]["reputation"]
        self.assertIsNone(rep["score"])
        self.assertEqual(rep["based_on"]["grant_status"], "revoked")
        self.assertIs(rep["based_on"]["revocation_recorded"], True)


class KyaRatingUnitTests(unittest.TestCase):
    """compute_agent_rating: reputation is a rating formed from
    the attestation history (Bayo, Oct 21, 2026). Proof points by
    verdict, the latest attestation weighted 0.6 against the
    history mean's 0.4, revoked attestations at zero, expired
    standing at half. No history: no rating at all."""

    AS_OF = "2026-10-21T00:00:00+00:00"

    def _att(self, verdict, tested_at, expires_at=None, revoked=False,
             att_id=None, created_at=None):
        return {"id": att_id or ("att_" + tested_at),
                "verdict": verdict, "tested_at": tested_at,
                "created_at": created_at or tested_at,
                "expires_at": expires_at, "revoked": revoked}

    def test_new_agent_has_no_rating_and_no_reputation(self):
        self.assertIsNone(kya.compute_agent_rating([], as_of=self.AS_OF))
        self.assertIsNone(kya.compute_agent_rating(None,
                                                   as_of=self.AS_OF))

    def test_single_live_verified_is_100(self):
        rep = kya.compute_agent_rating(
            [self._att("verified", "2026-10-01T00:00:00+00:00",
                       expires_at="2027-10-01T00:00:00+00:00")],
            as_of=self.AS_OF)
        self.assertEqual(rep["rating"], 100.0)
        self.assertEqual(rep["state"], "rated")
        self.assertIs(rep["computed"], True)
        self.assertEqual(rep["rule"], "npc-agent-rating")
        self.assertEqual(rep["rule_version"], "1.0.0")
        self.assertEqual(rep["based_on"]["attestations"], 1)
        self.assertEqual(rep["based_on"]["by_verdict"],
                         {"verified": 1})
        self.assertEqual(rep["based_on"]["revocations"], 0)
        self.assertIs(rep["based_on"]["latest_expired"], False)

    def test_single_caveated_is_70(self):
        rep = kya.compute_agent_rating(
            [self._att("verified_with_caveats",
                       "2026-10-01T00:00:00+00:00")],
            as_of=self.AS_OF)
        self.assertEqual(rep["rating"], 70.0)

    def test_single_not_verified_is_a_real_zero_rating(self):
        rep = kya.compute_agent_rating(
            [self._att("not_verified", "2026-10-01T00:00:00+00:00")],
            as_of=self.AS_OF)
        # a poor reputation is still a reputation; it is not the
        # new agent's null
        self.assertIsNotNone(rep)
        self.assertEqual(rep["rating"], 0.0)

    def test_latest_weighs_more_than_the_history_mean(self):
        rep = kya.compute_agent_rating(
            [self._att("verified", "2026-09-01T00:00:00+00:00"),
             self._att("not_verified", "2026-10-01T00:00:00+00:00")],
            as_of=self.AS_OF)
        # 0.6 * 0 (latest) + 0.4 * 50 (mean of 100, 0)
        self.assertEqual(rep["rating"], 20.0)
        self.assertEqual(rep["based_on"]["attestations"], 2)
        self.assertEqual(rep["based_on"]["latest_verdict"],
                         "not_verified")

    def test_history_is_ordered_by_tested_at_not_input_order(self):
        rep = kya.compute_agent_rating(
            [self._att("not_verified", "2026-10-01T00:00:00+00:00"),
             self._att("verified", "2026-09-01T00:00:00+00:00")],
            as_of=self.AS_OF)
        self.assertEqual(rep["rating"], 20.0)
        self.assertEqual(rep["based_on"]["latest_verdict"],
                         "not_verified")

    def test_revoked_latest_counts_against_the_agent(self):
        rep = kya.compute_agent_rating(
            [self._att("verified", "2026-09-01T00:00:00+00:00"),
             self._att("verified", "2026-10-01T00:00:00+00:00",
                       revoked=True)],
            as_of=self.AS_OF)
        # points are 100 and 0 (revoked); latest adjusted is 0
        self.assertEqual(rep["rating"], 20.0)
        self.assertEqual(rep["based_on"]["revocations"], 1)
        self.assertIs(rep["based_on"]["latest_revoked"], True)

    def test_expired_latest_standing_counts_at_half(self):
        rep = kya.compute_agent_rating(
            [self._att("verified", "2026-09-01T00:00:00+00:00",
                       expires_at="2026-10-01T00:00:00+00:00")],
            as_of=self.AS_OF)
        # 0.6 * 50 (halved) + 0.4 * 100 (proof points stand)
        self.assertEqual(rep["rating"], 70.0)
        self.assertIs(rep["based_on"]["latest_expired"], True)

    def test_recompute_from_the_same_records_matches(self):
        history = [
            self._att("verified", "2026-08-01T00:00:00+00:00"),
            self._att("verified_with_caveats",
                      "2026-09-01T00:00:00+00:00"),
            self._att("verified", "2026-10-01T00:00:00+00:00",
                      revoked=True),
        ]
        first = kya.compute_agent_rating(history, as_of=self.AS_OF)
        second = kya.compute_agent_rating(list(history),
                                          as_of=self.AS_OF)
        self.assertEqual(first, second)
        self.assertEqual(first["as_of"], self.AS_OF)

    def test_rating_takes_the_reputation_slot_over_standing_facts(self):
        rating = kya.compute_agent_rating(
            [self._att("verified", "2026-10-01T00:00:00+00:00")],
            as_of=self.AS_OF)
        block = kya.kya_for_scope(
            scope={"capabilities": ["navigate"]},
            verdict="verified", revoked=False, rating=rating)
        self.assertEqual(block["reputation"]["state"], "rated")
        self.assertEqual(block["reputation"]["rating"], 100.0)
        # and without a rating the standing-facts entry is what a
        # caller still gets, unchanged from before the rating existed
        block = kya.kya_for_scope(
            scope={"capabilities": ["navigate"]},
            verdict="verified", revoked=False)
        self.assertEqual(block["reputation"]["state"],
                         "not_computed")
        self.assertIsNone(block["reputation"]["score"])


class AgentDeclaredScopeTests(KyaFlagMixin, ApiTestCase):
    """The gap fills at registration: an optional declared scope
    (permissions and constraints from birth) and an optional
    agent_id (the recorded chain from an attestation's subject
    back to the accountable owner)."""

    SCOPE = {"capabilities": ["test-navigation", "test-cataloging"],
             "limits": ["no-payments"]}

    def _register_agent(self, email, extra=None):
        body = {"agent_name": "Harbor Helper",
                "owner_name": "Test Owner",
                "owner_email": email,
                "homepage": "https://example.com/harbor-helper"}
        body.update(extra or {})
        return self.post("/v1/register/agent", body=body)

    def _attest(self, agent_id, verdict="verified",
                tested_at="2026-10-20T00:00:00+00:00"):
        body = {"subject_type": "agent", "subject_id": agent_id,
                "verdict": verdict,
                "scope": {"capabilities": ["test-navigation"]},
                "tested_at": tested_at, "expires_at": None,
                "findings_summary": "Checked."}
        status, _, data = self.post("/v1/attestations", body=body,
                                    key=self.issuer_key)
        self.assertEqual(status, 201)
        return json.loads(data)["id"]

    def test_declared_scope_fills_registration_kya(self):
        self.set_kya("1")
        status, _, data = self._register_agent(
            "kya-scope@example.com",
            extra={"agent_id": "agent_declared_1",
                   "declared_scope": self.SCOPE})
        self.assertEqual(status, 201)
        rec = json.loads(data)
        self.assertTrue(pact.verify_record(self.app.keys, rec))
        self.assertEqual(rec["agent_id"], "agent_declared_1")
        self.assertEqual(rec["declared_scope"], self.SCOPE)
        block = rec["kya"]
        self.assertEqual(block["permissions"],
                         {"capabilities": self.SCOPE["capabilities"]})
        self.assertEqual(block["constraints"],
                         {"limits": ["no-payments"]})
        self.assertIsNone(block["reputation"])
        checks = {c["check"] for c in rec["checks_run"]}
        self.assertIn("declared_scope", checks)
        # the declaration is recorded as a declaration: scope review
        # still has not run
        not_run = {c["check"] for c in rec["checks_not_run"]}
        self.assertIn("scope_review", not_run)

    def test_declared_scope_is_carried_with_the_flag_off(self):
        status, _, data = self._register_agent(
            "kya-scope-off@example.com",
            extra={"agent_id": "agent_declared_2",
                   "declared_scope": self.SCOPE})
        self.assertEqual(status, 201)
        rec = json.loads(data)
        self.assertNotIn("kya", rec)
        self.assertEqual(rec["agent_id"], "agent_declared_2")
        self.assertEqual(rec["declared_scope"], self.SCOPE)

    def test_registration_without_declarations_is_the_old_shape(self):
        self.set_kya("1")
        status, _, data = self._register_agent("kya-plain@example.com")
        self.assertEqual(status, 201)
        rec = json.loads(data)
        self.assertEqual(set(rec), REGISTRATION_KEYS | {"kya"})
        self.assertIsNone(rec["kya"]["permissions"])
        self.assertIsNone(rec["kya"]["constraints"])

    def test_invalid_agent_id_is_refused(self):
        status, _, _ = self._register_agent(
            "kya-bad-id@example.com",
            extra={"agent_id": "not an agent id!"})
        self.assertEqual(status, 422)

    def test_invalid_declared_scope_is_refused(self):
        status, _, _ = self._register_agent(
            "kya-bad-scope@example.com",
            extra={"declared_scope": {"capabilities": "navigate"}})
        self.assertEqual(status, 422)
        status, _, _ = self._register_agent(
            "kya-bad-scope2@example.com",
            extra={"declared_scope": ["navigate"]})
        self.assertEqual(status, 422)

    def test_principal_resolves_from_the_recorded_chain(self):
        status, _, data = self._register_agent(
            "kya-chain@example.com",
            extra={"agent_id": "agent_chain_1",
                   "declared_scope": self.SCOPE})
        self.assertEqual(status, 201)
        reg_id = json.loads(data)["record_id"]
        att_id = self._attest("agent_chain_1")
        self.set_kya("1")
        status, _, data = self.get("/v1/records/" + att_id)
        self.assertEqual(status, 200)
        block = json.loads(data)["kya"]
        self.assertEqual(
            block["principal"],
            {"name": "Test Owner", "role": "accountable_owner",
             "registration_record_id": reg_id})
        # the agent's history is this one verified attestation
        self.assertEqual(block["reputation"]["rating"], 100.0)

    def test_principal_stays_null_without_a_recorded_chain(self):
        att_id = self._attest("agent_chain_none")
        self.set_kya("1")
        status, _, data = self.get("/v1/records/" + att_id)
        self.assertEqual(status, 200)
        block = json.loads(data)["kya"]
        self.assertIsNone(block["principal"])
        # the rating still computes: reputation needs attestations,
        # not a registration
        self.assertEqual(block["reputation"]["rating"], 100.0)

    def test_agent_body_resolves_principal_and_rating(self):
        status, _, data = self._register_agent(
            "kya-chain2@example.com",
            extra={"agent_id": "agent_chain_2"})
        self.assertEqual(status, 201)
        reg_id = json.loads(data)["record_id"]
        att_id = self._attest("agent_chain_2")
        self.app.store.insert_agent(
            "agent_chain_2", "verified",
            {"capabilities": ["test-navigation"]},
            "2026-10-20T00:00:00+00:00", None, att_id, "")
        self.set_kya("1")
        status, _, data = self.get(
            "/v1/agents/agent_chain_2/attestation",
            key=self.verifier_key)
        self.assertEqual(status, 200)
        block = json.loads(data)["kya"]
        self.assertEqual(block["principal"]["name"], "Test Owner")
        self.assertEqual(
            block["principal"]["registration_record_id"], reg_id)
        self.assertEqual(block["reputation"]["rating"], 100.0)

    def test_rating_moves_with_the_history(self):
        self._attest("agent_chain_3", verdict="verified",
                     tested_at="2026-09-20T00:00:00+00:00")
        att2 = self._attest("agent_chain_3", verdict="not_verified",
                            tested_at="2026-10-20T00:00:00+00:00")
        self.set_kya("1")
        status, _, data = self.get("/v1/records/" + att2)
        self.assertEqual(status, 200)
        rep = json.loads(data)["kya"]["reputation"]
        self.assertEqual(rep["rating"], 20.0)
        self.assertEqual(rep["based_on"]["attestations"], 2)


if __name__ == "__main__":
    unittest.main()
