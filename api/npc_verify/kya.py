"""The agent fields on NPC's records: principal, permissions,
constraints, reputation.

Origin of the shape: a16z crypto's KYA ("Know Your Agent") essay
(April 2026; research note research_notes/
a16zcrypto-digest-2026-10-20.md, Takeaway 1) names four things a
signed credential should link an agent to: its principal, its
permissions, its constraints, and its reputation. NPC adopted the
four names because they map cleanly onto what NPC's records
already carried under other names, split across surfaces. The
names are where the borrowing stops (Bayo, October 21, 2026): the
contents are NPC's own, defined in NPC's words, and where an
outside framework's definition and NPC's differ, NPC's governs.
Reputation is the clearest case: its definition below is NPC's,
stated by Bayo, not the essay's.

This module makes the four fields explicit as one additive block
named ``kya``. The block is gated by NPC_KYA_FIELDS=1, in the same
style as NPC_IDENTITY_SIGNALS and NPC_SOCIAL_PROFILES. With the
flag off, callers add no block at all: existing records serialize
byte-identical to the records this API has always minted (signed
records keep the exact signed core they had), which the tests in
tests/test_kya_fields.py prove against the flag-off shape.

Per-surface mapping (the audit this module implements):

- Agent registration (npc.registry.agent_registration,
  registry.mint_agent_registration):
  principal EXISTS: owner_name, the named accountable owner the
  Agent Registry spec requires. Linked identity_signals, when the
  record carries them, are the principal's linked checks and ride
  under the principal entry. permissions and constraints EXIST
  only when the owner declared a scope at registration (the
  optional declared_scope intake, registry.py): what is recorded
  is the owner's declaration, in the same scope shape
  attestations use, and the record says so; a declaration is not
  a review, and scope_review stays in checks_not_run.
  Registration accepts no scope from anyone who does not declare
  one, so on a registration without a declaration both are null.
  reputation: null. A registration is not an attestation, and a
  rating is never minted into a record at registration time; see
  the reputation section.
- Agent attestation (Attestation with subject_type "agent", and
  the agents table read by GET /v1/agents/{id}/attestation):
  principal is resolved at read time on the store-backed read
  paths (server._agent_body, server._attestation_body): when the
  agent's registration names this agent (the agent_id the owner
  recorded on the registration), the principal is that
  registration's accountable owner, cited by registration record
  id. When no registration names the agent, the chain is not
  recorded anywhere and principal is honestly null; this module's
  bare model serializers (Attestation.public_dict,
  AgentAttestation.public_dict) have no store access and never
  resolve it. permissions PARTLY EXIST: scope.capabilities (and
  any other scope keys that are not limits) are what the record
  states about what the agent does. constraints PARTLY EXIST:
  scope.limits, plus the record's own time bound (expires_at /
  valid_until) and its revoked flag. reputation: on the
  store-backed read paths, the agent's rating, computed at read
  time from the agent's attestation history; on the bare model
  serializers, which cannot see a history, the standing-facts
  entry described in the reputation section below.
- Delegation grant (npc.pact.consent_record and the signed
  npc.pact.grant_status read, pact.py): principal EXISTS:
  user_id_at_brand and pa_sub, the user the personal agent acts
  for. permissions EXIST: scopes_granted, the subset approved at
  the consent ceremony. constraints EXIST: scopes_requested minus
  scopes_granted (what the principal withheld), and expires_at.
  reputation: at consent issuance, null (nothing has happened
  under the grant yet). On the status read, the standing-facts
  entry: the grant's status, whether a revocation record exists,
  and the count of signed audit entries. A delegation grant is
  not an agent and has no attestation history, so it has no
  rating; its standing facts are carried here exactly as this
  build has always carried them, and they are never a score.

Reputation (NPC's definition; Bayo, October 21, 2026):

  "Reputation is formed from our attestations. We can treat
  performing agents as a rating certified by proof and
  effectiveness mathematically. That's essentially what a
  reputation is. A new agent has no rating and therefore no
  reputation."

  So: an agent's reputation IS its rating, and the rating is a
  number computed by the published rule below from NPC's
  attestation history for that agent, and from nothing else.
  Proof is what the attestations say: their verdicts, and that
  they stand on signed records. Effectiveness is how that
  standing held up over time: the latest attestation weighs most,
  a revoked attestation counts against the agent, and standing
  that has expired counts at half.

  The rule (RATING_RULE, version RATING_RULE_VERSION; the rule
  name and version are printed in every rating this module
  emits, so a beholder can recompute the same value from the
  same signed records):

  - Inputs: every attestation ever issued for the agent subject
    (subject_type "agent", this subject_id), revoked ones
    included. Signed records only; no registrations, no identity
    signals, no outside data. Order: tested_at, then created_at,
    then id.
  - Proof points per attestation, by verdict: verified 100,
    verified_with_caveats 70, unknown 30, not_verified 0. A
    revoked attestation earns 0 proof points whatever its verdict
    was, and is counted in the rating's revocations.
  - The latest attestation's points, after standing adjustments
    (revoked already zeroes it; expired at the as-of instant
    halves it), are the effectiveness component.
  - rating = round to one decimal of
    0.6 * (latest attestation's adjusted points)
    + 0.4 * (mean proof points over all the attestations).

  Worked examples: one live verified attestation: 100.0. One
  verified_with_caveats: 70.0. A verified attestation followed by
  a not_verified one: 0.6*0 + 0.4*50 = 20.0. A single not_verified
  attestation: 0.0. That zero is a real rating, a poor reputation,
  and it is not the new agent's state: with no attestations at
  all there is nothing to compute from, the rating does not
  exist, and this module emits null. No rating, no reputation;
  never a zero and never a neutral score in its place.

  This rule is the original spec for a truthful computed
  reputation, settled: the first build of this module specified
  an aggregation over signed records only, a published
  deterministic versioned rule, the value issued as its own
  signed record when it travels, and a stated cold-start answer,
  and until the rule existed it emitted no score. Bayo's ruling
  supplies the definition the spec was waiting for (reputation
  is the rating; proof and effectiveness are its inputs; cold
  start is no rating, not a neutral score), and this build
  implements the aggregation, the published rule, and the cold
  start. The signed-record issuance stays the pattern for travel,
  as a separate build.

  The standing-facts entry predates the rating and stays where
  it has always been used: where a surface can see a record's own
  standing but not a history behind it (the bare model
  serializers, the PACT grant status read), ``reputation`` is an
  object whose ``score`` is null, whose ``computed`` is False,
  whose ``state`` is "not_computed", and whose ``based_on`` lists
  exactly those standing facts, copied verbatim. It states
  plainly that the facts are the record's own standing, not a
  reputation rating, and it never carries a number. Where no
  standing fact exists either, ``reputation`` is plain null.

  The rating is computed at read time from the signed records
  themselves, and the rating object carries its inputs (counts by
  verdict, revocations, the latest attestation's standing, the
  as-of instant) so the computation can be checked, not just
  trusted. Where a rating needs to travel as an artifact of its
  own, the pattern is the one this registry already uses: issue
  it as its own new signed record citing its input record ids
  and its as-of window, never as an edit to an earlier record.
  That issuance is a separate build; nothing here mints one.
"""
import copy
import os
from datetime import datetime, timezone

KYA_FIELDS_ENV = "NPC_KYA_FIELDS"

# Scope keys that state what an agent may do (permissions) and
# scope keys that state bounds on that (constraints). Any other
# scope key is carried verbatim under permissions["scope"]: it is
# part of the declared scope the record states, and this module
# does not rename it into a claim the record did not make.
PERMISSION_SCOPE_KEYS = ("capabilities", "permissions",
                         "allowed_actions", "actions",
                         "scopes_granted")
CONSTRAINT_SCOPE_KEYS = ("limits", "limit", "constraints")

# The agent rating rule (see the module docstring). The name and
# version print in every rating, and a change to the rule's math
# is a version change, so two ratings are never silently computed
# by different rules under one version.
RATING_RULE = "npc-agent-rating"
RATING_RULE_VERSION = "1.0.0"
VERDICT_POINTS = {
    "verified": 100.0,
    "verified_with_caveats": 70.0,
    "unknown": 30.0,
    "not_verified": 0.0,
}
LATEST_WEIGHT = 0.6
HISTORY_WEIGHT = 0.4

_RATING_DETAIL = (
    "This agent's rating, computed by the NPC agent rating rule "
    "from its attestation history on record: the verdicts NPC "
    "issued, weighted toward the latest, with revoked attestations "
    "counted against it and expired standing counted at half.")


def kya_enabled():
    return os.environ.get(KYA_FIELDS_ENV) == "1"


def _parse_iso(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def compute_agent_rating(attestations, as_of=None):
    """The agent's rating from its attestation history, or None.

    ``attestations`` is the history to compute over: dict-shaped
    attestation reads (the store rows, or an attestation's public
    shape) carrying verdict, tested_at, created_at, expires_at,
    and revoked. Only signed attestation records are inputs;
    callers pass nothing else. ``as_of`` is the ISO instant the
    rating is computed at (expiry is judged against it); the
    current time when omitted.

    Returns None when there is no attestation to compute from: a
    new agent has no rating and therefore no reputation. Otherwise
    returns the rating object described in the module docstring,
    deterministic in its inputs: the same signed records and the
    same as-of instant always produce the same rating.
    """
    rows = []
    for att in attestations or []:
        if not isinstance(att, dict):
            continue
        verdict = att.get("verdict")
        if verdict not in VERDICT_POINTS:
            continue
        rows.append({
            "id": att.get("id") or "",
            "verdict": verdict,
            "tested_at": att.get("tested_at") or "",
            "created_at": att.get("created_at") or "",
            "expires_at": att.get("expires_at"),
            "revoked": bool(att.get("revoked")),
        })
    if not rows:
        return None
    rows.sort(key=lambda r: (r["tested_at"], r["created_at"],
                             r["id"]))
    points = [0.0 if r["revoked"] else VERDICT_POINTS[r["verdict"]]
              for r in rows]
    latest = rows[-1]
    latest_points = points[-1]
    as_of_dt = _parse_iso(as_of)
    if as_of_dt is None:
        as_of_dt = datetime.now(timezone.utc)
        as_of = as_of_dt.isoformat(timespec="seconds")
    expires_dt = _parse_iso(latest["expires_at"])
    latest_expired = bool(expires_dt is not None
                          and as_of_dt > expires_dt)
    if latest_expired:
        latest_points = latest_points / 2.0
    rating = round(LATEST_WEIGHT * latest_points
                   + HISTORY_WEIGHT * (sum(points) / len(points)), 1)
    by_verdict = {}
    for r in rows:
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
    return {
        "rating": rating,
        "state": "rated",
        "computed": True,
        "rule": RATING_RULE,
        "rule_version": RATING_RULE_VERSION,
        "as_of": as_of,
        "based_on": {
            "attestations": len(rows),
            "by_verdict": by_verdict,
            "revocations": sum(1 for r in rows if r["revoked"]),
            "latest_verdict": latest["verdict"],
            "latest_revoked": latest["revoked"],
            "latest_expired": latest_expired,
        },
        "detail": _RATING_DETAIL,
    }


def registration_principal(owner_name, identity_signals=None,
                           registration_record_id=None):
    """The principal entry for an agent registration: the named
    accountable owner, with the owner's linked identity signals
    when the registration carries them (they are checks about the
    owner). Resolved onto another record at read time, the entry
    also cites the registration it came from, so the chain a
    beholder is asked to trust is itself on record."""
    principal = {"name": owner_name, "role": "accountable_owner"}
    if identity_signals:
        principal["identity_signals"] = copy.deepcopy(
            identity_signals)
    if registration_record_id:
        principal["registration_record_id"] = registration_record_id
    return principal


def principal_from_registration(record):
    """The principal an agent registration names, or None.

    ``record`` is a signed registration record (the stored JSON).
    Anything that is not an agent registration naming an owner
    yields None: the chain is either recorded or it is absent, and
    absent stays null."""
    if not isinstance(record, dict):
        return None
    if record.get("kind") != "agent":
        return None
    owner = record.get("owner_name")
    if not isinstance(owner, str) or not owner.strip():
        return None
    return registration_principal(
        owner, record.get("identity_signals"),
        registration_record_id=record.get("record_id"))


_REPUTATION_DETAIL = (
    "No reputation score is computed from signed records yet. "
    "The facts listed are this record's own standing, not a "
    "reputation rating.")


def _rep(score_basis):
    """The standing-facts reputation entry for one record.

    score_basis holds only standing facts copied from the record
    itself (verdict, revoked, grant status, revocation presence,
    audit entry count). Empty basis: reputation is null. Non-empty:
    an object that states plainly that no score was computed. This
    entry predates the agent rating and stays on the surfaces that
    see a record's own standing but no attestation history behind
    it; where a rating is computed, the rating takes this slot
    instead (build_kya_block's ``reputation`` argument).
    """
    basis = {k: copy.deepcopy(v) for k, v in (score_basis or {}).items()
             if v is not None}
    if not basis:
        return None
    return {
        "score": None,
        "computed": False,
        "state": "not_computed",
        "based_on": basis,
        "detail": _REPUTATION_DETAIL,
    }


def build_kya_block(principal=None, scope=None, expires_at=None,
                    valid_from=None, valid_until=None, revoked=None,
                    extra_permissions=None, extra_constraints=None,
                    reputation_basis=None, reputation=None):
    """Build the ``kya`` block from a record's existing data.

    Every argument is data the caller already holds; a principal is
    resolved by the caller from the recorded chain, and nothing is
    invented here. The block always carries exactly the four keys,
    in order: principal, permissions, constraints, reputation. A
    key whose underlying data does not exist is None.

    Reputation: a computed agent rating (``reputation``, from
    compute_agent_rating) takes the slot when the caller computed
    one. Otherwise ``reputation_basis`` standing facts produce the
    not-computed entry, exactly as before the rating existed.
    """
    # -- principal ---------------------------------------------------
    principal_out = None
    if principal:
        principal_out = copy.deepcopy(principal)

    # -- permissions + constraints from a scope dict -----------------
    permissions = {}
    if extra_permissions:
        permissions.update(copy.deepcopy(extra_permissions))
    constraints = {}
    if isinstance(scope, dict):
        residual = {}
        for key, value in scope.items():
            if key in CONSTRAINT_SCOPE_KEYS:
                constraints[key] = copy.deepcopy(value)
            elif key in PERMISSION_SCOPE_KEYS:
                permissions[key] = copy.deepcopy(value)
            else:
                residual[key] = copy.deepcopy(value)
        if residual:
            permissions["scope"] = residual
    if extra_constraints:
        constraints.update(copy.deepcopy(extra_constraints))
    if valid_from is not None:
        constraints["valid_from"] = valid_from
    if valid_until is not None:
        constraints["valid_until"] = valid_until
    if expires_at is not None:
        constraints["expires_at"] = expires_at
    if revoked is not None:
        constraints["revoked"] = bool(revoked)

    if reputation is not None:
        reputation_out = copy.deepcopy(reputation)
    else:
        reputation_out = _rep(reputation_basis)
    return {
        "principal": principal_out,
        "permissions": permissions or None,
        "constraints": constraints or None,
        "reputation": reputation_out,
    }


def kya_for_scope(scope=None, **kwargs):
    """build_kya_block for the common attestation-shaped caller.

    Without a rating, the caller's reputation basis is its verdict
    and revoked flag (the standing-facts entry). A caller that
    computed the subject's rating from its attestation history
    passes ``rating=`` and the rating takes the slot.
    """
    rating = kwargs.pop("rating", None)
    verdict = kwargs.pop("verdict", None)
    revoked = kwargs.get("revoked")
    basis = {}
    if verdict is not None:
        basis["verdict"] = verdict
    if revoked is not None:
        basis["revoked"] = bool(revoked)
    if "reputation_basis" in kwargs:
        basis.update(kwargs.pop("reputation_basis") or {})
    return build_kya_block(scope=scope, reputation_basis=basis,
                           reputation=rating, **kwargs)
