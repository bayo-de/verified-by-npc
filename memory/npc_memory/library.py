"""MemoryClient: the write/read/recall API for trust-layer memory.

A Fleet agent constructs one client per session:

    store = MemoryStore.open("~/.npc/memory.db")
    identity = AgentIdentity.load("~/.npc/agent.seed", "sentinel")
    client = MemoryClient(store, identity,
                          Scope(company_id="acme", team_id="core",
                                agent_id="sentinel"))
    client.register_self()
    client.assert_memory("SOL funding rates spike before listings",
                         tags=["defi", "funding-rates"],
                         provenance={"derived_from": ["evt_abc"],
                                     "source": "session"})

Every write is scrubbed at the boundary, signed with the agent's
attestation key, scope-checked, and appended to the stream's hash chain.
Every recall returns each memory with its verification status.
"""
from npc_verify.models import utcnow_iso

from .identity import AgentIdentity
from .records import (GENESIS_PREV, new_record_id, public_dict, record_hash,
                      signing_core, validate_shape)
from .scope import (Scope, agent_may_write, key_may_read, stream_key)
from .scrub import scrub_check, scrub_tag, scrub_text
from .store import MemoryStore
from .verify import StreamVerifier


class MemoryError(Exception):
    pass


def _provenance(prov) -> dict:
    prov = dict(prov or {})
    prov.setdefault("derived_from", [])
    prov.setdefault("source", "session")
    prov.setdefault("trust", "trusted")
    return prov


class MemoryClient:
    def __init__(self, store: MemoryStore, identity: AgentIdentity,
                 scope: Scope, clock=None):
        problems = scope.validate()
        if problems:
            raise MemoryError("; ".join(problems))
        if scope.agent_id is not None and scope.agent_id != identity.agent_id:
            raise MemoryError("client scope agent_id must match the identity")
        self.store = store
        self.identity = identity
        self.scope = Scope(company_id=scope.company_id,
                           team_id=scope.team_id,
                           agent_id=identity.agent_id)
        self._clock = clock or utcnow_iso
        self._verifier = StreamVerifier(store)

    # -- registration ---------------------------------------------------
    def register_self(self, registered_by: str = "local"):
        """Publish this agent's public key to the store (idempotent)."""
        if self.store.get_agent(self.identity.agent_id) is not None:
            return
        self.store.register_agent(
            self.identity.agent_id, self.scope.company_id, self.scope.team_id,
            self.identity.public_key_b64, self.identity.key_id,
            self._clock(), registered_by)

    # -- stream selection -------------------------------------------------
    def _stream_for(self, kind: str):
        if kind == "fleet":
            dims = ("fleet", None, None, None)
        elif kind == "company":
            dims = ("company", self.scope.company_id, None, None)
        elif kind == "team":
            dims = ("team", self.scope.company_id, self.scope.team_id, None)
        elif kind == "agent":
            dims = ("agent", self.scope.company_id, self.scope.team_id,
                    self.identity.agent_id)
        else:
            raise MemoryError(f"unknown stream kind: {kind!r}")
        sk = stream_key(*dims)
        if not agent_may_write(self.scope, *dims):
            raise MemoryError(
                f"agent {self.identity.agent_id} may not write {sk}")
        return sk, dims

    def _fill_dims(self, kind, company_id, team_id, stream_agent_id):
        """Default an explicit stream's dimensions from the client scope."""
        if kind == "fleet":
            return "fleet", None, None, None
        company_id = company_id or self.scope.company_id
        if kind == "company":
            return "company", company_id, None, None
        team_id = team_id or self.scope.team_id
        if kind == "team":
            return "team", company_id, team_id, None
        stream_agent_id = stream_agent_id or self.identity.agent_id
        return "agent", company_id, team_id, stream_agent_id

    def _readable_streams(self, kind=None, company_id=None, team_id=None,
                          stream_agent_id=None):
        """Stream keys this client may read, optionally narrowed."""
        out = []
        if kind is not None:
            kind, company_id, team_id, stream_agent_id = self._fill_dims(
                kind, company_id, team_id, stream_agent_id)
            sk = stream_key(kind, company_id, team_id, stream_agent_id)
            if key_may_read(self.scope, kind, company_id, team_id,
                            stream_agent_id):
                out.append(sk)
            return out
        for s in self.store.distinct_streams():
            if key_may_read(self.scope, s["stream_kind"], s["company_id"],
                            s["team_id"], s["stream_agent_id"]):
                out.append(s["stream_key"])
        return out

    # -- writes -----------------------------------------------------------
    def _build(self, rtype: str, text: str, tags, confidence, provenance,
               stream: str, target_id=None, reason=None) -> dict:
        sk, (kind, cid, tid, said) = self._stream_for(stream)
        content = {"text": text, "tags": list(tags or []),
                   "confidence": confidence}
        if target_id is not None:
            content["target_id"] = target_id
        if reason is not None:
            content["reason"] = reason
        prov = _provenance(provenance)
        # Write-boundary scrubbing: refuse, never store.
        scrub_check(content)
        scrub_check(prov)
        scrub_text(text)
        for t in content["tags"]:
            scrub_tag(t)
        last = self.store.last_in_stream(sk)
        seq = 0 if last is None else last["seq"] + 1
        prev = GENESIS_PREV if last is None else last["record_hash"]
        rec = {
            "id": new_record_id(),
            "seq": seq,
            "ts": self._clock(),
            "stream_kind": kind,
            "stream_key": sk,
            "company_id": cid,
            "team_id": tid,
            "stream_agent_id": said,
            "agent_id": self.identity.agent_id,
            "writer_company_id": self.scope.company_id,
            "writer_team_id": self.scope.team_id,
            "type": rtype,
            "content": content,
            "provenance": prov,
            "prev_hash": prev,
            "signature_b64": "",
            "key_id": self.identity.key_id,
        }
        rec["signature_b64"] = self.identity.sign_record_core(
            signing_core(rec))
        rec["record_hash"] = record_hash(rec)
        problems = validate_shape(rec)
        if problems:
            raise MemoryError("; ".join(problems))
        return rec

    def _check_target(self, rtype: str, target_id: str, stream_key_: str):
        """Validate a supersede/retract target.

        Targets must live in the same stream and not be withdrawn. A
        supersede may target an assert or an earlier supersede (changing
        your mind about a correction is itself a correction). A retract
        may target an assert or a supersede: withdrawing a supersede
        revives the belief it had replaced. Retractions themselves are
        never targeted; to move on, assert something new.
        """
        target = self.store.get(target_id)
        if target is None or target["stream_key"] != stream_key_:
            raise MemoryError(f"target {target_id!r} not found in stream")
        if self.store.live_retract(target_id, stream_key_) is not None:
            raise MemoryError(f"target {target_id!r} is already retracted")
        if rtype == "memory.supersede":
            if target["type"] == "memory.retract":
                raise MemoryError("a retraction cannot be superseded")
            if self.store.live_supersede(target_id, stream_key_) is not None:
                raise MemoryError(
                    f"target {target_id!r} is already superseded")
        else:
            if target["type"] == "memory.retract":
                raise MemoryError(
                    "a retraction cannot be retracted; assert a new "
                    "memory instead")
        return target

    def assert_memory(self, text: str, tags=(), confidence: float = 1.0,
                      provenance=None, stream: str = "agent") -> dict:
        rec = self._build("memory.assert", text, tags, confidence,
                          provenance, stream)
        self.store.append(rec)
        self._verifier._chain_cache.pop(rec["stream_key"], None)
        return public_dict(rec)

    def supersede(self, target_id: str, text: str, tags=(), confidence=1.0,
                  provenance=None, stream: str = "agent") -> dict:
        sk, _ = self._stream_for(stream)
        self._check_target("memory.supersede", target_id, sk)
        rec = self._build("memory.supersede", text, tags, confidence,
                          provenance, stream, target_id=target_id)
        self.store.append(rec)
        self._verifier._chain_cache.pop(sk, None)
        return public_dict(rec)

    def retract(self, target_id: str, reason: str = "",
                stream: str = "agent") -> dict:
        sk, _ = self._stream_for(stream)
        self._check_target("memory.retract", target_id, sk)
        rec = self._build("memory.retract",
                          f"Retracted {target_id}." +
                          (f" {reason}" if reason else ""),
                          tags=["retraction"], confidence=1.0,
                          provenance={"derived_from": [target_id],
                                      "source": "memory"},
                          stream=stream, target_id=target_id, reason=reason)
        self.store.append(rec)
        self._verifier._chain_cache.pop(sk, None)
        return public_dict(rec)

    # -- reads --------------------------------------------------------------
    def get(self, record_id: str):
        """Return (record, verification_status). None when unknown."""
        row = self.store.get(record_id)
        if row is None:
            return None
        rec = MemoryStore._inflate(row)
        if not key_may_read(self.scope, rec["stream_kind"],
                            rec["company_id"], rec["team_id"],
                            rec["stream_agent_id"]):
            return None
        return rec, self._verifier.status_for(rec)

    def recall(self, tags=None, q=None, since=None, until=None, limit=50,
               stream: str = None, live_only: bool = False,
               **stream_dims):
        """Tag + recency + keyword recall. Every hit carries verification.

        stream: one of agent/team/company/fleet (defaults to every stream
        this client may read). stream_dims narrows an explicit stream.
        """
        keys = self._readable_streams(stream, **stream_dims) \
            if stream else self._readable_streams()
        rows = self.store.query(stream_keys=keys or ["__none__"], tags=tags,
                                keyword=q, since=since, until=until,
                                limit=limit)
        out = self._verifier.status_many(rows)
        if live_only:
            out = [(r, s) for r, s in out if s["standing"] == "live"]
        return out

    def verify_stream(self, stream: str = "agent", **stream_dims) -> dict:
        """Full integrity report for a stream: chain, signatures, counts."""
        keys = self._readable_streams(stream, **stream_dims)
        if not keys:
            raise MemoryError("no readable stream matches")
        sk = keys[0]
        validity = self._verifier.chain_validity(sk)
        records = self.store.ordered_stream(sk)
        bad_sig = [r["id"] for r in records
                   if self._verifier.signature_status(r) != "valid"]
        return {
            "stream_key": sk,
            "records": len(records),
            "chain_intact": all(validity.values()) if validity else True,
            "broken_at_seq": next((s for s, ok in sorted(validity.items())
                                   if not ok), None),
            "invalid_signatures": bad_sig,
        }
