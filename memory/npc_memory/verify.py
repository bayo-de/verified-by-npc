"""Verification status for recalled memories.

Every recalled memory carries its standing, per DESIGN v1 section 5:

  signature:   valid | invalid | unverifiable
               (unverifiable: writer not registered, or key_id mismatch)
  chain_intact: every hash link from the record back to genesis holds
  superseded_by: id of the live memory.supersede targeting it, else None
  retracted:   a live memory.retract targets it
  standing:    live | superseded | retracted

Chain validity is computed once per stream (a single walk from the newest
link back to genesis), so recalling many records from one stream stays
cheap.
"""
import base64

from npc_verify import ed25519
from npc_verify.canonical import canonicalize

from .records import GENESIS_PREV, record_hash, signing_core


class ChainBreak(Exception):
    pass


def _pubkey_for(store, agent_id: str, key_id: str):
    agent = store.get_agent(agent_id)
    if agent is None or agent["key_id"] != key_id:
        return None
    try:
        return base64.b64decode(agent["public_key_b64"])
    except Exception:
        return None


class StreamVerifier:
    def __init__(self, store):
        self.store = store
        self._chain_cache = {}  # stream_key -> {seq: bool intact}

    def chain_validity(self, stream_key: str) -> dict:
        """Map seq -> True when every link from that seq back to genesis
        holds. Hashes are recomputed from stored fields (the stored hash
        column is never trusted). One walk per stream; cached."""
        if stream_key in self._chain_cache:
            return self._chain_cache[stream_key]
        records = self.store.ordered_stream(stream_key)
        validity = {}
        ok = True
        prev_hash = GENESIS_PREV
        for rec in records:
            if rec["prev_hash"] != prev_hash:
                ok = False
            recomputed = record_hash(rec)
            if recomputed != rec["record_hash"]:
                ok = False
            validity[rec["seq"]] = ok
            # A break poisons this link and everything after it; keep
            # walking so later seqs are marked invalid too.
            prev_hash = recomputed
        self._chain_cache[stream_key] = validity
        return validity

    def signature_status(self, rec: dict) -> str:
        pub = _pubkey_for(self.store, rec["agent_id"], rec["key_id"])
        if pub is None:
            return "unverifiable"
        try:
            sig = base64.b64decode(rec["signature_b64"])
        except Exception:
            return "invalid"
        ok = ed25519.verify(pub, canonicalize(signing_core(rec)), sig)
        return "valid" if ok else "invalid"

    def status_for(self, rec: dict) -> dict:
        stream_key = rec["stream_key"]
        validity = self.chain_validity(stream_key)
        supersede = self.store.live_supersede(rec["id"], stream_key)
        retract = self.store.live_retract(rec["id"], stream_key)
        retracted = retract is not None
        superseded_by = supersede["id"] if supersede else None
        standing = ("retracted" if retracted
                    else "superseded" if superseded_by else "live")
        return {
            "signature": self.signature_status(rec),
            "chain_intact": bool(validity.get(rec["seq"], False)),
            "superseded_by": superseded_by,
            "retracted": retracted,
            "standing": standing,
        }

    def status_many(self, records: list) -> list:
        """Attach verification status to each record. Returns
        [(record, status)]."""
        return [(rec, self.status_for(rec)) for rec in records]
