"""RemoteMemoryClient: MemoryClient-shaped access to /v1/memory/ over HTTP.

Records are built and signed locally with the agent's attestation key,
then POSTed to the API. Every API response is signature-checked against
the published API keys (fail-closed on tamper), mirroring the MCP client.

Standard library only (http.client).
"""
import base64
import http.client
import json
from urllib.parse import urlparse

from npc_verify import ed25519
from npc_verify.canonical import canonicalize

from .identity import AgentIdentity
from .library import MemoryError, _provenance
from .records import (GENESIS_PREV, new_record_id, record_hash, signing_core,
                      validate_shape)
from .scope import Scope, agent_may_write, stream_key
from .scrub import scrub_check, scrub_tag, scrub_text


class RemoteError(MemoryError):
    pass


class RemoteMemoryClient:
    def __init__(self, base_url: str, api_key: str, identity: AgentIdentity,
                 scope: Scope):
        problems = scope.validate()
        if problems:
            raise MemoryError("; ".join(problems))
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.identity = identity
        self.scope = Scope(company_id=scope.company_id,
                           team_id=scope.team_id,
                           agent_id=identity.agent_id)
        self._keys_doc = None
        parts = urlparse(self.base_url)
        if parts.scheme not in ("http", "https"):
            raise MemoryError("base_url must be http(s)")

    # -- transport --------------------------------------------------------
    def _conn(self):
        parts = urlparse(self.base_url)
        if parts.scheme == "https":
            return http.client.HTTPSConnection(parts.netloc, timeout=15)
        return http.client.HTTPConnection(parts.netloc, timeout=15)

    def _http(self, method, path, body=None):
        conn = self._conn()
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, self._path_prefix() + path, body=payload,
                     headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        hdrs = {k: v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, hdrs, data

    def _path_prefix(self):
        return urlparse(self.base_url).path.rstrip("/")

    def _signing_keys(self):
        if self._keys_doc is None:
            status, _, data = self._http("GET", "/v1/keys")
            if status != 200:
                raise RemoteError(f"GET /v1/keys returned {status}")
            self._keys_doc = json.loads(data)
        return self._keys_doc

    def _public_key_for(self, key_id):
        doc = self._signing_keys()
        cur = doc["api_signing"]["current"]
        if cur and cur["key_id"] == key_id:
            return base64.b64decode(cur["public_key"])
        for h in doc["api_signing"].get("history", []):
            if h["key_id"] == key_id:
                return base64.b64decode(h["public_key"])
        return None

    def _verified(self, status, headers, body_bytes):
        sig_b64 = headers.get("X-NPC-Signature")
        key_id = headers.get("X-NPC-Key-ID")
        if not sig_b64 or not key_id:
            raise RemoteError("response missing X-NPC-Signature/X-NPC-Key-ID")
        pub = self._public_key_for(key_id)
        if pub is None:
            raise RemoteError(f"signing key {key_id!r} not published")
        try:
            parsed = json.loads(body_bytes)
        except ValueError as exc:
            raise RemoteError("response is not valid JSON") from exc
        if canonicalize(parsed) != body_bytes:
            raise RemoteError("response body is not canonical JSON")
        try:
            sig = base64.b64decode(sig_b64)
        except ValueError as exc:
            raise RemoteError("bad signature encoding") from exc
        if not ed25519.verify(pub, body_bytes, sig):
            raise RemoteError("response signature FAILED")
        return status, parsed

    def _call(self, method, path, body=None):
        status, headers, data = self._http(method, path, body)
        if status in (400, 401, 403, 404, 409, 422, 429):
            try:
                detail = json.loads(data)
            except ValueError:
                detail = {"error": "unparseable"}
            raise RemoteError(f"{method} {path} -> {status}: {detail}")
        if status not in (200, 201):
            raise RemoteError(f"{method} {path} -> unexpected {status}")
        return self._verified(status, headers, data)

    # -- agent registration -------------------------------------------------
    def register_agent(self):
        _, doc = self._call("POST", "/v1/memory/agents", {
            "agent_id": self.identity.agent_id,
            "company_id": self.scope.company_id,
            "team_id": self.scope.team_id,
            "public_key_b64": self.identity.public_key_b64,
        })
        return doc

    # -- writes (built + signed locally, stored remotely) -------------------
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
        if not agent_may_write(self.scope, *dims):
            raise MemoryError(
                f"agent {self.identity.agent_id} may not write {dims[0]}")
        return stream_key(*dims), dims

    def _fill_dims(self, kind, company_id, team_id, stream_agent_id):
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

    def _next_seq(self, stream_key_: str):
        """Ask the API for the stream head (fail-closed when unknown)."""
        _, doc = self._call("POST", "/v1/memory/recall", {
            "stream_key": stream_key_, "limit": 1})
        items = doc.get("records", [])
        if not items:
            return 0, GENESIS_PREV
        head = items[0]["record"]
        return head["seq"] + 1, head["record_hash"]

    def _build(self, rtype, text, tags, confidence, provenance, stream,
               target_id=None, reason=None):
        sk, (kind, cid, tid, said) = self._stream_for(stream)
        content = {"text": text, "tags": list(tags or []),
                   "confidence": confidence}
        if target_id is not None:
            content["target_id"] = target_id
        if reason is not None:
            content["reason"] = reason
        prov = _provenance(provenance)
        scrub_check(content)
        scrub_check(prov)
        scrub_text(text)
        for t in content["tags"]:
            scrub_tag(t)
        seq, prev = self._next_seq(sk)
        from npc_verify.models import utcnow_iso
        rec = {
            "id": new_record_id(), "seq": seq, "ts": utcnow_iso(),
            "stream_kind": kind, "stream_key": sk,
            "company_id": cid, "team_id": tid, "stream_agent_id": said,
            "agent_id": self.identity.agent_id,
            "writer_company_id": self.scope.company_id,
            "writer_team_id": self.scope.team_id,
            "type": rtype, "content": content, "provenance": prov,
            "prev_hash": prev, "signature_b64": "",
            "key_id": self.identity.key_id,
        }
        rec["signature_b64"] = self.identity.sign_record_core(
            signing_core(rec))
        rec["record_hash"] = record_hash(rec)
        problems = validate_shape(rec)
        if problems:
            raise MemoryError("; ".join(problems))
        return rec

    def _post_record(self, rec: dict):
        _, doc = self._call("POST", "/v1/memory/records", rec)
        return doc

    def assert_memory(self, text, tags=(), confidence=1.0, provenance=None,
                      stream="agent"):
        return self._post_record(
            self._build("memory.assert", text, tags, confidence, provenance,
                        stream))

    def supersede(self, target_id, text, tags=(), confidence=1.0,
                  provenance=None, stream="agent"):
        return self._post_record(
            self._build("memory.supersede", text, tags, confidence,
                        provenance, stream, target_id=target_id))

    def retract(self, target_id, reason="", stream="agent"):
        return self._post_record(self._build(
            "memory.retract", f"Retracted {target_id}." +
            (f" {reason}" if reason else ""), tags=["retraction"],
            confidence=1.0,
            provenance={"derived_from": [target_id], "source": "memory"},
            stream=stream, target_id=target_id, reason=reason))

    # -- reads ---------------------------------------------------------------
    def get(self, record_id: str):
        try:
            _, doc = self._call("GET", f"/v1/memory/records/{record_id}")
        except RemoteError as exc:
            if "-> 404" in str(exc):
                return None
            raise
        return doc["record"], doc["verification"]

    def recall(self, tags=None, q=None, since=None, until=None, limit=50,
               stream=None, live_only=False, **stream_dims):
        body = {"tags": list(tags or []), "q": q, "since": since,
                "until": until, "limit": limit, "live_only": live_only}
        if stream is not None:
            kind, cid, tid, said = self._fill_dims(
                stream, stream_dims.get("company_id"),
                stream_dims.get("team_id"), stream_dims.get("agent_id"))
            body["stream_key"] = stream_key(kind, cid, tid, said)
        _, doc = self._call("POST", "/v1/memory/recall", body)
        return [(item["record"], item["verification"])
                for item in doc.get("records", [])]
