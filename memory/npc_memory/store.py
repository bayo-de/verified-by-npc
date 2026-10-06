"""SQLite store for trust-layer memory.

Portable SQL (TEXT columns, ISO-8601 TEXT timestamps, JSON in TEXT), same
conventions as the Verification API store. The store wraps a caller-owned
sqlite3 connection (so the API can share its connection and lock) or opens
its own file via MemoryStore.open().

Tables:
  memory_agents  : registered agent identities (public keys only)
  memory_records : the append-only belief ledger, one hash chain per stream
"""
import json
import sqlite3
import threading

MEMORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_agents (
  agent_id       TEXT PRIMARY KEY,
  company_id     TEXT,
  team_id        TEXT,
  public_key_b64 TEXT NOT NULL,
  key_id         TEXT NOT NULL,
  registered_at  TEXT NOT NULL,
  registered_by  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_records (
  id              TEXT PRIMARY KEY,
  seq             INTEGER NOT NULL,
  ts              TEXT NOT NULL,
  stream_kind     TEXT NOT NULL,
  company_id      TEXT,
  team_id         TEXT,
  stream_agent_id TEXT,
  stream_key      TEXT NOT NULL,
  agent_id        TEXT NOT NULL,
  writer_company_id TEXT,
  writer_team_id  TEXT,
  type            TEXT NOT NULL,
  content_json    TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  prev_hash       TEXT NOT NULL,
  record_hash     TEXT NOT NULL,
  signature_b64   TEXT NOT NULL,
  key_id          TEXT NOT NULL,
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mem_stream
  ON memory_records (stream_key, seq);
CREATE INDEX IF NOT EXISTS idx_mem_agent
  ON memory_records (agent_id, seq);
CREATE INDEX IF NOT EXISTS idx_mem_target
  ON memory_records (type, stream_key, seq);
"""


def _rows(cursor):
    return [dict(r) for r in cursor.fetchall()]


def _one(cursor):
    r = cursor.fetchone()
    return dict(r) if r is not None else None


class MemoryStoreError(Exception):
    pass


class MemoryStore:
    def __init__(self, conn: sqlite3.Connection, lock=None):
        self.db = conn
        self.db.row_factory = sqlite3.Row
        self._lock = lock or threading.RLock()
        with self._lock:
            self.db.executescript(MEMORY_SCHEMA)
            self.db.commit()

    @classmethod
    def open(cls, path: str) -> "MemoryStore":
        conn = sqlite3.connect(path, check_same_thread=False)
        store = cls(conn, threading.RLock())
        with store._lock:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
        return store

    def close(self):
        with self._lock:
            self.db.close()

    # -- agents ----------------------------------------------------------
    def register_agent(self, agent_id, company_id, team_id, public_key_b64,
                       key_id, registered_at, registered_by):
        with self._lock:
            try:
                self.db.execute(
                    "INSERT INTO memory_agents (agent_id, company_id, team_id,"
                    " public_key_b64, key_id, registered_at, registered_by)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (agent_id, company_id, team_id, public_key_b64, key_id,
                     registered_at, registered_by))
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                raise MemoryStoreError(
                    f"agent {agent_id!r} already registered") from exc

    def get_agent(self, agent_id):
        with self._lock:
            return _one(self.db.execute(
                "SELECT * FROM memory_agents WHERE agent_id=?", (agent_id,)))

    # -- records ----------------------------------------------------------
    def append(self, rec: dict) -> dict:
        """Atomic check-and-insert: seq must continue the stream chain.

        rec is a validated record dict (see records.validate_shape) plus
        'record_hash'. Raises MemoryStoreError on id collision or fork.
        """
        with self._lock:
            last = _one(self.db.execute(
                "SELECT seq, record_hash FROM memory_records"
                " WHERE stream_key=? ORDER BY seq DESC LIMIT 1",
                (rec["stream_key"],)))
            expect_seq = 0 if last is None else last["seq"] + 1
            expect_prev = ("0" * 64) if last is None else last["record_hash"]
            if rec["seq"] != expect_seq:
                raise MemoryStoreError(
                    f"seq fork: stream {rec['stream_key']} expects seq "
                    f"{expect_seq}, got {rec['seq']}")
            if rec["prev_hash"] != expect_prev:
                raise MemoryStoreError(
                    f"chain break: stream {rec['stream_key']} expects "
                    f"prev_hash {expect_prev[:12]}..., got "
                    f"{rec['prev_hash'][:12]}...")
            try:
                self.db.execute(
                    "INSERT INTO memory_records (id, seq, ts, stream_kind,"
                    " company_id, team_id, stream_agent_id, stream_key,"
                    " agent_id, writer_company_id, writer_team_id, type,"
                    " content_json, provenance_json, prev_hash, record_hash,"
                    " signature_b64, key_id, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rec["id"], rec["seq"], rec["ts"], rec["stream_kind"],
                     rec.get("company_id"), rec.get("team_id"),
                     rec.get("stream_agent_id"), rec["stream_key"],
                     rec["agent_id"], rec.get("writer_company_id"),
                     rec.get("writer_team_id"), rec["type"],
                     json.dumps(rec["content"]),
                     json.dumps(rec["provenance"]), rec["prev_hash"],
                     rec["record_hash"], rec["signature_b64"], rec["key_id"],
                     rec["ts"]))
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                raise MemoryStoreError(
                    f"record id {rec['id']!r} already stored") from exc
            return rec

    def get(self, record_id: str):
        with self._lock:
            return _one(self.db.execute(
                "SELECT * FROM memory_records WHERE id=?", (record_id,)))

    def last_in_stream(self, stream_key: str):
        with self._lock:
            return _one(self.db.execute(
                "SELECT * FROM memory_records WHERE stream_key=?"
                " ORDER BY seq DESC LIMIT 1", (stream_key,)))

    def ordered_stream(self, stream_key: str):
        """Full inflated records for a stream, oldest first."""
        with self._lock:
            rows = _rows(self.db.execute(
                "SELECT * FROM memory_records WHERE stream_key=?"
                " ORDER BY seq ASC", (stream_key,)))
        return [self._inflate(r) for r in rows]

    def stream_links(self, stream_key: str):
        """Ordered (seq, record_hash, prev_hash) for chain verification."""
        with self._lock:
            rows = _rows(self.db.execute(
                "SELECT seq, record_hash, prev_hash FROM memory_records"
                " WHERE stream_key=? ORDER BY seq ASC", (stream_key,)))
        return [(r["seq"], r["record_hash"], r["prev_hash"]) for r in rows]

    def distinct_streams(self):
        with self._lock:
            rows = _rows(self.db.execute(
                "SELECT DISTINCT stream_kind, company_id, team_id,"
                " stream_agent_id, stream_key FROM memory_records"))
        return rows

    def query(self, stream_keys=None, tags=None, keyword=None, since=None,
              until=None, types=None, limit=50):
        """Recall query. tags = any-match. keyword = substring on text."""
        sql = ("SELECT * FROM memory_records")
        clauses, params = [], []
        if stream_keys:
            clauses.append("stream_key IN (%s)" % ",".join("?" * len(
                stream_keys)))
            params.extend(stream_keys)
        if types:
            clauses.append("type IN (%s)" % ",".join("?" * len(types)))
            params.extend(types)
        if keyword:
            clauses.append("LOWER(json_extract(content_json, '$.text'))"
                           " LIKE ? ESCAPE '\\'")
            esc = (keyword.lower().replace("\\", "\\\\")
                   .replace("%", "\\%").replace("_", "\\_"))
            params.append("%" + esc + "%")
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts <= ?")
            params.append(until)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC, seq DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock:
            rows = _rows(self.db.execute(sql, params))
        if tags:
            want = {t.lower() for t in tags}
            rows = [r for r in rows
                    if want & {t.lower() for t in
                               json.loads(r["content_json"]).get("tags", [])}]
        return [self._inflate(r) for r in rows]

    def live_supersede(self, target_id: str, stream_key: str):
        """Latest non-retracted supersede targeting target_id, or None."""
        with self._lock:
            rows = _rows(self.db.execute(
                "SELECT * FROM memory_records"
                " WHERE type='memory.supersede' AND stream_key=?"
                " AND json_extract(content_json, '$.target_id')=?"
                " ORDER BY seq DESC", (stream_key, target_id)))
            for r in rows:
                if not self._is_retracted_locked(r["id"], r["stream_key"]):
                    return self._inflate(r)
        return None

    def live_retract(self, target_id: str, stream_key: str):
        with self._lock:
            row = _one(self.db.execute(
                "SELECT * FROM memory_records"
                " WHERE type='memory.retract' AND stream_key=?"
                " AND json_extract(content_json, '$.target_id')=?"
                " ORDER BY seq DESC LIMIT 1", (stream_key, target_id)))
        return self._inflate(row) if row else None

    def _is_retracted_locked(self, record_id: str, stream_key: str) -> bool:
        """Caller must hold the lock."""
        row = _one(self.db.execute(
            "SELECT 1 FROM memory_records WHERE type='memory.retract'"
            " AND stream_key=?"
            " AND json_extract(content_json, '$.target_id')=? LIMIT 1",
            (stream_key, record_id)))
        return row is not None

    @staticmethod
    def _inflate(row: dict) -> dict:
        row = dict(row)
        row["content"] = json.loads(row.pop("content_json"))
        row["provenance"] = json.loads(row.pop("provenance_json"))
        row.pop("created_at", None)
        return row
