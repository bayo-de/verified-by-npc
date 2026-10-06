"""SQLite store for the Verification API v1.

The schema is written in portable SQL (TEXT / INTEGER columns, ISO-8601
timestamps as TEXT, JSON in TEXT columns) so it moves to Postgres with
minimal changes: the only SQLite-specific calls are the connection setup
and PRAGMAs.

Thread safety: the HTTP server handles requests on worker threads, so the
connection is opened with check_same_thread=False and every database
operation runs under a re-entrant lock.

Attestations are append-only. Revocation is a new signed record in the
revocations table; the attestations row is flagged, never edited otherwise.
"""
import json
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS attestations (
  id            TEXT PRIMARY KEY,
  subject_type  TEXT NOT NULL,
  subject_id    TEXT NOT NULL,
  verdict       TEXT NOT NULL,
  scope_json    TEXT NOT NULL DEFAULT '{}',
  tested_at     TEXT NOT NULL,
  expires_at    TEXT,
  findings_summary TEXT NOT NULL,
  claim_hash    TEXT,
  signature_b64 TEXT NOT NULL,
  key_id        TEXT NOT NULL,
  anchor_chain  TEXT NOT NULL DEFAULT 'base',
  anchor_tx     TEXT,
  anchor_hash   TEXT NOT NULL,
  anchor_status TEXT NOT NULL DEFAULT 'not_anchored',
  revoked       INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_att_subject
  ON attestations (subject_type, subject_id, created_at);
CREATE INDEX IF NOT EXISTS idx_att_claim ON attestations (claim_hash);

CREATE TABLE IF NOT EXISTS revocations (
  id            TEXT PRIMARY KEY,
  attestation_id TEXT NOT NULL,
  reason        TEXT NOT NULL,
  signature_b64 TEXT NOT NULL,
  key_id        TEXT NOT NULL,
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rev_att ON revocations (attestation_id);

CREATE TABLE IF NOT EXISTS credentials (
  id            TEXT PRIMARY KEY,
  status        TEXT NOT NULL,
  title         TEXT NOT NULL,
  issuer        TEXT NOT NULL,
  holder_name   TEXT,
  holder_public INTEGER NOT NULL DEFAULT 0,
  issued_at     TEXT NOT NULL,
  expires_at    TEXT,
  skills_json   TEXT NOT NULL DEFAULT '[]',
  signature_b64 TEXT NOT NULL DEFAULT '',
  key_id        TEXT NOT NULL DEFAULT '',
  verification_url TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS products (
  tag_id        TEXT PRIMARY KEY,
  status        TEXT NOT NULL,
  name          TEXT NOT NULL,
  creator       TEXT NOT NULL,
  description   TEXT NOT NULL DEFAULT '',
  provenance_json TEXT NOT NULL DEFAULT '[]',
  attestation_id TEXT
);

CREATE TABLE IF NOT EXISTS agents (
  agent_id      TEXT PRIMARY KEY,
  verdict       TEXT NOT NULL,
  scope_json    TEXT NOT NULL DEFAULT '{}',
  valid_from    TEXT NOT NULL,
  valid_until   TEXT,
  attestation_id TEXT NOT NULL,
  notes         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS api_keys (
  key_hash      TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  role          TEXT NOT NULL,
  per_minute    INTEGER NOT NULL DEFAULT 60,
  created_at    TEXT NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS key_registry (
  key_id        TEXT PRIMARY KEY,
  purpose       TEXT NOT NULL,
  public_key_b64 TEXT NOT NULL,
  status        TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  retired_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_keyreg_purpose
  ON key_registry (purpose, status);
"""


def _rows(cursor):
    return [dict(r) for r in cursor.fetchall()]


def _one(cursor):
    r = cursor.fetchone()
    return dict(r) if r is not None else None


class Store:
    def __init__(self, path: str):
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.RLock()
        self.db.row_factory = sqlite3.Row
        with self._lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.executescript(SCHEMA)
            self._migrate_api_keys()
            self.db.commit()

    @property
    def db_lock(self):
        """Shared lock, so the memory store can guard the same connection."""
        return self._lock

    def _migrate_api_keys(self):
        """Company-layer columns on api_keys (added in Phase 3).

        Older databases created before the migration get the columns via
        ALTER TABLE; the column names are fixed literals, not user input.
        """
        cols = {r["name"]
                for r in self.db.execute("PRAGMA table_info(api_keys)")}
        for col in ("company_id", "team_id", "agent_id"):
            if col not in cols:
                self.db.execute(
                    f"ALTER TABLE api_keys ADD COLUMN {col} TEXT")

    def close(self):
        with self._lock:
            self.db.close()

    # -- low-level helpers (always under lock) --------------------------------
    def _fetchone(self, sql, params=()):
        with self._lock:
            return _one(self.db.execute(sql, params))

    def _fetchall(self, sql, params=()):
        with self._lock:
            return _rows(self.db.execute(sql, params))

    def _write(self, sql, params=()):
        with self._lock:
            cur = self.db.execute(sql, params)
            self.db.commit()
            return cur.rowcount

    def _write_multi(self, statements):
        """Run several writes atomically. statements: [(sql, params)]."""
        with self._lock:
            counts = []
            for sql, params in statements:
                counts.append(self.db.execute(sql, params).rowcount)
            self.db.commit()
            return counts

    # -- attestations -------------------------------------------------------
    def add_attestation(self, a) -> None:
        self._write(
            "INSERT INTO attestations (id, subject_type, subject_id, verdict,"
            " scope_json, tested_at, expires_at, findings_summary, claim_hash,"
            " signature_b64, key_id, anchor_chain, anchor_tx, anchor_hash,"
            " anchor_status, revoked, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (a.id, a.subject_type, a.subject_id, a.verdict,
             json.dumps(a.scope), a.tested_at, a.expires_at,
             a.findings_summary, a.claim_hash, a.signature_b64, a.key_id,
             a.anchor_chain, a.anchor_tx, a.anchor_hash, a.anchor_status,
             1 if a.revoked else 0, a.created_at))

    def get_attestation(self, att_id):
        return self._fetchone(
            "SELECT * FROM attestations WHERE id=?", (att_id,))

    def latest_attestation(self, subject_type, subject_id):
        return self._fetchone(
            "SELECT * FROM attestations WHERE subject_type=? AND subject_id=?"
            " AND revoked=0 ORDER BY created_at DESC LIMIT 1",
            (subject_type, subject_id))

    def attestations_by_claim_hash(self, claim_hash):
        return self._fetchall(
            "SELECT * FROM attestations WHERE claim_hash=? AND revoked=0"
            " ORDER BY created_at DESC",
            (claim_hash,))

    def revoke_attestation(self, att_id, rev_id, reason, sig_b64, key_id,
                           created_at):
        with self._lock:
            cur = self.db.execute(
                "UPDATE attestations SET revoked=1 WHERE id=? AND revoked=0",
                (att_id,))
            if cur.rowcount == 0:
                self.db.rollback()
                return False
            self.db.execute(
                "INSERT INTO revocations (id, attestation_id, reason,"
                " signature_b64, key_id, created_at) VALUES (?,?,?,?,?,?)",
                (rev_id, att_id, reason, sig_b64, key_id, created_at))
            self.db.commit()
            return True

    # -- credentials / products / agents ------------------------------------
    def get_credential(self, cred_id):
        return self._fetchone(
            "SELECT * FROM credentials WHERE id=?", (cred_id,))

    def get_product(self, tag_id):
        return self._fetchone(
            "SELECT * FROM products WHERE tag_id=?", (tag_id,))

    def get_agent(self, agent_id):
        return self._fetchone(
            "SELECT * FROM agents WHERE agent_id=?", (agent_id,))

    def insert_credential(self, c):
        self._write(
            "INSERT INTO credentials (id, status, title, issuer, holder_name,"
            " holder_public, issued_at, expires_at, skills_json,"
            " signature_b64, key_id, verification_url)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (c.id, c.status, c.title, c.issuer, c.holder_name,
             1 if c.holder_public else 0, c.issued_at, c.expires_at,
             json.dumps(c.assessed_skills), c.signature_b64, c.key_id,
             c.verification_url))

    def insert_product(self, p):
        self._write(
            "INSERT INTO products (tag_id, status, name, creator, description,"
            " provenance_json, attestation_id) VALUES (?,?,?,?,?,?,?)",
            (p.tag_id, p.status, p.name, p.creator, p.description,
             json.dumps(p.provenance), p.attestation_id))

    def insert_agent(self, agent_id, verdict, scope, valid_from, valid_until,
                     attestation_id, notes):
        self._write(
            "INSERT INTO agents (agent_id, verdict, scope_json, valid_from,"
            " valid_until, attestation_id, notes) VALUES (?,?,?,?,?,?,?)",
            (agent_id, verdict, json.dumps(scope), valid_from, valid_until,
             attestation_id, notes))

    # -- api keys ------------------------------------------------------------
    def add_api_key(self, key_hash, name, role, per_minute, created_at,
                    company_id=None, team_id=None, agent_id=None):
        self._write(
            "INSERT INTO api_keys (key_hash, name, role, per_minute,"
            " created_at, revoked, company_id, team_id, agent_id)"
            " VALUES (?,?,?,?,?,0,?,?,?)",
            (key_hash, name, role, per_minute, created_at,
             company_id, team_id, agent_id))

    def get_api_key(self, key_hash):
        return self._fetchone(
            "SELECT * FROM api_keys WHERE key_hash=? AND revoked=0",
            (key_hash,))

    # -- key registry ----------------------------------------------------------
    def register_key(self, key_id, purpose, public_key_b64, created_at):
        self._write_multi([
            ("UPDATE key_registry SET status='retired', retired_at=? "
             "WHERE purpose=? AND status='active'", (created_at, purpose)),
            ("INSERT INTO key_registry (key_id, purpose, public_key_b64,"
             " status, created_at, retired_at) VALUES (?,?,?,?,?,NULL)",
             (key_id, purpose, public_key_b64, "active", created_at)),
        ])

    def active_key_id(self, purpose):
        row = self._fetchone(
            "SELECT key_id FROM key_registry WHERE purpose=? AND status='active'",
            (purpose,))
        return row["key_id"] if row else None

    def public_key_b64(self, key_id):
        row = self._fetchone(
            "SELECT public_key_b64 FROM key_registry WHERE key_id=?",
            (key_id,))
        return row["public_key_b64"] if row else None

    def all_keys(self):
        return self._fetchall(
            "SELECT key_id, purpose, public_key_b64, status, created_at,"
            " retired_at FROM key_registry ORDER BY created_at")
