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

The PACT record layer tables (pact_consents, pact_audit_entries,
pact_revocations) follow the same rule: rows are inserted, never updated.
The registrations table (public verification-start) is append-only too.
"""
import hashlib
import json
import os
import sqlite3
import threading


def registration_email_hash(email):
    """SHA-256 of the normalized submitter email.

    The cap counters key on this hash (audit item D6): the raw email
    is retained for 12 months and then purged, while the hash — not
    reversible into the address — keeps the counters meaningful for
    rows whose raw email is gone.
    """
    return hashlib.sha256(
        (email or "").strip().lower().encode("utf-8")).hexdigest()

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

-- PACT record layer (flywheel #73): consent records, the hash-chained
-- grant audit log, and grant revocations. Every row stores the full
-- signed record as JSON so each artifact stays independently checkable;
-- all three tables are append-only (a revocation is a new row, and the
-- consent / audit rows are never edited).
CREATE TABLE IF NOT EXISTS pact_consents (
  record_id     TEXT PRIMARY KEY,
  grant_id      TEXT NOT NULL UNIQUE,
  record_json   TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pact_audit_entries (
  grant_id      TEXT NOT NULL,
  seq           INTEGER NOT NULL,
  entry_hash    TEXT NOT NULL,
  record_json   TEXT NOT NULL,
  PRIMARY KEY (grant_id, seq)
);

CREATE TABLE IF NOT EXISTS pact_revocations (
  record_id     TEXT PRIMARY KEY,
  grant_id      TEXT NOT NULL UNIQUE,
  record_json   TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

-- Public registration layer (verification-start): signed content and
-- agent registration records minted by POST /v1/register/*. The full
-- signed record is stored as JSON so it stays independently checkable.
-- The submitter email and client IP live in their own columns, server
-- side only: they exist for the per-email / per-IP submission caps
-- and are never part of the signed public record.
CREATE TABLE IF NOT EXISTS registrations (
  record_id     TEXT PRIMARY KEY,
  kind          TEXT NOT NULL,
  email         TEXT NOT NULL,
  email_hash    TEXT NOT NULL DEFAULT '',
  client_ip     TEXT NOT NULL DEFAULT '',
  record_json   TEXT NOT NULL,
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reg_email
  ON registrations (email, created_at);
CREATE INDEX IF NOT EXISTS idx_reg_email_hash
  ON registrations (email_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_reg_ip
  ON registrations (client_ip, created_at);

-- Verification requests (cycle completion, 2026-10-15): one row per
-- registration that has asked for step two. The signed request
-- record is the queue item NPC works; the registration record
-- itself is immutable and never edited. Attempts are logged with
-- the match outcome so the caps can count probes as well as real
-- requests, mirroring the registration caps. The registrant email
-- is stored as a hash only, exactly like registration caps data.
CREATE TABLE IF NOT EXISTS verification_requests (
  subject_record_id TEXT PRIMARY KEY,
  request_record_id TEXT NOT NULL UNIQUE,
  email_hash        TEXT NOT NULL DEFAULT '',
  client_ip         TEXT NOT NULL DEFAULT '',
  requested_at      TEXT NOT NULL,
  record_json       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verification_request_attempts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id    TEXT NOT NULL,
  email_hash   TEXT NOT NULL DEFAULT '',
  client_ip    TEXT NOT NULL DEFAULT '',
  matched      INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vreqatt_email
  ON verification_request_attempts (email_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_vreqatt_ip
  ON verification_request_attempts (client_ip, created_at);

-- Idempotency keys (audit item D4): one row per (Idempotency-Key,
-- route) for the minting POSTs that honor the header. Stores the
-- request body's canonical hash and the full response, so a replay
-- returns the original response instead of minting a duplicate, and
-- the same key with a different body is a conflict.
CREATE TABLE IF NOT EXISTS idempotency_keys (
  idem_key      TEXT NOT NULL,
  route         TEXT NOT NULL,
  body_hash     TEXT NOT NULL,
  status        INTEGER NOT NULL,
  response_json TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  PRIMARY KEY (idem_key, route)
);

-- Biblo chat (biblo-chat-SPEC-2026-10-15.md section 4). Transcripts
-- and feedback are conversational data, never records: nothing here
-- is signed, and every row carries ttl_epoch (creation + 90 days).
-- SQLite has no native TTL; the column is stored so the retention
-- contract is visible and testable, and the DynamoDB backend expires
-- the same rows for real.
CREATE TABLE IF NOT EXISTS chat_turns (
  thread_id  TEXT NOT NULL,
  seq        INTEGER NOT NULL,
  role       TEXT NOT NULL,
  text       TEXT NOT NULL,
  page       TEXT NOT NULL DEFAULT '',
  sources    TEXT NOT NULL DEFAULT '[]',
  no_answer  INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  ttl_epoch  INTEGER NOT NULL,
  PRIMARY KEY (thread_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_chat_turns_created
  ON chat_turns (created_at);
CREATE TABLE IF NOT EXISTS chat_feedback (
  thread_id  TEXT NOT NULL,
  turn       INTEGER NOT NULL,
  rating     TEXT NOT NULL,
  comment    TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  ttl_epoch  INTEGER NOT NULL,
  PRIMARY KEY (thread_id, turn)
);
CREATE TABLE IF NOT EXISTS chat_daily (
  day           TEXT PRIMARY KEY,
  conversations INTEGER NOT NULL DEFAULT 0,
  turns         INTEGER NOT NULL DEFAULT 0,
  est_micro_usd INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS chat_ip_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  client_ip  TEXT NOT NULL,
  created_at TEXT NOT NULL,
  ttl_epoch  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_ip
  ON chat_ip_events (client_ip, created_at);
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
            self._migrate_registrations()
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

    def _migrate_registrations(self):
        """email_hash column on registrations (added for audit D6).

        Databases created before the retention change get the column
        via ALTER TABLE and a one-time backfill from the raw email,
        so the hash-keyed cap counters cover historical rows too.
        """
        cols = {r["name"]
                for r in self.db.execute("PRAGMA table_info(registrations)")}
        if "email_hash" not in cols:
            self.db.execute(
                "ALTER TABLE registrations ADD COLUMN email_hash"
                " TEXT NOT NULL DEFAULT ''")
            self.db.execute(
                "CREATE INDEX IF NOT EXISTS idx_reg_email_hash"
                " ON registrations (email_hash, created_at)")
        rows = self.db.execute(
            "SELECT record_id, email FROM registrations"
            " WHERE email_hash='' AND email<>''").fetchall()
        for r in rows:
            self.db.execute(
                "UPDATE registrations SET email_hash=? WHERE record_id=?",
                (registration_email_hash(r["email"]), r["record_id"]))

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

    def activate_key(self, key_id, purpose, now):
        """Reactivate an on-record key (retire the purpose's others).

        Mirrors the DynamoDB store's method of the same name; used
        when a key that is already registered (a stable deployment
        key) must become the active signer again. False if the key
        is not on record for that purpose.
        """
        row = self._fetchone(
            "SELECT key_id FROM key_registry WHERE key_id=?"
            " AND purpose=?", (key_id, purpose))
        if row is None:
            return False
        self._write_multi([
            ("UPDATE key_registry SET status='retired', retired_at=? "
             "WHERE purpose=? AND status='active' AND key_id<>?",
             (now, purpose, key_id)),
            ("UPDATE key_registry SET status='active', retired_at=NULL "
             "WHERE key_id=?", (key_id,)),
        ])
        return True

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

    # -- PACT record layer -------------------------------------------------
    def add_pact_consent(self, record) -> bool:
        """Insert a signed consent record. False if the grant exists."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO pact_consents (record_id, grant_id,"
                " record_json, created_at) VALUES (?,?,?,?)",
                (record["record_id"], record["grant_id"],
                 json.dumps(record), record["granted_at"]))
            self.db.commit()
            return cur.rowcount == 1

    def get_pact_consent(self, grant_id):
        row = self._fetchone(
            "SELECT record_json FROM pact_consents WHERE grant_id=?",
            (grant_id,))
        return json.loads(row["record_json"]) if row else None

    def add_pact_audit_entry(self, entry) -> bool:
        """Append one signed audit entry. False on a (grant_id, seq) clash."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO pact_audit_entries (grant_id, seq,"
                " entry_hash, record_json) VALUES (?,?,?,?)",
                (entry["grant_id"], entry["seq"], entry["entry_hash"],
                 json.dumps(entry)))
            self.db.commit()
            return cur.rowcount == 1

    def pact_audit_entries(self, grant_id):
        rows = self._fetchall(
            "SELECT record_json FROM pact_audit_entries WHERE grant_id=?"
            " ORDER BY seq", (grant_id,))
        return [json.loads(r["record_json"]) for r in rows]

    def last_pact_audit_entry(self, grant_id):
        row = self._fetchone(
            "SELECT record_json FROM pact_audit_entries WHERE grant_id=?"
            " ORDER BY seq DESC LIMIT 1", (grant_id,))
        return json.loads(row["record_json"]) if row else None

    def add_pact_revocation(self, record) -> bool:
        """Insert a signed revocation. False if the grant is already revoked."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO pact_revocations (record_id,"
                " grant_id, record_json, created_at) VALUES (?,?,?,?)",
                (record["record_id"], record["grant_id"],
                 json.dumps(record), record["revoked_at"]))
            self.db.commit()
            return cur.rowcount == 1

    def get_pact_revocation(self, grant_id):
        row = self._fetchone(
            "SELECT record_json FROM pact_revocations WHERE grant_id=?",
            (grant_id,))
        return json.loads(row["record_json"]) if row else None

    def get_pact_consent_by_record_id(self, record_id):
        row = self._fetchone(
            "SELECT record_json FROM pact_consents WHERE record_id=?",
            (record_id,))
        return json.loads(row["record_json"]) if row else None

    # -- public registration layer --------------------------------------
    def add_registration(self, record, email, client_ip) -> None:
        """Store a signed registration record (append-only).

        email / client_ip are server-side only (submission caps);
        they are never part of the signed record itself. The email
        hash is stored alongside so the cap counters survive the
        retention purge of the raw email (audit D6).
        """
        self._write(
            "INSERT INTO registrations (record_id, kind, email,"
            " email_hash, client_ip, record_json, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (record["record_id"], record["kind"], email,
             registration_email_hash(email), client_ip or "",
             json.dumps(record), record["registered_at"]))

    def get_registration(self, record_id):
        row = self._fetchone(
            "SELECT record_json FROM registrations WHERE record_id=?",
            (record_id,))
        return json.loads(row["record_json"]) if row else None

    def count_registrations_since(self, dimension, value, since_iso):
        """Count registrations in a rolling window, for the caps.

        dimension is 'email' or 'ip' (a fixed literal chosen by the
        caller, never user input). The email dimension counts by
        email HASH, so rows whose raw email was purged under the
        retention policy still count (audit D6). Timestamps are
        ISO-8601 UTC, so lexicographic comparison is chronological
        comparison.
        """
        if dimension == "email":
            row = self._fetchone(
                "SELECT COUNT(*) AS n FROM registrations"
                " WHERE email_hash=? AND created_at>=?",
                (registration_email_hash(value), since_iso))
        else:
            row = self._fetchone(
                "SELECT COUNT(*) AS n FROM registrations"
                " WHERE client_ip=? AND created_at>=?",
                (value, since_iso))
        return row["n"] if row else 0

    def purge_registration_emails(self, cutoff_iso) -> int:
        """Retention sweep (audit D6): blank the raw email on every
        registration created before cutoff_iso. The signed record and
        the email hash (the cap counter key) are untouched. Returns
        how many rows were purged."""
        return self._write(
            "UPDATE registrations SET email='' WHERE created_at<?"
            " AND email<>''", (cutoff_iso,))

    # -- verification requests (cycle completion) ----------------------
    def registration_email_hash(self, record_id):
        """The stored submitter email hash for a registration, or
        None when the record is not a registration. The hash survives
        the retention purge, so a registrant can still be matched
        after their raw email is gone."""
        row = self._fetchone(
            "SELECT email_hash FROM registrations WHERE record_id=?",
            (record_id,))
        return row["email_hash"] if row else None

    def registration_email(self, record_id):
        """The stored raw submitter email for a registration, or
        None. Server-side only, like every email accessor here: it
        exists so the record's own lifecycle mail (npc_verify.
        mailer) can reach the registrant. After the D6 retention
        purge the raw email is gone and this returns None, even
        though the hash survives."""
        row = self._fetchone(
            "SELECT email FROM registrations WHERE record_id=?",
            (record_id,))
        if row is None:
            return None
        return row["email"] or None

    def add_verification_request(self, record, subject_record_id,
                                 email, client_ip) -> bool:
        """Store a signed verification-request record. Put-if-absent
        on the subject: False when a request already exists (the
        caller returns the existing one)."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO verification_requests"
                " (subject_record_id, request_record_id, email_hash,"
                " client_ip, requested_at, record_json)"
                " VALUES (?,?,?,?,?,?)",
                (subject_record_id, record["record_id"],
                 registration_email_hash(email), client_ip or "",
                 record["requested_at"], json.dumps(record)))
            self.db.commit()
            return cur.rowcount > 0

    def get_verification_request(self, subject_record_id):
        row = self._fetchone(
            "SELECT record_json FROM verification_requests"
            " WHERE subject_record_id=?", (subject_record_id,))
        return json.loads(row["record_json"]) if row else None

    def list_verification_requests(self):
        """Every open verification request, oldest first: NPC's
        step-two work queue."""
        rows = self._fetchall(
            "SELECT record_json FROM verification_requests"
            " ORDER BY requested_at ASC")
        return [json.loads(r["record_json"]) for r in rows]

    def record_verification_request_attempt(self, record_id, email,
                                            client_ip, matched,
                                            created_at):
        self._write(
            "INSERT INTO verification_request_attempts (record_id,"
            " email_hash, client_ip, matched, created_at)"
            " VALUES (?,?,?,?,?)",
            (record_id, registration_email_hash(email),
             client_ip or "", 1 if matched else 0, created_at))

    def count_verification_request_attempts_since(self, dimension,
                                                  value, since_iso):
        """Count request-verification attempts in a rolling window,
        mirroring count_registrations_since: the email dimension
        counts by hash."""
        if dimension == "email":
            row = self._fetchone(
                "SELECT COUNT(*) AS n FROM"
                " verification_request_attempts"
                " WHERE email_hash=? AND created_at>=?",
                (registration_email_hash(value), since_iso))
        else:
            row = self._fetchone(
                "SELECT COUNT(*) AS n FROM"
                " verification_request_attempts"
                " WHERE client_ip=? AND created_at>=?",
                (value, since_iso))
        return row["n"] if row else 0

    # -- idempotency keys (audit D4) -------------------------------------
    def get_idempotency(self, idem_key, route):
        """The stored response for (key, route), or None."""
        row = self._fetchone(
            "SELECT body_hash, status, response_json FROM"
            " idempotency_keys WHERE idem_key=? AND route=?",
            (idem_key, route))
        if row is None:
            return None
        return {"body_hash": row["body_hash"], "status": row["status"],
                "response": json.loads(row["response_json"])}

    def put_idempotency(self, idem_key, route, body_hash, status,
                        response, created_at) -> bool:
        """Store a response under (key, route). False if the pair is
        already taken (a concurrent mint won the race)."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO idempotency_keys (idem_key,"
                " route, body_hash, status, response_json, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (idem_key, route, body_hash, status,
                 json.dumps(response), created_at))
            self.db.commit()
            return cur.rowcount == 1

    # -- Biblo chat (spec section 4) --------------------------------------
    def append_chat_turn(self, thread_id, role, text, page, sources,
                         no_answer, created_at, ttl_epoch) -> int:
        """Append one turn to a thread; returns its 1-based seq."""
        with self._lock:
            row = self.db.execute(
                "SELECT COALESCE(MAX(seq), 0) AS m FROM chat_turns"
                " WHERE thread_id=?", (thread_id,)).fetchone()
            seq = int(row["m"]) + 1
            self.db.execute(
                "INSERT INTO chat_turns (thread_id, seq, role, text,"
                " page, sources, no_answer, created_at, ttl_epoch)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (thread_id, seq, role, text, page or "",
                 json.dumps(list(sources or [])),
                 1 if no_answer else 0, created_at, int(ttl_epoch)))
            self.db.commit()
            return seq

    def get_chat_turns(self, thread_id):
        """All turns of a thread, in order. Empty list: no such thread."""
        rows = self._fetchall(
            "SELECT seq, role, text, page, sources, no_answer,"
            " created_at, ttl_epoch FROM chat_turns WHERE thread_id=?"
            " ORDER BY seq", (thread_id,))
        for r in rows:
            r["sources"] = json.loads(r["sources"])
            r["no_answer"] = bool(r["no_answer"])
        return rows

    def chat_thread_exists(self, thread_id) -> bool:
        return self._fetchone(
            "SELECT 1 AS x FROM chat_turns WHERE thread_id=? LIMIT 1",
            (thread_id,)) is not None

    def put_chat_feedback(self, thread_id, turn, rating, comment,
                          created_at, ttl_epoch) -> None:
        self._write(
            "INSERT OR REPLACE INTO chat_feedback (thread_id, turn,"
            " rating, comment, created_at, ttl_epoch)"
            " VALUES (?,?,?,?,?,?)",
            (thread_id, int(turn), rating, comment or "", created_at,
             int(ttl_epoch)))

    def get_chat_feedback(self, thread_id):
        rows = self._fetchall(
            "SELECT turn, rating, comment, created_at, ttl_epoch FROM"
            " chat_feedback WHERE thread_id=? ORDER BY turn",
            (thread_id,))
        return rows

    def get_chat_daily(self, day):
        row = self._fetchone(
            "SELECT conversations, turns, est_micro_usd FROM chat_daily"
            " WHERE day=?", (day,))
        if row is None:
            return {"conversations": 0, "turns": 0, "est_micro_usd": 0}
        return {"conversations": int(row["conversations"]),
                "turns": int(row["turns"]),
                "est_micro_usd": int(row["est_micro_usd"])}

    def bump_chat_daily(self, day, conversations=0, turns=0,
                        est_micro_usd=0, ttl_epoch=None) -> None:
        # ttl_epoch is accepted for interface parity with the
        # DynamoDB backend (whose CHATCAP item carries the attribute);
        # the SQLite counter row is an aggregate, not a transcript,
        # and the transcripts themselves carry the TTL.
        with self._lock:
            self.db.execute(
                "INSERT INTO chat_daily (day, conversations, turns,"
                " est_micro_usd) VALUES (?,?,?,?)"
                " ON CONFLICT(day) DO UPDATE SET"
                " conversations=conversations+excluded.conversations,"
                " turns=turns+excluded.turns,"
                " est_micro_usd=est_micro_usd+excluded.est_micro_usd",
                (day, int(conversations), int(turns),
                 int(est_micro_usd)))
            self.db.commit()

    def record_chat_ip_event(self, client_ip, created_at,
                             ttl_epoch) -> None:
        self._write(
            "INSERT INTO chat_ip_events (client_ip, created_at,"
            " ttl_epoch) VALUES (?,?,?)",
            (client_ip, created_at, int(ttl_epoch)))

    def count_chat_ip_events(self, client_ip, since_iso) -> int:
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM chat_ip_events WHERE"
            " client_ip=? AND created_at>=?", (client_ip, since_iso))
        return int(row["n"]) if row else 0

    def note_chat_thread_day(self, thread_id, day, created_at,
                             ttl_epoch) -> None:
        """Interface parity with the DynamoDB backend, which keeps a
        per-day thread index. SQLite derives the same answer from
        chat_turns directly (see chat_threads_on), so this is a no-op."""

    def chat_threads_on(self, day):
        """Thread ids with any turn created on the given UTC day
        (created_at is ISO-8601 UTC, so the day is a prefix)."""
        rows = self._fetchall(
            "SELECT DISTINCT thread_id FROM chat_turns WHERE"
            " substr(created_at, 1, 10)=? ORDER BY thread_id", (day,))
        return [r["thread_id"] for r in rows]


def make_store(path: str):
    """Construct the store backend selected by the environment.

    Default (NPC_STORE_BACKEND absent or anything but "dynamodb") is
    the SQLite Store above, so local dev and the test suite are
    untouched. NPC_STORE_BACKEND=dynamodb selects the DynamoDB store
    (npc_verify.ddb_store) against NPC_DDB_TABLE (default
    "npc-verify-store"); the region comes from NPC_AWS_REGION or the
    standard AWS_REGION / AWS_DEFAULT_REGION the Lambda runtime sets.
    """
    if os.environ.get("NPC_STORE_BACKEND", "").strip().lower() \
            == "dynamodb":
        from .ddb_store import DynamoDBStore
        return DynamoDBStore(
            table_name=os.environ.get("NPC_DDB_TABLE")
            or "npc-verify-store",
            region=os.environ.get("NPC_AWS_REGION") or None)
    return Store(path)
