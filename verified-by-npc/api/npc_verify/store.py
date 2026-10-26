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

-- Federated identity linking (phase 1, 2026-10-19; design in
-- integrations/federated-identity-signals-DESIGN-2026-10-19.md).
-- Everything here lives behind NPC_IDENTITY_SIGNALS=1. A link is its
-- own signed record in identity_links, never an edit to the
-- registration it attaches to. Challenges (a SIWE nonce, an OAuth
-- state) are single-use and short-lived; the email is stored as a
-- hash only, like every other server-side email touch. Observations
-- are append-only: each Coinbase re-read adds a row, and the panel
-- reads the latest one per (record, wallet, signal), so a revoked
-- or expired attestation stops producing its signal without
-- rewriting history.
CREATE TABLE IF NOT EXISTS identity_link_challenges (
  challenge_id      TEXT PRIMARY KEY,
  kind              TEXT NOT NULL,
  provider          TEXT NOT NULL DEFAULT '',
  subject_record_id TEXT NOT NULL,
  email_hash        TEXT NOT NULL DEFAULT '',
  secret            TEXT NOT NULL,
  wallet            TEXT NOT NULL DEFAULT '',
  created_at        TEXT NOT NULL,
  expires_at        TEXT NOT NULL,
  consumed_at       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS identity_links (
  link_id           TEXT PRIMARY KEY,
  subject_record_id TEXT NOT NULL,
  provider          TEXT NOT NULL,
  signal            TEXT NOT NULL,
  subject_ref       TEXT NOT NULL,
  linked_at         TEXT NOT NULL,
  record_json       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ilink_subject
  ON identity_links (subject_record_id, linked_at);
CREATE TABLE IF NOT EXISTS identity_observations (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_record_id TEXT NOT NULL,
  wallet            TEXT NOT NULL,
  provider          TEXT NOT NULL,
  signal            TEXT NOT NULL,
  attestation_uid   TEXT NOT NULL DEFAULT '',
  state             TEXT NOT NULL,
  attested_at       TEXT NOT NULL DEFAULT '',
  expires_at        TEXT NOT NULL DEFAULT '',
  observed_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iobs_subject
  ON identity_observations (subject_record_id, wallet, signal, id);
CREATE TABLE IF NOT EXISTS identity_link_attempts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id    TEXT NOT NULL,
  email_hash   TEXT NOT NULL DEFAULT '',
  client_ip    TEXT NOT NULL DEFAULT '',
  matched      INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ilatt_email
  ON identity_link_attempts (email_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_ilatt_ip
  ON identity_link_attempts (client_ip, created_at);

-- Social profiles content-registration lane (build pass 1,
-- 2026-10-19; design in integrations/DESIGN.md). Everything here
-- lives behind NPC_SOCIAL_PROFILES=1. A connection is NPC's
-- server-side handle on a customer's platform account: it holds
-- the OAuth tokens (server-side only, never written into a signed
-- record, a batch receipt, or a response) and the platform's own
-- account id, which is the identity anchor for idempotency, so a
-- reconnect dedupes against the same registrations. The owner's
-- email is stored as a hash only, like every other server-side
-- email touch. Scans are the cached platform metadata from one
-- enumeration; registrations are indexed per owner so a rescan
-- classifies unchanged / new-version instead of duplicating.
-- Batches hold the signed batch receipt records.
CREATE TABLE IF NOT EXISTS social_challenges (
  challenge_id TEXT PRIMARY KEY,
  platform     TEXT NOT NULL,
  email_hash   TEXT NOT NULL DEFAULT '',
  secret       TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  consumed_at  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS social_connections (
  connection_id       TEXT PRIMARY KEY,
  platform            TEXT NOT NULL,
  email_hash          TEXT NOT NULL DEFAULT '',
  platform_account_id TEXT NOT NULL,
  account_display_name TEXT NOT NULL DEFAULT '',
  access_token        TEXT NOT NULL DEFAULT '',
  refresh_token       TEXT NOT NULL DEFAULT '',
  token_expires_at    TEXT NOT NULL DEFAULT '',
  scopes              TEXT NOT NULL DEFAULT '',
  status              TEXT NOT NULL DEFAULT 'active',
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_soconn_owner
  ON social_connections (platform, email_hash, platform_account_id);
CREATE TABLE IF NOT EXISTS social_scans (
  scan_id       TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL,
  enumerated_at TEXT NOT NULL,
  item_count    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS social_scan_items (
  scan_id         TEXT NOT NULL,
  external_id     TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  item_json       TEXT NOT NULL,
  PRIMARY KEY (scan_id, external_id)
);
CREATE TABLE IF NOT EXISTS social_registrations (
  email_hash      TEXT NOT NULL,
  identity_key    TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  record_id       TEXT NOT NULL,
  batch_id        TEXT NOT NULL DEFAULT '',
  platform        TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL,
  PRIMARY KEY (email_hash, identity_key)
);
CREATE TABLE IF NOT EXISTS social_batches (
  batch_id      TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL DEFAULT '',
  record_json   TEXT NOT NULL,
  created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS social_attempts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  target     TEXT NOT NULL DEFAULT '',
  email_hash TEXT NOT NULL DEFAULT '',
  client_ip  TEXT NOT NULL DEFAULT '',
  matched    INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_soatt_email
  ON social_attempts (email_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_soatt_ip
  ON social_attempts (client_ip, created_at);
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

    def attestations_for_subject(self, subject_type, subject_id):
        """Every attestation ever issued for a subject, revoked
        ones included, oldest first. This is the input set for the
        agent rating (npc_verify.kya.compute_agent_rating):
        reputation is formed from the whole history, so unlike the
        latest-attestation reads this one filters nothing out."""
        return self._fetchall(
            "SELECT * FROM attestations WHERE subject_type=?"
            " AND subject_id=? ORDER BY tested_at ASC,"
            " created_at ASC, id ASC",
            (subject_type, subject_id))

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

    def registration_for_agent(self, agent_id):
        """The agent registration that names this agent_id, or None.

        Agent registrations record the agent_id they cover only
        when the owner supplied one (registry.validate_agent_input);
        that recorded agent_id is the chain from an attestation's
        subject back to the registration that names its accountable
        owner. The newest matching registration wins. When no
        registration names the agent, the chain is not recorded and
        this returns None: callers print the principal as absent
        rather than guess at one.
        """
        if not agent_id:
            return None
        rows = self._fetchall(
            "SELECT record_json FROM registrations WHERE kind='agent'"
            " ORDER BY created_at DESC")
        for row in rows:
            try:
                record = json.loads(row["record_json"])
            except (ValueError, TypeError):
                continue
            if isinstance(record, dict) \
                    and record.get("agent_id") == agent_id:
                return record
        return None

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

    # -- federated identity linking (phase 1) ---------------------------
    def add_identity_link_challenge(self, row) -> bool:
        """Store a pending link challenge (a SIWE nonce or an OAuth
        state). Put-if-absent on the challenge id."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO identity_link_challenges"
                " (challenge_id, kind, provider, subject_record_id,"
                " email_hash, secret, wallet, created_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (row["challenge_id"], row["kind"],
                 row.get("provider", ""), row["subject_record_id"],
                 row.get("email_hash", ""), row["secret"],
                 row.get("wallet", ""), row["created_at"],
                 row["expires_at"]))
            self.db.commit()
            return cur.rowcount > 0

    def get_identity_link_challenge(self, challenge_id):
        return self._fetchone(
            "SELECT * FROM identity_link_challenges"
            " WHERE challenge_id=?", (challenge_id,))

    def find_identity_link_challenge(self, kind, provider, secret):
        """The open challenge carrying this secret (an OAuth state),
        or None. Secrets are random and single-use; the lookup is by
        exact match on all three fields."""
        return self._fetchone(
            "SELECT * FROM identity_link_challenges"
            " WHERE kind=? AND provider=? AND secret=?"
            " AND consumed_at=''",
            (kind, provider, secret))

    def consume_identity_link_challenge(self, challenge_id,
                                        consumed_at) -> bool:
        """Mark a challenge used. False when it was already consumed
        (or never existed), so a replay fails closed."""
        return self._write(
            "UPDATE identity_link_challenges SET consumed_at=?"
            " WHERE challenge_id=? AND consumed_at=''",
            (consumed_at, challenge_id)) > 0

    def add_identity_link(self, record) -> bool:
        """Store a signed identity-link record. Put-if-absent on the
        link id; the signal summary columns are denormalized from
        the record's own signal entry for panel reads."""
        entry = record["signal"]
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO identity_links (link_id,"
                " subject_record_id, provider, signal, subject_ref,"
                " linked_at, record_json) VALUES (?,?,?,?,?,?,?)",
                (record["record_id"], record["subject_record_id"],
                 entry["provider"], entry["signal"],
                 entry["subject_ref"], record["linked_at"],
                 json.dumps(record)))
            self.db.commit()
            return cur.rowcount > 0

    def get_identity_link(self, link_id):
        row = self._fetchone(
            "SELECT record_json FROM identity_links WHERE link_id=?",
            (link_id,))
        return json.loads(row["record_json"]) if row else None

    def list_identity_links(self, subject_record_id):
        """Every link record attached to a registration, oldest
        first."""
        rows = self._fetchall(
            "SELECT record_json FROM identity_links"
            " WHERE subject_record_id=? ORDER BY linked_at ASC",
            (subject_record_id,))
        return [json.loads(r["record_json"]) for r in rows]

    def add_identity_observation(self, row) -> None:
        """Append one provider observation (a Coinbase re-read).
        History is kept; readers take the latest row per key."""
        self._write(
            "INSERT INTO identity_observations (subject_record_id,"
            " wallet, provider, signal, attestation_uid, state,"
            " attested_at, expires_at, observed_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (row["subject_record_id"], row["wallet"].lower(),
             row["provider"], row["signal"],
             row.get("attestation_uid", ""), row["state"],
             row.get("attested_at", ""), row.get("expires_at", ""),
             row["observed_at"]))

    def latest_identity_observations(self, subject_record_id):
        """The latest observation per (wallet, provider, signal) for
        a record, keyed by that tuple. The wallet key is lowercase;
        callers compare case-insensitively."""
        rows = self._fetchall(
            "SELECT * FROM identity_observations"
            " WHERE subject_record_id=? ORDER BY id ASC",
            (subject_record_id,))
        latest = {}
        for row in rows:
            latest[(row["wallet"], row["provider"],
                    row["signal"])] = row
        return latest

    def record_identity_link_attempt(self, record_id, email,
                                     client_ip, matched, created_at):
        self._write(
            "INSERT INTO identity_link_attempts (record_id,"
            " email_hash, client_ip, matched, created_at)"
            " VALUES (?,?,?,?,?)",
            (record_id, registration_email_hash(email),
             client_ip or "", 1 if matched else 0, created_at))

    def count_identity_link_attempts_since(self, dimension, value,
                                           since_iso):
        """Count link attempts in a rolling window, mirroring the
        verification-request counters: the email dimension counts by
        hash."""
        if dimension == "email":
            row = self._fetchone(
                "SELECT COUNT(*) AS n FROM identity_link_attempts"
                " WHERE email_hash=? AND created_at>=?",
                (registration_email_hash(value), since_iso))
        else:
            row = self._fetchone(
                "SELECT COUNT(*) AS n FROM identity_link_attempts"
                " WHERE client_ip=? AND created_at>=?",
                (value, since_iso))
        return row["n"] if row else 0

    # -- social profiles lane (build pass 1) ----------------------------
    def add_social_challenge(self, row) -> bool:
        """Store a pending connect challenge (an OAuth state).
        Put-if-absent on the challenge id."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO social_challenges"
                " (challenge_id, platform, email_hash, secret,"
                " created_at, expires_at) VALUES (?,?,?,?,?,?)",
                (row["challenge_id"], row["platform"],
                 row.get("email_hash", ""), row["secret"],
                 row["created_at"], row["expires_at"]))
            self.db.commit()
            return cur.rowcount > 0

    def find_social_challenge(self, platform, secret):
        """The open challenge carrying this OAuth state, or None.
        States are random and single-use; the lookup is by exact
        match on both fields."""
        return self._fetchone(
            "SELECT * FROM social_challenges"
            " WHERE platform=? AND secret=? AND consumed_at=''",
            (platform, secret))

    def consume_social_challenge(self, challenge_id,
                                 consumed_at) -> bool:
        """Mark a challenge used. False when it was already consumed
        (or never existed), so a replay fails closed."""
        return self._write(
            "UPDATE social_challenges SET consumed_at=?"
            " WHERE challenge_id=? AND consumed_at=''",
            (consumed_at, challenge_id)) > 0

    def add_social_connection(self, row) -> bool:
        """Store a platform connection. Put-if-absent on the
        connection id. Tokens live only in this row."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO social_connections"
                " (connection_id, platform, email_hash,"
                " platform_account_id, account_display_name,"
                " access_token, refresh_token, token_expires_at,"
                " scopes, status, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (row["connection_id"], row["platform"],
                 row.get("email_hash", ""),
                 row["platform_account_id"],
                 row.get("account_display_name", ""),
                 row.get("access_token", ""),
                 row.get("refresh_token", ""),
                 row.get("token_expires_at", ""),
                 row.get("scopes", ""),
                 row.get("status", "active"),
                 row["created_at"], row["updated_at"]))
            self.db.commit()
            return cur.rowcount > 0

    def get_social_connection(self, connection_id):
        return self._fetchone(
            "SELECT * FROM social_connections"
            " WHERE connection_id=?", (connection_id,))

    def find_social_connection(self, platform, email_hash,
                               platform_account_id):
        """The connection for one (platform, owner, platform
        account), any status, or None. This is the reconnect
        lookup: the platform account is the identity anchor."""
        return self._fetchone(
            "SELECT * FROM social_connections WHERE platform=?"
            " AND email_hash=? AND platform_account_id=?"
            " ORDER BY created_at DESC",
            (platform, email_hash, platform_account_id))

    def list_social_connections(self, email_hash):
        """Every active connection the owner holds, oldest first.
        Rows carry tokens; the service strips them before any
        response."""
        return self._fetchall(
            "SELECT * FROM social_connections WHERE email_hash=?"
            " AND status='active' ORDER BY created_at ASC",
            (email_hash,))

    def update_social_connection(self, connection_id, fields) -> bool:
        """Refresh a connection's tokens and display fields (a
        reconnect, a token refresh). Only the named columns move;
        the column names are fixed literals chosen by the caller,
        never user input."""
        allowed = ("access_token", "refresh_token",
                   "token_expires_at", "account_display_name",
                   "scopes", "status", "updated_at")
        sets = [(k, fields[k]) for k in allowed if k in fields]
        if not sets:
            return False
        sql = "UPDATE social_connections SET %s WHERE connection_id=?" \
            % ", ".join("%s=?" % k for k, _v in sets)
        return self._write(sql, tuple(v for _k, v in sets)
                           + (connection_id,)) > 0

    def disconnect_social_connection(self, connection_id,
                                     updated_at) -> bool:
        """End a connection: status disconnected, tokens blanked.
        The signed records the customer holds are untouched."""
        return self._write(
            "UPDATE social_connections SET status='disconnected',"
            " access_token='', refresh_token='', updated_at=?"
            " WHERE connection_id=? AND status='active'",
            (updated_at, connection_id)) > 0

    def add_social_scan(self, row) -> bool:
        """Store one enumeration (the scan header). Put-if-absent
        on the scan id."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO social_scans (scan_id,"
                " connection_id, enumerated_at, item_count)"
                " VALUES (?,?,?,?)",
                (row["scan_id"], row["connection_id"],
                 row["enumerated_at"], row.get("item_count", 0)))
            self.db.commit()
            return cur.rowcount > 0

    def get_social_scan(self, scan_id):
        return self._fetchone(
            "SELECT * FROM social_scans WHERE scan_id=?",
            (scan_id,))

    def add_social_scan_item(self, scan_id, item) -> bool:
        """Store one enumerated work under its scan. Put-if-absent
        on (scan, external id)."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO social_scan_items (scan_id,"
                " external_id, idempotency_key, item_json)"
                " VALUES (?,?,?,?)",
                (scan_id, item["external_id"],
                 item["idempotency_key"], json.dumps(item)))
            self.db.commit()
            return cur.rowcount > 0

    def list_social_scan_items(self, scan_id):
        """Every work one scan enumerated, in scan order."""
        rows = self._fetchall(
            "SELECT item_json FROM social_scan_items"
            " WHERE scan_id=? ORDER BY rowid ASC", (scan_id,))
        return [json.loads(r["item_json"]) for r in rows]

    def delete_social_scans(self, connection_id) -> None:
        """Drop a connection's cached enumerations (the platform
        metadata the disconnect duty covers). Signed records are
        never touched."""
        with self._lock:
            self.db.execute(
                "DELETE FROM social_scan_items WHERE scan_id IN"
                " (SELECT scan_id FROM social_scans"
                " WHERE connection_id=?)", (connection_id,))
            self.db.execute(
                "DELETE FROM social_scans WHERE connection_id=?",
                (connection_id,))
            self.db.commit()

    def get_social_registration(self, email_hash, identity_key):
        return self._fetchone(
            "SELECT * FROM social_registrations"
            " WHERE email_hash=? AND identity_key=?",
            (email_hash, identity_key))

    def list_social_registrations(self, email_hash):
        """Every lane registration the owner holds, for the
        planner's existing-map."""
        return self._fetchall(
            "SELECT * FROM social_registrations WHERE email_hash=?",
            (email_hash,))

    def add_social_registration(self, row) -> bool:
        """Index one minted registration under its owner and
        identity key. Put-if-absent: False when the identity is
        already indexed (the caller returns the existing record)."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO social_registrations"
                " (email_hash, identity_key, idempotency_key,"
                " record_id, batch_id, platform, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (row["email_hash"], row["identity_key"],
                 row["idempotency_key"], row["record_id"],
                 row.get("batch_id", ""), row.get("platform", ""),
                 row["created_at"]))
            self.db.commit()
            return cur.rowcount > 0

    def update_social_registration(self, email_hash, identity_key,
                                   idempotency_key, record_id,
                                   batch_id) -> None:
        """Repoint an identity at its newest version's record (a
        changed work registers as a new record; the index follows
        it, the earlier record is never edited)."""
        self._write(
            "UPDATE social_registrations SET idempotency_key=?,"
            " record_id=?, batch_id=? WHERE email_hash=?"
            " AND identity_key=?",
            (idempotency_key, record_id, batch_id, email_hash,
             identity_key))

    def add_social_batch(self, record, connection_id) -> bool:
        """Store a signed batch receipt record. Put-if-absent on
        the batch id."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO social_batches (batch_id,"
                " connection_id, record_json, created_at)"
                " VALUES (?,?,?,?)",
                (record["record_id"], connection_id or "",
                 json.dumps(record), record["registered_at"]))
            self.db.commit()
            return cur.rowcount > 0

    def get_social_batch(self, batch_id):
        row = self._fetchone(
            "SELECT record_json FROM social_batches WHERE batch_id=?",
            (batch_id,))
        return json.loads(row["record_json"]) if row else None

    def list_social_scans(self, connection_id):
        """Every stored scan header for one connection, oldest
        first (the overview's last-scan read)."""
        return self._fetchall(
            "SELECT * FROM social_scans WHERE connection_id=?"
            " ORDER BY enumerated_at ASC, scan_id ASC",
            (connection_id,))

    def list_social_batches(self, connection_id):
        """Every batch receipt minted for one connection, oldest
        first, as the parsed signed records."""
        rows = self._fetchall(
            "SELECT record_json FROM social_batches"
            " WHERE connection_id=?"
            " ORDER BY created_at ASC, batch_id ASC",
            (connection_id,))
        return [json.loads(r["record_json"]) for r in rows]

    def record_social_attempt(self, target, email, client_ip,
                              matched, created_at):
        self._write(
            "INSERT INTO social_attempts (target, email_hash,"
            " client_ip, matched, created_at) VALUES (?,?,?,?,?)",
            (target or "", registration_email_hash(email),
             client_ip or "", 1 if matched else 0, created_at))

    def count_social_attempts_since(self, dimension, value,
                                    since_iso):
        """Count lane attempts in a rolling window, mirroring the
        other counters: the email dimension counts by hash."""
        if dimension == "email":
            row = self._fetchone(
                "SELECT COUNT(*) AS n FROM social_attempts"
                " WHERE email_hash=? AND created_at>=?",
                (registration_email_hash(value), since_iso))
        else:
            row = self._fetchone(
                "SELECT COUNT(*) AS n FROM social_attempts"
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
