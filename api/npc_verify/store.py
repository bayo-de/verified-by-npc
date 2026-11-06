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
import re
import sqlite3
import threading

from . import credits as credits_module


def registration_email_hash(email):
    """SHA-256 of the normalized submitter email.

    The cap counters key on this hash (audit item D6): the raw email
    is retained for 12 months and then purged, while the hash — not
    reversible into the address — keeps the counters meaningful for
    rows whose raw email is gone.
    """
    return hashlib.sha256(
        (email or "").strip().lower().encode("utf-8")).hexdigest()


_CONTENT_HASH_LOCATOR_RE = re.compile(
    r"^(?:sha256:)?([0-9a-fA-F]{32,128})$")


def registration_claim_hashes(record):
    """The claim hashes a content registration answers to.

    A registration carries no claim_hash column (that is attestation
    vocabulary); it is findable by the hashes its own fields imply:

    - the SHA-256 of its locator, when the locator is a URL. This is
      the lookup the browser extension performs: it hashes the web
      address of the image it is checking.
    - the SHA-256 of the content bytes, recorded at intake in the
      content_fetch check entry when the locator yielded the work
      itself; or the hash the creator supplied when the locator IS
      a content hash (the extension's forensics layer hashes the
      bytes it read).

    Returns a set of lowercase hex strings. Agent registrations and
    malformed records answer to nothing.
    """
    hashes = set()
    if not isinstance(record, dict) or record.get("kind") != "content":
        return hashes
    locator = record.get("locator")
    if isinstance(locator, str):
        loc = locator.strip()
        if loc.startswith("https://") or loc.startswith("http://"):
            hashes.add(hashlib.sha256(
                loc.encode("utf-8")).hexdigest())
        else:
            m = _CONTENT_HASH_LOCATOR_RE.match(loc)
            if m:
                hashes.add(m.group(1).lower())
    for entry in record.get("checks_run") or []:
        if isinstance(entry, dict) \
                and entry.get("check") == "content_fetch":
            sha = entry.get("sha256")
            if isinstance(sha, str) and sha.strip():
                hashes.add(sha.strip().lower())
    return hashes

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

-- Paid check credits (npc_verify.credits, 2026-10-28). Codes are
-- stored only as SHA-256 hashes; the plaintext lives in the
-- purchase row until the buyer collects it, then it is wiped.
-- A charge row exists per (code, image) pair ever charged, and
-- the UNIQUE constraint makes a second charge for the same image
-- structurally impossible: a re-check can never consume twice.
CREATE TABLE IF NOT EXISTS credit_codes (
  code_hash         TEXT PRIMARY KEY,
  pack_id           TEXT NOT NULL,
  credits_total     INTEGER NOT NULL,
  credits_used      INTEGER NOT NULL DEFAULT 0,
  status            TEXT NOT NULL DEFAULT 'active',
  stripe_session_id TEXT UNIQUE,
  buyer_email       TEXT,
  created_at        TEXT NOT NULL,
  redeemed_at       TEXT,
  last_used_at      TEXT
);
CREATE TABLE IF NOT EXISTS credit_charges (
  id             TEXT PRIMARY KEY,
  code_hash      TEXT NOT NULL,
  image_identity TEXT NOT NULL,
  claim_hash     TEXT,
  kind           TEXT NOT NULL DEFAULT 'standard',
  funded_by      TEXT NOT NULL DEFAULT '',
  created_at     TEXT NOT NULL,
  UNIQUE (code_hash, image_identity)
);
CREATE INDEX IF NOT EXISTS idx_ccharge_code
  ON credit_charges (code_hash, created_at);
CREATE TABLE IF NOT EXISTS credit_purchases (
  session_id     TEXT PRIMARY KEY,
  pack_id        TEXT NOT NULL,
  code_hash      TEXT,
  code_plaintext TEXT,
  status         TEXT NOT NULL DEFAULT 'pending',
  buyer_email    TEXT,
  code_delivered INTEGER NOT NULL DEFAULT 0,
  referral_hash  TEXT,
  created_at     TEXT NOT NULL,
  completed_at   TEXT
);
-- Verifier Pass (switched on 2026-10-28). A Pass code's balance
-- lives in grants, not in the code row's counters: each grant is
-- one month's allowance (amount checks, at most ai_cap of them
-- spendable on AI generation checks), spendable until expires_at
-- (the end of the month after the grant month: one rollover).
-- A subscription row ties the Stripe subscription to its code and
-- carries the monthly figures renewals grant by.
CREATE TABLE IF NOT EXISTS credit_grants (
  grant_id   TEXT PRIMARY KEY,
  code_hash  TEXT NOT NULL,
  amount     INTEGER NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0,
  ai_cap     INTEGER NOT NULL DEFAULT 0,
  ai_used    INTEGER NOT NULL DEFAULT 0,
  source     TEXT NOT NULL DEFAULT 'pass',
  granted_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cgrant_code
  ON credit_grants (code_hash, granted_at);
CREATE TABLE IF NOT EXISTS credit_subscriptions (
  subscription_id TEXT PRIMARY KEY,
  code_hash       TEXT NOT NULL UNIQUE,
  pack_id         TEXT NOT NULL,
  customer_id     TEXT,
  buyer_email     TEXT,
  monthly_checks  INTEGER NOT NULL,
  ai_checks       INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'active',
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);
-- Referrals (Bayo, 2026-10-28). Every code carries a personal
-- referral code: a separate string, stored only as its SHA-256
-- hash, with the plaintext resting in the row until its one-time
-- delivery, exactly like a redeem code in its purchase row. A
-- referral row records one attribution, referee code to referrer
-- code; the referee code is the primary key, so a user can be
-- referred exactly once and the bonuses can land exactly once.
CREATE TABLE IF NOT EXISTS credit_referral_codes (
  referral_hash  TEXT PRIMARY KEY,
  code_hash      TEXT NOT NULL UNIQUE,
  code_plaintext TEXT,
  delivered      INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credit_referrals (
  referee_code_hash     TEXT PRIMARY KEY,
  referrer_code_hash    TEXT NOT NULL,
  referral_hash         TEXT NOT NULL,
  referee_grant_id      TEXT,
  referrer_grant_id     TEXT,
  referrer_link_grant_id TEXT,
  referrer_bonus        INTEGER NOT NULL DEFAULT 0,
  referrer_link_bonus   INTEGER NOT NULL DEFAULT 0,
  linked_at             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cref_referrer
  ON credit_referrals (referrer_code_hash, linked_at);

-- Onchain anchoring (npc_verify.anchor): one row per batch of
-- registrations whose Merkle root is written to Base, and one row
-- per record carrying its leaf hash and Merkle proof. The batch row
-- is written before anything is broadcast (root, record IDs,
-- leaves, and then the signed transaction and its hash), so a crash
-- anywhere recovers from these rows plus the chain itself. Batch
-- rows change status over their life (prepared -> submitted ->
-- confirmed / failed); record rows are inserted once and released
-- (flagged, never deleted) only when their batch fails onchain,
-- which returns the record to the unanchored pool. No submitter email or IP ever lands here:
-- leaves hash the signed public record only.
CREATE TABLE IF NOT EXISTS anchor_batches (
  batch_id        TEXT PRIMARY KEY,
  merkle_root     TEXT NOT NULL,
  batch_sig       TEXT,
  record_ids      TEXT NOT NULL,
  leaves          TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'prepared',
  nonce           INTEGER,
  tx_hash         TEXT,
  raw_tx          TEXT,
  block_number    INTEGER,
  block_timestamp TEXT,
  error           TEXT,
  created_at      TEXT NOT NULL,
  submitted_at    TEXT,
  confirmed_at    TEXT
);
CREATE TABLE IF NOT EXISTS record_anchors (
  record_id TEXT PRIMARY KEY,
  batch_id  TEXT NOT NULL,
  leaf_hash TEXT NOT NULL,
  proof     TEXT NOT NULL,
  released  INTEGER NOT NULL DEFAULT 0
);
-- Rotation notices (npc_verify.anchor): owner-signed statements
-- that move anchor authority from one anchor wallet to the next.
-- A notice lands here only after its signature verifies against
-- the configured owner address; the rows are the public rotation
-- history the status endpoint reports from.
CREATE TABLE IF NOT EXISTS anchor_rotations (
  notice_id TEXT PRIMARY KEY,
  notice    TEXT NOT NULL,
  created_at TEXT NOT NULL
);
-- Unified accounts (npc_verify.accounts, Gate G1). One account per
-- person, rooted at an email address. Every secret at rest is a
-- hash: session tokens, email-link tokens, handoff secrets, and
-- recovery codes are stored only as SHA-256 digests, and the
-- plaintext is returned exactly once at creation. Passkey public
-- keys are stored as base64url COSE encodings (public material).
CREATE TABLE IF NOT EXISTS accounts (
  account_id TEXT PRIMARY KEY,
  email      TEXT NOT NULL UNIQUE,
  email_hash TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS account_credentials (
  credential_id   TEXT PRIMARY KEY,
  account_id      TEXT NOT NULL,
  public_key_cose TEXT NOT NULL,
  alg             INTEGER NOT NULL,
  sign_count      INTEGER NOT NULL DEFAULT 0,
  aaguid          TEXT NOT NULL DEFAULT '',
  transports      TEXT NOT NULL DEFAULT '',
  label           TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL,
  last_used_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_acct_cred_account
  ON account_credentials (account_id);
CREATE TABLE IF NOT EXISTS account_challenges (
  challenge_id TEXT PRIMARY KEY,
  account_id   TEXT NOT NULL DEFAULT '',
  kind         TEXT NOT NULL,
  challenge    TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  consumed_at  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS account_email_tokens (
  token_hash  TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL,
  handoff_id  TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  consumed_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS account_recovery_codes (
  account_id  TEXT NOT NULL,
  code_hash   TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  consumed_at TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (account_id, code_hash)
);
CREATE TABLE IF NOT EXISTS account_sessions (
  session_id   TEXT PRIMARY KEY,
  account_id   TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  surface      TEXT NOT NULL DEFAULT 'web',
  device_label TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  revoked_at   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_acct_sess_account
  ON account_sessions (account_id);
CREATE TABLE IF NOT EXISTS account_handoffs (
  handoff_id   TEXT PRIMARY KEY,
  secret_hash  TEXT NOT NULL,
  device_label TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'pending',
  account_id   TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  completed_at TEXT NOT NULL DEFAULT '',
  consumed_at  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS account_events (
  event_id   TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  kind       TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acct_events_account
  ON account_events (account_id, created_at);
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
            self._migrate_credits()
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

    def _migrate_credits(self):
        """kind column on credit_charges (added with the Verifier
        Pass, 2026-10-28): charges record whether they were a
        standard registry check or an AI generation check. source
        column on credit_grants and referral_hash on
        credit_purchases (added with referrals, 2026-10-28):
        grants record what landed them (a Pass month, or a
        referral bonus), and a purchase records the referral code
        it was carried in with, as a hash. funded_by on
        credit_charges and the referrer_link_* columns on
        credit_referrals (added with the unlimited Pass and the
        two-sided referral reward, later on 2026-10-28): a charge
        covered by an active Verifier Pass is marked 'pass', and a
        referral records the referrer's at-link bonus beside the
        first-purchase bonus."""
        cols = {r["name"]
                for r in self.db.execute(
                    "PRAGMA table_info(credit_charges)")}
        if "kind" not in cols:
            self.db.execute(
                "ALTER TABLE credit_charges ADD COLUMN kind"
                " TEXT NOT NULL DEFAULT 'standard'")
        if "funded_by" not in cols:
            self.db.execute(
                "ALTER TABLE credit_charges ADD COLUMN funded_by"
                " TEXT NOT NULL DEFAULT ''")
        cols = {r["name"]
                for r in self.db.execute(
                    "PRAGMA table_info(credit_grants)")}
        if "source" not in cols:
            self.db.execute(
                "ALTER TABLE credit_grants ADD COLUMN source"
                " TEXT NOT NULL DEFAULT 'pass'")
        cols = {r["name"]
                for r in self.db.execute(
                    "PRAGMA table_info(credit_purchases)")}
        if "referral_hash" not in cols:
            self.db.execute(
                "ALTER TABLE credit_purchases"
                " ADD COLUMN referral_hash TEXT")
        cols = {r["name"]
                for r in self.db.execute(
                    "PRAGMA table_info(credit_referrals)")}
        if "referrer_link_grant_id" not in cols:
            self.db.execute(
                "ALTER TABLE credit_referrals"
                " ADD COLUMN referrer_link_grant_id TEXT")
        if "referrer_link_bonus" not in cols:
            self.db.execute(
                "ALTER TABLE credit_referrals"
                " ADD COLUMN referrer_link_bonus"
                " INTEGER NOT NULL DEFAULT 0")

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

    def registrations_by_claim_hash(self, claim_hash):
        """Content registrations findable by this claim hash, newest
        first. The registration-layer counterpart of
        attestations_by_claim_hash: a registration answers to the
        hash of its locator address and to the content hash recorded
        at intake (see registration_claim_hashes). Records are the
        parsed signed dicts, exactly as get_registration returns
        them; the caller presents the match as a registration, never
        as an attestation."""
        rows = self._fetchall(
            "SELECT record_json FROM registrations"
            " WHERE kind='content' ORDER BY created_at DESC")
        out = []
        for row in rows:
            try:
                record = json.loads(row["record_json"])
            except (ValueError, TypeError):
                continue
            if claim_hash in registration_claim_hashes(record):
                out.append(record)
        return out

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

    def oldest_registration_since(self, dimension, value, since_iso):
        """Oldest created_at among registrations in a rolling
        window, or None when the window holds none for the value.
        The cap companion of count_registrations_since: a capped
        caller can be told when the oldest counted submission ages
        out. Same dimension discipline (a fixed literal chosen by
        the caller; the email dimension matches by hash, so purged
        rows still count)."""
        if dimension == "email":
            row = self._fetchone(
                "SELECT MIN(created_at) AS t FROM registrations"
                " WHERE email_hash=? AND created_at>=?",
                (registration_email_hash(value), since_iso))
        else:
            row = self._fetchone(
                "SELECT MIN(created_at) AS t FROM registrations"
                " WHERE client_ip=? AND created_at>=?",
                (value, since_iso))
        return row["t"] if row else None

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

    # -- paid check credits (npc_verify.credits) ---------------------------
    # The ledger is the source of truth for balances. Composite
    # read-check-write sequences run under the store lock, like the
    # DynamoDB backend, so a consume is atomic: the charge row and
    # the counter move together or not at all.

    def create_credit_purchase(self, session_id, pack_id, buyer_email,
                               now, referral_hash=None):
        self._write(
            "INSERT OR IGNORE INTO credit_purchases (session_id,"
            " pack_id, status, buyer_email, created_at, referral_hash)"
            " VALUES (?,?, 'pending', ?, ?, ?)",
            (session_id, pack_id, buyer_email, now, referral_hash))

    def get_credit_purchase(self, session_id):
        return self._fetchone(
            "SELECT * FROM credit_purchases WHERE session_id=?",
            (session_id,))

    def complete_credit_purchase(self, session_id, code_hash,
                                 code_plaintext, pack, buyer_email, now):
        """Mark a purchase paid and mint its code, exactly once.

        Returns the code row. A replayed completion (a duplicate
        webhook) returns the originally minted code row unchanged:
        one paid session can never mint two codes.
        """
        with self._lock:
            purchase = _one(self.db.execute(
                "SELECT * FROM credit_purchases WHERE session_id=?",
                (session_id,)))
            if purchase is None:
                return None
            if purchase["status"] == "paid" \
                    and purchase["code_hash"]:
                return _one(self.db.execute(
                    "SELECT * FROM credit_codes WHERE code_hash=?",
                    (purchase["code_hash"],)))
            self.db.execute(
                "INSERT INTO credit_codes (code_hash, pack_id,"
                " credits_total, credits_used, status,"
                " stripe_session_id, buyer_email, created_at)"
                " VALUES (?,?,?,0,'active',?,?,?)",
                (code_hash, pack["id"], pack["checks"], session_id,
                 buyer_email, now))
            self.db.execute(
                "UPDATE credit_purchases SET status='paid',"
                " code_hash=?, code_plaintext=?, buyer_email=?,"
                " completed_at=? WHERE session_id=?",
                (code_hash, code_plaintext, buyer_email, now,
                 session_id))
            self.db.commit()
            return _one(self.db.execute(
                "SELECT * FROM credit_codes WHERE code_hash=?",
                (code_hash,)))

    def expire_credit_purchase(self, session_id, now):
        self._write(
            "UPDATE credit_purchases SET status='expired'"
            " WHERE session_id=? AND status='pending'",
            (session_id,))

    def take_credit_code_delivery(self, session_id):
        """Hand the plaintext code to the buyer's browser, once.

        Returns (code_plaintext, purchase_row) on first delivery,
        (None, purchase_row) when the code was already delivered
        (the plaintext is wiped at delivery), and (None, None) for
        an unknown or unpaid session.
        """
        with self._lock:
            purchase = _one(self.db.execute(
                "SELECT * FROM credit_purchases WHERE session_id=?",
                (session_id,)))
            if purchase is None or purchase["status"] != "paid":
                return None, purchase
            if purchase["code_delivered"] or \
                    not purchase["code_plaintext"]:
                return None, purchase
            code = purchase["code_plaintext"]
            self.db.execute(
                "UPDATE credit_purchases SET code_delivered=1,"
                " code_plaintext=NULL WHERE session_id=?",
                (session_id,))
            self.db.commit()
            purchase = _one(self.db.execute(
                "SELECT * FROM credit_purchases WHERE session_id=?",
                (session_id,)))
            return code, purchase

    # -- Verifier Pass: subscriptions and monthly grants ---------------
    # A Pass code's counters stay at zero; its spendable balance is
    # the sum over its live grants. The helpers below compute that
    # view, and every public read of a code row carries it.

    def _credit_grants(self, code_hash):
        """All grants on a code, oldest first."""
        return self._fetchall(
            "SELECT * FROM credit_grants WHERE code_hash=?"
            " ORDER BY granted_at, grant_id", (code_hash,))

    def _augment_credit_row(self, row, now):
        """Attach the grant view to a raw credit_codes row: the
        spendable grant balance and AI balance at `now` (grants past
        their expiry count for nothing), the live grants with their
        remaining amounts, and the Pass subscription status when the
        code belongs to one. The AI balance is the Pass grants' AI
        room plus the bonus grants' balances plus the code row's
        own pack counters, which fund AI checks out of their whole
        remainder (credits.pack_grant_view); Pass codes carry zero
        counters, so nothing is added for them."""
        if row is None:
            return None
        out = dict(row)
        grant_balance = 0
        ai_balance = 0
        live = []
        if now is not None:
            ai_balance += credits_module.grant_ai_room(
                credits_module.pack_grant_view(out))
            for g in self._credit_grants(row["code_hash"]):
                if g["expires_at"] <= now:
                    continue
                remaining = g["amount"] - g["used"]
                ai_remaining = credits_module.grant_ai_room(g)
                grant_balance += remaining
                ai_balance += ai_remaining
                entry = dict(g)
                entry["remaining"] = remaining
                entry["ai_remaining"] = ai_remaining
                live.append(entry)
        out["grant_balance"] = grant_balance
        out["ai_balance"] = ai_balance
        out["grants"] = live
        sub = self._fetchone(
            "SELECT * FROM credit_subscriptions WHERE code_hash=?",
            (row["code_hash"],))
        out["subscription_status"] = sub["status"] if sub else None
        return out

    def activate_pass_subscription(self, session_id, code_hash,
                                   code_plaintext, pack, buyer_email,
                                   subscription_id, customer_id,
                                   grant_id, now, expires_at):
        """Mark a Pass purchase paid, mint its code, open the
        subscription, and land the first monthly grant, exactly
        once. Returns the (augmented) code row. A replayed
        activation returns the originally minted code row and
        grants nothing twice."""
        with self._lock:
            purchase = _one(self.db.execute(
                "SELECT * FROM credit_purchases WHERE session_id=?",
                (session_id,)))
            if purchase is None:
                return None
            if purchase["status"] == "paid" \
                    and purchase["code_hash"]:
                return self._augment_credit_row(_one(self.db.execute(
                    "SELECT * FROM credit_codes WHERE code_hash=?",
                    (purchase["code_hash"],))), now)
            self.db.execute(
                "INSERT INTO credit_codes (code_hash, pack_id,"
                " credits_total, credits_used, status,"
                " stripe_session_id, buyer_email, created_at)"
                " VALUES (?,?,0,0,'active',?,?,?)",
                (code_hash, pack["id"], session_id, buyer_email, now))
            self.db.execute(
                "INSERT INTO credit_subscriptions (subscription_id,"
                " code_hash, pack_id, customer_id, buyer_email,"
                " monthly_checks, ai_checks, status, created_at,"
                " updated_at) VALUES (?,?,?,?,?,?,?,'active',?,?)",
                (subscription_id, code_hash, pack["id"], customer_id,
                 buyer_email, pack["checks"],
                 pack.get("ai_checks", 0), now, now))
            self.db.execute(
                "INSERT INTO credit_grants (grant_id, code_hash,"
                " amount, used, ai_cap, ai_used, granted_at,"
                " expires_at) VALUES (?,?,?,0,?,0,?,?)",
                (grant_id, code_hash, pack["checks"],
                 pack.get("ai_checks", 0), now, expires_at))
            self.db.execute(
                "UPDATE credit_purchases SET status='paid',"
                " code_hash=?, code_plaintext=?, buyer_email=?,"
                " completed_at=? WHERE session_id=?",
                (code_hash, code_plaintext, buyer_email, now,
                 session_id))
            self.db.commit()
            return self._augment_credit_row(_one(self.db.execute(
                "SELECT * FROM credit_codes WHERE code_hash=?",
                (code_hash,))), now)

    def get_subscription(self, subscription_id):
        return self._fetchone(
            "SELECT * FROM credit_subscriptions"
            " WHERE subscription_id=?", (subscription_id,))

    def grant_subscription_allowance(self, subscription_id, grant_id,
                                     now, expires_at):
        """Land one renewal grant for a subscription, keyed by the
        Stripe invoice id, so a replayed invoice.paid grants once.
        Outcomes: "granted", "duplicate" (this grant id already
        landed), "inactive" (the subscription is canceled, so
        renewals have stopped), "not_found"."""
        with self._lock:
            sub = _one(self.db.execute(
                "SELECT * FROM credit_subscriptions"
                " WHERE subscription_id=?", (subscription_id,)))
            if sub is None:
                return {"outcome": "not_found", "grant": None}
            existing = _one(self.db.execute(
                "SELECT * FROM credit_grants WHERE grant_id=?",
                (grant_id,)))
            if existing is not None:
                return {"outcome": "duplicate", "grant": existing}
            if sub["status"] != "active":
                return {"outcome": "inactive", "grant": None}
            self.db.execute(
                "INSERT INTO credit_grants (grant_id, code_hash,"
                " amount, used, ai_cap, ai_used, granted_at,"
                " expires_at) VALUES (?,?,?,0,?,0,?,?)",
                (grant_id, sub["code_hash"], sub["monthly_checks"],
                 sub["ai_checks"], now, expires_at))
            self.db.commit()
            grant = _one(self.db.execute(
                "SELECT * FROM credit_grants WHERE grant_id=?",
                (grant_id,)))
            return {"outcome": "granted", "grant": grant}

    def cancel_subscription(self, subscription_id, now):
        """Stop a subscription's future grants. Already-granted
        checks are untouched and live until their expiry."""
        with self._lock:
            sub = _one(self.db.execute(
                "SELECT * FROM credit_subscriptions"
                " WHERE subscription_id=?", (subscription_id,)))
            if sub is None:
                return None
            if sub["status"] != "canceled":
                self.db.execute(
                    "UPDATE credit_subscriptions SET status='canceled',"
                    " updated_at=? WHERE subscription_id=?",
                    (now, subscription_id))
                self.db.commit()
                sub = _one(self.db.execute(
                    "SELECT * FROM credit_subscriptions"
                    " WHERE subscription_id=?", (subscription_id,)))
            return sub

    # -- referrals (npc_verify.credits, Bayo 2026-10-28) ---------------
    # A referral code is a second string per redeem code, under the
    # same discipline: the server keeps only its SHA-256 hash as the
    # lookup key, and the plaintext rests in the referral row until
    # its one-time delivery. Attribution and both bonuses land in
    # one locked sequence (attribute_referral), and the referral
    # row itself is the idempotency record: its primary key is the
    # referee code, so a user is referred exactly once and no
    # replay, retry, or second link can grant twice.

    def ensure_referral_code(self, code_hash, referral_hash,
                             code_plaintext, now):
        """Record a code's personal referral code, first one wins.
        Returns the referral row for the code (an existing row is
        returned unchanged, so a replayed mint records nothing
        new)."""
        with self._lock:
            self.db.execute(
                "INSERT OR IGNORE INTO credit_referral_codes"
                " (referral_hash, code_hash, code_plaintext,"
                " delivered, created_at) VALUES (?,?,?,0,?)",
                (referral_hash, code_hash, code_plaintext, now))
            self.db.commit()
            return _one(self.db.execute(
                "SELECT * FROM credit_referral_codes"
                " WHERE code_hash=?", (code_hash,)))

    def get_referral_code_for(self, code_hash):
        """The referral row owned by a redeem code, or None."""
        return self._fetchone(
            "SELECT * FROM credit_referral_codes WHERE code_hash=?",
            (code_hash,))

    def get_referral_owner(self, referral_hash):
        """The referral row a referral code hash names, or None."""
        return self._fetchone(
            "SELECT * FROM credit_referral_codes"
            " WHERE referral_hash=?", (referral_hash,))

    def take_referral_code_delivery(self, code_hash):
        """Hand a code's referral plaintext to its owner, once.

        Returns (plaintext, referral_row) on first delivery,
        (None, referral_row) when the plaintext was already
        delivered (it is wiped at delivery), and (None, None) when
        the code has no referral row. Mirrors
        take_credit_code_delivery."""
        with self._lock:
            row = _one(self.db.execute(
                "SELECT * FROM credit_referral_codes"
                " WHERE code_hash=?", (code_hash,)))
            if row is None:
                return None, None
            if row["delivered"] or not row["code_plaintext"]:
                return None, row
            plain = row["code_plaintext"]
            self.db.execute(
                "UPDATE credit_referral_codes SET delivered=1,"
                " code_plaintext=NULL WHERE code_hash=?",
                (code_hash,))
            self.db.commit()
            row = _one(self.db.execute(
                "SELECT * FROM credit_referral_codes"
                " WHERE code_hash=?", (code_hash,)))
            return plain, row

    def get_referral(self, referee_code_hash):
        """The referral row attributing a code, or None."""
        return self._fetchone(
            "SELECT * FROM credit_referrals"
            " WHERE referee_code_hash=?", (referee_code_hash,))

    def _referral_month_total(self, referrer_code_hash, month):
        """Bonus checks already granted to a referrer as referral
        bonuses inside one calendar month (an ISO "YYYY-MM"
        prefix), counting the at-link and first-purchase bonuses
        together. The monthly cap is measured against this sum."""
        row = self._fetchone(
            "SELECT COALESCE(SUM(amount), 0) AS total"
            " FROM credit_grants WHERE code_hash=?"
            " AND source IN ('referral_referrer', 'referral_link')"
            " AND substr(granted_at, 1, 7)=?",
            (referrer_code_hash, month))
        return row["total"] or 0

    def referral_stats(self, code_hash, now):
        """Referral view for one code: how many users it has
        referred, the bonus it earned inside the current calendar
        month, and whether the code itself was referred."""
        count = self._fetchone(
            "SELECT COUNT(*) AS n FROM credit_referrals"
            " WHERE referrer_code_hash=?", (code_hash,))
        return {
            "referred_count": count["n"] if count else 0,
            "referral_bonus_this_month":
                self._referral_month_total(code_hash, now[:7]),
            "referred_by":
                self.get_referral(code_hash) is not None,
        }

    def attribute_referral(self, referee_code_hash, referral_hash,
                           referee_grant_id, referrer_grant_id, now,
                           expires_at, referee_bonus, referrer_bonus,
                           monthly_cap, referrer_link_bonus=0,
                           referrer_link_grant_id=None):
        """Attribute a referee code to a referral code's owner and
        land the bonuses, atomically and exactly once.

        Outcomes: "linked", "already_referred" (the referee was
        attributed before; nothing moves), "self_referral" (the
        referral code belongs to the referee code itself, or both
        codes carry the same purchaser email; nothing is recorded
        and nothing is granted), "referral_not_found",
        "not_found" (the referee code is unknown), "revoked".

        On "linked" the referral row is written, the referee
        receives `referee_bonus` checks as a grant, and
        the referrer receives two grants: `referrer_link_bonus`
        for the link itself (source "referral_link") and
        `referrer_bonus` for the referee's first paid purchase
        (source "referral_referrer"). Both referrer grants are
        trimmed in that order so the referrer's referral bonuses
        inside the calendar month of `now` never pass
        `monthly_cap` in total (a grant trimmed to 0 is not
        written, and the shortfall is not owed later). Bonus
        grants carry ai_cap 0 in storage, but a bonus check is
        not standard-only: an AI generation check may spend a
        bonus grant's whole remaining balance, drawn after any
        Pass grant's AI sub-allowance (credits.BONUS_GRANT_SOURCES
        and credits.grant_ai_room govern that draw). They expire
        at `expires_at`, which the caller computes with
        credits.grant_expiry: the same one-month rollover rule as
        Pass grants.

        First-purchase semantics: a code exists only because a
        paid purchase minted it, so attribution, whether it
        arrives with the purchase at checkout or later through the
        link route, attributes that first purchase, and the
        referral row guarantees both referrer bonuses fire for it
        exactly once."""
        with self._lock:
            referee = _one(self.db.execute(
                "SELECT * FROM credit_codes WHERE code_hash=?",
                (referee_code_hash,)))
            if referee is None:
                return {"outcome": "not_found", "referral": None,
                        "referee_bonus": 0, "referrer_bonus": 0,
                        "referrer_link_bonus": 0}
            if referee["status"] == "revoked":
                return {"outcome": "revoked", "referral": None,
                        "referee_bonus": 0, "referrer_bonus": 0,
                        "referrer_link_bonus": 0}
            owner = _one(self.db.execute(
                "SELECT * FROM credit_referral_codes"
                " WHERE referral_hash=?", (referral_hash,)))
            if owner is None:
                return {"outcome": "referral_not_found",
                        "referral": None, "referee_bonus": 0,
                        "referrer_bonus": 0, "referrer_link_bonus": 0}
            referrer_hash = owner["code_hash"]
            referrer = _one(self.db.execute(
                "SELECT * FROM credit_codes WHERE code_hash=?",
                (referrer_hash,)))
            referee_email = (referee["buyer_email"] or "").strip() \
                .casefold()
            referrer_email = ""
            if referrer is not None:
                referrer_email = (referrer["buyer_email"] or "") \
                    .strip().casefold()
            if referrer_hash == referee_code_hash or (
                    referee_email and referee_email == referrer_email):
                return {"outcome": "self_referral", "referral": None,
                        "referee_bonus": 0, "referrer_bonus": 0,
                        "referrer_link_bonus": 0}
            existing = _one(self.db.execute(
                "SELECT * FROM credit_referrals"
                " WHERE referee_code_hash=?", (referee_code_hash,)))
            if existing is not None:
                return {"outcome": "already_referred",
                        "referral": existing, "referee_bonus": 0,
                        "referrer_bonus":
                            existing["referrer_bonus"],
                        "referrer_link_bonus":
                            existing["referrer_link_bonus"]}
            month_total = self._referral_month_total(
                referrer_hash, now[:7])
            link_amount = max(0, min(referrer_link_bonus,
                                     monthly_cap - month_total))
            amount = max(0, min(
                referrer_bonus,
                monthly_cap - month_total - link_amount))
            self.db.execute(
                "INSERT INTO credit_referrals (referee_code_hash,"
                " referrer_code_hash, referral_hash,"
                " referee_grant_id, referrer_grant_id,"
                " referrer_link_grant_id, referrer_bonus,"
                " referrer_link_bonus, linked_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (referee_code_hash, referrer_hash, referral_hash,
                 referee_grant_id,
                 referrer_grant_id if amount > 0 else None,
                 referrer_link_grant_id if link_amount > 0 else None,
                 amount, link_amount, now))
            self.db.execute(
                "INSERT INTO credit_grants (grant_id, code_hash,"
                " amount, used, ai_cap, ai_used, source, granted_at,"
                " expires_at) VALUES (?,?,?,0,0,0,"
                " 'referral_referee',?,?)",
                (referee_grant_id, referee_code_hash, referee_bonus,
                 now, expires_at))
            if link_amount > 0:
                self.db.execute(
                    "INSERT INTO credit_grants (grant_id, code_hash,"
                    " amount, used, ai_cap, ai_used, source,"
                    " granted_at, expires_at) VALUES (?,?,?,0,0,0,"
                    " 'referral_link',?,?)",
                    (referrer_link_grant_id, referrer_hash,
                     link_amount, now, expires_at))
            if amount > 0:
                self.db.execute(
                    "INSERT INTO credit_grants (grant_id, code_hash,"
                    " amount, used, ai_cap, ai_used, source,"
                    " granted_at, expires_at) VALUES (?,?,?,0,0,0,"
                    " 'referral_referrer',?,?)",
                    (referrer_grant_id, referrer_hash, amount, now,
                     expires_at))
            self.db.commit()
            row = _one(self.db.execute(
                "SELECT * FROM credit_referrals"
                " WHERE referee_code_hash=?", (referee_code_hash,)))
            return {"outcome": "linked", "referral": row,
                    "referee_bonus": referee_bonus,
                    "referrer_bonus": amount,
                    "referrer_link_bonus": link_amount}

    def get_credit_code(self, code_hash, now=None):
        row = self._fetchone(
            "SELECT * FROM credit_codes WHERE code_hash=?", (code_hash,))
        return self._augment_credit_row(row, now)

    def redeem_credit_code(self, code_hash, now):
        """First presentation of a code stamps redeemed_at. Returns
        the code row, or None for an unknown code."""
        with self._lock:
            row = _one(self.db.execute(
                "SELECT * FROM credit_codes WHERE code_hash=?",
                (code_hash,)))
            if row is None:
                return None
            if not row["redeemed_at"]:
                self.db.execute(
                    "UPDATE credit_codes SET redeemed_at=?"
                    " WHERE code_hash=?", (now, code_hash))
                self.db.commit()
                row = _one(self.db.execute(
                    "SELECT * FROM credit_codes WHERE code_hash=?",
                    (code_hash,)))
            return self._augment_credit_row(row, now)

    def consume_credit(self, code_hash, image_identity, claim_hash,
                       charge_id, now, kind="standard",
                       hourly_limit=None):
        """Charge one credit for one new image, atomically.

        Outcomes: "charged" (a new charge row, counter moved),
        "duplicate" (this image was already charged to this code;
        nothing moves), "no_credits" (nothing spendable remains),
        "no_ai_credits" (checks remain but none of them can fund
        an AI generation check: every Pass grant's AI
        sub-allowance is spent, no bonus balance stands, and the
        pack counters are empty, while some grant remainder that
        only funds standard checks is left), "rate_limited"
        (the code's charged consumes inside the trailing hour
        reached the anti-scripting backstop; nothing moves),
        "revoked", "not_found". The UNIQUE(code_hash,
        image_identity) row is the guard: even a raced second
        insert cannot land.

        Pack codes spend from the code row's own counters, exactly
        as before. A code with grants spends oldest live grant
        first; an AI charge also draws that grant's AI
        sub-allowance. While the code's Verifier Pass subscription
        is active, a standard charge is covered by the Pass itself
        (registry checks are unlimited for subscribers): the charge
        row lands marked funded_by 'pass', so usage stays
        countable, and no counter or grant moves. Cancellation
        ends that coverage at once, and the finite pools are
        drawn again. A Pass code's status never flips to
        exhausted: the subscription renews it.

        An AI charge draws, in order, the oldest live Pass grant
        with AI sub-allowance left, then bonus grants oldest
        first, then the code's pack counters; a bonus grant funds
        an AI check from its whole remaining balance, the same
        pool its standard checks spend, and a pack balance funds
        one from its whole remainder too (credits.grant_ai_room).
        A charge drawn from a bonus grant lands with funded_by
        "bonus" and one drawn from the pack counters with
        funded_by "pack", so the ledger can say exactly how many
        AI checks each source paid for.
        """
        with self._lock:
            row = _one(self.db.execute(
                "SELECT * FROM credit_codes WHERE code_hash=?",
                (code_hash,)))
            if row is None:
                return {"outcome": "not_found", "code": None}
            if row["status"] == "revoked":
                return {"outcome": "revoked",
                        "code": self._augment_credit_row(row, now)}
            prior = _one(self.db.execute(
                "SELECT id FROM credit_charges WHERE code_hash=?"
                " AND image_identity=?", (code_hash, image_identity)))
            if prior is not None:
                return {"outcome": "duplicate",
                        "code": self._augment_credit_row(row, now)}
            if hourly_limit is None:
                hourly_limit = credits_module.CONSUME_HOURLY_LIMIT
            if hourly_limit:
                recent = self._fetchone(
                    "SELECT COUNT(*) AS n FROM credit_charges"
                    " WHERE code_hash=? AND created_at>=?",
                    (code_hash, credits_module.hour_ago(now)))
                if recent is not None \
                        and recent["n"] >= hourly_limit:
                    return {"outcome": "rate_limited",
                            "code": self._augment_credit_row(row, now)}
            if kind == "standard":
                sub = self._fetchone(
                    "SELECT * FROM credit_subscriptions"
                    " WHERE code_hash=?", (code_hash,))
                if sub is not None and sub["status"] == "active":
                    return self._consume_covered_by_pass(
                        row, image_identity, claim_hash, charge_id,
                        now)
            grants = self._credit_grants(code_hash)
            if grants:
                return self._consume_with_grants(
                    row, grants, image_identity, claim_hash, charge_id,
                    now, kind)
            if row["credits_used"] >= row["credits_total"]:
                return {"outcome": "no_credits",
                        "code": self._augment_credit_row(row, now)}
            # The code's own pack counters fund this charge; an AI
            # charge drawn from them is marked funded_by "pack".
            funded_by = "pack" if kind == "ai" else ""
            try:
                self.db.execute(
                    "INSERT INTO credit_charges (id, code_hash,"
                    " image_identity, claim_hash, kind, funded_by,"
                    " created_at) VALUES (?,?,?,?,?,?,?)",
                    (charge_id, code_hash, image_identity, claim_hash,
                     kind, funded_by, now))
            except Exception:
                self.db.rollback()
                return {"outcome": "duplicate",
                        "code": self._augment_credit_row(row, now)}
            used = row["credits_used"] + 1
            status = "exhausted" if used >= row["credits_total"] \
                else row["status"]
            self.db.execute(
                "UPDATE credit_codes SET credits_used=?, status=?,"
                " last_used_at=? WHERE code_hash=?",
                (used, status, now, code_hash))
            self.db.commit()
            row = _one(self.db.execute(
                "SELECT * FROM credit_codes WHERE code_hash=?",
                (code_hash,)))
            return {"outcome": "charged",
                    "code": self._augment_credit_row(row, now)}

    def _consume_covered_by_pass(self, row, image_identity,
                                 claim_hash, charge_id, now):
        """The Pass-covered path of consume_credit, called under
        the store lock with the duplicate check already done and
        the subscription known active: record the charge marked
        funded_by 'pass' and move nothing else. The charge row is
        the usage record (and feeds the hourly backstop count);
        the code's last_used_at is the only field that moves."""
        code_hash = row["code_hash"]
        try:
            self.db.execute(
                "INSERT INTO credit_charges (id, code_hash,"
                " image_identity, claim_hash, kind, funded_by,"
                " created_at) VALUES (?,?,?,?,'standard','pass',?)",
                (charge_id, code_hash, image_identity, claim_hash,
                 now))
        except Exception:
            self.db.rollback()
            return {"outcome": "duplicate",
                    "code": self._augment_credit_row(row, now)}
        self.db.execute(
            "UPDATE credit_codes SET last_used_at=?"
            " WHERE code_hash=?", (now, code_hash))
        self.db.commit()
        row = _one(self.db.execute(
            "SELECT * FROM credit_codes WHERE code_hash=?",
            (code_hash,)))
        return {"outcome": "charged",
                "code": self._augment_credit_row(row, now)}

    def _consume_with_grants(self, row, grants, image_identity,
                             claim_hash, charge_id, now, kind):
        """The grant path of consume_credit, called under the store
        lock with the duplicate check already done. Draws the oldest
        live grant first; grants past expiry are invisible. AI
        charges follow the draw order instead: Pass grants' AI
        sub-allowances first (oldest first), then bonus grants
        (oldest first), each bonus draw spending the grant's shared
        pool and landing marked funded_by "bonus", then the code's
        pack counters, landing marked funded_by "pack"."""
        code_hash = row["code_hash"]
        live = [g for g in grants if g["expires_at"] > now]
        grant_remaining = sum(g["amount"] - g["used"] for g in live)
        legacy_remaining = row["credits_total"] - row["credits_used"]
        target = None
        if kind == "ai":
            for g in live:
                if g["source"] not in \
                        credits_module.BONUS_GRANT_SOURCES \
                        and credits_module.grant_ai_room(g) > 0:
                    target = g
                    break
            if target is None:
                for g in live:
                    if g["source"] in \
                            credits_module.BONUS_GRANT_SOURCES \
                            and credits_module.grant_ai_room(g) > 0:
                        target = g
                        break
            if target is None and credits_module.grant_ai_room(
                    credits_module.pack_grant_view(row)) <= 0:
                outcome = "no_credits" \
                    if grant_remaining + legacy_remaining <= 0 \
                    else "no_ai_credits"
                return {"outcome": outcome,
                        "code": self._augment_credit_row(row, now)}
        else:
            if grant_remaining + legacy_remaining <= 0:
                return {"outcome": "no_credits",
                        "code": self._augment_credit_row(row, now)}
            for g in live:
                if g["amount"] - g["used"] > 0:
                    target = g
                    break
        funded_by = ""
        if kind == "ai" and target is not None \
                and target["source"] in \
                credits_module.BONUS_GRANT_SOURCES:
            funded_by = "bonus"
        elif kind == "ai" and target is None:
            # No grant could fund this AI charge, so it falls to
            # the code's pack counters (their room was checked
            # above); the spend itself happens in the counters
            # branch below.
            funded_by = "pack"
        try:
            self.db.execute(
                "INSERT INTO credit_charges (id, code_hash,"
                " image_identity, claim_hash, kind, funded_by,"
                " created_at) VALUES (?,?,?,?,?,?,?)",
                (charge_id, code_hash, image_identity, claim_hash,
                 kind, funded_by, now))
        except Exception:
            self.db.rollback()
            return {"outcome": "duplicate",
                    "code": self._augment_credit_row(row, now)}
        if target is not None:
            self.db.execute(
                "UPDATE credit_grants SET used=?, ai_used=?"
                " WHERE grant_id=?",
                (target["used"] + 1,
                 target["ai_used"] + (1 if kind == "ai" else 0),
                 target["grant_id"]))
            self.db.execute(
                "UPDATE credit_codes SET last_used_at=?"
                " WHERE code_hash=?", (now, code_hash))
        else:
            # No live grant can fund this charge, but the code row
            # still holds counters (a hand-minted hybrid): spend
            # from them, without flipping a Pass code to exhausted.
            used = row["credits_used"] + 1
            sub = self._fetchone(
                "SELECT * FROM credit_subscriptions"
                " WHERE code_hash=?", (code_hash,))
            status = row["status"]
            if used >= row["credits_total"] and not (
                    sub and sub["status"] == "active"):
                status = "exhausted"
            self.db.execute(
                "UPDATE credit_codes SET credits_used=?, status=?,"
                " last_used_at=? WHERE code_hash=?",
                (used, status, now, code_hash))
        self.db.commit()
        row = _one(self.db.execute(
            "SELECT * FROM credit_codes WHERE code_hash=?",
            (code_hash,)))
        return {"outcome": "charged",
                "code": self._augment_credit_row(row, now)}

    # -- onchain anchoring (npc_verify.anchor) -------------------------
    # The store half of the anchor engine. JSON columns carry the
    # batch's record IDs, the aligned leaf hashes, and each record's
    # Merkle proof, so the batch row plus the record rows are the
    # complete state the engine recovers from after a crash.

    _ANCHOR_BATCH_FIELDS = (
        "merkle_root", "batch_sig", "status", "nonce", "tx_hash",
        "raw_tx", "block_number", "block_timestamp", "error",
        "submitted_at", "confirmed_at")

    @staticmethod
    def _anchor_batch_out(row):
        if row is None:
            return None
        out = dict(row)
        out["record_ids"] = json.loads(out["record_ids"])
        out["leaves"] = json.loads(out["leaves"])
        return out

    def create_anchor_batch(self, batch) -> None:
        self._write(
            "INSERT INTO anchor_batches (batch_id, merkle_root,"
            " batch_sig, record_ids, leaves, status, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (batch["batch_id"], batch["merkle_root"],
             batch.get("batch_sig"),
             json.dumps(batch["record_ids"]),
             json.dumps(batch["leaves"]), batch["status"],
             batch["created_at"]))

    def get_anchor_batch(self, batch_id):
        return self._anchor_batch_out(self._fetchone(
            "SELECT * FROM anchor_batches WHERE batch_id=?",
            (batch_id,)))

    def open_anchor_batch(self):
        """The oldest batch still in flight (prepared or submitted),
        or None. The engine works one batch at a time so a stuck
        batch is always the next thing it looks at."""
        return self._anchor_batch_out(self._fetchone(
            "SELECT * FROM anchor_batches"
            " WHERE status IN ('prepared','submitted')"
            " ORDER BY created_at ASC, batch_id ASC LIMIT 1"))

    def update_anchor_batch(self, batch_id, fields) -> None:
        """Update the mutable fields of a batch row. Field names are
        checked against the fixed list above; values are always
        bound parameters."""
        cols = [k for k in fields if k in self._ANCHOR_BATCH_FIELDS]
        if not cols:
            return
        sql = ("UPDATE anchor_batches SET "
               + ", ".join("%s=?" % k for k in cols)
               + " WHERE batch_id=?")
        self._write(sql, tuple(fields[k] for k in cols) + (batch_id,))

    def release_anchor_batch(self, batch_id) -> None:
        """Flag a failed batch's record rows released so its
        records return to the unanchored pool. Rows are flagged,
        never deleted, and the batch row itself stays, marked
        failed by the caller, as the record of the attempt."""
        self._write(
            "UPDATE record_anchors SET released=1 WHERE batch_id=?",
            (batch_id,))

    def count_anchor_batches(self):
        rows = self._fetchall(
            "SELECT status, COUNT(*) AS n FROM anchor_batches"
            " GROUP BY status")
        return {r["status"]: r["n"] for r in rows}

    def add_record_anchor(self, row) -> None:
        self._write(
            "INSERT OR REPLACE INTO record_anchors"
            " (record_id, batch_id, leaf_hash, proof)"
            " VALUES (?,?,?,?)",
            (row["record_id"], row["batch_id"], row["leaf_hash"],
             json.dumps(row["proof"])))

    def get_record_anchor(self, record_id):
        row = self._fetchone(
            "SELECT * FROM record_anchors WHERE record_id=?"
            " AND released=0",
            (record_id,))
        if row is None:
            return None
        out = dict(row)
        out.pop("released", None)
        out["proof"] = json.loads(out["proof"])
        return out

    def unanchored_registrations(self, limit):
        """Registration records in no anchor batch, oldest first
        (registration time, then record ID, so batch composition is
        deterministic). Returns the parsed signed records."""
        rows = self._fetchall(
            "SELECT r.record_json FROM registrations r"
            " LEFT JOIN record_anchors a"
            " ON a.record_id = r.record_id AND a.released = 0"
            " WHERE a.record_id IS NULL"
            " ORDER BY r.created_at ASC, r.record_id ASC LIMIT ?",
            (limit,))
        out = []
        for row in rows:
            try:
                record = json.loads(row["record_json"])
            except (ValueError, TypeError):
                continue
            if isinstance(record, dict):
                out.append(record)
        return out

    def count_anchored_records(self) -> int:
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM record_anchors a"
            " JOIN anchor_batches b ON b.batch_id = a.batch_id"
            " WHERE b.status='confirmed'")
        return row["n"] if row else 0

    def add_anchor_rotation(self, notice_id, notice, created_at) \
            -> bool:
        """Record a verified rotation notice. Returns False when
        the notice is already on record (recording is idempotent:
        the same notice is the same rotation)."""
        existing = self._fetchone(
            "SELECT notice_id FROM anchor_rotations"
            " WHERE notice_id=?", (notice_id,))
        if existing is not None:
            return False
        self._write(
            "INSERT INTO anchor_rotations (notice_id, notice,"
            " created_at) VALUES (?,?,?)",
            (notice_id, json.dumps(notice), created_at))
        return True

    def list_anchor_rotations(self):
        """Every recorded rotation notice, oldest first: the
        rotation history the authority answer is computed from."""
        rows = self._fetchall(
            "SELECT notice FROM anchor_rotations"
            " ORDER BY created_at ASC, notice_id ASC")
        return [json.loads(r["notice"]) for r in rows]

    # -- unified accounts (Gate G1, npc_verify.accounts) ----------------
    # Every secret column holds a SHA-256 hash, never a plaintext:
    # session tokens, email-link tokens, handoff secrets, recovery
    # codes. Consume methods are guarded updates, so a replay fails
    # closed exactly like the identity-link challenges above.

    def add_account(self, row) -> bool:
        """Put-if-absent on the account id; the email is unique."""
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO accounts"
                " (account_id, email, email_hash, created_at,"
                " updated_at) VALUES (?,?,?,?,?)",
                (row["account_id"], row["email"],
                 row.get("email_hash", ""), row["created_at"],
                 row["updated_at"]))
            self.db.commit()
            return cur.rowcount > 0

    def get_account(self, account_id):
        return self._fetchone(
            "SELECT * FROM accounts WHERE account_id=?",
            (account_id,))

    def get_account_by_email(self, email):
        return self._fetchone(
            "SELECT * FROM accounts WHERE email=?", (email,))

    def add_account_credential(self, row) -> bool:
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO account_credentials"
                " (credential_id, account_id, public_key_cose, alg,"
                " sign_count, aaguid, transports, label, created_at,"
                " last_used_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (row["credential_id"], row["account_id"],
                 row["public_key_cose"], row["alg"],
                 row.get("sign_count", 0), row.get("aaguid", ""),
                 row.get("transports", ""), row.get("label", ""),
                 row["created_at"], row.get("last_used_at", "")))
            self.db.commit()
            return cur.rowcount > 0

    def get_account_credential(self, credential_id):
        return self._fetchone(
            "SELECT * FROM account_credentials"
            " WHERE credential_id=?", (credential_id,))

    def list_account_credentials(self, account_id):
        return self._fetchall(
            "SELECT * FROM account_credentials WHERE account_id=?"
            " ORDER BY created_at ASC", (account_id,))

    def update_credential_use(self, credential_id, sign_count,
                              last_used_at) -> bool:
        return self._write(
            "UPDATE account_credentials SET sign_count=?,"
            " last_used_at=? WHERE credential_id=?",
            (sign_count, last_used_at, credential_id)) > 0

    def add_account_challenge(self, row) -> bool:
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO account_challenges"
                " (challenge_id, account_id, kind, challenge,"
                " created_at, expires_at) VALUES (?,?,?,?,?,?)",
                (row["challenge_id"], row.get("account_id", ""),
                 row["kind"], row["challenge"], row["created_at"],
                 row["expires_at"]))
            self.db.commit()
            return cur.rowcount > 0

    def get_account_challenge(self, challenge_id):
        return self._fetchone(
            "SELECT * FROM account_challenges WHERE challenge_id=?",
            (challenge_id,))

    def consume_account_challenge(self, challenge_id,
                                  consumed_at) -> bool:
        return self._write(
            "UPDATE account_challenges SET consumed_at=?"
            " WHERE challenge_id=? AND consumed_at=''",
            (consumed_at, challenge_id)) > 0

    def add_email_token(self, row) -> bool:
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO account_email_tokens"
                " (token_hash, account_id, handoff_id, created_at,"
                " expires_at) VALUES (?,?,?,?,?)",
                (row["token_hash"], row["account_id"],
                 row.get("handoff_id", ""), row["created_at"],
                 row["expires_at"]))
            self.db.commit()
            return cur.rowcount > 0

    def get_email_token(self, token_hash):
        return self._fetchone(
            "SELECT * FROM account_email_tokens WHERE token_hash=?",
            (token_hash,))

    def consume_email_token(self, token_hash, consumed_at) -> bool:
        return self._write(
            "UPDATE account_email_tokens SET consumed_at=?"
            " WHERE token_hash=? AND consumed_at=''",
            (consumed_at, token_hash)) > 0

    def invalidate_email_tokens(self, account_id, consumed_at) -> int:
        """Retire every still-unused email link for the account, so
        only the freshest link can ever be redeemed."""
        return self._write(
            "UPDATE account_email_tokens SET consumed_at=?"
            " WHERE account_id=? AND consumed_at=''",
            (consumed_at, account_id))

    def add_recovery_codes(self, rows) -> None:
        with self._lock:
            for row in rows:
                self.db.execute(
                    "INSERT OR IGNORE INTO account_recovery_codes"
                    " (account_id, code_hash, created_at)"
                    " VALUES (?,?,?)",
                    (row["account_id"], row["code_hash"],
                     row["created_at"]))
            self.db.commit()

    def find_recovery_code(self, account_id, code_hash):
        return self._fetchone(
            "SELECT * FROM account_recovery_codes"
            " WHERE account_id=? AND code_hash=?",
            (account_id, code_hash))

    def consume_recovery_code(self, account_id, code_hash,
                              consumed_at) -> bool:
        return self._write(
            "UPDATE account_recovery_codes SET consumed_at=?"
            " WHERE account_id=? AND code_hash=? AND consumed_at=''",
            (consumed_at, account_id, code_hash)) > 0

    def count_recovery_codes(self, account_id):
        total = self._fetchone(
            "SELECT COUNT(*) AS n FROM account_recovery_codes"
            " WHERE account_id=?", (account_id,))
        unused = self._fetchone(
            "SELECT COUNT(*) AS n FROM account_recovery_codes"
            " WHERE account_id=? AND consumed_at=''",
            (account_id,))
        return (total["n"] if total else 0,
                unused["n"] if unused else 0)

    def add_account_session(self, row) -> bool:
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO account_sessions"
                " (session_id, account_id, token_hash, surface,"
                " device_label, created_at, last_seen_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (row["session_id"], row["account_id"],
                 row["token_hash"], row.get("surface", "web"),
                 row.get("device_label", ""), row["created_at"],
                 row["last_seen_at"], row["expires_at"]))
            self.db.commit()
            return cur.rowcount > 0

    def get_account_session(self, session_id):
        return self._fetchone(
            "SELECT * FROM account_sessions WHERE session_id=?",
            (session_id,))

    def find_account_session_by_token(self, token_hash):
        return self._fetchone(
            "SELECT * FROM account_sessions WHERE token_hash=?",
            (token_hash,))

    def list_account_sessions(self, account_id):
        return self._fetchall(
            "SELECT * FROM account_sessions WHERE account_id=?"
            " ORDER BY created_at ASC", (account_id,))

    def touch_account_session(self, session_id, last_seen_at) -> bool:
        return self._write(
            "UPDATE account_sessions SET last_seen_at=?"
            " WHERE session_id=?",
            (last_seen_at, session_id)) > 0

    def revoke_account_session(self, session_id, revoked_at) -> bool:
        return self._write(
            "UPDATE account_sessions SET revoked_at=?"
            " WHERE session_id=? AND revoked_at=''",
            (revoked_at, session_id)) > 0

    def add_account_handoff(self, row) -> bool:
        with self._lock:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO account_handoffs"
                " (handoff_id, secret_hash, device_label, status,"
                " created_at, expires_at) VALUES (?,?,?,?,?,?)",
                (row["handoff_id"], row["secret_hash"],
                 row.get("device_label", ""), row.get("status",
                 "pending"), row["created_at"], row["expires_at"]))
            self.db.commit()
            return cur.rowcount > 0

    def get_account_handoff(self, handoff_id):
        return self._fetchone(
            "SELECT * FROM account_handoffs WHERE handoff_id=?",
            (handoff_id,))

    def complete_account_handoff(self, handoff_id, account_id,
                                 completed_at) -> bool:
        """Move a pending handoff to ready, bound to the account
        the browser just signed in. False when it was not pending."""
        return self._write(
            "UPDATE account_handoffs SET status='ready',"
            " account_id=?, completed_at=?"
            " WHERE handoff_id=? AND status='pending'",
            (account_id, completed_at, handoff_id)) > 0

    def consume_account_handoff(self, handoff_id, consumed_at) -> bool:
        return self._write(
            "UPDATE account_handoffs SET status='consumed',"
            " consumed_at=? WHERE handoff_id=? AND status='ready'",
            (consumed_at, handoff_id)) > 0

    def add_account_event(self, row) -> None:
        with self._lock:
            self.db.execute(
                "INSERT OR IGNORE INTO account_events"
                " (event_id, account_id, kind, detail, created_at)"
                " VALUES (?,?,?,?,?)",
                (row["event_id"], row["account_id"], row["kind"],
                 row.get("detail", "{}"), row["created_at"]))
            self.db.commit()

    def list_account_events(self, account_id, limit=50):
        return self._fetchall(
            "SELECT * FROM account_events WHERE account_id=?"
            " ORDER BY created_at DESC, event_id DESC LIMIT ?",
            (account_id, int(limit)))


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
