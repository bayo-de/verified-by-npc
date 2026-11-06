"""DynamoDB-backed store for the Verification API v1.

Implements exactly the interface of npc_verify.store.Store, against a
single DynamoDB table (default npc-verify-store, on-demand), selected
by environment: NPC_STORE_BACKEND=dynamodb (see store.make_store).
With the variable absent the app keeps using SQLite, so local dev and
the test suite are untouched.

Single-table design: partition key pk (String), sort key sk (String),
and one data attribute holding the row as a JSON string, with the same
column names and value shapes the SQLite store returns (JSON columns
stay JSON strings, flags stay 0/1 ints), so every caller sees identical
row dicts. Storing JSON (rather than native DynamoDB types) also keeps
Ed25519-signed payloads byte-stable and sidesteps Decimal coercion.

Mapping (pk / sk):
  attestations        ATT                    / attestation id
  revocations         REV                    / revocation id
  credentials         CRED                   / credential id
  products            PROD                   / tag_id
  agents              AGENT                  / agent_id
  api_keys            APIKEY                 / key_hash
  key_registry        KEYREG                 / key_id
  pact_consents       PACT_CONSENT           / grant_id
  pact consent index  PACT_CONSENT_REC       / record_id -> grant_id
  pact_audit_entries  PACT_AUDIT#<grant_id>  / seq, zero-padded
  pact_revocations    PACT_REV               / grant_id
  registrations       REG                    / record_id
  credit codes        CREDIT_CODE            / code_hash
  credit charges      CREDIT_CHARGE#<hash>   / image_identity
  credit purchases    CREDIT_PURCHASE        / session_id
  credit grants       CREDIT_GRANT#<hash>    / grant_id
  credit subs         CREDIT_SUBSCRIPTION    / subscription_id
  referral codes      CREDIT_REFERRAL_CODE   / referral_hash
  referrals           CREDIT_REFERRAL        / referee code_hash
  idempotency keys    IDEM                   / route + TAB + key
  verification reqs   VREQ                   / subject record_id
  verification tries  VREQATT                / created_at + # + hex
  anchor batches      ANCHOR_BATCH           / batch_id
  record anchors      RECORD_ANCHOR          / record_id
  anchor rotations    ANCHOR_ROTATION        / notice_id

Only three DynamoDB operations are used: GetItem, PutItem (some with
an attribute_not_exists condition, mirroring INSERT OR IGNORE), and
Query on a single partition. Subject / claim-hash / counter lookups
filter client-side after the partition Query; at this service's scale
that is deliberate (no GSIs to provision or keep consistent).

Like the SQLite store, composite read-check-write sequences run under
one re-entrant lock, so single-process semantics match v1/v2 exactly.

boto3 is imported lazily, only when this backend is constructed: the
Lambda Python 3.12 runtime ships it, and SQLite deployments never
import it. A prebuilt table/resource may be injected (tests, sims).
"""
import json
import threading

from . import credits as credits_module
from .store import (registration_claim_hashes,
                    registration_email_hash)

DEFAULT_TABLE = "npc-verify-store"


def _is_conditional_failure(exc) -> bool:
    code = ""
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        code = (resp.get("Error") or {}).get("Code", "")
    return code == "ConditionalCheckFailedException" \
        or "ConditionalCheckFailed" in type(exc).__name__


class DynamoDBStore:
    def __init__(self, table_name=DEFAULT_TABLE, region=None,
                 table=None, resource=None):
        self._lock = threading.RLock()
        self.db = None  # no sqlite connection; App handles memory wiring
        self.path = f"dynamodb://{table_name}"
        if table is not None:
            self.table = table
        else:
            if resource is None:
                import boto3
                kwargs = {}
                if region:
                    kwargs["region_name"] = region
                resource = boto3.resource("dynamodb", **kwargs)
            self.table = resource.Table(table_name)

    @property
    def db_lock(self):
        return self._lock

    def close(self):
        pass

    # -- low-level helpers (always under lock) ----------------------------
    def _get_row(self, pk, sk):
        resp = self.table.get_item(Key={"pk": pk, "sk": sk})
        item = resp.get("Item")
        return json.loads(item["data"]) if item else None

    def _put_row(self, pk, sk, row, if_absent=False):
        """Put one row. Returns False when if_absent and the item exists."""
        item = {"pk": pk, "sk": sk, "data": json.dumps(row)}
        if not if_absent:
            self.table.put_item(Item=item)
            return True
        from boto3.dynamodb.conditions import Attr
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression=Attr("pk").not_exists())
            return True
        except Exception as exc:
            if _is_conditional_failure(exc):
                return False
            raise

    def _query_rows(self, pk, reverse=False, limit=None):
        """All rows in one partition, in sort-key order (or reversed)."""
        from boto3.dynamodb.conditions import Key
        kwargs = {"KeyConditionExpression": Key("pk").eq(pk),
                  "ScanIndexForward": not reverse}
        if limit is not None:
            kwargs["Limit"] = limit
        rows = []
        while True:
            resp = self.table.query(**kwargs)
            for item in resp.get("Items", []):
                rows.append(json.loads(item["data"]))
            last = resp.get("LastEvaluatedKey")
            if not last or limit is not None:
                return rows
            kwargs["ExclusiveStartKey"] = last

    # -- attestations ------------------------------------------------------
    def add_attestation(self, a) -> None:
        row = {
            "id": a.id, "subject_type": a.subject_type,
            "subject_id": a.subject_id, "verdict": a.verdict,
            "scope_json": json.dumps(a.scope), "tested_at": a.tested_at,
            "expires_at": a.expires_at,
            "findings_summary": a.findings_summary,
            "claim_hash": a.claim_hash, "signature_b64": a.signature_b64,
            "key_id": a.key_id, "anchor_chain": a.anchor_chain,
            "anchor_tx": a.anchor_tx, "anchor_hash": a.anchor_hash,
            "anchor_status": a.anchor_status,
            "revoked": 1 if a.revoked else 0, "created_at": a.created_at,
        }
        with self._lock:
            self._put_row("ATT", a.id, row)

    def get_attestation(self, att_id):
        with self._lock:
            return self._get_row("ATT", att_id)

    def latest_attestation(self, subject_type, subject_id):
        with self._lock:
            rows = [r for r in self._query_rows("ATT")
                    if r["subject_type"] == subject_type
                    and r["subject_id"] == subject_id
                    and not r["revoked"]]
        if not rows:
            return None
        rows.sort(key=lambda r: (r["created_at"], r["id"]), reverse=True)
        return rows[0]

    def attestations_by_claim_hash(self, claim_hash):
        with self._lock:
            rows = [r for r in self._query_rows("ATT")
                    if r.get("claim_hash") == claim_hash
                    and not r["revoked"]]
        rows.sort(key=lambda r: (r["created_at"], r["id"]), reverse=True)
        return rows

    def attestations_for_subject(self, subject_type, subject_id):
        """Every attestation ever issued for a subject, revoked
        ones included, oldest first. Mirrors the SQLite store: the
        input set for the agent rating, so nothing is filtered
        out."""
        with self._lock:
            rows = [r for r in self._query_rows("ATT")
                    if r["subject_type"] == subject_type
                    and r["subject_id"] == subject_id]
        rows.sort(key=lambda r: (r["tested_at"], r["created_at"],
                                 r["id"]))
        return rows

    def revoke_attestation(self, att_id, rev_id, reason, sig_b64, key_id,
                           created_at):
        with self._lock:
            row = self._get_row("ATT", att_id)
            if row is None or row["revoked"]:
                return False
            row["revoked"] = 1
            self._put_row("ATT", att_id, row)
            self._put_row("REV", rev_id, {
                "id": rev_id, "attestation_id": att_id, "reason": reason,
                "signature_b64": sig_b64, "key_id": key_id,
                "created_at": created_at})
            return True

    # -- credentials / products / agents ------------------------------------
    def get_credential(self, cred_id):
        with self._lock:
            return self._get_row("CRED", cred_id)

    def get_product(self, tag_id):
        with self._lock:
            return self._get_row("PROD", tag_id)

    def get_agent(self, agent_id):
        with self._lock:
            return self._get_row("AGENT", agent_id)

    def insert_credential(self, c):
        row = {
            "id": c.id, "status": c.status, "title": c.title,
            "issuer": c.issuer, "holder_name": c.holder_name,
            "holder_public": 1 if c.holder_public else 0,
            "issued_at": c.issued_at, "expires_at": c.expires_at,
            "skills_json": json.dumps(c.assessed_skills),
            "signature_b64": c.signature_b64, "key_id": c.key_id,
            "verification_url": c.verification_url,
        }
        with self._lock:
            self._put_row("CRED", c.id, row)

    def insert_product(self, p):
        row = {
            "tag_id": p.tag_id, "status": p.status, "name": p.name,
            "creator": p.creator, "description": p.description,
            "provenance_json": json.dumps(p.provenance),
            "attestation_id": p.attestation_id,
        }
        with self._lock:
            self._put_row("PROD", p.tag_id, row)

    def insert_agent(self, agent_id, verdict, scope, valid_from, valid_until,
                     attestation_id, notes):
        row = {
            "agent_id": agent_id, "verdict": verdict,
            "scope_json": json.dumps(scope), "valid_from": valid_from,
            "valid_until": valid_until, "attestation_id": attestation_id,
            "notes": notes,
        }
        with self._lock:
            self._put_row("AGENT", agent_id, row)

    # -- api keys -------------------------------------------------------------
    def add_api_key(self, key_hash, name, role, per_minute, created_at,
                    company_id=None, team_id=None, agent_id=None):
        row = {
            "key_hash": key_hash, "name": name, "role": role,
            "per_minute": per_minute, "created_at": created_at,
            "revoked": 0, "company_id": company_id, "team_id": team_id,
            "agent_id": agent_id,
        }
        with self._lock:
            self._put_row("APIKEY", key_hash, row)

    def get_api_key(self, key_hash):
        with self._lock:
            row = self._get_row("APIKEY", key_hash)
        if row is None or row.get("revoked"):
            return None
        return row

    # -- key registry ---------------------------------------------------------
    def register_key(self, key_id, purpose, public_key_b64, created_at):
        with self._lock:
            for row in self._query_rows("KEYREG"):
                if row["purpose"] == purpose and row["status"] == "active":
                    row["status"] = "retired"
                    row["retired_at"] = created_at
                    self._put_row("KEYREG", row["key_id"], row)
            self._put_row("KEYREG", key_id, {
                "key_id": key_id, "purpose": purpose,
                "public_key_b64": public_key_b64, "status": "active",
                "created_at": created_at, "retired_at": None})

    def activate_key(self, key_id, purpose, now):
        """Reactivate an on-record key (retire the purpose's others).

        Used by the Lambda bootstrap when a stable key exists in the
        registry but is not the active one; DynamoDB PutItem upserts,
        so this is a plain row rewrite under the lock.
        """
        with self._lock:
            row = self._get_row("KEYREG", key_id)
            if row is None:
                return False
            for other in self._query_rows("KEYREG"):
                if (other["purpose"] == purpose
                        and other["status"] == "active"
                        and other["key_id"] != key_id):
                    other["status"] = "retired"
                    other["retired_at"] = now
                    self._put_row("KEYREG", other["key_id"], other)
            row["status"] = "active"
            row["retired_at"] = None
            self._put_row("KEYREG", key_id, row)
            return True

    def active_key_id(self, purpose):
        with self._lock:
            for row in self._query_rows("KEYREG"):
                if row["purpose"] == purpose and row["status"] == "active":
                    return row["key_id"]
        return None

    def public_key_b64(self, key_id):
        with self._lock:
            row = self._get_row("KEYREG", key_id)
        return row["public_key_b64"] if row else None

    def all_keys(self):
        with self._lock:
            rows = self._query_rows("KEYREG")
        rows.sort(key=lambda r: (r["created_at"], r["key_id"]))
        return [{k: r[k] for k in ("key_id", "purpose", "public_key_b64",
                                   "status", "created_at", "retired_at")}
                for r in rows]

    # -- PACT record layer ----------------------------------------------------
    def add_pact_consent(self, record) -> bool:
        """Insert a signed consent record. False if the grant exists."""
        row = {"record_id": record["record_id"],
               "grant_id": record["grant_id"],
               "record_json": json.dumps(record),
               "created_at": record["granted_at"]}
        with self._lock:
            if not self._put_row("PACT_CONSENT", record["grant_id"], row,
                                 if_absent=True):
                return False
            self._put_row("PACT_CONSENT_REC", record["record_id"],
                          {"grant_id": record["grant_id"]})
            return True

    def get_pact_consent(self, grant_id):
        with self._lock:
            row = self._get_row("PACT_CONSENT", grant_id)
        return json.loads(row["record_json"]) if row else None

    def get_pact_consent_by_record_id(self, record_id):
        with self._lock:
            idx = self._get_row("PACT_CONSENT_REC", record_id)
            if idx is None:
                return None
            return self.get_pact_consent(idx["grant_id"])

    def add_pact_audit_entry(self, entry) -> bool:
        """Append one signed audit entry. False on a (grant_id, seq) clash."""
        row = {"grant_id": entry["grant_id"], "seq": entry["seq"],
               "entry_hash": entry["entry_hash"],
               "record_json": json.dumps(entry)}
        with self._lock:
            return self._put_row(f"PACT_AUDIT#{entry['grant_id']}",
                                 f"{entry['seq']:012d}", row,
                                 if_absent=True)

    def pact_audit_entries(self, grant_id):
        with self._lock:
            rows = self._query_rows(f"PACT_AUDIT#{grant_id}")
        return [json.loads(r["record_json"]) for r in rows]

    def last_pact_audit_entry(self, grant_id):
        with self._lock:
            rows = self._query_rows(f"PACT_AUDIT#{grant_id}",
                                    reverse=True, limit=1)
        return json.loads(rows[0]["record_json"]) if rows else None

    def add_pact_revocation(self, record) -> bool:
        """Insert a signed revocation. False if the grant is already revoked."""
        row = {"record_id": record["record_id"],
               "grant_id": record["grant_id"],
               "record_json": json.dumps(record),
               "created_at": record["revoked_at"]}
        with self._lock:
            return self._put_row("PACT_REV", record["grant_id"], row,
                                 if_absent=True)

    def get_pact_revocation(self, grant_id):
        with self._lock:
            row = self._get_row("PACT_REV", grant_id)
        return json.loads(row["record_json"]) if row else None

    # -- public registration layer --------------------------------------------
    def add_registration(self, record, email, client_ip) -> None:
        """Store a signed registration record (append-only).

        email / client_ip are server-side only (submission caps);
        they are never part of the signed record itself. The email
        hash rides along so the cap counters survive the retention
        purge of the raw email (audit D6).
        """
        row = {"record_id": record["record_id"], "kind": record["kind"],
               "email": email,
               "email_hash": registration_email_hash(email),
               "client_ip": client_ip or "",
               "record_json": json.dumps(record),
               "created_at": record["registered_at"]}
        with self._lock:
            self._put_row("REG", record["record_id"], row)

    def get_registration(self, record_id):
        with self._lock:
            row = self._get_row("REG", record_id)
        return json.loads(row["record_json"]) if row else None

    def registration_for_agent(self, agent_id):
        """The agent registration that names this agent_id, or
        None. Mirrors the SQLite store: the recorded agent_id on a
        registration is the chain from an attestation's subject to
        its accountable owner; the newest match wins, and no match
        means the chain is not recorded."""
        if not agent_id:
            return None
        with self._lock:
            rows = self._query_rows("REG")
        rows.sort(key=lambda r: r["created_at"], reverse=True)
        for row in rows:
            if row.get("kind") != "agent":
                continue
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
        first. Mirrors the SQLite store: a registration answers to
        the hash of its locator address and to the content hash
        recorded at intake (registration_claim_hashes in
        npc_verify.store)."""
        with self._lock:
            rows = self._query_rows("REG")
        rows.sort(key=lambda r: r["created_at"], reverse=True)
        out = []
        for row in rows:
            if row.get("kind") != "content":
                continue
            try:
                record = json.loads(row["record_json"])
            except (ValueError, TypeError):
                continue
            if claim_hash in registration_claim_hashes(record):
                out.append(record)
        return out

    def count_registrations_since(self, dimension, value, since_iso):
        """Count registrations in a rolling window, for the caps.

        Same contract as the SQLite store: dimension is 'email' or 'ip'
        (a fixed literal chosen by the caller); ISO-8601 UTC timestamps
        compare lexicographically. The email dimension counts by
        email HASH so rows purged under the retention policy still
        count (audit D6); rows written before hashes existed fall
        back to hashing their stored email.
        """
        with self._lock:
            rows = self._query_rows("REG")
        if dimension == "email":
            wanted = registration_email_hash(value)
            return sum(
                1 for r in rows
                if (r.get("email_hash")
                    or registration_email_hash(r.get("email", "")))
                == wanted and r["created_at"] >= since_iso)
        return sum(1 for r in rows
                   if r["client_ip"] == value
                   and r["created_at"] >= since_iso)

    def oldest_registration_since(self, dimension, value, since_iso):
        """Oldest created_at among registrations in a rolling
        window, or None. Mirrors the SQLite store, same contract as
        count_registrations_since above (email matched by hash with
        the pre-hash fallback; ISO timestamps compare
        lexicographically)."""
        with self._lock:
            rows = self._query_rows("REG")
        if dimension == "email":
            wanted = registration_email_hash(value)
            times = [r["created_at"] for r in rows
                     if (r.get("email_hash")
                         or registration_email_hash(
                             r.get("email", "")))
                     == wanted and r["created_at"] >= since_iso]
        else:
            times = [r["created_at"] for r in rows
                     if r["client_ip"] == value
                     and r["created_at"] >= since_iso]
        return min(times) if times else None

    def purge_registration_emails(self, cutoff_iso) -> int:
        """Retention sweep (audit D6): blank the raw email on every
        registration created before cutoff_iso. The signed record
        and the email hash (the cap counter key) are untouched.
        Returns how many rows were purged."""
        purged = 0
        with self._lock:
            for row in self._query_rows("REG"):
                if row["created_at"] < cutoff_iso and row.get("email"):
                    if not row.get("email_hash"):
                        row["email_hash"] = registration_email_hash(
                            row["email"])
                    row["email"] = ""
                    self._put_row("REG", row["record_id"], row)
                    purged += 1
        return purged

    # -- verification requests (cycle completion) -----------------------
    def registration_email_hash(self, record_id):
        """The stored submitter email hash for a registration, or
        None when the record is not a registration. Same contract as
        the SQLite store; the hash survives the retention purge."""
        with self._lock:
            row = self._get_row("REG", record_id)
        if row is None:
            return None
        return row.get("email_hash") or registration_email_hash(
            row.get("email", ""))

    def registration_email(self, record_id):
        """The stored raw submitter email for a registration, or
        None. Same contract as the SQLite store: server-side only,
        for the record's own lifecycle mail; None after the D6
        retention purge blanks the raw email."""
        with self._lock:
            row = self._get_row("REG", record_id)
        if row is None:
            return None
        return row.get("email") or None

    def add_verification_request(self, record, subject_record_id,
                                 email, client_ip) -> bool:
        """Store a signed verification-request record, put-if-absent
        on the subject. False when a request already exists."""
        row = {"subject_record_id": subject_record_id,
               "request_record_id": record["record_id"],
               "email_hash": registration_email_hash(email),
               "client_ip": client_ip or "",
               "requested_at": record["requested_at"],
               "record_json": json.dumps(record)}
        with self._lock:
            return self._put_row("VREQ", subject_record_id, row,
                                 if_absent=True)

    def get_verification_request(self, subject_record_id):
        with self._lock:
            row = self._get_row("VREQ", subject_record_id)
        return json.loads(row["record_json"]) if row else None

    def list_verification_requests(self):
        """Every open verification request, oldest first: NPC's
        step-two work queue."""
        with self._lock:
            rows = self._query_rows("VREQ")
        records = [json.loads(r["record_json"]) for r in rows]
        records.sort(key=lambda r: r.get("requested_at", ""))
        return records

    def record_verification_request_attempt(self, record_id, email,
                                            client_ip, matched,
                                            created_at):
        import secrets as _secrets
        row = {"record_id": record_id,
               "email_hash": registration_email_hash(email),
               "client_ip": client_ip or "",
               "matched": bool(matched),
               "created_at": created_at}
        sk = created_at + "#" + _secrets.token_hex(6)
        with self._lock:
            self._put_row("VREQATT", sk, row)

    def count_verification_request_attempts_since(self, dimension,
                                                  value, since_iso):
        """Count attempts in a rolling window, mirroring the
        registration counters: the email dimension counts by hash."""
        with self._lock:
            rows = self._query_rows("VREQATT")
        if dimension == "email":
            wanted = registration_email_hash(value)
            return sum(1 for r in rows
                       if r.get("email_hash") == wanted
                       and r["created_at"] >= since_iso)
        return sum(1 for r in rows
                   if r.get("client_ip") == value
                   and r["created_at"] >= since_iso)

    # -- federated identity linking (phase 1) ---------------------------
    # Partitions: challenges under "ILCHAL" (sk = challenge id), link
    # records under "ILINK" (sk = link id), observations under
    # "IOBS#<subject_record_id>" (sk = wallet|provider|signal, latest
    # write wins: this backend keeps the latest observation per key,
    # which is all the panel reads), attempts under "ILATT".
    def add_identity_link_challenge(self, row) -> bool:
        """Store a pending link challenge. Put-if-absent on the id."""
        with self._lock:
            return self._put_row("ILCHAL", row["challenge_id"],
                                 dict(row), if_absent=True)

    def get_identity_link_challenge(self, challenge_id):
        with self._lock:
            return self._get_row("ILCHAL", challenge_id)

    def find_identity_link_challenge(self, kind, provider, secret):
        """The open challenge carrying this secret (an OAuth state),
        or None, mirroring the SQLite store."""
        with self._lock:
            rows = self._query_rows("ILCHAL")
        for row in rows:
            if row.get("kind") == kind \
                    and row.get("provider") == provider \
                    and row.get("secret") == secret \
                    and not row.get("consumed_at"):
                return row
        return None

    def consume_identity_link_challenge(self, challenge_id,
                                        consumed_at) -> bool:
        """Mark a challenge used. False when already consumed, so a
        replay fails closed. (Read-modify-write under the store
        lock, the same pattern the rest of this backend uses.)"""
        with self._lock:
            row = self._get_row("ILCHAL", challenge_id)
            if row is None or row.get("consumed_at"):
                return False
            row["consumed_at"] = consumed_at
            self._put_row("ILCHAL", challenge_id, row)
            return True

    def add_identity_link(self, record) -> bool:
        """Store a signed identity-link record, put-if-absent."""
        entry = record["signal"]
        row = {"link_id": record["record_id"],
               "subject_record_id": record["subject_record_id"],
               "provider": entry["provider"],
               "signal": entry["signal"],
               "subject_ref": entry["subject_ref"],
               "linked_at": record["linked_at"],
               "record_json": json.dumps(record)}
        with self._lock:
            return self._put_row("ILINK", record["record_id"], row,
                                 if_absent=True)

    def get_identity_link(self, link_id):
        with self._lock:
            row = self._get_row("ILINK", link_id)
        return json.loads(row["record_json"]) if row else None

    def list_identity_links(self, subject_record_id):
        """Every link record attached to a registration, oldest
        first."""
        with self._lock:
            rows = self._query_rows("ILINK")
        records = [json.loads(r["record_json"]) for r in rows
                   if r["subject_record_id"] == subject_record_id]
        records.sort(key=lambda r: r.get("linked_at", ""))
        return records

    def add_identity_observation(self, row) -> None:
        """Record the latest provider observation for a key. This
        backend keeps only the latest per (subject, wallet, provider,
        signal); the SQLite backend keeps the full history. The
        panel contract reads the latest either way."""
        sk = "|".join((row["wallet"].lower(), row["provider"],
                       row["signal"]))
        with self._lock:
            self._put_row("IOBS#" + row["subject_record_id"], sk,
                          dict(row))

    def latest_identity_observations(self, subject_record_id):
        """The latest observation per (wallet, provider, signal),
        keyed by that tuple, mirroring the SQLite store."""
        with self._lock:
            rows = self._query_rows("IOBS#" + subject_record_id)
        latest = {}
        for row in rows:
            latest[(row["wallet"].lower(), row["provider"],
                    row["signal"])] = row
        return latest

    def record_identity_link_attempt(self, record_id, email,
                                     client_ip, matched, created_at):
        import secrets as _secrets
        row = {"record_id": record_id,
               "email_hash": registration_email_hash(email),
               "client_ip": client_ip or "",
               "matched": bool(matched),
               "created_at": created_at}
        sk = created_at + "#" + _secrets.token_hex(6)
        with self._lock:
            self._put_row("ILATT", sk, row)

    def count_identity_link_attempts_since(self, dimension, value,
                                           since_iso):
        """Count link attempts in a rolling window, mirroring the
        verification-request counters."""
        with self._lock:
            rows = self._query_rows("ILATT")
        if dimension == "email":
            wanted = registration_email_hash(value)
            return sum(1 for r in rows
                       if r.get("email_hash") == wanted
                       and r["created_at"] >= since_iso)
        return sum(1 for r in rows
                   if r.get("client_ip") == value
                   and r["created_at"] >= since_iso)

    # -- social profiles lane (build pass 1) ----------------------------
    # Partitions: connect challenges under "SOCHAL" (sk = challenge
    # id), connections under "SOCONN" (sk = connection id), scan
    # headers under "SOSCAN" (sk = scan id), scan items under
    # "SOSCANITEM#<scan_id>" (sk = external id), the registration
    # index under "SOREG" (sk = email hash + "|" + identity key),
    # batch receipts under "SOBATCH" (sk = batch id), attempts
    # under "SOATT". This backend uses only Get/Put/Query like the
    # rest of the store, so a disconnect tombstones the cached scan
    # rows (their data is replaced by a purged marker) instead of
    # deleting them; readers treat a tombstone as gone, which is
    # what the platform data-deletion duty covers.
    def add_social_challenge(self, row) -> bool:
        with self._lock:
            return self._put_row("SOCHAL", row["challenge_id"],
                                 dict(row), if_absent=True)

    def find_social_challenge(self, platform, secret):
        with self._lock:
            rows = self._query_rows("SOCHAL")
        for row in rows:
            if row.get("platform") == platform \
                    and row.get("secret") == secret \
                    and not row.get("consumed_at"):
                return row
        return None

    def consume_social_challenge(self, challenge_id,
                                 consumed_at) -> bool:
        with self._lock:
            row = self._get_row("SOCHAL", challenge_id)
            if row is None or row.get("consumed_at"):
                return False
            row["consumed_at"] = consumed_at
            self._put_row("SOCHAL", challenge_id, row)
            return True

    def add_social_connection(self, row) -> bool:
        with self._lock:
            return self._put_row("SOCONN", row["connection_id"],
                                 dict(row), if_absent=True)

    def get_social_connection(self, connection_id):
        with self._lock:
            row = self._get_row("SOCONN", connection_id)
        return row if row and not row.get("purged") else None

    def find_social_connection(self, platform, email_hash,
                               platform_account_id):
        with self._lock:
            rows = self._query_rows("SOCONN")
        matches = [r for r in rows
                   if r.get("platform") == platform
                   and r.get("email_hash") == email_hash
                   and r.get("platform_account_id")
                   == platform_account_id]
        if not matches:
            return None
        matches.sort(key=lambda r: r.get("created_at", ""))
        return matches[-1]

    def list_social_connections(self, email_hash):
        with self._lock:
            rows = self._query_rows("SOCONN")
        out = [r for r in rows
               if r.get("email_hash") == email_hash
               and r.get("status") == "active"]
        out.sort(key=lambda r: r.get("created_at", ""))
        return out

    def update_social_connection(self, connection_id, fields) -> bool:
        allowed = ("access_token", "refresh_token",
                   "token_expires_at", "account_display_name",
                   "scopes", "status", "updated_at")
        with self._lock:
            row = self._get_row("SOCONN", connection_id)
            if row is None:
                return False
            for key in allowed:
                if key in fields:
                    row[key] = fields[key]
            self._put_row("SOCONN", connection_id, row)
            return True

    def disconnect_social_connection(self, connection_id,
                                     updated_at) -> bool:
        with self._lock:
            row = self._get_row("SOCONN", connection_id)
            if row is None or row.get("status") != "active":
                return False
            row["status"] = "disconnected"
            row["access_token"] = ""
            row["refresh_token"] = ""
            row["updated_at"] = updated_at
            self._put_row("SOCONN", connection_id, row)
            return True

    def add_social_scan(self, row) -> bool:
        with self._lock:
            return self._put_row("SOSCAN", row["scan_id"],
                                 dict(row), if_absent=True)

    def get_social_scan(self, scan_id):
        with self._lock:
            row = self._get_row("SOSCAN", scan_id)
        return row if row and not row.get("purged") else None

    def add_social_scan_item(self, scan_id, item) -> bool:
        row = {"scan_id": scan_id,
               "external_id": item["external_id"],
               "idempotency_key": item["idempotency_key"],
               "item_json": json.dumps(item)}
        with self._lock:
            return self._put_row("SOSCANITEM#" + scan_id,
                                 item["external_id"], row,
                                 if_absent=True)

    def list_social_scan_items(self, scan_id):
        with self._lock:
            rows = self._query_rows("SOSCANITEM#" + scan_id)
        return [json.loads(r["item_json"]) for r in rows
                if not r.get("purged")]

    def delete_social_scans(self, connection_id) -> None:
        """Tombstone the connection's cached enumerations (see the
        section note). Signed records are never touched."""
        with self._lock:
            scans = [r for r in self._query_rows("SOSCAN")
                     if r.get("connection_id") == connection_id
                     and not r.get("purged")]
            for scan in scans:
                items = self._query_rows(
                    "SOSCANITEM#" + scan["scan_id"])
                for item in items:
                    self._put_row(
                        "SOSCANITEM#" + scan["scan_id"],
                        item["external_id"],
                        {"scan_id": scan["scan_id"],
                         "external_id": item["external_id"],
                         "purged": True})
                self._put_row("SOSCAN", scan["scan_id"],
                              {"scan_id": scan["scan_id"],
                               "connection_id": connection_id,
                               "purged": True})

    def get_social_registration(self, email_hash, identity_key):
        with self._lock:
            return self._get_row(
                "SOREG", email_hash + "|" + identity_key)

    def list_social_registrations(self, email_hash):
        with self._lock:
            rows = self._query_rows("SOREG")
        return [r for r in rows
                if r.get("email_hash") == email_hash]

    def add_social_registration(self, row) -> bool:
        with self._lock:
            return self._put_row(
                "SOREG",
                row["email_hash"] + "|" + row["identity_key"],
                dict(row), if_absent=True)

    def update_social_registration(self, email_hash, identity_key,
                                   idempotency_key, record_id,
                                   batch_id) -> None:
        with self._lock:
            row = self._get_row(
                "SOREG", email_hash + "|" + identity_key)
            if row is None:
                return
            row["idempotency_key"] = idempotency_key
            row["record_id"] = record_id
            row["batch_id"] = batch_id
            self._put_row(
                "SOREG", email_hash + "|" + identity_key, row)

    def add_social_batch(self, record, connection_id) -> bool:
        row = {"batch_id": record["record_id"],
               "connection_id": connection_id or "",
               "record_json": json.dumps(record),
               "created_at": record["registered_at"]}
        with self._lock:
            return self._put_row("SOBATCH", record["record_id"],
                                 row, if_absent=True)

    def get_social_batch(self, batch_id):
        with self._lock:
            row = self._get_row("SOBATCH", batch_id)
        return json.loads(row["record_json"]) if row else None

    def list_social_scans(self, connection_id):
        """Every stored scan header for one connection, oldest
        first; tombstoned rows are gone, as everywhere."""
        with self._lock:
            rows = self._query_rows("SOSCAN")
        out = [r for r in rows
               if r.get("connection_id") == connection_id
               and not r.get("purged")]
        out.sort(key=lambda r: (r.get("enumerated_at", ""),
                                r.get("scan_id", "")))
        return out

    def list_social_batches(self, connection_id):
        """Every batch receipt minted for one connection, oldest
        first, as the parsed signed records."""
        with self._lock:
            rows = self._query_rows("SOBATCH")
        mine = [r for r in rows
                if r.get("connection_id") == (connection_id or "")]
        mine.sort(key=lambda r: (r.get("created_at", ""),
                                 r.get("batch_id", "")))
        return [json.loads(r["record_json"]) for r in mine]

    def record_social_attempt(self, target, email, client_ip,
                              matched, created_at):
        import secrets as _secrets
        row = {"target": target or "",
               "email_hash": registration_email_hash(email),
               "client_ip": client_ip or "",
               "matched": bool(matched),
               "created_at": created_at}
        sk = created_at + "#" + _secrets.token_hex(6)
        with self._lock:
            self._put_row("SOATT", sk, row)

    def count_social_attempts_since(self, dimension, value,
                                    since_iso):
        with self._lock:
            rows = self._query_rows("SOATT")
        if dimension == "email":
            wanted = registration_email_hash(value)
            return sum(1 for r in rows
                       if r.get("email_hash") == wanted
                       and r["created_at"] >= since_iso)
        return sum(1 for r in rows
                   if r.get("client_ip") == value
                   and r["created_at"] >= since_iso)

    # -- idempotency keys (audit D4) ---------------------------------------
    def get_idempotency(self, idem_key, route):
        """The stored response for (key, route), or None."""
        with self._lock:
            row = self._get_row("IDEM", route + "\t" + idem_key)
        if row is None:
            return None
        return {"body_hash": row["body_hash"], "status": row["status"],
                "response": json.loads(row["response_json"])}

    def put_idempotency(self, idem_key, route, body_hash, status,
                        response, created_at) -> bool:
        """Store a response under (key, route). False if the pair is
        already taken (a concurrent mint won the race)."""
        row = {"body_hash": body_hash, "status": status,
               "response_json": json.dumps(response),
               "created_at": created_at}
        with self._lock:
            return self._put_row("IDEM", route + "\t" + idem_key, row,
                                 if_absent=True)

    # -- Biblo chat (spec section 4) --------------------------------------
    # Transcripts live under pk "CHAT#<thread_id>", feedback under
    # "CHATFB#<thread_id>", the daily spend counter under pk "CHATCAP"
    # (sk = UTC date), per-IP rate events under "CHATIP#<sha256(ip)>",
    # and a per-day thread index under "CHATDAY#<date>". Every chat
    # item carries a ttl_epoch attribute (creation + 90 days) next to
    # the usual data envelope; DynamoDB TTL must be enabled on that
    # attribute for the table (deploy-time step) for expiry to run.
    def _put_chat_item(self, pk, sk, row, ttl_epoch):
        item = {"pk": pk, "sk": sk, "data": json.dumps(row),
                "ttl_epoch": int(ttl_epoch)}
        self.table.put_item(Item=item)
        return True

    def append_chat_turn(self, thread_id, role, text, page, sources,
                         no_answer, created_at, ttl_epoch) -> int:
        """Append one turn to a thread; returns its 1-based seq."""
        with self._lock:
            existing = self._query_rows("CHAT#" + thread_id)
            seq = len(existing) + 1
            row = {"seq": seq, "role": role, "text": text,
                   "page": page or "", "sources": list(sources or []),
                   "no_answer": bool(no_answer),
                   "created_at": created_at,
                   "ttl_epoch": int(ttl_epoch)}
            self._put_chat_item("CHAT#" + thread_id, "%06d" % seq, row,
                                ttl_epoch)
            return seq

    def get_chat_turns(self, thread_id):
        """All turns of a thread, in order. Empty list: no such thread."""
        with self._lock:
            return self._query_rows("CHAT#" + thread_id)

    def chat_thread_exists(self, thread_id) -> bool:
        with self._lock:
            return bool(self._query_rows("CHAT#" + thread_id, limit=1))

    def put_chat_feedback(self, thread_id, turn, rating, comment,
                          created_at, ttl_epoch) -> None:
        row = {"turn": int(turn), "rating": rating,
               "comment": comment or "", "created_at": created_at,
               "ttl_epoch": int(ttl_epoch)}
        with self._lock:
            self._put_chat_item("CHATFB#" + thread_id,
                                "%06d" % int(turn), row, ttl_epoch)

    def get_chat_feedback(self, thread_id):
        with self._lock:
            return self._query_rows("CHATFB#" + thread_id)

    def get_chat_daily(self, day):
        with self._lock:
            row = self._get_row("CHATCAP", day)
        if row is None:
            return {"conversations": 0, "turns": 0, "est_micro_usd": 0}
        return {"conversations": int(row["conversations"]),
                "turns": int(row["turns"]),
                "est_micro_usd": int(row["est_micro_usd"])}

    def bump_chat_daily(self, day, conversations=0, turns=0,
                        est_micro_usd=0, ttl_epoch=None) -> None:
        with self._lock:
            cur = self.get_chat_daily(day)
            row = {"conversations": cur["conversations"]
                   + int(conversations),
                   "turns": cur["turns"] + int(turns),
                   "est_micro_usd": cur["est_micro_usd"]
                   + int(est_micro_usd)}
            if ttl_epoch is None:
                ttl_epoch = 0
            self._put_chat_item("CHATCAP", day, row, ttl_epoch)

    def record_chat_ip_event(self, client_ip, created_at,
                             ttl_epoch) -> None:
        import hashlib
        pk = "CHATIP#" + hashlib.sha256(
            (client_ip or "").encode("utf-8")).hexdigest()
        with self._lock:
            n = len(self._query_rows(pk))
            row = {"created_at": created_at,
                   "ttl_epoch": int(ttl_epoch)}
            self._put_chat_item(pk, "%s#%06d" % (created_at, n), row,
                                ttl_epoch)

    def count_chat_ip_events(self, client_ip, since_iso) -> int:
        import hashlib
        pk = "CHATIP#" + hashlib.sha256(
            (client_ip or "").encode("utf-8")).hexdigest()
        with self._lock:
            rows = self._query_rows(pk)
        return sum(1 for r in rows if r["created_at"] >= since_iso)

    def note_chat_thread_day(self, thread_id, day, created_at,
                             ttl_epoch) -> None:
        """Index a new thread under its creation day (digest export)."""
        row = {"thread_id": thread_id, "created_at": created_at,
               "ttl_epoch": int(ttl_epoch)}
        with self._lock:
            self._put_chat_item("CHATDAY#" + day, thread_id, row,
                                ttl_epoch)

    def chat_threads_on(self, day):
        """Thread ids created on the given UTC day."""
        with self._lock:
            rows = self._query_rows("CHATDAY#" + day)
        return sorted(r["thread_id"] for r in rows)

    # -- paid check credits (npc_verify.credits) ---------------------------
    # Same ledger contract as the SQLite store: balances live in the
    # code row, a charge item exists per (code, image) pair ever
    # charged, and composite sequences run under the store lock.

    def create_credit_purchase(self, session_id, pack_id, buyer_email,
                               now, referral_hash=None):
        row = {"session_id": session_id, "pack_id": pack_id,
               "code_hash": None, "code_plaintext": None,
               "status": "pending", "buyer_email": buyer_email,
               "code_delivered": 0, "created_at": now,
               "completed_at": None, "referral_hash": referral_hash}
        with self._lock:
            self._put_row("CREDIT_PURCHASE", session_id, row,
                          if_absent=True)

    def get_credit_purchase(self, session_id):
        with self._lock:
            return self._get_row("CREDIT_PURCHASE", session_id)

    def complete_credit_purchase(self, session_id, code_hash,
                                 code_plaintext, pack, buyer_email, now):
        """Mark a purchase paid and mint its code, exactly once; a
        replayed completion returns the original code row."""
        with self._lock:
            purchase = self._get_row("CREDIT_PURCHASE", session_id)
            if purchase is None:
                return None
            if purchase["status"] == "paid" and purchase["code_hash"]:
                return self._get_row("CREDIT_CODE",
                                     purchase["code_hash"])
            code_row = {"code_hash": code_hash, "pack_id": pack["id"],
                        "credits_total": pack["checks"],
                        "credits_used": 0, "status": "active",
                        "stripe_session_id": session_id,
                        "buyer_email": buyer_email, "created_at": now,
                        "redeemed_at": None, "last_used_at": None}
            self._put_row("CREDIT_CODE", code_hash, code_row)
            purchase.update({
                "status": "paid", "code_hash": code_hash,
                "code_plaintext": code_plaintext,
                "buyer_email": buyer_email, "completed_at": now})
            self._put_row("CREDIT_PURCHASE", session_id, purchase)
            return code_row

    def expire_credit_purchase(self, session_id, now):
        with self._lock:
            purchase = self._get_row("CREDIT_PURCHASE", session_id)
            if purchase is not None \
                    and purchase["status"] == "pending":
                purchase["status"] = "expired"
                self._put_row("CREDIT_PURCHASE", session_id, purchase)

    def take_credit_code_delivery(self, session_id):
        """Hand the plaintext code to the buyer's browser, once;
        the stored plaintext is wiped at delivery."""
        with self._lock:
            purchase = self._get_row("CREDIT_PURCHASE", session_id)
            if purchase is None or purchase["status"] != "paid":
                return None, purchase
            if purchase["code_delivered"] \
                    or not purchase["code_plaintext"]:
                return None, purchase
            code = purchase["code_plaintext"]
            purchase["code_delivered"] = 1
            purchase["code_plaintext"] = None
            self._put_row("CREDIT_PURCHASE", session_id, purchase)
            return code, purchase

    # -- Verifier Pass: subscriptions and monthly grants ---------------
    # Same contract as the SQLite store: grants live in their own
    # partition per code, subscriptions in one partition keyed by
    # the Stripe subscription id, and every code read carries the
    # computed grant view.

    def _credit_grants(self, code_hash):
        """All grants on a code, oldest first."""
        rows = self._query_rows("CREDIT_GRANT#" + code_hash)
        return sorted(rows, key=lambda g: (g["granted_at"],
                                           g["grant_id"]))

    def _subscription_for_code(self, code_hash):
        for sub in self._query_rows("CREDIT_SUBSCRIPTION"):
            if sub["code_hash"] == code_hash:
                return sub
        return None

    def _augment_credit_row(self, row, now):
        """Attach the grant view to a raw code row. Same fields and
        semantics as the SQLite store's view: the AI balance is
        the Pass grants' AI room plus the bonus grants' balances
        plus the code row's own pack counters, priced through
        credits.pack_grant_view."""
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
        sub = self._subscription_for_code(row["code_hash"])
        out["subscription_status"] = sub["status"] if sub else None
        return out

    def activate_pass_subscription(self, session_id, code_hash,
                                   code_plaintext, pack, buyer_email,
                                   subscription_id, customer_id,
                                   grant_id, now, expires_at):
        """Mark a Pass purchase paid, mint its code, open the
        subscription, and land the first monthly grant, exactly
        once; a replayed activation returns the original code row."""
        with self._lock:
            purchase = self._get_row("CREDIT_PURCHASE", session_id)
            if purchase is None:
                return None
            if purchase["status"] == "paid" and purchase["code_hash"]:
                return self._augment_credit_row(
                    self._get_row("CREDIT_CODE", purchase["code_hash"]),
                    now)
            code_row = {"code_hash": code_hash, "pack_id": pack["id"],
                        "credits_total": 0, "credits_used": 0,
                        "status": "active",
                        "stripe_session_id": session_id,
                        "buyer_email": buyer_email, "created_at": now,
                        "redeemed_at": None, "last_used_at": None}
            self._put_row("CREDIT_CODE", code_hash, code_row)
            sub = {"subscription_id": subscription_id,
                   "code_hash": code_hash, "pack_id": pack["id"],
                   "customer_id": customer_id,
                   "buyer_email": buyer_email,
                   "monthly_checks": pack["checks"],
                   "ai_checks": pack.get("ai_checks", 0),
                   "status": "active", "created_at": now,
                   "updated_at": now}
            self._put_row("CREDIT_SUBSCRIPTION", subscription_id, sub)
            grant = {"grant_id": grant_id, "code_hash": code_hash,
                     "amount": pack["checks"], "used": 0,
                     "ai_cap": pack.get("ai_checks", 0), "ai_used": 0,
                     "source": "pass",
                     "granted_at": now, "expires_at": expires_at}
            self._put_row("CREDIT_GRANT#" + code_hash, grant_id, grant)
            purchase.update({
                "status": "paid", "code_hash": code_hash,
                "code_plaintext": code_plaintext,
                "buyer_email": buyer_email, "completed_at": now})
            self._put_row("CREDIT_PURCHASE", session_id, purchase)
            return self._augment_credit_row(code_row, now)

    def get_subscription(self, subscription_id):
        with self._lock:
            return self._get_row("CREDIT_SUBSCRIPTION",
                                 subscription_id)

    def grant_subscription_allowance(self, subscription_id, grant_id,
                                     now, expires_at):
        """Land one renewal grant, keyed by the Stripe invoice id.
        Same outcomes as the SQLite store: granted / duplicate /
        inactive / not_found."""
        with self._lock:
            sub = self._get_row("CREDIT_SUBSCRIPTION",
                                subscription_id)
            if sub is None:
                return {"outcome": "not_found", "grant": None}
            pk = "CREDIT_GRANT#" + sub["code_hash"]
            existing = self._get_row(pk, grant_id)
            if existing is not None:
                return {"outcome": "duplicate", "grant": existing}
            if sub["status"] != "active":
                return {"outcome": "inactive", "grant": None}
            grant = {"grant_id": grant_id,
                     "code_hash": sub["code_hash"],
                     "amount": sub["monthly_checks"], "used": 0,
                     "ai_cap": sub["ai_checks"], "ai_used": 0,
                     "source": "pass",
                     "granted_at": now, "expires_at": expires_at}
            self._put_row(pk, grant_id, grant)
            return {"outcome": "granted", "grant": grant}

    def cancel_subscription(self, subscription_id, now):
        """Stop future grants; granted checks live until expiry."""
        with self._lock:
            sub = self._get_row("CREDIT_SUBSCRIPTION",
                                subscription_id)
            if sub is None:
                return None
            if sub["status"] != "canceled":
                sub["status"] = "canceled"
                sub["updated_at"] = now
                self._put_row("CREDIT_SUBSCRIPTION",
                              subscription_id, sub)
            return sub

    # -- referrals (npc_verify.credits, Bayo 2026-10-28) ---------------
    # Same contract as the SQLite store: a referral code per redeem
    # code, stored only as its hash with the plaintext resting until
    # one-time delivery, and attribution plus both bonuses in one
    # locked sequence keyed by the referral row.

    def ensure_referral_code(self, code_hash, referral_hash,
                             code_plaintext, now):
        """Record a code's personal referral code, first one wins.
        Returns the referral row for the code."""
        with self._lock:
            existing = self.get_referral_code_for(code_hash)
            if existing is not None:
                return existing
            row = {"referral_hash": referral_hash,
                   "code_hash": code_hash,
                   "code_plaintext": code_plaintext, "delivered": 0,
                   "created_at": now}
            if not self._put_row("CREDIT_REFERRAL_CODE",
                                 referral_hash, row, if_absent=True):
                return self.get_referral_code_for(code_hash)
            return row

    def get_referral_code_for(self, code_hash):
        """The referral row owned by a redeem code, or None."""
        for row in self._query_rows("CREDIT_REFERRAL_CODE"):
            if row["code_hash"] == code_hash:
                return row
        return None

    def get_referral_owner(self, referral_hash):
        """The referral row a referral code hash names, or None."""
        with self._lock:
            return self._get_row("CREDIT_REFERRAL_CODE",
                                 referral_hash)

    def take_referral_code_delivery(self, code_hash):
        """Hand a code's referral plaintext to its owner, once;
        the stored plaintext is wiped at delivery. Same returns as
        the SQLite store."""
        with self._lock:
            row = self.get_referral_code_for(code_hash)
            if row is None:
                return None, None
            if row["delivered"] or not row["code_plaintext"]:
                return None, row
            plain = row["code_plaintext"]
            row["delivered"] = 1
            row["code_plaintext"] = None
            self._put_row("CREDIT_REFERRAL_CODE",
                          row["referral_hash"], row)
            return plain, row

    def get_referral(self, referee_code_hash):
        """The referral row attributing a code, or None."""
        with self._lock:
            return self._get_row("CREDIT_REFERRAL",
                                 referee_code_hash)

    def _referral_month_total(self, referrer_code_hash, month):
        """Bonus checks already granted to a referrer as referral
        bonuses inside one calendar month ("YYYY-MM" prefix),
        counting the at-link and first-purchase bonuses together."""
        total = 0
        for g in self._credit_grants(referrer_code_hash):
            if g.get("source") in ("referral_referrer",
                                   "referral_link") \
                    and g["granted_at"][:7] == month:
                total += g["amount"]
        return total

    def referral_stats(self, code_hash, now):
        """Referral view for one code: referrals made, this
        month's referral bonus, and whether it was referred."""
        with self._lock:
            count = 0
            for row in self._query_rows("CREDIT_REFERRAL"):
                if row["referrer_code_hash"] == code_hash:
                    count += 1
            return {
                "referred_count": count,
                "referral_bonus_this_month":
                    self._referral_month_total(code_hash, now[:7]),
                "referred_by":
                    self._get_row("CREDIT_REFERRAL",
                                  code_hash) is not None,
            }

    def attribute_referral(self, referee_code_hash, referral_hash,
                           referee_grant_id, referrer_grant_id, now,
                           expires_at, referee_bonus, referrer_bonus,
                           monthly_cap, referrer_link_bonus=0,
                           referrer_link_grant_id=None):
        """Attribute a referee code to a referral code's owner and
        land the bonuses, atomically and exactly once. Same
        outcomes and rules as the SQLite store: the referral row
        is the idempotency record, self-referral (same code, or
        the same purchaser email on both codes) records and grants
        nothing, the referrer's two grants (the at-link bonus,
        then the first-purchase bonus) are trimmed in that order
        so the month's referral total never passes the cap, and
        bonus grants carry ai_cap 0 in storage (an AI check may
        still spend a bonus grant's whole remaining balance,
        drawn after any Pass sub-allowance; see
        credits.grant_ai_room) and the caller's rollover
        expiry."""
        with self._lock:
            referee = self._get_row("CREDIT_CODE",
                                    referee_code_hash)
            if referee is None:
                return {"outcome": "not_found", "referral": None,
                        "referee_bonus": 0, "referrer_bonus": 0,
                        "referrer_link_bonus": 0}
            if referee["status"] == "revoked":
                return {"outcome": "revoked", "referral": None,
                        "referee_bonus": 0, "referrer_bonus": 0,
                        "referrer_link_bonus": 0}
            owner = self._get_row("CREDIT_REFERRAL_CODE",
                                  referral_hash)
            if owner is None:
                return {"outcome": "referral_not_found",
                        "referral": None, "referee_bonus": 0,
                        "referrer_bonus": 0,
                        "referrer_link_bonus": 0}
            referrer_hash = owner["code_hash"]
            referrer = self._get_row("CREDIT_CODE", referrer_hash)
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
            existing = self._get_row("CREDIT_REFERRAL",
                                     referee_code_hash)
            if existing is not None:
                return {"outcome": "already_referred",
                        "referral": existing, "referee_bonus": 0,
                        "referrer_bonus":
                            existing["referrer_bonus"],
                        "referrer_link_bonus":
                            existing.get("referrer_link_bonus", 0)}
            month_total = self._referral_month_total(
                referrer_hash, now[:7])
            link_amount = max(0, min(referrer_link_bonus,
                                     monthly_cap - month_total))
            amount = max(0, min(
                referrer_bonus,
                monthly_cap - month_total - link_amount))
            row = {"referee_code_hash": referee_code_hash,
                   "referrer_code_hash": referrer_hash,
                   "referral_hash": referral_hash,
                   "referee_grant_id": referee_grant_id,
                   "referrer_grant_id":
                       referrer_grant_id if amount > 0 else None,
                   "referrer_link_grant_id":
                       referrer_link_grant_id
                       if link_amount > 0 else None,
                   "referrer_bonus": amount,
                   "referrer_link_bonus": link_amount,
                   "linked_at": now}
            if not self._put_row("CREDIT_REFERRAL",
                                 referee_code_hash, row,
                                 if_absent=True):
                existing = self._get_row("CREDIT_REFERRAL",
                                         referee_code_hash)
                return {"outcome": "already_referred",
                        "referral": existing, "referee_bonus": 0,
                        "referrer_bonus":
                            existing["referrer_bonus"],
                        "referrer_link_bonus":
                            existing.get("referrer_link_bonus", 0)}
            grant = {"grant_id": referee_grant_id,
                     "code_hash": referee_code_hash,
                     "amount": referee_bonus, "used": 0,
                     "ai_cap": 0, "ai_used": 0,
                     "source": "referral_referee",
                     "granted_at": now, "expires_at": expires_at}
            self._put_row("CREDIT_GRANT#" + referee_code_hash,
                          referee_grant_id, grant)
            if link_amount > 0:
                grant = {"grant_id": referrer_link_grant_id,
                         "code_hash": referrer_hash,
                         "amount": link_amount, "used": 0,
                         "ai_cap": 0, "ai_used": 0,
                         "source": "referral_link",
                         "granted_at": now,
                         "expires_at": expires_at}
                self._put_row("CREDIT_GRANT#" + referrer_hash,
                              referrer_link_grant_id, grant)
            if amount > 0:
                grant = {"grant_id": referrer_grant_id,
                         "code_hash": referrer_hash,
                         "amount": amount, "used": 0,
                         "ai_cap": 0, "ai_used": 0,
                         "source": "referral_referrer",
                         "granted_at": now,
                         "expires_at": expires_at}
                self._put_row("CREDIT_GRANT#" + referrer_hash,
                              referrer_grant_id, grant)
            return {"outcome": "linked", "referral": row,
                    "referee_bonus": referee_bonus,
                    "referrer_bonus": amount,
                    "referrer_link_bonus": link_amount}

    def get_credit_code(self, code_hash, now=None):
        with self._lock:
            return self._augment_credit_row(
                self._get_row("CREDIT_CODE", code_hash), now)

    def redeem_credit_code(self, code_hash, now):
        with self._lock:
            row = self._get_row("CREDIT_CODE", code_hash)
            if row is None:
                return None
            if not row["redeemed_at"]:
                row["redeemed_at"] = now
                self._put_row("CREDIT_CODE", code_hash, row)
            return self._augment_credit_row(row, now)

    def consume_credit(self, code_hash, image_identity, claim_hash,
                       charge_id, now, kind="standard",
                       hourly_limit=None):
        """Charge one credit for one new image, atomically. Same
        outcomes as the SQLite store: charged / duplicate /
        no_credits / no_ai_credits / rate_limited / revoked /
        not_found. While the code's Pass subscription is active a
        standard charge is covered by the Pass (the charge row
        lands with funded_by "pass" and no pool moves); the
        hourly backstop counts charged consumes per code."""
        with self._lock:
            row = self._get_row("CREDIT_CODE", code_hash)
            if row is None:
                return {"outcome": "not_found", "code": None}
            if row["status"] == "revoked":
                return {"outcome": "revoked",
                        "code": self._augment_credit_row(row, now)}
            pk = "CREDIT_CHARGE#" + code_hash
            prior = self._get_row(pk, image_identity)
            if prior is not None:
                return {"outcome": "duplicate",
                        "code": self._augment_credit_row(row, now)}
            if hourly_limit is None:
                hourly_limit = credits_module.CONSUME_HOURLY_LIMIT
            if hourly_limit:
                window_start = credits_module.hour_ago(now)
                recent = sum(
                    1 for c in self._query_rows(pk)
                    if c["created_at"] >= window_start)
                if recent >= hourly_limit:
                    return {"outcome": "rate_limited",
                            "code": self._augment_credit_row(row, now)}
            if kind == "standard":
                sub = self._subscription_for_code(code_hash)
                if sub is not None and sub["status"] == "active":
                    charge = {"id": charge_id,
                              "code_hash": code_hash,
                              "image_identity": image_identity,
                              "claim_hash": claim_hash,
                              "kind": "standard",
                              "funded_by": "pass",
                              "created_at": now}
                    if not self._put_row(pk, image_identity, charge,
                                         if_absent=True):
                        return {"outcome": "duplicate",
                                "code": self._augment_credit_row(
                                    row, now)}
                    row["last_used_at"] = now
                    self._put_row("CREDIT_CODE", code_hash, row)
                    return {"outcome": "charged",
                            "code": self._augment_credit_row(row, now)}
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
            charge = {"id": charge_id, "code_hash": code_hash,
                      "image_identity": image_identity,
                      "claim_hash": claim_hash, "kind": kind,
                      "funded_by": "pack" if kind == "ai" else "",
                      "created_at": now}
            if not self._put_row(pk, image_identity, charge,
                                 if_absent=True):
                return {"outcome": "duplicate",
                        "code": self._augment_credit_row(row, now)}
            row["credits_used"] = row["credits_used"] + 1
            if row["credits_used"] >= row["credits_total"]:
                row["status"] = "exhausted"
            row["last_used_at"] = now
            self._put_row("CREDIT_CODE", code_hash, row)
            return {"outcome": "charged",
                    "code": self._augment_credit_row(row, now)}

    def _consume_with_grants(self, row, grants, image_identity,
                             claim_hash, charge_id, now, kind):
        """The grant path of consume_credit, under the store lock
        with the duplicate check already done. Same draw rules as
        the SQLite store: standard draws take the oldest live
        grant first; AI draws take Pass grants' AI sub-allowances
        first, then bonus grants oldest first, each bonus draw
        spending the grant's shared pool and landing marked
        funded_by "bonus", then the code's pack counters, landing
        marked funded_by "pack"."""
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
        charge = {"id": charge_id, "code_hash": code_hash,
                  "image_identity": image_identity,
                  "claim_hash": claim_hash, "kind": kind,
                  "funded_by": funded_by,
                  "created_at": now}
        if not self._put_row("CREDIT_CHARGE#" + code_hash,
                             image_identity, charge, if_absent=True):
            return {"outcome": "duplicate",
                    "code": self._augment_credit_row(row, now)}
        if target is not None:
            target["used"] = target["used"] + 1
            if kind == "ai":
                target["ai_used"] = target["ai_used"] + 1
            self._put_row("CREDIT_GRANT#" + code_hash,
                          target["grant_id"], target)
            row["last_used_at"] = now
            self._put_row("CREDIT_CODE", code_hash, row)
        else:
            row["credits_used"] = row["credits_used"] + 1
            sub = self._subscription_for_code(code_hash)
            if row["credits_used"] >= row["credits_total"] and not (
                    sub and sub["status"] == "active"):
                row["status"] = "exhausted"
            row["last_used_at"] = now
            self._put_row("CREDIT_CODE", code_hash, row)
        return {"outcome": "charged",
                "code": self._augment_credit_row(
                    self._get_row("CREDIT_CODE", code_hash), now)}

    # -- onchain anchoring (npc_verify.anchor) -------------------------
    # Mirrors the SQLite store exactly: the batch dict is stored as
    # one row (record IDs and leaves as native lists here; the JSON
    # boundary hides the difference), record rows carry the proof as
    # a native list too.

    _ANCHOR_BATCH_FIELDS = (
        "merkle_root", "batch_sig", "status", "nonce", "tx_hash",
        "raw_tx", "block_number", "block_timestamp", "error",
        "submitted_at", "confirmed_at")

    def create_anchor_batch(self, batch) -> None:
        with self._lock:
            self._put_row("ANCHOR_BATCH", batch["batch_id"],
                          dict(batch))

    def get_anchor_batch(self, batch_id):
        with self._lock:
            return self._get_row("ANCHOR_BATCH", batch_id)

    def open_anchor_batch(self):
        """The oldest batch still in flight (prepared or submitted),
        or None. Mirrors the SQLite store."""
        with self._lock:
            rows = self._query_rows("ANCHOR_BATCH")
        open_rows = [r for r in rows
                     if r.get("status") in ("prepared", "submitted")]
        if not open_rows:
            return None
        open_rows.sort(key=lambda r: (r["created_at"], r["batch_id"]))
        return open_rows[0]

    def update_anchor_batch(self, batch_id, fields) -> None:
        cols = {k: v for k, v in fields.items()
                if k in self._ANCHOR_BATCH_FIELDS}
        if not cols:
            return
        with self._lock:
            row = self._get_row("ANCHOR_BATCH", batch_id)
            if row is None:
                return
            row.update(cols)
            self._put_row("ANCHOR_BATCH", batch_id, row)

    def release_anchor_batch(self, batch_id) -> None:
        """Flag a failed batch's record rows released (its records
        return to the unanchored pool); rows are flagged, never
        deleted, and the batch row stays as the record of the
        attempt. Uses PutItem only, like every write here."""
        with self._lock:
            rows = self._query_rows("RECORD_ANCHOR")
            for row in rows:
                if row.get("batch_id") == batch_id \
                        and not row.get("released"):
                    row["released"] = True
                    self._put_row("RECORD_ANCHOR", row["record_id"],
                                  row)

    def count_anchor_batches(self):
        with self._lock:
            rows = self._query_rows("ANCHOR_BATCH")
        counts = {}
        for row in rows:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        return counts

    def add_record_anchor(self, row) -> None:
        with self._lock:
            self._put_row("RECORD_ANCHOR", row["record_id"],
                          dict(row))

    def get_record_anchor(self, record_id):
        with self._lock:
            row = self._get_row("RECORD_ANCHOR", record_id)
        if row is None or row.get("released"):
            return None
        out = dict(row)
        out.pop("released", None)
        return out

    def unanchored_registrations(self, limit):
        """Registration records in no live anchor batch, oldest
        first. Mirrors the SQLite store: both partitions are small
        at this service's scale, and the diff is deliberate."""
        with self._lock:
            regs = self._query_rows("REG")
            anchored = {r["record_id"]
                        for r in self._query_rows("RECORD_ANCHOR")
                        if not r.get("released")}
        regs.sort(key=lambda r: (r["created_at"], r["record_id"]))
        out = []
        for row in regs:
            if row["record_id"] in anchored:
                continue
            try:
                record = json.loads(row["record_json"])
            except (ValueError, TypeError):
                continue
            if isinstance(record, dict):
                out.append(record)
            if len(out) >= limit:
                break
        return out

    def count_anchored_records(self) -> int:
        with self._lock:
            anchors = self._query_rows("RECORD_ANCHOR")
            batches = {r["batch_id"]: r
                       for r in self._query_rows("ANCHOR_BATCH")}
        n = 0
        for row in anchors:
            batch = batches.get(row["batch_id"])
            if batch is not None and batch.get("status") == "confirmed":
                n += 1
        return n

    def add_anchor_rotation(self, notice_id, notice, created_at) \
            -> bool:
        """Record a verified rotation notice (idempotent: the same
        notice is the same rotation). Mirrors the SQLite store."""
        with self._lock:
            if self._get_row("ANCHOR_ROTATION", notice_id) \
                    is not None:
                return False
            self._put_row("ANCHOR_ROTATION", notice_id, {
                "notice_id": notice_id, "notice": notice,
                "created_at": created_at})
            return True

    def list_anchor_rotations(self):
        """Every recorded rotation notice, oldest first."""
        with self._lock:
            rows = self._query_rows("ANCHOR_ROTATION")
        rows.sort(key=lambda r: (r["created_at"],
                                 r.get("notice_id", "")))
        return [r["notice"] for r in rows]

    # -- unified accounts (Gate G1, npc_verify.accounts) ----------------
    # Partitions: accounts under "ACCT" (sk = account id; the email
    # lookup scans the partition, like the challenge-by-secret lookup
    # above), credentials under "ACRED" (sk = credential id),
    # challenges under "ACHAL", email tokens under "AETOK" (sk =
    # token hash), recovery codes under "AREC#<account_id>" (sk =
    # code hash), sessions under "ASESS" (sk = session id), handoffs
    # under "AHAND", events under "AEVT#<account_id>" (sk = event
    # id). Mutations are read-modify-write under the store lock, the
    # same pattern the rest of this backend uses; consume methods
    # fail closed on a replay, mirroring the SQLite store.

    def add_account(self, row) -> bool:
        with self._lock:
            return self._put_row("ACCT", row["account_id"], dict(row),
                                 if_absent=True)

    def get_account(self, account_id):
        with self._lock:
            return self._get_row("ACCT", account_id)

    def get_account_by_email(self, email):
        with self._lock:
            rows = self._query_rows("ACCT")
        for row in rows:
            if row.get("email") == email:
                return row
        return None

    def add_account_credential(self, row) -> bool:
        with self._lock:
            return self._put_row("ACRED", row["credential_id"],
                                 dict(row), if_absent=True)

    def get_account_credential(self, credential_id):
        with self._lock:
            return self._get_row("ACRED", credential_id)

    def list_account_credentials(self, account_id):
        with self._lock:
            rows = self._query_rows("ACRED")
        out = [r for r in rows if r.get("account_id") == account_id]
        out.sort(key=lambda r: r["created_at"])
        return out

    def update_credential_use(self, credential_id, sign_count,
                              last_used_at) -> bool:
        with self._lock:
            row = self._get_row("ACRED", credential_id)
            if row is None:
                return False
            row["sign_count"] = sign_count
            row["last_used_at"] = last_used_at
            self._put_row("ACRED", credential_id, row)
            return True

    def add_account_challenge(self, row) -> bool:
        with self._lock:
            return self._put_row("ACHAL", row["challenge_id"],
                                 dict(row), if_absent=True)

    def get_account_challenge(self, challenge_id):
        with self._lock:
            return self._get_row("ACHAL", challenge_id)

    def consume_account_challenge(self, challenge_id,
                                  consumed_at) -> bool:
        with self._lock:
            row = self._get_row("ACHAL", challenge_id)
            if row is None or row.get("consumed_at"):
                return False
            row["consumed_at"] = consumed_at
            self._put_row("ACHAL", challenge_id, row)
            return True

    def add_email_token(self, row) -> bool:
        with self._lock:
            return self._put_row("AETOK", row["token_hash"],
                                 dict(row), if_absent=True)

    def get_email_token(self, token_hash):
        with self._lock:
            return self._get_row("AETOK", token_hash)

    def consume_email_token(self, token_hash, consumed_at) -> bool:
        with self._lock:
            row = self._get_row("AETOK", token_hash)
            if row is None or row.get("consumed_at"):
                return False
            row["consumed_at"] = consumed_at
            self._put_row("AETOK", token_hash, row)
            return True

    def invalidate_email_tokens(self, account_id, consumed_at) -> int:
        count = 0
        with self._lock:
            rows = self._query_rows("AETOK")
            for row in rows:
                if row.get("account_id") == account_id \
                        and not row.get("consumed_at"):
                    row["consumed_at"] = consumed_at
                    self._put_row("AETOK", row["token_hash"], row)
                    count += 1
        return count

    def add_recovery_codes(self, rows) -> None:
        with self._lock:
            for row in rows:
                self._put_row("AREC#" + row["account_id"],
                              row["code_hash"], dict(row),
                              if_absent=True)

    def _recovery_rows(self, account_id):
        with self._lock:
            return self._query_rows("AREC#" + account_id)

    def find_recovery_code(self, account_id, code_hash):
        with self._lock:
            return self._get_row("AREC#" + account_id, code_hash)

    def consume_recovery_code(self, account_id, code_hash,
                              consumed_at) -> bool:
        with self._lock:
            row = self._get_row("AREC#" + account_id, code_hash)
            if row is None or row.get("consumed_at"):
                return False
            row["consumed_at"] = consumed_at
            self._put_row("AREC#" + account_id, code_hash, row)
            return True

    def count_recovery_codes(self, account_id):
        rows = self._recovery_rows(account_id)
        unused = sum(1 for r in rows if not r.get("consumed_at"))
        return len(rows), unused

    def add_account_session(self, row) -> bool:
        with self._lock:
            return self._put_row("ASESS", row["session_id"],
                                 dict(row), if_absent=True)

    def get_account_session(self, session_id):
        with self._lock:
            return self._get_row("ASESS", session_id)

    def find_account_session_by_token(self, token_hash):
        with self._lock:
            rows = self._query_rows("ASESS")
        for row in rows:
            if row.get("token_hash") == token_hash:
                return row
        return None

    def list_account_sessions(self, account_id):
        with self._lock:
            rows = self._query_rows("ASESS")
        out = [r for r in rows if r.get("account_id") == account_id]
        out.sort(key=lambda r: r["created_at"])
        return out

    def touch_account_session(self, session_id, last_seen_at) -> bool:
        with self._lock:
            row = self._get_row("ASESS", session_id)
            if row is None:
                return False
            row["last_seen_at"] = last_seen_at
            self._put_row("ASESS", session_id, row)
            return True

    def revoke_account_session(self, session_id, revoked_at) -> bool:
        with self._lock:
            row = self._get_row("ASESS", session_id)
            if row is None or row.get("revoked_at"):
                return False
            row["revoked_at"] = revoked_at
            self._put_row("ASESS", session_id, row)
            return True

    def add_account_handoff(self, row) -> bool:
        with self._lock:
            return self._put_row("AHAND", row["handoff_id"],
                                 dict(row), if_absent=True)

    def get_account_handoff(self, handoff_id):
        with self._lock:
            return self._get_row("AHAND", handoff_id)

    def complete_account_handoff(self, handoff_id, account_id,
                                 completed_at) -> bool:
        with self._lock:
            row = self._get_row("AHAND", handoff_id)
            if row is None or row.get("status") != "pending":
                return False
            row["status"] = "ready"
            row["account_id"] = account_id
            row["completed_at"] = completed_at
            self._put_row("AHAND", handoff_id, row)
            return True

    def consume_account_handoff(self, handoff_id, consumed_at) -> bool:
        with self._lock:
            row = self._get_row("AHAND", handoff_id)
            if row is None or row.get("status") != "ready":
                return False
            row["status"] = "consumed"
            row["consumed_at"] = consumed_at
            self._put_row("AHAND", handoff_id, row)
            return True

    def add_account_event(self, row) -> None:
        with self._lock:
            self._put_row("AEVT#" + row["account_id"], row["event_id"],
                          dict(row), if_absent=True)

    def list_account_events(self, account_id, limit=50):
        with self._lock:
            rows = self._query_rows("AEVT#" + account_id)
        rows.sort(key=lambda r: (r["created_at"], r["event_id"]),
                  reverse=True)
        return rows[:int(limit)]

    def install_seed_records(self, records) -> int:
        """Cold-start recovery seed: put each signed registration
        record if absent, and never overwrite an existing item.

        records are parsed record dicts; each is stored through the
        same record_json path as a live registration, so the record
        (and its signature) survives byte-for-byte at the JSON level.
        The submitter email / IP were never public, so the side
        columns start empty: the submission counters are fresh.
        Returns how many records were actually installed.
        """
        installed = 0
        with self._lock:
            for record in records:
                row = {"record_id": record["record_id"],
                       "kind": record["kind"], "email": "",
                       "email_hash": registration_email_hash(""),
                       "client_ip": "",
                       "record_json": json.dumps(record),
                       "created_at": record["registered_at"]}
                if self._put_row("REG", record["record_id"], row,
                                 if_absent=True):
                    installed += 1
        return installed
