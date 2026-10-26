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
  idempotency keys    IDEM                   / route + TAB + key
  verification reqs   VREQ                   / subject record_id
  verification tries  VREQATT                / created_at + # + hex

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

from .store import registration_email_hash

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
