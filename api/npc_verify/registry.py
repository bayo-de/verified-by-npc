"""Public registration layer: verification-start for verify.npclabs.xyz.

Two public, unauthenticated endpoints mint signed registration records:

- POST /v1/register/content -> npc.registry.content_registration
- POST /v1/register/agent   -> npc.registry.agent_registration

Registration is NOT verification. A registration record says: this was
registered, by this named person, at this time; these checks ran at
intake and these have not run yet. No verdict is issued, no
verification mark exists anywhere in this flow, and registration is
free (there is no payment surface at all). Records are signed at
issuance with the issuer key, on the pact record layer's signing
convention, so each record stays verifiable as a portable artifact
against GET /v1/keys, independent of the response envelope.

Agent registration follows the Agent Registry spec
(trust-tab/agent-registry/SPEC.md): registration is free, a named
accountable owner is required (no anonymous or team-alias owners), and
the issued claim states registration, not verification.

Intake checks (content): what can be honestly checked from what was
provided runs at intake and is written into the record:

- a fetchable image URL is fetched once; its SHA-256 is recorded;
- the C2PA structural parse runs on fetched image bytes: credentials
  present are recorded as present_not_cryptographically_validated
  (structural presence is not cryptographic validation);
- the AI generation check runs on fetched image bytes when a detector
  is configured: its result is recorded as a signal (an integer
  percent) with its uncertainty stated, never as a hard stamp.

Checks that do not run at intake are listed in the record as not run,
with the reason: C2PA cryptographic validation, human review, and the
verification decision itself. Nothing is silently skipped.

Abuse minimums for launch: a creator/owner email is required;
per-email and per-IP submission caps are counted in the store layer
(store.count_registrations_since); the server-wide body cap bounds
payloads. Creator and owner emails are kept server-side only (cap
counting and contact): they are never written into the signed public
record and never returned by GET /v1/records/{id}.
"""
import hashlib
import ipaddress
import os
import re
import secrets
import socket
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

from . import c2pa, c2pa_validate, media_probe, pact
from .detector import DetectorError
from .models import is_iso8601, utcnow_iso

CONTENT_RECORD_TYPE = "npc.registry.content_registration"
AGENT_RECORD_TYPE = "npc.registry.agent_registration"

CONTENT_KINDS = ("image", "text", "audio", "video", "other")
STATUS = "registered_checks_pending"
STATUS_LABEL = "registered, checks pending"

# Abuse minimums: rolling-window submission caps, counted in the store.
EMAIL_DAILY_CAP = 10
IP_DAILY_CAP = 50
CAP_WINDOW = timedelta(hours=24)

# Retention (audit item D6, 2026-10-15): submitter emails are kept
# server-side for the submission caps only. The stated retention is
# 12 months: past that, the raw email is purged by the store-layer
# sweep (the signed record and the email-HASH cap counter survive, so
# the caps and the public record are unaffected by the purge).
EMAIL_RETENTION_MONTHS = 12

FETCH_TIMEOUT = 8
FETCH_MAX_BYTES = 8 * 1024 * 1024

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
_HASH_RE = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{32,128}$")

# -- integration source provenance (optional, additive) ---------------------
# POST /v1/register/content may carry a `source` object when the work
# arrives through a connected platform account (the integrations batch
# lane; design in integrations/DESIGN.md). It is provenance, not a
# verdict: it records which platform listed the work, for an account
# the customer connected, and what the platform said about the work.
# Connecting an account shows control of that account at connect time
# and nothing more. Records without a source are exactly the records
# this API has always minted: the field is omitted, never null.
SOURCE_PLATFORMS = ("youtube", "instagram", "tiktok", "x", "spotify",
                    "google_drive", "microsoft_onedrive", "box")
SOURCE_BYTE_CLASSES = ("bytes_fetchable", "metadata_only",
                       "permalink_only")
_SOURCE_CHECKSUM_ALGORITHMS = ("md5", "sha1", "sha256", "crc32",
                               "quickxor")
_METADATA_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_RECORD_ID_RE = re.compile(r"^reg_[A-Za-z0-9]{8,64}$")


# -- fetching -----------------------------------------------------------------
# SSRF guard (audit item D3, 2026-10-15): the intake fetch follows a
# submitter-supplied URL server-side. It stays bounded (size, timeout,
# http(s) only) and the bytes are never returned to the caller, but the
# target itself is now validated before every connection: literal
# private, loopback, link-local, multicast, reserved, and unspecified
# hosts are refused, the name "localhost" (and *.localhost) is refused,
# and every redirect target is re-validated the same way, so a public
# URL cannot bounce the fetch into a refused range. DNS names other
# than localhost are NOT resolved for the check (no TOCTOU-safe way to
# pin resolution in urllib); the refused set is the literal set.
#
# Test-mode allowance: the local test fixtures serve over loopback,
# redirects included. NPC_ALLOW_LOOPBACK_FETCH=1 permits LOOPBACK
# literals — for the submitted URL and, validated the same way, its
# redirect hops — and never private/link-local ranges. Production
# never sets the variable, so in production loopback is refused at
# the first hop and at every hop after it.
LOOPBACK_FETCH_ENV = "NPC_ALLOW_LOOPBACK_FETCH"


def _loopback_fetch_allowed():
    return os.environ.get(LOOPBACK_FETCH_ENV) == "1"


def _ip_literal(host):
    """Parse a host as an IP literal, or return None.

    Handles the dotted/colon forms ipaddress knows, plus the legacy
    inet_aton forms ("127.1", "0x7f000001", "2130706433") that urllib
    would otherwise resolve as addresses without ever looking like
    literals to a naive check.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if host and all(c in "0123456789abcdefABCDEFxX." for c in host):
        try:
            packed = socket.inet_aton(host)
        except (OSError, socket.error):
            return None
        return ipaddress.ip_address(packed)
    return None


def _host_permitted(hostname, allow_loopback=False):
    """True when a fetch (or a redirect hop) may connect to hostname."""
    if not hostname:
        return False
    host = hostname.strip().lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return False
    ip = _ip_literal(host)
    if ip is None:
        return True  # a DNS name (not resolved here; see the note above)
    if ip.is_loopback:
        return allow_loopback
    return not (ip.is_private or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)


def _url_fetch_permitted(url, allow_loopback=False):
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    return _host_permitted(parts.hostname, allow_loopback=allow_loopback)


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every redirect target the same way the submitted
    URL was validated; a refused hop ends the fetch."""

    def __init__(self, allow_loopback=False):
        super().__init__()
        self.allow_loopback = allow_loopback

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Relative Location values arrive unresolved; make the target
        # absolute against the request URL before validating it.
        absolute = urllib.parse.urljoin(req.get_full_url(), newurl)
        if not _url_fetch_permitted(
                absolute, allow_loopback=self.allow_loopback):
            return None  # refuse: urllib surfaces the 3xx as an error
        return super().redirect_request(req, fp, code, msg, headers,
                                        absolute)


def fetch_url_bytes(url, timeout=FETCH_TIMEOUT, max_bytes=FETCH_MAX_BYTES):
    """Fetch a URL's bytes once, bounded. Returns bytes or None.

    Any failure (DNS, TLS, HTTP status, oversize, timeout) is data:
    the intake checks record "not fetched" and registration proceeds.
    Only http(s) URLs are fetched, and only to hosts the SSRF guard
    above permits.
    """
    if not isinstance(url, str) or not (
            url.startswith("https://") or url.startswith("http://")):
        return None
    allow_loopback = _loopback_fetch_allowed()
    if not _url_fetch_permitted(url, allow_loopback=allow_loopback):
        return None
    opener = urllib.request.build_opener(
        _GuardedRedirectHandler(allow_loopback=allow_loopback))
    req = urllib.request.Request(
        url, headers={"User-Agent": "NPCVerify/1.0 "
                                   "(+https://verify.npclabs.xyz)"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            chunks = []
            total = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return None
                chunks.append(chunk)
            return b"".join(chunks)
    except Exception:
        return None


def locator_kind(locator):
    """Classify a locator: 'url' or 'content_hash', else None."""
    if not isinstance(locator, str):
        return None
    loc = locator.strip()
    if loc.startswith("https://") or loc.startswith("http://"):
        return "url"
    if _HASH_RE.match(loc):
        return "content_hash"
    return None


# -- validation (house style: a list of problems, or []) -----------------------
def _check_str(problems, fields, name, max_len, required=True):
    v = fields.get(name)
    if v is None and not required:
        return
    if not isinstance(v, str) or not v.strip() or len(v) > max_len:
        problems.append(
            "%s is required (string, max %d chars)" % (name, max_len)
            if required else
            "%s must be a string (max %d chars)" % (name, max_len))


def _check_email(problems, fields, name):
    v = fields.get(name)
    if not isinstance(v, str) or len(v) > 254 or not _EMAIL_RE.match(v):
        problems.append("%s is required (a valid email address)" % name)


def validate_content_input(fields):
    problems = []
    _check_str(problems, fields, "title", 200)
    kind = fields.get("kind")
    if kind not in CONTENT_KINDS:
        problems.append("kind must be one of %s" % (list(CONTENT_KINDS),))
    locator = fields.get("locator")
    if not isinstance(locator, str) or not locator.strip() \
            or len(locator) > 2048:
        problems.append("locator is required (string, max 2048 chars)")
    elif locator_kind(locator) is None:
        problems.append(
            "locator must be an http(s) URL or a content hash")
    _check_str(problems, fields, "creator_name", 128)
    _check_email(problems, fields, "creator_email")
    source = fields.get("source")
    if source is not None:
        problems.extend(validate_source(source))
    return problems


def _check_source_str(problems, source, name, max_len, required=True):
    v = source.get(name)
    if v is None and not required:
        return
    if not isinstance(v, str) or not v.strip() or len(v) > max_len:
        problems.append(
            "source.%s is required (string, max %d chars)"
            % (name, max_len) if required else
            "source.%s must be a string (max %d chars)"
            % (name, max_len))


def validate_source(source):
    """Validate the optional integration `source` object.

    Shape only: this checks that the provenance block is well formed,
    never that its claims are true. Truth about the work is what the
    checks are for, and none of them run differently because a source
    is present, beyond the honest intake entries in run_content_intake.
    """
    problems = []
    if not isinstance(source, dict):
        return ["source must be an object"]
    if source.get("platform") not in SOURCE_PLATFORMS:
        problems.append(
            "source.platform must be one of %s"
            % (list(SOURCE_PLATFORMS),))
    _check_source_str(problems, source, "external_id", 256)
    permalink = source.get("permalink")
    if not isinstance(permalink, str) or not permalink.strip() \
            or len(permalink) > 2048 \
            or not (permalink.startswith("https://")
                    or permalink.startswith("http://")):
        problems.append(
            "source.permalink is required (an http(s) URL, "
            "max 2048 chars)")
    if source.get("byte_class") not in SOURCE_BYTE_CLASSES:
        problems.append(
            "source.byte_class must be one of %s"
            % (list(SOURCE_BYTE_CLASSES),))
    _check_source_str(problems, source, "account_display_name", 128,
                      required=False)
    _check_source_str(problems, source, "native_type", 128,
                      required=False)
    for name in ("published_at", "modified_at"):
        v = source.get(name)
        if v is not None and (not isinstance(v, str)
                              or not is_iso8601(v)):
            problems.append(
                "source.%s must be an ISO-8601 timestamp" % name)
    marker = source.get("version_marker")
    if marker is not None:
        if not isinstance(marker, dict):
            problems.append("source.version_marker must be an object")
        else:
            for name, max_len in (("kind", 64), ("value", 512)):
                v = marker.get(name)
                if not isinstance(v, str) or not v.strip() \
                        or len(v) > max_len:
                    problems.append(
                        "source.version_marker.%s is required "
                        "(string, max %d chars)" % (name, max_len))
    checksum = source.get("platform_checksum")
    if checksum is not None:
        if not isinstance(checksum, dict):
            problems.append(
                "source.platform_checksum must be an object")
        else:
            if checksum.get("algorithm") \
                    not in _SOURCE_CHECKSUM_ALGORITHMS:
                problems.append(
                    "source.platform_checksum.algorithm must be one "
                    "of %s" % (list(_SOURCE_CHECKSUM_ALGORITHMS),))
            v = checksum.get("value")
            if not isinstance(v, str) or not v.strip() \
                    or len(v) > 256:
                problems.append(
                    "source.platform_checksum.value is required "
                    "(string, max 256 chars)")
    metadata_hash = source.get("metadata_hash")
    if metadata_hash is not None:
        if not isinstance(metadata_hash, str) \
                or not _METADATA_HASH_RE.match(metadata_hash):
            problems.append(
                "source.metadata_hash must be a lowercase SHA-256 "
                "hex string (64 chars)")
    _check_source_str(problems, source, "rendition", 200,
                      required=False)
    previous = source.get("previous_record_id")
    if previous is not None:
        if not isinstance(previous, str) \
                or not _RECORD_ID_RE.match(previous):
            problems.append(
                "source.previous_record_id must be an NPC "
                "registration record ID (reg_...)")
    return problems


def normalize_source(source):
    """Return the cleaned `source` dict for the signed record core,
    or None when there is no usable source.

    Only known fields survive, in a fixed key order, strings trimmed:
    the signed record shape stays under this module's control even
    though the caller supplied the values. Callers validate first
    (validate_content_input); this function assumes a valid shape and
    stays defensive about types rather than re-reporting problems.
    """
    if not isinstance(source, dict):
        return None
    if source.get("platform") not in SOURCE_PLATFORMS:
        return None
    if source.get("byte_class") not in SOURCE_BYTE_CLASSES:
        return None

    def _s(name):
        v = source.get(name)
        return v.strip() if isinstance(v, str) and v.strip() else None

    external_id = _s("external_id")
    permalink = _s("permalink")
    if external_id is None or permalink is None:
        return None
    out = {
        "platform": source["platform"],
        "external_id": external_id,
        "permalink": permalink,
        "byte_class": source["byte_class"],
    }
    for name in ("account_display_name", "native_type",
                 "published_at", "modified_at", "metadata_hash",
                 "rendition", "previous_record_id"):
        v = _s(name)
        if v is not None:
            out[name] = v
    marker = source.get("version_marker")
    if isinstance(marker, dict):
        kind = marker.get("kind")
        value = marker.get("value")
        if isinstance(kind, str) and kind.strip() \
                and isinstance(value, str) and value.strip():
            out["version_marker"] = {"kind": kind.strip(),
                                     "value": value.strip()}
    checksum = source.get("platform_checksum")
    if isinstance(checksum, dict):
        algorithm = checksum.get("algorithm")
        value = checksum.get("value")
        if algorithm in _SOURCE_CHECKSUM_ALGORITHMS \
                and isinstance(value, str) and value.strip():
            out["platform_checksum"] = {
                "algorithm": algorithm, "value": value.strip()}
    return out


def validate_verification_request_input(fields):
    """POST /v1/records/{id}:request-verification body: the
    registrant proves the record is theirs with the email they
    registered with. Nothing else is asked."""
    problems = []
    _check_email(problems, fields, "email")
    return problems


def verification_request_cap_exceeded(store, email, client_ip, now_iso):
    """The request-verification caps mirror the registration caps:
    same per-email and per-IP ceilings over the same rolling window,
    counted over attempts (matched and not), so probing record IDs
    or emails is rate-limited exactly like registering."""
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    since = (now - CAP_WINDOW).isoformat(timespec="seconds")
    if store.count_verification_request_attempts_since(
            "email", email, since) >= EMAIL_DAILY_CAP:
        return "email"
    if client_ip and store.count_verification_request_attempts_since(
            "ip", client_ip, since) >= IP_DAILY_CAP:
        return "ip"
    return None


VERIFICATION_REQUEST_RECORD_TYPE = "npc.registry.verification_request"


def verification_request_email_matches(store, record_id, email):
    """True when the presented email is the one the record was
    registered with, compared by hash (the store's pattern: raw
    emails are compared server-side, hashes everywhere else). Works
    after the retention purge, which keeps the hash."""
    from .store import registration_email_hash
    stored = store.registration_email_hash(record_id)
    if stored is None:
        return False
    return stored == registration_email_hash(
        email.strip().lower())


def mint_verification_request(store, keys, subject, email, client_ip):
    """Sign and store a verification-request record for a
    registration. Returns (record, created): a repeat request for
    the same record returns the existing record with created False,
    so the endpoint can answer idempotently."""
    existing = store.get_verification_request(subject["record_id"])
    if existing is not None:
        return existing, False
    now = utcnow_iso()
    core = {
        "record_type": VERIFICATION_REQUEST_RECORD_TYPE,
        "record_id": "vreq_" + secrets.token_hex(12),
        "subject_record_id": subject["record_id"],
        "subject_kind": subject.get("kind"),
        "status": "verification_requested",
        "status_label": "Verification requested",
        "requested_at": now,
        "detail": "The registrant asked NPC to run verification on "
                  "this record. The request is in NPC's queue; "
                  "verification itself is a separate step, and no "
                  "verification mark is issued by asking.",
    }
    rec = pact.sign_record(keys, core)
    created = store.add_verification_request(
        rec, subject["record_id"], email, client_ip)
    if not created:
        existing = store.get_verification_request(subject["record_id"])
        if existing is not None:
            return existing, False
    return rec, created


def validate_agent_input(fields):
    problems = []
    _check_str(problems, fields, "agent_name", 128)
    # The Agent Registry spec: a named accountable owner is required.
    _check_str(problems, fields, "owner_name", 128)
    _check_email(problems, fields, "owner_email")
    homepage = fields.get("homepage")
    if homepage is not None:
        if not isinstance(homepage, str) or len(homepage) > 2048 \
                or not (homepage.startswith("https://")
                        or homepage.startswith("http://")):
            problems.append("homepage must be an http(s) URL")
    _check_str(problems, fields, "description", 2000, required=False)
    if not (isinstance(homepage, str) and homepage.strip()) \
            and not (isinstance(fields.get("description"), str)
                     and fields["description"].strip()):
        problems.append("provide a homepage or a description")
    return problems


# -- caps -----------------------------------------------------------------------
def cap_exceeded(store, email, client_ip, now_iso):
    """True when the email or IP is at its rolling-window cap.

    Counts live in the store layer; this only reads them. `now_iso`
    is the request time; the window start is derived from it so tests
    can reason about the same clock the records carry.
    """
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    since = (now - CAP_WINDOW).isoformat(timespec="seconds")
    if store.count_registrations_since("email", email, since) \
            >= EMAIL_DAILY_CAP:
        return "email"
    if client_ip and store.count_registrations_since(
            "ip", client_ip, since) >= IP_DAILY_CAP:
        return "ip"
    return None


# -- intake checks ---------------------------------------------------------------
_PENDING_DECISION = {
    "check": "verification_decision",
    "reason": "Registration is not verification. No verification "
              "decision has been made, and no verification mark is "
              "issued at registration.",
}
_PENDING_REVIEW = {
    "check": "human_review",
    "reason": "A person has not reviewed this registration yet.",
}
_PENDING_MEDIA_PROBE = {
    "check": "media_probe",
    "reason": "The fetched bytes could not be read as a media "
              "container this API can probe (MP4, MOV, WAV, MP3, "
              "FLAC, OGG, or WebM).",
}
_PENDING_FRAME_CHECKS = {
    "check": "video_frame_checks",
    "reason": "Frame checks need a video decoder, and none ships in "
              "this API's runtime. Container facts and any C2PA "
              "manifest on the file itself are still read at intake.",
}
_PENDING_AUDIO_AI = {
    "check": "ai_generation_signal",
    "reason": "AI audio detection has not been cleared for the "
              "registry yet, so no audio signal is recorded. This is "
              "on the detector roadmap.",
}
_PENDING_AUDIO_C2PA = {
    "check": "c2pa_credentials",
    "reason": "No standard C2PA carriage for audio files is read "
              "yet, so credentials embedded in audio are not "
              "checked at intake.",
}


def _validation_summary(validation):
    """Flatten a c2pa_validate result into record-safe fields."""
    signer = validation.get("signer") or {}
    return {
        "status": validation["status"],
        "signature": validation["signature"]["state"],
        "signature_algorithm": validation["signature"]["algorithm"],
        "assertions": validation["assertions"]["state"],
        "assertions_checked": validation["assertions"]["checked"],
        "asset_binding": validation["asset_binding"]["state"],
        "signer_subject": signer.get("subject"),
        "signer_issuer": signer.get("issuer"),
        "signer_chain": signer.get("chain"),
        "signer_trust": "as_presented_not_rated" if signer else None,
        "detail": validation["detail"],
    }


def _validation_detail(validation):
    """The checks_run detail sentence for a validation outcome,
    naming the signer exactly as presented when there is one."""
    detail = validation["detail"]
    signer = validation.get("signer") or {}
    if signer.get("subject"):
        detail += (" Signer as presented in the certificate: %s. "
                   "NPC does not rate signers." % signer["subject"])
    return detail


def _c2pa_check_entries(data):
    """Run the C2PA checks on fetched bytes. Returns
    (run_entries, not_run_entries): the structural credentials read
    plus real cryptographic validation (c2pa_validate) whenever a
    manifest is present to validate."""
    run, not_run = [], []
    creds = c2pa.parse_credentials(data)
    if creds is None:
        run.append({
            "check": "c2pa_credentials",
            "status": "not_present",
            "validated": False,
            "detail": "No readable C2PA Content Credentials were "
                      "found in the fetched file.",
        })
        not_run.append({
            "check": "c2pa_cryptographic_validation",
            "reason": "No C2PA manifest is present in the file, so "
                      "there is nothing to validate.",
        })
        return run, not_run
    entry = {"check": "c2pa_credentials"}
    entry.update(creds)
    run.append(entry)
    validation = c2pa_validate.validate_credentials(data)
    if validation is None:
        not_run.append({
            "check": "c2pa_cryptographic_validation",
            "reason": "The manifest is present, but it could not be "
                      "read closely enough to run cryptographic "
                      "validation.",
        })
        return run, not_run
    entry["validation"] = _validation_summary(validation)
    if validation["status"] == "valid":
        entry["status"] = "validated"
        entry["validated"] = True
    elif validation["status"] == "invalid":
        entry["status"] = "present_cryptographic_validation_failed"
    run.append({
        "check": "c2pa_cryptographic_validation",
        "status": validation["status"],
        "detail": _validation_detail(validation),
    })
    return run, not_run


def run_content_intake(detector, fetcher, content_kind, locator,
                       source=None):
    """Run the intake checks that can honestly run. Returns
    (checks_run, checks_not_run); never raises.

    With a `source` (a platform-connected registration), the generic
    URL fetch does NOT run: a platform permalink is a human page, not
    the work's bytes, and fetching it would record a hash of the wrong
    thing. What ran is the platform metadata observation, and the byte
    fetch is listed as not run. The batch lane fetches real bytes
    through the platform API itself when a lane supports it, and that
    observation belongs to a later, separate record.
    """
    run, not_run = [], []
    kind_of_locator = locator_kind(locator)
    data = None
    if source is not None:
        run.append({
            "check": "platform_metadata",
            "status": "observed",
            "platform": source["platform"],
            "external_id": source["external_id"],
            "detail": "The platform returned this work's details for "
                      "an account the customer connected to Verified "
                      "by NPC. The details are recorded as the "
                      "platform gave them. Connecting an account "
                      "shows control of that account at connect "
                      "time; it is not verification of the work.",
        })
        checksum = source.get("platform_checksum")
        if checksum:
            run.append({
                "check": "platform_checksum",
                "status": "provided_by_platform",
                "algorithm": checksum["algorithm"],
                "detail": "The checksum was supplied by the platform "
                          "for the work as the platform stores it. "
                          "NPC did not fetch the bytes for this "
                          "registration.",
            })
        not_run.append({
            "check": "content_fetch",
            "reason": "The work's bytes were not fetched for this "
                      "registration. The record covers the platform's "
                      "details and the work's address on the "
                      "platform.",
        })
    elif kind_of_locator == "url":
        data = fetcher(locator)
        if data is not None:
            run.append({
                "check": "content_fetch",
                "status": "fetched",
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "detail": "The content at the locator was fetched once "
                          "at intake and its SHA-256 recorded.",
            })
        else:
            run.append({
                "check": "content_fetch",
                "status": "not_fetched",
                "detail": "The content at the locator could not be "
                          "fetched at intake (unreachable, unreadable, "
                          "or larger than the intake limit).",
            })
    else:
        run.append({
            "check": "content_hash",
            "status": "provided_by_creator",
            "locator": locator,
            "detail": "The creator provided this content hash. NPC "
                      "has not seen the content itself.",
        })

    if content_kind == "image":
        if data is not None:
            c2pa_run, c2pa_not_run = _c2pa_check_entries(data)
            run.extend(c2pa_run)
            not_run.extend(c2pa_not_run)
            if detector is not None and detector.configured:
                try:
                    prob = detector.check_ai(image_bytes=data)
                    percent = int(prob * 100 + 0.5)
                    percent = max(0, min(100, percent))
                    run.append({
                        "check": "ai_generation_signal",
                        "status": "recorded",
                        "ai_generated_percent": percent,
                        "provider": detector.provider,
                        "model": detector.model,
                        "detail": "A signal with uncertainty, not a "
                                  "verdict. A high percent is a reason "
                                  "to look closer; a low one is not "
                                  "proof an image is human-made.",
                    })
                except DetectorError:
                    not_run.append({
                        "check": "ai_generation_signal",
                        "reason": "The detection service could not "
                                  "complete the check at intake.",
                    })
            else:
                not_run.append({
                    "check": "ai_generation_signal",
                    "reason": "The AI image check is not configured on "
                              "this API yet.",
                })
        else:
            not_run.append({
                "check": "c2pa_credentials",
                "reason": "Needs the image itself: the locator did "
                          "not yield fetchable image bytes at intake.",
            })
            not_run.append({
                "check": "c2pa_cryptographic_validation",
                "reason": "Needs the image itself: the locator did "
                          "not yield fetchable image bytes at intake.",
            })
            not_run.append({
                "check": "ai_generation_signal",
                "reason": "Needs the image itself: the locator did "
                          "not yield fetchable image bytes at intake.",
            })
    elif content_kind == "video":
        if data is not None:
            probe = media_probe.probe_media(data, "video")
            if probe is not None:
                run.append(probe)
            else:
                not_run.append(dict(_PENDING_MEDIA_PROBE))
            c2pa_run, c2pa_not_run = _c2pa_check_entries(data)
            run.extend(c2pa_run)
            not_run.extend(c2pa_not_run)
            not_run.append(dict(_PENDING_FRAME_CHECKS))
            not_run.append({
                "check": "ai_generation_signal",
                "reason": "The AI signal runs on image frames, and "
                          "frame checks need a video decoder this "
                          "API's runtime does not carry.",
            })
        else:
            for check in ("media_probe", "c2pa_credentials",
                          "c2pa_cryptographic_validation",
                          "video_frame_checks", "ai_generation_signal"):
                not_run.append({
                    "check": check,
                    "reason": "Needs the video itself: the locator "
                              "did not yield fetchable video bytes "
                              "at intake.",
                })
    elif content_kind == "audio":
        if data is not None:
            probe = media_probe.probe_media(data, "audio")
            if probe is not None:
                run.append(probe)
            else:
                not_run.append(dict(_PENDING_MEDIA_PROBE))
            not_run.append(dict(_PENDING_AUDIO_C2PA))
            not_run.append(dict(_PENDING_AUDIO_AI))
        else:
            for check in ("media_probe", "c2pa_credentials",
                          "ai_generation_signal"):
                not_run.append({
                    "check": check,
                    "reason": "Needs the audio itself: the locator "
                              "did not yield fetchable audio bytes "
                              "at intake.",
                })
    not_run.append(dict(_PENDING_REVIEW))
    not_run.append(dict(_PENDING_DECISION))
    return run, not_run


# -- minting ----------------------------------------------------------------------
def mint_content_registration(store, keys, fields, checks_run,
                              checks_not_run, email, client_ip):
    """Sign and store a content registration record. Returns it."""
    now = utcnow_iso()
    core = {
        "record_type": CONTENT_RECORD_TYPE,
        "record_id": "reg_" + secrets.token_hex(12),
        "kind": "content",
        "status": STATUS,
        "status_label": STATUS_LABEL,
        "title": fields["title"],
        "content_kind": fields["kind"],
        "locator": fields["locator"].strip(),
        "locator_kind": locator_kind(fields["locator"]),
        "creator_name": fields["creator_name"],
        "registered_at": now,
        "checks_run": checks_run,
        "checks_not_run": checks_not_run,
    }
    source = normalize_source(fields.get("source"))
    if source is not None:
        core["source"] = source
    rec = pact.sign_record(keys, core)
    store.add_registration(rec, email, client_ip)
    return rec


# -- retention sweep (maintenance entry point) -------------------------------
def retention_cutoff_iso(now_iso, months=EMAIL_RETENTION_MONTHS):
    """The ISO instant `months` calendar months before now_iso."""
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    total = (now.year * 12 + (now.month - 1)) - months
    year, month0 = divmod(total, 12)
    month = month0 + 1
    # Clamp the day for shorter target months (e.g. Mar 31 -> Feb 28).
    day = now.day
    while True:
        try:
            cut = now.replace(year=year, month=month, day=day)
            break
        except ValueError:
            day -= 1
    return cut.isoformat(timespec="seconds")


def run_email_retention_sweep(store, now_iso=None):
    """Purge raw submitter emails older than the retention period.

    Maintenance entry point: call from a scheduled job or an operator
    shell against the live store. Returns how many registration rows
    had their raw email purged. The signed records, and the per-email
    cap counters (keyed by email hash in the store layer), are left
    intact.
    """
    now_iso = now_iso or utcnow_iso()
    cutoff = retention_cutoff_iso(now_iso)
    return store.purge_registration_emails(cutoff)


def mint_agent_registration(store, keys, fields, email, client_ip):
    """Sign and store an agent registration claim. Returns it.

    Per the Agent Registry spec: registration is free, the owner is a
    named accountable person, and the claim states registration, not
    verification.
    """
    now = utcnow_iso()
    homepage = fields.get("homepage")
    description = fields.get("description")
    core = {
        "record_type": AGENT_RECORD_TYPE,
        "record_id": "reg_" + secrets.token_hex(12),
        "kind": "agent",
        "status": STATUS,
        "status_label": STATUS_LABEL,
        "agent_name": fields["agent_name"],
        "owner_name": fields["owner_name"],
        "homepage": homepage.strip() if isinstance(homepage, str)
        and homepage.strip() else None,
        "description": description.strip()
        if isinstance(description, str) and description.strip() else None,
        "registered_at": now,
        "checks_run": [
            {
                "check": "named_owner",
                "status": "recorded",
                "detail": "The registration names an accountable "
                          "owner, as the registry requires. NPC "
                          "records the owner; it does not operate "
                          "the agent.",
            },
            {
                "check": "registration_claim",
                "status": "issued",
                "detail": "This signed claim records the registration "
                          "of the agent. Registration is not "
                          "verification.",
            },
        ],
        "checks_not_run": [
            {
                "check": "scope_review",
                "reason": "The agent's declared scope of authority "
                          "has not been reviewed yet.",
            },
            dict(_PENDING_REVIEW),
            dict(_PENDING_DECISION),
        ],
    }
    rec = pact.sign_record(keys, core)
    store.add_registration(rec, email, client_ip)
    return rec
