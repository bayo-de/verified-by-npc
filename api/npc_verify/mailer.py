"""Registrant email follow-up (built 2026-10-16, Bayo's go).

Until now the API had no email capability at all: a registrant's only
thread back to their record was an ID they copied off a success
screen. This module gives every registration a lifecycle in the
registrant's inbox:

- registration confirmation (content and agent): the record ID, the
  public record link, and the status in plain words;
- verification-request received: the request ID and what happens
  next (no timeline is ever promised);
- status update: sent when a verification decision lands on a
  record, through notify_status_change below.

Design rules, in line with the rest of the codebase:

- Config comes from the environment only (NPC_MAIL_* below). No
  credentials live in code or files; in AWS the Lambda execution
  role carries ses:SendEmail on the verified identity.
- The sender is hello@npclabs.xyz, NPC Labs' public contact of
  record and a real mailbox, so a registrant's reply reaches a
  person. (A records@ sender was considered and rejected: no such
  mailbox exists, and replies would go nowhere.)
- FAIL SOFT, always: a mail failure is logged and swallowed. It
  never fails a registration, a verification request, or a status
  change. Callers do not need try/except around these functions.
- boto3 is imported lazily, only when a real SES mailer is built:
  the Lambda Python 3.12 runtime ships it, and local dev and the
  test suite never import it (tests inject a stub client).
- Privacy: the registrant address is used ONLY for that record's
  own lifecycle messages. No marketing use, no lists, no sharing.
  Raw addresses are already purged server-side at 12 months
  (audit item D6); after a purge, no further lifecycle mail can
  be sent for that record, which notify_status_change honors by
  quietly doing nothing.
"""
import html
import logging
import os
import string

log = logging.getLogger("npc_verify.mailer")

TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "email_templates")

DEFAULT_FROM = "hello@npclabs.xyz"
DEFAULT_FROM_NAME = "NPC Labs"
DEFAULT_REGION = "us-east-2"
DEFAULT_SITE_BASE = "https://verify.npclabs.xyz"

SUBJECTS = {
    "registration_content": "Your work is on record with NPC",
    "registration_agent": "Your agent is on record with NPC",
    "verification_request": "We received your verification request",
    "status_update": "An update on your NPC record",
}


def _site_base(env=None):
    """The public site the record links point at. NPC_MAIL_SITE_BASE
    overrides it for non-production testing only; production never
    sets it."""
    env = os.environ if env is None else env
    return (env.get("NPC_MAIL_SITE_BASE") or "").strip() \
        or DEFAULT_SITE_BASE


def record_link(record_id, site_base=None):
    """The public, keepable link for a record: the Search view by
    ID, the same link the success screen offers."""
    base = site_base if site_base is not None else _site_base()
    return "%s/search?id=%s" % (base.rstrip("/"), record_id)


def _render(name, fmt, values):
    """Render one template file. Text values are used as given;
    HTML values are escaped first (record fields are public input).
    """
    path = os.path.join(TEMPLATES_DIR, "%s.%s" % (name, fmt))
    with open(path, encoding="utf-8") as f:
        template = string.Template(f.read())
    if fmt == "html":
        values = {k: html.escape(str(v), quote=True)
                  for k, v in values.items()}
    return template.substitute(values)


class DisabledMailer:
    """The resting mailer: email follow-up is off, sends are no-ops.

    Mirrors detector.UnconfiguredDetector: the API runs and answers
    honestly with the capability switched off."""

    enabled = False

    def send(self, to, subject, text, html_body):
        return False


class SesMailer:
    """Sends through Amazon SES (boto3 ses client, lazily built).

    `client` may be injected (tests pass a stub); otherwise it is
    constructed on first send with tight timeouts, so a slow SES
    can never eat a request's budget. send() never raises.
    """

    enabled = True

    def __init__(self, sender, from_name=DEFAULT_FROM_NAME,
                 reply_to=None, region=DEFAULT_REGION, client=None):
        self.sender = sender
        self.from_name = from_name
        self.reply_to = reply_to or sender
        self.region = region
        self._client = client

    def _ses(self):
        if self._client is None:
            import boto3
            from botocore.config import Config
            cfg = Config(connect_timeout=3, read_timeout=5,
                         retries={"max_attempts": 1})
            self._client = boto3.client(
                "ses", region_name=self.region, config=cfg)
        return self._client

    @property
    def source(self):
        return "%s <%s>" % (self.from_name, self.sender)

    def send(self, to, subject, text, html_body):
        try:
            resp = self._ses().send_email(
                Source=self.source,
                Destination={"ToAddresses": [to]},
                ReplyToAddresses=[self.reply_to],
                Message={
                    "Subject": {"Data": subject, "Charset": "UTF-8"},
                    "Body": {
                        "Text": {"Data": text, "Charset": "UTF-8"},
                        "Html": {"Data": html_body, "Charset": "UTF-8"},
                    },
                })
            log.info("mail sent to %s (subject %r, SES id %s)",
                     to, subject, resp.get("MessageId"))
            return True
        except Exception:
            log.exception("mail send failed (to %s, subject %r); "
                          "continuing without it", to, subject)
            return False


def mailer_from_env(env=None):
    """Build the mailer from the environment, detector-style.

    NPC_MAIL_ENABLED=1 turns follow-up on; anything else rests.
    NPC_MAIL_FROM overrides the sender (default hello@npclabs.xyz),
    NPC_MAIL_FROM_NAME the display name, NPC_MAIL_REPLY_TO the
    reply address, NPC_MAIL_REGION the SES region (then AWS_REGION,
    then us-east-2, the API's region).
    """
    env = os.environ if env is None else env
    if (env.get("NPC_MAIL_ENABLED") or "").strip() != "1":
        return DisabledMailer()
    return SesMailer(
        sender=(env.get("NPC_MAIL_FROM") or "").strip() or DEFAULT_FROM,
        from_name=(env.get("NPC_MAIL_FROM_NAME") or "").strip()
        or DEFAULT_FROM_NAME,
        reply_to=(env.get("NPC_MAIL_REPLY_TO") or "").strip() or None,
        region=(env.get("NPC_MAIL_REGION") or "").strip()
        or (env.get("AWS_REGION") or "").strip()
        or (env.get("AWS_DEFAULT_REGION") or "").strip()
        or DEFAULT_REGION)


# -- lifecycle sends (every one fails soft) -----------------------------------

def _subject_name(record):
    """The human name of a registration record, for email bodies."""
    if record.get("kind") == "agent":
        return record.get("agent_name") or record["record_id"]
    return record.get("title") or record["record_id"]


def send_registration_confirmation(mailer, record, email):
    """Trigger (a): a registration just landed. Carries the record
    ID, the keepable record link, and the status in plain words."""
    if mailer is None or not getattr(mailer, "enabled", False) \
            or not email:
        return False
    try:
        if record.get("kind") == "agent":
            name = "registration_agent"
            values = {
                "recipient_name": record.get("owner_name") or "Hello",
                "agent_name": record.get("agent_name") or "",
            }
        else:
            name = "registration_content"
            values = {
                "recipient_name": record.get("creator_name") or "Hello",
                "title": record.get("title") or "",
            }
        values["record_id"] = record["record_id"]
        values["record_link"] = record_link(record["record_id"])
        return mailer.send(email, SUBJECTS[name],
                           _render(name, "txt", values),
                           _render(name, "html", values))
    except Exception:
        log.exception("registration confirmation failed for %s; "
                      "continuing", record.get("record_id"))
        return False


def send_verification_request_received(mailer, subject, request, email):
    """Trigger (b): a verification request was accepted. Carries
    the request ID and what happens next; no timeline is promised.
    Only sent when a request is newly created (the caller passes
    the minted record); repeat requests do not re-send."""
    if mailer is None or not getattr(mailer, "enabled", False) \
            or not email:
        return False
    try:
        values = {
            "subject_name": _subject_name(subject),
            "subject_record_id": subject["record_id"],
            "request_id": request["record_id"],
            "record_link": record_link(subject["record_id"]),
        }
        return mailer.send(email, SUBJECTS["verification_request"],
                           _render("verification_request", "txt", values),
                           _render("verification_request", "html",
                                   values))
    except Exception:
        log.exception("verification-request email failed for %s; "
                      "continuing", subject.get("record_id"))
        return False


def send_status_update(mailer, record, email, status_label, detail):
    """Trigger (c) send: the record's new state, in plain words,
    with the record link. Called by notify_status_change; the
    decision flow may also call it directly with the address it
    already holds."""
    if mailer is None or not getattr(mailer, "enabled", False) \
            or not email:
        return False
    try:
        values = {
            "subject_name": _subject_name(record),
            "record_id": record["record_id"],
            "status_label": status_label,
            "detail": detail,
            "record_link": record_link(record["record_id"]),
        }
        return mailer.send(email, SUBJECTS["status_update"],
                           _render("status_update", "txt", values),
                           _render("status_update", "html", values))
    except Exception:
        log.exception("status-update email failed for %s; "
                      "continuing", record.get("record_id"))
        return False


def notify_status_change(mailer, store, record_id, status_label,
                         detail):
    """THE status-change hook.

    As of this build (2026-10-16) no verification-decision surface
    exists in the API yet: registrations are immutable signed
    records, and nothing transitions one. The step-two decision
    flow, when it is built, ends by calling this function with the
    record's ID, its new status label in plain words, and one or
    two plain sentences saying what the outcome means. The hook
    resolves the record and the registrant's server-side address,
    and sends the status email. It returns True only when an email
    actually went out; a record whose raw address was purged under
    the 12-month retention rule gets no email, by design.
    """
    if mailer is None or not getattr(mailer, "enabled", False):
        return False
    record = store.get_registration(record_id)
    if record is None:
        return False
    email = store.registration_email(record_id)
    if not email:
        return False
    return send_status_update(mailer, record, email, status_label,
                              detail)
