"""Paid check credits for NPC Verify (built 2026-10-28, Bayo's go).

The shipped extension gives every install 10 free checks, counted
locally, and then stops: at zero the button disables and there is no
way to get more. This module is the server half of the way to get
more, designed so extension users never need an account:

- Packs are configuration, not code (NPC_CREDITS_PACKS_JSON). The
  built-in defaults are Bayo's decided launch prices (2026-10-28):
  100 checks for $9 as the headline pack, 250 checks for $19 as the
  upsell behind it. Environment configuration can replace the list
  without a code change; a malformed value falls back to the
  decided defaults rather than inventing a price. Checkout still
  refuses to run until payment credentials are configured.
- Pack entries carry a "kind". Kind "pack" is a one-time grant.
  Kind "access" is the Verifier Pass, switched ON by Bayo on
  2026-10-28: a $25 monthly subscription whose checkout runs in
  Stripe subscription mode. On activation and on each renewal the
  subscriber's code receives a grant of the pack's checks (1,000)
  on this same ledger; a grant lives through the end of the month
  after the month it was granted in (one rollover, matching the
  locked $NPC model's one-month rollover max), and consumption
  draws the oldest live grant first. While the subscription is
  active, standard (registry) checks are unlimited (Bayo's call,
  later on 2026-10-28: registry checks cost us nothing): a
  standard consume succeeds without drawing any pool, and the
  charge row lands marked funded_by "pass" so usage stays
  observable. Of each grant, at most the pack's "ai_checks" (400)
  may be spent on AI generation checks, which carry a third-party
  per-call cost; that sub-allowance is what the monthly grant
  carries, and the grant otherwise stands as the code's finite
  balance for the day the subscription ends. Bonus grants (the
  referral bonuses below, and the registration bonus when it is
  wired) carry no AI sub-allowance of their own, but an AI check
  may spend a bonus grant's whole remaining balance once the
  Pass sub-allowances are drawn (Bayo, 2026-10-28: the referral
  cap includes all AI checks); the charge that does so is marked
  funded_by "bonus" on its ledger row. One-time pack credits
  fund AI checks too, at one check per AI check with no
  sub-cap beyond the pack size, drawn after the Pass
  sub-allowances and the bonus grants (Bayo, later still on
  2026-10-28: "Pack credits include the AI checks"); a charge
  drawn from a pack balance is marked funded_by "pack".
  Cancellation ends the unlimited standard side at once; granted checks live
  until their expiry and are drawn as a finite pool again. The
  Pass is also the entry tier of the NPC desktop app: that framing
  lives in the purchase page copy, honestly worded as future,
  never as a feature available today.
- Buying a pack mints a redeem code (100 bits of entropy, shown as
  NPC-XXXX-... groups). The server stores only the code's SHA-256
  hash; the plaintext exists once, in the purchase row, until the
  buyer's browser collects it on the success page (or the purchase
  email carries it), and is wiped on delivery.
- The code is the credential, like a gift card: whoever presents it
  spends its checks. The extension stores it locally and presents it
  per check. Balances live server-side in the store's credit ledger
  (credit_codes / credit_charges / credit_purchases), which is the
  single source of truth.
- A credit is consumed only by a completed, signature-verified
  registry answer about a NEW image identity. A re-check of an
  image already charged to the code inserts no charge row (the
  ledger's UNIQUE(code_hash, image_identity) makes a second charge
  structurally impossible), and a failed or unreachable check never
  reaches the consume call at all, so it never consumes. The toll
  follows the signature: no signature, no toll.
- Payments run through Stripe Checkout. Like the detector and the
  mailer, this integration reads credentials from the environment
  only, builds its transport lazily, fails closed and honest when
  unconfigured, and takes an injectable transport so tests and the
  local demo never touch the network or a live key. The fleet has
  no earlier Stripe checkout code to reuse (searched 2026-10-28);
  this module follows the detector's urllib pattern instead.
- Checkout charges the Stripe CATALOG, never an inline price
  (Bayo, 2026-10-29: "just wire in the catalog ... so we don't
  have to circle back later"). Every pack entry carries the
  "stripe_price_id" of the catalog price Bayo created for it in
  the Stripe Dashboard; a checkout session names that price as
  its line item, so the amount, currency and (for the Pass)
  monthly recurrence are whatever the catalog says. A pack
  carrying no price id cannot check out at all: the checkout
  route refuses it, public_pack reports its checkout_available
  as false, and StripePayments raises rather than inventing an
  inline price fallback. On the webhook side, when an event
  names the price that was charged (a session's expanded line
  items, an invoice's lines), pack_by_price_id resolves it and
  the resolution must agree with what the server recorded; an
  unknown or disagreeing price mints and grants nothing.
- Webhook signatures are verified with the stdlib HMAC scheme
  Stripe documents, over the exact raw request bytes, so the
  critical path needs no SDK.
"""
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

STRIPE_API_BASE = "https://api.stripe.com/v1"
WEBHOOK_TOLERANCE_SECONDS = 300

# Crockford base32 (no I, L, O, U: the letters most often misread).
CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CODE_SYMBOLS = 20  # 20 symbols * 5 bits = 100 bits of entropy

# Bayo's decided launch prices (2026-10-28), in sale order: the
# Verifier Pass leads (Bayo switched it on the same day: $25 a
# month; the monthly grant of 1,000 carries the 400 AI generation
# checks, and standard registry checks are unlimited while the
# subscription runs, per Bayo's later call the same evening), the
# 100-check pack is the headline one-time pack, and the 250-check
# pack is the upsell behind it. NPC_CREDITS_PACKS_JSON replaces
# this list wholesale. Each entry's stripe_price_id is the Stripe
# catalog price Bayo created in the Bayo LLC Dashboard on
# 2026-10-28 (catalog wiring ordered 2026-10-29): checkout charges
# that price, so the catalog is the money truth; price_cents
# remains what the packs endpoint renders and what the purchase
# page shows.
DEFAULT_PACKS = [
    {"id": "verifier-pass", "label": "Verifier Pass", "checks": 1000,
     "price_cents": 2500, "currency": "usd", "kind": "access",
     "ai_checks": 400, "interval": "month",
     "stripe_price_id": "price_1UVmNkAmXrDzn7XPqeRHwIkZ"},
    {"id": "checks-100", "label": "100 checks", "checks": 100,
     "price_cents": 900, "currency": "usd", "kind": "pack",
     "stripe_price_id": "price_1UVmMeAmXrDzn7XPOECPoeSR"},
    {"id": "checks-250", "label": "250 checks", "checks": 250,
     "price_cents": 1900, "currency": "usd", "kind": "pack",
     "stripe_price_id": "price_1UVmMeAmXrDzn7XP7lSWVGBR"},
]

# Pack kinds the loader preserves. Both are on sale: "pack" is a
# one-time grant, "access" is the monthly Verifier Pass.
PACK_KINDS = ("pack", "access")

# Check kinds a consume call can charge. "standard" is a registry
# check; "ai" is an AI generation check. An AI check draws, in
# order, a Pass grant's AI sub-allowance, then bonus grants, then
# the code's one-time pack balance (grant_ai_room prices each).
CHECK_KINDS = ("standard", "ai")

# Anti-scripting backstop on the consume path (2026-10-28): one
# code may land at most this many charged consumes inside a
# trailing hour. It is an engineering guard against a script
# draining or probing the ledger, not a usage cap: no human
# checking images comes close to it. Bayo set the figure the same
# evening: "increase backstop to 1000 checks per hour."
# Duplicate answers (an image already charged to the code) never
# count toward it and are never refused by it.
CONSUME_HOURLY_LIMIT = 1000

# Referral figures (Bayo, 2026-10-28; amounts revised the same
# evening). Every redeem code and every Pass subscription carries
# a personal referral code, a separate string under the same
# hash-only discipline as redeem codes. On a successful referral
# link both sides are rewarded at once, so users invite more and
# push their invites to pay: the referee receives
# REFEREE_BONUS_CHECKS bonus checks and the referrer
# REFERRER_LINK_BONUS_CHECKS, each once. When the referred user
# makes their first paid purchase, the referrer receives
# REFERRER_BONUS_CHECKS more, once per referred user. One
# referrer's referral grants (link and purchase bonuses together)
# are capped at REFERRAL_MONTHLY_CAP_CHECKS per calendar month.
# Bonus checks spend like regular checks: standard and AI draws
# share the one pool, so a bonus grant's whole remaining balance
# can fund an AI generation check too, drawn only after any Pass
# grant's own AI sub-allowance (Bayo, later still on 2026-10-28:
# the 500 cap includes all AI checks, and the margin is good
# enough to eat the cost; see BONUS_GRANT_SOURCES and
# grant_ai_room). Bonus grants expire under the same one-month
# rollover rule as Pass grants. The ledger mechanics live in the
# store's attribute_referral.
REFEREE_BONUS_CHECKS = 10
REFERRER_LINK_BONUS_CHECKS = 10
REFERRER_BONUS_CHECKS = 100
REFERRAL_MONTHLY_CAP_CHECKS = 500

# Registration bonus (SPEC ONLY, not built; Bayo, 2026-10-28): a
# completed first registration of a work or an agent pays
# REGISTRATION_BONUS_CHECKS checks when the registry and this
# ledger are wired together. It is deliberately worth more than a
# referral link (+10): registering grows the registry the checks
# verify against, an invite only grows the user list.
REGISTRATION_BONUS_CHECKS = 25

# Grant sources whose checks are bonus checks: the referral
# bonuses (referee, at-link referrer, first-purchase referrer)
# and the registration bonus when it is wired (its grants will
# carry the source "registration"). A bonus grant stores ai_cap 0,
# because it has no AI sub-allowance of its own; that figure does
# not make it standard-only. An AI generation check may spend a
# bonus grant's whole remaining balance, drawn only after the
# Pass grants' AI sub-allowances (Bayo, 2026-10-28).
BONUS_GRANT_SOURCES = ("referral_referee", "referral_link",
                       "referral_referrer", "registration")

# Sources whose balance funds AI generation checks out of the
# whole remainder rather than an AI sub-allowance: the bonus
# grants above, and one-time pack purchases (Bayo, later still on
# 2026-10-28: "Pack credits include the AI checks"). A pack has
# no grant row: its balance rests on the code row's counters.
# pack_grant_view sees those counters as a grant under the source
# "pack", so grant_ai_room stays the one place that prices every
# balance's AI room, and the pack size itself is the only cap.
WHOLE_BALANCE_AI_SOURCES = BONUS_GRANT_SOURCES + ("pack",)


def pack_grant_view(row):
    """A code row's one-time pack counters, seen as a grant: the
    view grant_ai_room prices for AI room. Pass codes carry zero
    counters, so the view adds nothing for them."""
    return {"amount": row["credits_total"],
            "used": row["credits_used"],
            "ai_cap": 0, "ai_used": 0, "source": "pack"}


def grant_ai_room(grant):
    """How many AI generation checks one live grant can still
    fund.

    A Pass grant funds up to its remaining ai_cap sub-allowance.
    A bonus grant (BONUS_GRANT_SOURCES) or a pack balance (the
    pack_grant_view of a code row) funds out of its whole
    remaining balance: standard and AI draws share the one pool,
    so every draw of either kind lowers what is left for both.
    """
    remaining = grant["amount"] - grant["used"]
    if remaining <= 0:
        return 0
    if grant["source"] in WHOLE_BALANCE_AI_SOURCES:
        return remaining
    return max(0, min(remaining,
                      grant["ai_cap"] - grant["ai_used"]))


class PaymentsError(Exception):
    """The payment provider could not complete the operation."""


class PaymentsNotConfigured(PaymentsError):
    """No payment credentials are configured on this server."""


class WebhookSignatureError(PaymentsError):
    """The webhook signature did not verify. The event is refused."""


# -- pack configuration -------------------------------------------------------

def _valid_pack(p):
    if not (isinstance(p, dict)
            and isinstance(p.get("id"), str) and p.get("id")
            and isinstance(p.get("label"), str) and p.get("label")
            and isinstance(p.get("checks"), int) and p["checks"] > 0
            and isinstance(p.get("price_cents"), int)
            and p["price_cents"] >= 0
            and isinstance(p.get("currency"), str) and p.get("currency")
            and p.get("kind", "pack") in PACK_KINDS):
        return False
    # Optional Pass fields, validated when present: ai_checks is the
    # per-grant AI sub-allowance; interval is the billing period.
    if "ai_checks" in p and not (
            isinstance(p["ai_checks"], int) and p["ai_checks"] >= 0):
        return False
    if "interval" in p and p["interval"] != "month":
        return False
    # The catalog wiring, validated when present: a price id is a
    # non-empty string. A pack may omit it; such a pack is listed
    # but can never check out (fail closed, see public_pack and
    # StripePayments.create_checkout_session).
    if "stripe_price_id" in p and not (
            isinstance(p["stripe_price_id"], str)
            and p["stripe_price_id"]):
        return False
    return True


def packs_from_env(env=None):
    """(packs, is_default) from NPC_CREDITS_PACKS_JSON.

    The variable holds a JSON list of pack objects with id, label,
    checks, price_cents and currency, plus an optional kind ("pack"
    for a one-time grant, "access" for the Verifier Pass; an access
    entry may also carry ai_checks and interval) and an optional
    stripe_price_id (the Stripe catalog price checkout charges for
    the entry; an entry without one is listed but cannot check
    out). Anything missing or malformed falls back to
    DEFAULT_PACKS, Bayo's decided launch prices: a configuration
    mistake must never invent or lose a price.
    """
    env = os.environ if env is None else env
    raw = (env.get("NPC_CREDITS_PACKS_JSON") or "").strip()
    if raw:
        try:
            packs = json.loads(raw)
        except ValueError:
            packs = None
        if isinstance(packs, list) and packs \
                and all(_valid_pack(p) for p in packs):
            out = []
            for p in packs:
                entry = {
                    "id": p["id"], "label": p["label"],
                    "checks": p["checks"],
                    "price_cents": p["price_cents"],
                    "currency": p["currency"].lower(),
                    "kind": p.get("kind", "pack"),
                }
                if "ai_checks" in p:
                    entry["ai_checks"] = p["ai_checks"]
                if "interval" in p:
                    entry["interval"] = p["interval"]
                if "stripe_price_id" in p:
                    entry["stripe_price_id"] = p["stripe_price_id"]
                out.append(entry)
            return out, False
    return [dict(p) for p in DEFAULT_PACKS], True


def find_pack(packs, pack_id):
    for p in packs:
        if p["id"] == pack_id:
            return p
    return None


def public_pack(pack):
    out = {
        "id": pack["id"], "label": pack["label"],
        "checks": pack["checks"],
        "price_cents": pack["price_cents"],
        "currency": pack["currency"],
        "kind": pack.get("kind", "pack"),
        "on_sale": True,
        # Per-offer checkout truth: an offer is wired to a Stripe
        # catalog price or it cannot be bought, however the rest of
        # the rail is configured. The endpoint's top-level
        # checkout_available still reports the payments rail
        # itself; this flag is the offer's own wiring.
        "checkout_available": bool(pack.get("stripe_price_id")),
    }
    if pack.get("kind") == "access":
        out["ai_checks"] = pack.get("ai_checks", 0)
        out["interval"] = pack.get("interval", "month")
        # While the subscription runs, standard registry checks
        # are unlimited; only the AI sub-allowance is counted.
        out["registry_unlimited"] = True
    return out


def pack_by_price_id(packs, price_id):
    """The pack a Stripe catalog price id belongs to, or None.

    The webhook resolves what was actually charged through this
    map: a price id no configured pack carries resolves to
    nothing, and callers fail closed on None rather than guessing
    which pack the money bought.
    """
    if not isinstance(price_id, str) or not price_id:
        return None
    for p in packs:
        if p.get("stripe_price_id") == price_id:
            return p
    return None


def _first_price_id(items):
    """The first price id in a Stripe list of priced lines: each
    line's price may be an expanded object ({"id": ...}) or, in
    plainer payloads, the id string itself."""
    if isinstance(items, dict):
        items = items.get("data")
    if not isinstance(items, list):
        return None
    for item in items:
        if not isinstance(item, dict):
            continue
        price = item.get("price")
        if isinstance(price, dict) \
                and isinstance(price.get("id"), str) \
                and price["id"]:
            return price["id"]
        if isinstance(price, str) and price:
            return price
    return None


def session_price_id(obj):
    """The catalog price id a Checkout Session object names, from
    its line items when the payload carries them (deliveries with
    expanded line items, and honestly built fixtures, do; a plain
    session object names none). None when it names none."""
    if not isinstance(obj, dict):
        return None
    return _first_price_id(obj.get("line_items"))


def invoice_price_id(obj):
    """The catalog price id an invoice's lines name, in the
    2022-08-01 invoice shape the webhook handler assumes
    (lines.data[].price.id). None when it names none."""
    if not isinstance(obj, dict):
        return None
    return _first_price_id(obj.get("lines"))


def hour_ago(now):
    """The ISO timestamp one hour before `now`, in the store's
    utcnow_iso format: the trailing edge of the consume
    rate-limit window (CONSUME_HOURLY_LIMIT)."""
    dt = datetime.fromisoformat(now.replace("Z", "+00:00"))
    dt = dt.astimezone(timezone.utc) - timedelta(hours=1)
    return dt.isoformat(timespec="seconds")


def grant_expiry(granted_at):
    """When a Pass grant stops being spendable, as an ISO string.

    A grant made in month M stays spendable through the end of
    month M+1 (one rollover, the locked $NPC model's maximum), so
    it expires at the first instant of month M+2, UTC. The input is
    an ISO timestamp in the store's utcnow_iso format.
    """
    dt = datetime.fromisoformat(granted_at.replace("Z", "+00:00"))
    dt = dt.astimezone(timezone.utc)
    month = dt.month + 2
    year = dt.year + (month - 1) // 12
    month = (month - 1) % 12 + 1
    expiry = datetime(year, month, 1, tzinfo=timezone.utc)
    return expiry.isoformat(timespec="seconds")


# -- redeem codes ---------------------------------------------------------------

def generate_code():
    """A fresh redeem code: NPC-XXXX-XXXX-XXXX-XXXX-XXXX."""
    symbols = "".join(secrets.choice(CODE_ALPHABET)
                      for _ in range(CODE_SYMBOLS))
    groups = [symbols[i:i + 4] for i in range(0, CODE_SYMBOLS, 4)]
    return "NPC-" + "-".join(groups)


def normalize_code(code):
    """The canonical payload a code hashes from: the 20 symbols,
    uppercased, with separators and the NPC prefix removed, so a
    code pasted with stray spaces or lowercase still matches."""
    if not isinstance(code, str):
        return ""
    symbols = "".join(c for c in code.upper() if c.isalnum())
    if len(symbols) == CODE_SYMBOLS + 3 and symbols.startswith("NPC"):
        symbols = symbols[3:]
    return symbols


def code_hash(code):
    return hashlib.sha256(
        normalize_code(code).encode("utf-8")).hexdigest()


def valid_code_shape(code):
    symbols = normalize_code(code)
    return len(symbols) == CODE_SYMBOLS \
        and all(c in CODE_ALPHABET for c in symbols)


# -- Stripe payments ------------------------------------------------------------

def _urlopen_transport(method, url, headers, body_bytes, timeout=10):
    """Default transport: one HTTPS call. Returns (status, parsed)."""
    req = urllib.request.Request(url, data=body_bytes, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            parsed = json.loads(exc.read().decode("utf-8"))
        except Exception:
            raise PaymentsError("payment provider returned an error")
        return exc.code, parsed
    except Exception:
        raise PaymentsError("payment provider could not be reached")


class StripePayments:
    """Stripe Checkout over the provider's plain HTTPS API.

    `transport` may be injected (tests and the demo pass a fake);
    otherwise one real HTTPS call is made per operation. The secret
    key is used only in the Authorization header of calls this
    module makes; it is never logged and never returned.
    """

    configured = True

    def __init__(self, secret_key, webhook_secret, success_url,
                 cancel_url, transport=None):
        self._secret_key = secret_key
        self._webhook_secret = webhook_secret
        self.success_url = success_url
        self.cancel_url = cancel_url
        self._transport = transport or _urlopen_transport

    def create_checkout_session(self, pack, email=None):
        """Create a Checkout Session for one pack. Returns
        {"id": ..., "url": ...}; raises PaymentsError otherwise.

        The session charges the pack's Stripe catalog price
        (pack["stripe_price_id"]) as its single line item: the
        catalog carries the amount, the currency and, for the
        Pass, the monthly recurrence. A pack carrying no price id
        raises PaymentsError before any transport call: checkout
        fails closed rather than falling back to an inline price.

        One-time packs run in payment mode. The Verifier Pass (kind
        "access") runs in subscription mode against its recurring
        catalog price, so Stripe bills it monthly and reports
        renewals as invoice.paid webhooks against the same
        endpoint.
        """
        price_id = pack.get("stripe_price_id")
        if not isinstance(price_id, str) or not price_id:
            raise PaymentsError(
                "pack %s has no Stripe price configured"
                % pack.get("id"))
        is_pass = pack.get("kind") == "access"
        fields = {
            "mode": "subscription" if is_pass else "payment",
            "success_url": self.success_url,
            "cancel_url": self.cancel_url,
            "line_items[0][quantity]": "1",
            "line_items[0][price]": price_id,
            "metadata[pack_id]": pack["id"],
            "metadata[product]": "npc_verify_credits",
        }
        if is_pass:
            fields["subscription_data[metadata][pack_id]"] = pack["id"]
            fields["subscription_data[metadata][product]"] = \
                "npc_verify_credits"
        if email:
            fields["customer_email"] = email
        body = urllib.parse.urlencode(fields).encode("utf-8")
        status, parsed = self._transport(
            "POST", STRIPE_API_BASE + "/checkout/sessions",
            {"Authorization": "Bearer " + self._secret_key,
             "Content-Type": "application/x-www-form-urlencoded"},
            body)
        if status != 200 or not isinstance(parsed, dict) \
                or not parsed.get("id") or not parsed.get("url"):
            raise PaymentsError(
                "checkout session creation failed (status %s)" % status)
        return {"id": parsed["id"], "url": parsed["url"]}

    def verify_webhook(self, raw_body, signature_header, now=None):
        """Verify a Stripe webhook signature over the raw bytes and
        return the parsed event. Raises WebhookSignatureError for a
        missing, stale, or non-matching signature."""
        if not signature_header:
            raise WebhookSignatureError("missing signature header")
        timestamp = None
        signatures = []
        for part in signature_header.split(","):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            if k.strip() == "t":
                timestamp = v.strip()
            elif k.strip() == "v1":
                signatures.append(v.strip())
        if timestamp is None or not signatures:
            raise WebhookSignatureError("malformed signature header")
        try:
            ts = int(timestamp)
        except ValueError:
            raise WebhookSignatureError("malformed signature timestamp")
        current = int(time.time()) if now is None else now
        if abs(current - ts) > WEBHOOK_TOLERANCE_SECONDS:
            raise WebhookSignatureError("signature timestamp out of range")
        signed = str(ts).encode("utf-8") + b"." + raw_body
        expected = hmac.new(self._webhook_secret.encode("utf-8"),
                            signed, hashlib.sha256).hexdigest()
        if not any(hmac.compare_digest(expected, s) for s in signatures):
            raise WebhookSignatureError("signature mismatch")
        try:
            event = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise WebhookSignatureError("event body is not JSON")
        if not isinstance(event, dict) or not event.get("type"):
            raise WebhookSignatureError("event body has no type")
        return event


class UnconfiguredPayments:
    """The resting payments state: checkout is off, webhooks are
    refused, and the API answers honestly instead of faking a sale.
    Mirrors detector.UnconfiguredDetector."""

    configured = False

    def create_checkout_session(self, pack, email=None):
        raise PaymentsNotConfigured("payments are not configured")

    def verify_webhook(self, raw_body, signature_header, now=None):
        raise PaymentsNotConfigured("payments are not configured")


def payments_from_env(env=None):
    """Build the payments client from the environment.

    NPC_STRIPE_SECRET_KEY and NPC_STRIPE_WEBHOOK_SECRET plus the
    checkout return addresses NPC_CREDITS_SUCCESS_URL and
    NPC_CREDITS_CANCEL_URL must all be present; anything missing
    rests the whole purchase rail rather than half-configuring it.
    """
    env = os.environ if env is None else env
    secret = (env.get("NPC_STRIPE_SECRET_KEY") or "").strip()
    wh_secret = (env.get("NPC_STRIPE_WEBHOOK_SECRET") or "").strip()
    success = (env.get("NPC_CREDITS_SUCCESS_URL") or "").strip()
    cancel = (env.get("NPC_CREDITS_CANCEL_URL") or "").strip()
    if not (secret and wh_secret and success and cancel):
        return UnconfiguredPayments()
    return StripePayments(secret, wh_secret, success, cancel)


def sign_webhook_payload(webhook_secret, raw_body, timestamp):
    """The Stripe-Signature header value for a payload. Production
    code never signs webhooks; tests and the local demo use this to
    prove the verification path with honestly signed fixtures."""
    signed = str(timestamp).encode("utf-8") + b"." + raw_body
    sig = hmac.new(webhook_secret.encode("utf-8"), signed,
                   hashlib.sha256).hexdigest()
    return "t=%d,v1=%s" % (timestamp, sig)
