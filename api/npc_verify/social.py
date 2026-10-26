"""Social profiles content-registration lane (build pass 1).

Design: integrations/DESIGN.md (the platform integrations and the
bulk-registration engine), build order for this pass set by Bayo on
2026-10-19: social profiles first, so an owner can connect a
profile, enumerate the content that is provably theirs on it, and
register that content as signed records, ready for verification
and attestation.

The lane is the authenticated batch lane the design describes,
built beside the registry on the Phase 1 patterns
(npc_verify.linking): a feature flag off by default
(NPC_SOCIAL_PROFILES=1), fail closed when a platform is not
configured, credentials from the environment only, and every
registration its own signed record, never edited in place.

What the lane does, per platform:

- YouTube, Instagram, TikTok: read-only OAuth connect (NPC never
  sees a customer password and no adapter requests a write scope),
  enumeration of the connected account's works through the
  platform's own API, and batch registration of a selection (or
  the whole scan) under one consent call. Each registered work's
  record states it was enumerated from the owner's connected
  account at a stated time, and that the account controls this
  content on the platform, in those words.
- X: the manual permalink lane. The owner pastes permalinks; each
  registers as a permalink-only record. NPC does not read the post
  in v1, and the record says so.
- Spotify: the permalink and ISRC lane. No customer connection;
  NPC reads public catalog metadata with its own app credentials,
  from references the owner provides, and the record says that.

Provenance is not a verdict, on this lane exactly as everywhere
else in the registry: registration is the start of verification,
the status stays "registered, checks pending", and enumeration
shows control of content on a platform, never that a work is
verified.

Tokens live only in the connection row in the store (server-side),
never in a signed record, a batch receipt, or a response. The
connection's abuse control replaces the public caps for batch
registrations (per the design); owner-driven calls are themselves
counted under the same rolling per-email and per-IP ceilings the
rest of the API uses.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone

from . import linking, pact, registry  # noqa: F401  (linking is
# imported for its public_base_url, the house pattern)
from .models import utcnow_iso  # noqa: F401  (re-exported for the
# server routes, the house pattern)
from .store import registration_email_hash

SOCIAL_ENV = registry.SOCIAL_PROFILES_ENV
BATCH_RECORD_TYPE = "npc.social.registration_batch"
OAUTH_PLATFORMS = ("youtube", "instagram", "tiktok")
STATE_TTL = timedelta(minutes=10)
TITLE_MAX = 200  # the registry's title limit, as in the planner

# Lane ceilings. Enumeration stops at the scan ceiling rather
# than paging a platform forever; a register call works at most
# the batch ceiling and defers the rest to a later call; a Spotify
# artist or show enumeration stops at the catalog ceiling. Every
# stop is reported in the receipt, never silent.
MAX_SCAN_ITEMS = 2000
MAX_BATCH_ITEMS = 1000
MAX_CATALOG_ITEMS = 500

INSTAGRAM_API_BASE_DEFAULT = "https://graph.instagram.com/v21.0"
YOUTUBE_API = "https://www.googleapis.com/youtube/v3"
TIKTOK_API = "https://open.tiktokapis.com"
SPOTIFY_API = "https://api.spotify.com/v1"
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"

# The minimum scopes that carry each lane (DESIGN.md lane table).
OAUTH_SCOPES = {
    "youtube": "https://www.googleapis.com/auth/youtube.readonly",
    "instagram": "instagram_business_basic",
    "tiktok": "user.info.basic,video.list",
}


def social_enabled():
    return os.environ.get(SOCIAL_ENV) == "1"


def public_base_url():
    return linking.public_base_url()


def redirect_uri(platform):
    return "%s/v1/social/%s/callback" % (public_base_url(), platform)


def instagram_api_base():
    return (os.environ.get("NPC_INSTAGRAM_API_BASE")
            or INSTAGRAM_API_BASE_DEFAULT).rstrip("/")


# -- configuration (environment only) -----------------------------------------
def oauth_config(platform):
    """(client_key_or_id, client_secret) for a connect platform, or
    None when NPC's developer app for it is not configured."""
    env = {"youtube": ("NPC_YOUTUBE_CLIENT_ID",
                       "NPC_YOUTUBE_CLIENT_SECRET"),
           "instagram": ("NPC_INSTAGRAM_CLIENT_ID",
                         "NPC_INSTAGRAM_CLIENT_SECRET"),
           "tiktok": ("NPC_TIKTOK_CLIENT_KEY",
                      "NPC_TIKTOK_CLIENT_SECRET")}[platform]
    client_id = os.environ.get(env[0])
    client_secret = os.environ.get(env[1])
    if not client_id or not client_secret:
        return None
    return client_id, client_secret


def spotify_config():
    """NPC's own Spotify app credentials for the catalog lane, or
    None when not configured. The lane reads public catalog data
    with the app's client-credentials token; no customer scopes
    are requested (DESIGN.md lane 7)."""
    client_id = os.environ.get("NPC_SPOTIFY_CLIENT_ID")
    client_secret = os.environ.get("NPC_SPOTIFY_CLIENT_SECRET")
    if not client_id or not client_secret:
        return None
    return client_id, client_secret


# -- caps (mirroring the linking pattern) --------------------------------------
def social_cap_exceeded(store, email, client_ip, now_iso):
    """Owner-driven lane calls share the API's rolling ceilings:
    same per-email and per-IP caps over the same window, counted
    over attempts."""
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    since = (now - registry.CAP_WINDOW).isoformat(timespec="seconds")
    if store.count_social_attempts_since(
            "email", email, since) >= registry.EMAIL_DAILY_CAP:
        return "email"
    if client_ip and store.count_social_attempts_since(
            "ip", client_ip, since) >= registry.IP_DAILY_CAP:
        return "ip"
    return None


def _iso_after(a, b):
    return datetime.fromisoformat(a.replace("Z", "+00:00")) \
        > datetime.fromisoformat(b.replace("Z", "+00:00"))


def _expiry_iso(now_iso, expires_in):
    try:
        seconds = int(expires_in)
    except (TypeError, ValueError):
        return ""
    if seconds <= 0:
        return ""
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    return (now + timedelta(seconds=seconds)).isoformat(
        timespec="seconds")


# -- normalized items -----------------------------------------------------------
# An item here is the WorkItem of integrations/bulk_register in
# dict form, plus the platform account id and lane bookkeeping
# under "extra". The metadata hash follows the bulk lane's exact
# convention (canonical JSON over the same field list, account
# fields excluded), so the same work seen by either lane hashes
# the same.
_METADATA_FIELDS = ("platform", "external_id", "title", "kind",
                    "native_type", "permalink", "published_at",
                    "modified_at", "version_marker",
                    "version_marker_kind", "platform_checksum",
                    "byte_class")


def _canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def metadata_hash(item):
    return hashlib.sha256(_canonical_json(
        {name: item.get(name) for name in _METADATA_FIELDS})
    ).hexdigest()


def identity_key(item):
    """The work itself, apart from its version: platform, the
    platform's account id, and the work's platform id."""
    return "%s|%s|%s" % (item["platform"], item["account_id"],
                         item["external_id"])


def idempotency_key(item):
    """(platform, account, external ID, version), the design's
    key: the version part is the platform's version marker when it
    gives one, else its checksum, else the literal "unversioned".
    """
    if item.get("version_marker"):
        version = item["version_marker"]
    elif item.get("platform_checksum"):
        version = item["platform_checksum"].get("value", "")
    else:
        version = "unversioned"
    return "%s:%s:%s:%s" % (item["platform"], item["account_id"],
                            item["external_id"], version)


def _finalize_item(item):
    item["metadata_hash"] = metadata_hash(item)
    item["identity_key"] = identity_key(item)
    item["idempotency_key"] = idempotency_key(item)
    return item


def source_object(item, enumerated_at, enumerated_from,
                  previous_record_id=None):
    """The registry `source` object for one item, in the shape
    npc_verify.registry validates and signs: the planner's object
    plus this lane's provenance fields."""
    src = {
        "platform": item["platform"],
        "external_id": item["external_id"],
        "permalink": item["permalink"],
        "byte_class": item["byte_class"],
        "metadata_hash": item["metadata_hash"],
        "account_id": item["account_id"],
        "enumerated_at": enumerated_at,
        "enumerated_from": enumerated_from,
    }
    if item.get("account_display_name"):
        src["account_display_name"] = item["account_display_name"]
    if item.get("native_type"):
        src["native_type"] = item["native_type"]
    if item.get("published_at"):
        src["published_at"] = item["published_at"]
    if item.get("modified_at"):
        src["modified_at"] = item["modified_at"]
    if item.get("version_marker"):
        src["version_marker"] = {
            "kind": item.get("version_marker_kind") or "opaque",
            "value": item["version_marker"],
        }
    if item.get("platform_checksum"):
        src["platform_checksum"] = dict(item["platform_checksum"])
    if item.get("rendition"):
        src["rendition"] = item["rendition"]
    if previous_record_id:
        src["previous_record_id"] = previous_record_id
    return src


def _epoch_to_iso(epoch):
    return datetime.fromtimestamp(
        int(epoch), timezone.utc).isoformat(timespec="seconds")


# -- connection views -----------------------------------------------------------
def connection_public(row):
    """A connection as any response may show it. Tokens never
    leave the store row."""
    return {
        "connection_id": row["connection_id"],
        "platform": row["platform"],
        "platform_account_id": row["platform_account_id"],
        "account_display_name": row.get("account_display_name", ""),
        "scopes": row.get("scopes", ""),
        "status": row.get("status", "active"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


# The provenance sentence every connected-account record carries,
# verbatim (registry._platform_metadata_detail prints it inside
# the platform_metadata check detail). The connection overview
# below, and the dashboard view that renders it, print the
# sentence in exactly these words. It states account control of
# content on a platform; it is not, and never renders as, a
# verification claim.
PROVENANCE_SENTENCE = "The account controls this content on the platform."


def build_connection_overview(store, conn):
    """The read-only overview payload for one connection: the
    connection's public view, its last scan (when, and how many
    works it held), and the registration outcomes of every batch
    minted from the connection, per batch and in total. Built
    from stored rows only: this never reads a platform, never
    mints anything, and carries no token material (the connection
    rides in its public view). X and Spotify batches belong to no
    connection and never appear here."""
    scans = store.list_social_scans(conn["connection_id"])
    batches = store.list_social_batches(conn["connection_id"])
    last_scan = None
    if scans:
        latest = scans[-1]
        last_scan = {
            "scan_id": latest["scan_id"],
            "enumerated_at": latest.get("enumerated_at"),
            "item_count": latest.get("item_count", 0),
        }
    totals = {"registered": 0, "new_version": 0, "unchanged": 0,
              "failed": 0, "deferred": 0}
    batch_views = []
    for batch in batches:
        counts = batch.get("counts") or {}
        for key in totals:
            totals[key] += int(counts.get(key) or 0)
        batch_views.append({
            "batch_id": batch["record_id"],
            "registered_at": batch.get("registered_at"),
            "counts": counts,
        })
    return {
        "connection": connection_public(conn),
        "provenance": PROVENANCE_SENTENCE,
        "last_scan": last_scan,
        "scan_count": len(scans),
        "batches": batch_views,
        "totals": totals,
    }


# -- connect: OAuth start and callback ------------------------------------------
def start_connect(store, platform, email, now_iso):
    """Open a connect: store a single-use state challenge bound to
    the owner's email hash and return the platform authorize URL.
    The owner approves read-only access on the platform's own
    pages; NPC never sees their password."""
    config = oauth_config(platform)
    if config is None:
        return None, ["not_configured"]
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    state = secrets.token_urlsafe(24)
    expires_at = (now + STATE_TTL).isoformat(timespec="seconds")
    store.add_social_challenge({
        "challenge_id": "schg_" + secrets.token_hex(12),
        "platform": platform,
        "email_hash": registration_email_hash(email),
        "secret": state,
        "created_at": now_iso,
        "expires_at": expires_at,
    })
    client_id, _secret = config
    if platform == "youtube":
        query = {
            "client_id": client_id,
            "redirect_uri": redirect_uri(platform),
            "response_type": "code",
            "scope": OAUTH_SCOPES["youtube"],
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
        url = "https://accounts.google.com/o/oauth2/v2/auth?" \
            + urllib.parse.urlencode(query)
    elif platform == "instagram":
        query = {
            "client_id": client_id,
            "redirect_uri": redirect_uri(platform),
            "response_type": "code",
            "scope": OAUTH_SCOPES["instagram"],
            "state": state,
        }
        url = "https://www.instagram.com/oauth/authorize?" \
            + urllib.parse.urlencode(query)
    else:  # tiktok
        query = {
            "client_key": client_id,
            "scope": OAUTH_SCOPES["tiktok"],
            "response_type": "code",
            "redirect_uri": redirect_uri(platform),
            "state": state,
        }
        url = "https://www.tiktok.com/v2/auth/authorize/?" \
            + urllib.parse.urlencode(query)
    return {
        "platform": platform,
        "authorization_url": url,
        "state": state,
        "expires_at": expires_at,
        "redirect_uri": redirect_uri(platform),
    }, []


def complete_connect(store, platform, code, state, http, now_iso):
    """Finish a connect. The state is consumed before the token
    exchange (single-use states, the Phase 1 rule), the code is
    exchanged at the platform, the account's identity is read from
    the platform, and the connection is stored. A reconnect of the
    same platform account by the same owner updates the same
    connection, so its registrations dedupe."""
    row = store.find_social_challenge(platform, state)
    if row is None:
        return None, ["this connect link is not open"]
    if not _iso_after(row["expires_at"], now_iso):
        return None, ["this connect link has expired"]
    if not store.consume_social_challenge(row["challenge_id"],
                                           now_iso):
        return None, ["this connect link was already used"]
    tokens, problems = _exchange_code(platform, code, http)
    if problems:
        return None, problems
    account, problems = _fetch_account(platform, tokens, http)
    if problems:
        return None, problems
    email_hash = row["email_hash"]
    fields = {
        "access_token": tokens["access_token"],
        "token_expires_at": _expiry_iso(
            now_iso, tokens.get("expires_in")),
        "account_display_name": account["display_name"],
        "scopes": tokens.get("scope") or OAUTH_SCOPES[platform],
        "status": "active",
        "updated_at": now_iso,
    }
    if tokens.get("refresh_token"):
        fields["refresh_token"] = tokens["refresh_token"]
    existing = store.find_social_connection(
        platform, email_hash, account["account_id"])
    if existing is not None:
        store.update_social_connection(
            existing["connection_id"], fields)
        conn = store.get_social_connection(existing["connection_id"])
    else:
        conn = {
            "connection_id": "conn_" + secrets.token_hex(12),
            "platform": platform,
            "email_hash": email_hash,
            "platform_account_id": account["account_id"],
            "refresh_token": "",
            "created_at": now_iso,
        }
        conn.update(fields)
        store.add_social_connection(conn)
    return connection_public(conn), []


def _exchange_code(platform, code, http):
    """Authorization code to tokens, per platform. Returns
    ({access_token, refresh_token, expires_in, scope}, []) or
    (None, problems)."""
    config = oauth_config(platform)
    client_id, client_secret = config
    if platform == "youtube":
        _s, payload, _r = http("POST", GOOGLE_TOKEN_URL, form={
            "client_id": client_id, "client_secret": client_secret,
            "code": code, "redirect_uri": redirect_uri(platform),
            "grant_type": "authorization_code"})
        if not isinstance(payload, dict) \
                or not payload.get("access_token"):
            return None, ["the platform did not complete the "
                          "sign-in"]
        return {"access_token": payload["access_token"],
                "refresh_token": payload.get("refresh_token"),
                "expires_in": payload.get("expires_in"),
                "scope": payload.get("scope")}, []
    if platform == "instagram":
        _s, payload, _r = http(
            "POST", "https://api.instagram.com/oauth/access_token",
            form={"client_id": client_id,
                  "client_secret": client_secret,
                  "grant_type": "authorization_code",
                  "redirect_uri": redirect_uri(platform),
                  "code": code})
        if not isinstance(payload, dict) \
                or not payload.get("access_token"):
            return None, ["the platform did not complete the "
                          "sign-in"]
        short_token = payload["access_token"]
        query = urllib.parse.urlencode({
            "grant_type": "ig_exchange_token",
            "client_secret": client_secret,
            "access_token": short_token})
        _s, long_lived, _r = http(
            "GET", "https://graph.instagram.com/access_token?"
            + query)
        if not isinstance(long_lived, dict) \
                or not long_lived.get("access_token"):
            return None, ["the platform did not complete the "
                          "sign-in"]
        return ({"access_token": long_lived["access_token"],
                 "refresh_token": long_lived["access_token"],
                 "expires_in": long_lived.get("expires_in"),
                 "scope": OAUTH_SCOPES["instagram"],
                 "platform_user_id":
                     str(payload.get("user_id", ""))}, [])
    # tiktok
    _s, payload, _r = http(
        "POST", TIKTOK_API + "/v2/oauth/token/", form={
            "client_key": client_id,
            "client_secret": client_secret,
            "code": code, "grant_type": "authorization_code",
            "redirect_uri": redirect_uri(platform)})
    if not isinstance(payload, dict) \
            or not payload.get("access_token"):
        return None, ["the platform did not complete the sign-in"]
    return {"access_token": payload["access_token"],
            "refresh_token": payload.get("refresh_token"),
            "expires_in": payload.get("expires_in"),
            "scope": payload.get("scope"),
            "open_id": payload.get("open_id")}, []


def _bearer_headers(token):
    return {"Authorization": "Bearer " + token}


def _fetch_account(platform, tokens, http):
    """The connected account's platform id and display name, read
    from the platform itself. Returns ({account_id, display_name},
    []) or (None, problems)."""
    access = tokens["access_token"]
    if platform == "youtube":
        _s, payload, _r = http(
            "GET", YOUTUBE_API + "/channels"
            "?part=snippet,contentDetails&mine=true",
            headers=_bearer_headers(access))
        items = (payload or {}).get("items") or []
        if not items:
            return None, ["the connected account has no channel "
                          "to enumerate"]
        channel = items[0]
        return {"account_id": str(channel["id"]),
                "display_name": (channel.get("snippet") or {})
                .get("title", "")}, []
    if platform == "instagram":
        url = "%s/me?fields=id,username,account_type&access_token=%s" \
            % (instagram_api_base(),
               urllib.parse.quote(access, safe=""))
        _s, payload, _r = http("GET", url)
        if not isinstance(payload, dict) or not payload.get("id"):
            return None, ["the platform did not return the "
                          "connected account"]
        account_type = str(payload.get("account_type", "")).upper()
        if account_type not in ("BUSINESS", "MEDIA_CREATOR"):
            return None, ["this lane connects professional "
                          "Instagram accounts (business or creator); "
                          "personal accounts cannot be enumerated "
                          "through the platform's API"]
        return {"account_id": str(payload["id"]),
                "display_name": payload.get("username", "")}, []
    # tiktok
    fields = urllib.parse.quote(
        "open_id,display_name", safe=",")
    _s, payload, _r = http(
        "GET", TIKTOK_API + "/v2/user/info/?fields=" + fields,
        headers=_bearer_headers(access))
    user = ((payload or {}).get("data") or {}).get("user") or {}
    if not user.get("open_id"):
        return None, ["the platform did not return the connected "
                      "account"]
    return {"account_id": str(user["open_id"]),
            "display_name": user.get("display_name", "")}, []


def _refresh_token(platform, conn, http):
    """Exchange a stored refresh token for a fresh access token.
    Returns ({access_token, refresh_token, expires_in}, []) or
    (None, problems)."""
    config = oauth_config(platform)
    if config is None:
        return None, ["this lane is not configured on this "
                      "deployment"]
    client_id, client_secret = config
    refresh = conn.get("refresh_token", "")
    if not refresh:
        return None, ["the connection cannot be refreshed; "
                      "reconnect the account"]
    if platform == "youtube":
        _s, payload, _r = http("POST", GOOGLE_TOKEN_URL, form={
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh,
            "grant_type": "refresh_token"})
        if not isinstance(payload, dict) \
                or not payload.get("access_token"):
            return None, ["the connection could not be refreshed; "
                          "reconnect the account"]
        return {"access_token": payload["access_token"],
                "refresh_token": refresh,
                "expires_in": payload.get("expires_in")}, []
    if platform == "instagram":
        query = urllib.parse.urlencode({
            "grant_type": "ig_refresh_token",
            "access_token": refresh})
        _s, payload, _r = http(
            "GET", "https://graph.instagram.com/refresh_access_token?"
            + query)
        if not isinstance(payload, dict) \
                or not payload.get("access_token"):
            return None, ["the connection could not be refreshed; "
                          "reconnect the account"]
        return {"access_token": payload["access_token"],
                "refresh_token": payload["access_token"],
                "expires_in": payload.get("expires_in")}, []
    # tiktok: the refresh token rotates on every refresh.
    _s, payload, _r = http(
        "POST", TIKTOK_API + "/v2/oauth/token/", form={
            "client_key": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh})
    if not isinstance(payload, dict) \
            or not payload.get("access_token"):
        return None, ["the connection could not be refreshed; "
                      "reconnect the account"]
    return {"access_token": payload["access_token"],
            "refresh_token": payload.get("refresh_token") or refresh,
            "expires_in": payload.get("expires_in")}, []


def _fresh_connection(store, conn, http, now_iso):
    """The connection with a live access token, refreshing first
    when the stored one has expired (or is about to)."""
    expires_at = conn.get("token_expires_at", "")
    if not expires_at:
        return conn, []
    soon = (datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
            + timedelta(seconds=120)).isoformat(timespec="seconds")
    if _iso_after(expires_at, soon):
        return conn, []
    tokens, problems = _refresh_token(conn["platform"], conn, http)
    if problems:
        return None, problems
    store.update_social_connection(conn["connection_id"], {
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "token_expires_at": _expiry_iso(
            now_iso, tokens.get("expires_in")),
        "updated_at": now_iso,
    })
    return store.get_social_connection(conn["connection_id"]), []


# -- enumeration: the connected account's works, as the platform gives them ------
def _youtube_enumerate(http, conn):
    """The channel's videos: the uploads playlist, paged, then one
    videos.list call per page of ids (the shape the bulk lane's
    normalizer targets). Videos are metadata-only: the platform
    API gives details, not bytes."""
    access = conn["access_token"]
    headers = _bearer_headers(access)
    _s, channels, _r = http(
        "GET", YOUTUBE_API + "/channels"
        "?part=contentDetails&mine=true", headers=headers)
    found = (channels or {}).get("items") or []
    if not found:
        return None, [], ["the platform returned no channel for "
                          "this connection"]
    uploads = ((found[0].get("contentDetails") or {})
               .get("relatedPlaylists") or {}).get("uploads")
    if not uploads:
        return None, [], ["the platform returned no uploads "
                          "playlist for this channel"]
    video_ids = []
    page_token = ""
    while True:
        url = YOUTUBE_API + "/playlistItems?part=contentDetails" \
            "&maxResults=50&playlistId=" + uploads
        if page_token:
            url += "&pageToken=" + page_token
        _s, page, _r = http("GET", url, headers=headers)
        for entry in (page or {}).get("items") or []:
            video_id = ((entry.get("contentDetails") or {})
                        .get("videoId"))
            if video_id:
                video_ids.append(video_id)
        page_token = (page or {}).get("nextPageToken") or ""
        if not page_token or len(video_ids) >= MAX_SCAN_ITEMS:
            break
    items = []
    truncated = bool(page_token) or len(video_ids) > MAX_SCAN_ITEMS
    for start in range(0, min(len(video_ids), MAX_SCAN_ITEMS), 50):
        batch = video_ids[start:start + 50]
        _s, videos, _r = http(
            "GET", YOUTUBE_API + "/videos"
            "?part=snippet,contentDetails,status&id="
            + ",".join(batch), headers=headers)
        for video in (videos or {}).get("items") or []:
            snippet = video.get("snippet") or {}
            items.append(_finalize_item({
                "platform": "youtube",
                "account_id": conn["platform_account_id"],
                "account_display_name":
                    conn.get("account_display_name", ""),
                "external_id": str(video["id"]),
                "title": snippet.get("title", ""),
                "kind": "video",
                "native_type": "video",
                "permalink": "https://www.youtube.com/watch?v="
                             + str(video["id"]),
                "published_at": snippet.get("publishedAt"),
                "modified_at": None,
                "version_marker": None,
                "version_marker_kind": None,
                "platform_checksum": None,
                "byte_class": "metadata_only",
                "rendition": None,
                "extra": {
                    "duration": (video.get("contentDetails") or {})
                    .get("duration"),
                    "privacy_status": (video.get("status") or {})
                    .get("privacyStatus"),
                },
            }))
    return items, truncated, []


def _instagram_enumerate(http, conn):
    """The account's media via /me/media with cursor paging. A
    media item whose URL the platform returned is bytes_fetchable
    (the design's byte-class rule; the fetch itself is the
    verification lane's job, never this lane's)."""
    fields = ("id,caption,media_type,media_url,permalink,shortcode,"
              "thumbnail_url,timestamp,username,media_product_type")
    url = "%s/me/media?fields=%s&limit=100&access_token=%s" % (
        instagram_api_base(), fields,
        urllib.parse.quote(conn["access_token"], safe=""))
    items = []
    truncated = False
    while url:
        _s, payload, _r = http("GET", url)
        if not isinstance(payload, dict) or "data" not in payload:
            return None, False, ["the platform did not return the "
                                 "account's media"]
        for media in payload.get("data") or []:
            media_type = media.get("media_type", "")
            items.append(_finalize_item({
                "platform": "instagram",
                "account_id": conn["platform_account_id"],
                "account_display_name":
                    conn.get("account_display_name", ""),
                "external_id": str(media.get("id", "")),
                "title": (media.get("caption") or "").strip(),
                "kind": {"IMAGE": "image", "VIDEO": "video",
                         "CAROUSEL_ALBUM": "image"}.get(
                             media_type, "image"),
                "native_type": media_type or None,
                "permalink": media.get("permalink", ""),
                "published_at": media.get("timestamp"),
                "modified_at": None,
                "version_marker": None,
                "version_marker_kind": None,
                "platform_checksum": None,
                "byte_class": "bytes_fetchable"
                if media.get("media_url") else "metadata_only",
                "rendition": None,
                "extra": {
                    "media_url": media.get("media_url"),
                    "thumbnail_url": media.get("thumbnail_url"),
                    "media_product_type":
                        media.get("media_product_type"),
                },
            }))
            if len(items) >= MAX_SCAN_ITEMS:
                truncated = True
                break
        if truncated:
            break
        url = ((payload.get("paging") or {}).get("next")) or ""
    return items, truncated, []


def _tiktok_enumerate(http, conn):
    """The account's public videos via /v2/video/list/, cursor
    paging at the platform's page size. Metadata only: the
    platform's terms do not let NPC fetch the video bytes through
    this API."""
    fields = urllib.parse.quote(
        "id,title,video_description,create_time,share_url,"
        "embed_link,duration,is_aigc", safe=",")
    url = TIKTOK_API + "/v2/video/list/?fields=" + fields
    headers = _bearer_headers(conn["access_token"])
    headers["Content-Type"] = "application/json"
    items = []
    cursor = None
    truncated = False
    while True:
        body = {"max_count": 20}
        if cursor is not None:
            body["cursor"] = cursor
        _s, payload, _r = http("POST", url, headers=headers,
                               json_body=body)
        data = (payload or {}).get("data") or {}
        for video in data.get("videos") or []:
            title = video.get("title") \
                or video.get("video_description") or ""
            items.append(_finalize_item({
                "platform": "tiktok",
                "account_id": conn["platform_account_id"],
                "account_display_name":
                    conn.get("account_display_name", ""),
                "external_id": str(video.get("id", "")),
                "title": title,
                "kind": "video",
                "native_type": "video",
                "permalink": video.get("share_url", ""),
                "published_at": _epoch_to_iso(video["create_time"])
                if video.get("create_time") else None,
                "modified_at": None,
                "version_marker": None,
                "version_marker_kind": None,
                "platform_checksum": None,
                "byte_class": "metadata_only",
                "rendition": None,
                "extra": {
                    "embed_link": video.get("embed_link"),
                    "duration": video.get("duration"),
                    "is_aigc": video.get("is_aigc"),
                },
            }))
            if len(items) >= MAX_SCAN_ITEMS:
                truncated = True
                break
        if truncated or not data.get("has_more"):
            break
        cursor = data.get("cursor")
        if cursor is None:
            break
    return items, truncated, []


def scan_connection(store, conn, http, now_iso):
    """Enumerate a connected account and store the scan. Returns
    (summary, problems); the summary is the customer's catalog
    view of their own works on the platform."""
    conn, problems = _fresh_connection(store, conn, http, now_iso)
    if problems:
        return None, problems
    enumerator = {"youtube": _youtube_enumerate,
                  "instagram": _instagram_enumerate,
                  "tiktok": _tiktok_enumerate}[conn["platform"]]
    items, truncated, problems = enumerator(http, conn)
    if problems:
        return None, problems
    scan_id = "scan_" + secrets.token_hex(12)
    store.add_social_scan({
        "scan_id": scan_id,
        "connection_id": conn["connection_id"],
        "enumerated_at": now_iso,
        "item_count": len(items),
    })
    for item in items:
        store.add_social_scan_item(scan_id, item)
    by_kind = {}
    by_byte_class = {}
    for item in items:
        by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
        by_byte_class[item["byte_class"]] = \
            by_byte_class.get(item["byte_class"], 0) + 1
    return {
        "scan_id": scan_id,
        "connection_id": conn["connection_id"],
        "platform": conn["platform"],
        "enumerated_at": now_iso,
        "total": len(items),
        "by_kind": by_kind,
        "by_byte_class": by_byte_class,
        "truncated": truncated,
        "items": items,
    }, []


# -- registration: the batch engine ----------------------------------------------
_BATCH_DETAILS = {
    "connected_account":
        "enumerated from the owner's connected account on %s "
        "at %s",
    "public_catalog":
        "read from the public catalog on %s at %s, from "
        "references the owner provided",
    "owner_supplied":
        "recorded at %s from addresses the owner provided for %s",
}


def _batch_detail(platform, enumerated_at, enumerated_from):
    display = registry.SOURCE_PLATFORM_DISPLAY.get(
        platform, platform)
    if enumerated_from == "owner_supplied":
        phrase = _BATCH_DETAILS[enumerated_from] % (
            enumerated_at, display)
    else:
        phrase = _BATCH_DETAILS[enumerated_from] % (
            display, enumerated_at)
    return ("This receipt covers one batch of registrations %s. "
            "Each work listed has its own signed registration "
            "record; this receipt names them and does not stand "
            "in for any of them. Registration is the start of "
            "verification, not the result." % phrase)


def register_items(store, keys, email, creator_name, client_ip,
                   items, *, platform, account_id,
                   enumerated_at, enumerated_from, connection_id,
                   now_iso, extra_failures=(), detail_note=""):
    """Register a batch of normalized items for one owner. Per
    item, the planner's classification (integrations/DESIGN.md):
    the same work with the same version is unchanged and returns
    the existing record; the same work with a different version
    mints a new record linked to the earlier one; anything else
    mints fresh. An item that fails validation fails alone, in the
    receipt, never the batch. Returns (batch_record, summary)."""
    email_hash = registration_email_hash(email)
    existing = {row["identity_key"]: row
                for row in store.list_social_registrations(
                    email_hash)}
    account_display_name = next(
        (i.get("account_display_name") for i in items
         if i.get("account_display_name")), None)
    batch_id = "batch_" + secrets.token_hex(12)
    outcomes = []
    counts = {"total": 0, "registered": 0, "new_version": 0,
              "unchanged": 0, "failed": 0, "deferred": 0}
    seen_in_batch = set()
    for item in items:
        counts["total"] += 1
        if counts["total"] > MAX_BATCH_ITEMS:
            counts["deferred"] += 1
            counts["total"] -= 1
            continue
        ident = item["identity_key"]
        idem = item["idempotency_key"]
        if ident in seen_in_batch:
            prior = existing[ident]
            outcomes.append({
                "external_id": item["external_id"],
                "action": "duplicate_in_batch",
                "record_id": prior["record_id"]})
            counts["unchanged"] += 1
            continue
        prior = existing.get(ident)
        if prior is not None and prior["idempotency_key"] == idem:
            outcomes.append({
                "external_id": item["external_id"],
                "action": "unchanged",
                "record_id": prior["record_id"]})
            counts["unchanged"] += 1
            seen_in_batch.add(ident)
            continue
        source = source_object(
            item, enumerated_at, enumerated_from,
            previous_record_id=prior["record_id"] if prior else None)
        title = item.get("title") or ""
        fields = {
            "title": title[:TITLE_MAX],
            "kind": item["kind"],
            "locator": item["permalink"],
            "creator_name": creator_name,
            "creator_email": email,
            "source": source,
        }
        problems = registry.validate_content_input(fields)
        if problems:
            outcomes.append({
                "external_id": item["external_id"],
                "action": "failed", "problems": problems})
            counts["failed"] += 1
            continue
        checks_run, checks_not_run = registry.run_content_intake(
            None, registry.fetch_url_bytes, fields["kind"],
            fields["locator"],
            source=registry.normalize_source(source))
        record = registry.mint_content_registration(
            store, keys, fields, checks_run, checks_not_run,
            email, client_ip)
        row = {"email_hash": email_hash, "identity_key": ident,
               "idempotency_key": idem,
               "record_id": record["record_id"],
               "batch_id": batch_id, "platform": platform,
               "created_at": now_iso}
        if prior is not None:
            store.update_social_registration(
                email_hash, ident, idem, record["record_id"],
                batch_id)
            action = "new_version"
            counts["new_version"] += 1
        else:
            store.add_social_registration(row)
            action = "registered"
            counts["registered"] += 1
        existing[ident] = row
        seen_in_batch.add(ident)
        outcome = {"external_id": item["external_id"],
                   "action": action,
                   "record_id": record["record_id"]}
        if len(title) > TITLE_MAX:
            outcome["title_truncated"] = True
        outcomes.append(outcome)
    for failure in extra_failures:
        outcomes.append({"external_id": failure["external_id"],
                         "action": "failed",
                         "problems": failure["problems"]})
        counts["failed"] += 1
        counts["total"] += 1
    core = {
        "record_type": BATCH_RECORD_TYPE,
        "record_id": batch_id,
        "platform": platform,
        "account_id": account_id,
        "account_display_name": account_display_name,
        "connection_id": connection_id,
        "enumerated_at": enumerated_at,
        "enumerated_from": enumerated_from,
        "registered_at": now_iso,
        "creator_name": creator_name,
        "counts": counts,
        "items": outcomes,
        "detail": _batch_detail(platform, enumerated_at,
                                enumerated_from) + detail_note,
    }
    batch = pact.sign_record(keys, core)
    store.add_social_batch(batch, connection_id)
    return batch, {"counts": counts, "items": outcomes}


def register_scan(store, keys, conn, scan_id, email, creator_name,
                  client_ip, selected_ids, now_iso):
    """Register works from a stored scan: all of them, or the
    selected external ids. A selected id that is not in the scan
    fails alone in the receipt."""
    scan = store.get_social_scan(scan_id)
    if scan is None or scan["connection_id"] != conn["connection_id"]:
        return None, None, ["unknown_scan"]
    items = store.list_social_scan_items(scan_id)
    extra_failures = []
    if selected_ids is not None:
        wanted = list(dict.fromkeys(selected_ids))
        by_id = {item["external_id"]: item for item in items}
        items = []
        for external_id in wanted:
            if external_id in by_id:
                items.append(by_id[external_id])
            else:
                extra_failures.append({
                    "external_id": str(external_id)[:256],
                    "problems": ["this work is not in the scan"]})
    detail_note = ""
    if len(items) >= MAX_SCAN_ITEMS:
        detail_note = (" Enumeration reached the lane ceiling of "
                       "%d works; works beyond it were not read."
                       % MAX_SCAN_ITEMS)
    batch, summary = register_items(
        store, keys, email, creator_name, client_ip, items,
        platform=conn["platform"],
        account_id=conn["platform_account_id"],
        enumerated_at=scan["enumerated_at"],
        enumerated_from="connected_account",
        connection_id=conn["connection_id"], now_iso=now_iso,
        extra_failures=extra_failures, detail_note=detail_note)
    return batch, summary, []


# -- X: the manual permalink lane ---------------------------------------------------
_X_PERMALINK_RE = re.compile(
    r"^https?://(?:www\.)?(?:x\.com|twitter\.com)"
    r"/([A-Za-z0-9_]{1,30})/status/(\d{1,25})(?:[/?#].*)?$")


def parse_x_permalink(value):
    """(username, status_id) from an X or Twitter permalink, or
    None. The canonical permalink is rebuilt from the parts, so a
    pasted tracking query never reaches a record."""
    if not isinstance(value, str):
        return None
    match = _X_PERMALINK_RE.match(value.strip())
    if not match:
        return None
    return match.group(1), match.group(2)


def register_x_permalinks(store, keys, email, creator_name,
                          client_ip, permalinks, now_iso):
    """Register owner-supplied X permalinks. Each permalink is
    validated on its own: a bad one fails in the receipt, never
    the batch. NPC does not read the post in this lane; the item
    is permalink_only and its record says the owner provided the
    address."""
    items = []
    extra_failures = []
    for entry in permalinks:
        url = entry.get("url") if isinstance(entry, dict) else entry
        title = entry.get("title") if isinstance(entry, dict) else None
        parsed = parse_x_permalink(url)
        if parsed is None:
            extra_failures.append({
                "external_id": str(url)[:256],
                "problems": ["not an X post permalink "
                             "(expected https://x.com/<user>/status/"
                             "<id>)"]})
            continue
        username, status_id = parsed
        items.append(_finalize_item({
            "platform": "x",
            "account_id": username,
            "account_display_name": "@" + username,
            "external_id": status_id,
            "title": (title or "").strip()
            or "Post by @%s on X" % username,
            "kind": "text",
            "native_type": "post",
            "permalink": "https://x.com/%s/status/%s"
                         % (username, status_id),
            "published_at": None,
            "modified_at": None,
            "version_marker": None,
            "version_marker_kind": None,
            "platform_checksum": None,
            "byte_class": "permalink_only",
            "rendition": None,
            "extra": {},
        }))
    account_ids = {item["account_id"] for item in items}
    batch, summary = register_items(
        store, keys, email, creator_name, client_ip, items,
        platform="x",
        account_id=account_ids.pop() if len(account_ids) == 1
        else None,
        enumerated_at=now_iso, enumerated_from="owner_supplied",
        connection_id=None, now_iso=now_iso,
        extra_failures=extra_failures)
    return batch, summary


# -- Spotify: the permalink and ISRC catalog lane ------------------------------------
_SPOTIFY_URL_RE = re.compile(
    r"^https?://open\.spotify\.com/(track|episode|artist|show)"
    r"/([A-Za-z0-9]{22})(?:[/?#].*)?$")
_SPOTIFY_URI_RE = re.compile(
    r"^spotify:(track|episode|artist|show):([A-Za-z0-9]{22})$")
_ISRC_RE = re.compile(r"^[A-Z]{2}[A-Z0-9]{3}[0-9]{7}$")


def parse_spotify_reference(value):
    """Classify one owner-provided reference: ("track"|"episode"|
    "artist"|"show", id) from a permalink or URI, ("isrc", code)
    from a bare ISRC, else None."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    match = _SPOTIFY_URL_RE.match(value) or _SPOTIFY_URI_RE.match(value)
    if match:
        return match.group(1), match.group(2)
    code = value.upper().replace("-", "")
    if _ISRC_RE.match(code):
        return "isrc", code
    return None


def spotify_app_token(http):
    """NPC's app token (client credentials) for public catalog
    reads. (token, []) or (None, problems)."""
    config = spotify_config()
    if config is None:
        return None, ["not_configured"]
    client_id, client_secret = config
    basic = base64.b64encode(
        ("%s:%s" % (client_id, client_secret)).encode()).decode()
    _s, payload, _r = http(
        "POST", SPOTIFY_TOKEN_URL,
        headers={"Authorization": "Basic " + basic},
        form={"grant_type": "client_credentials"})
    if not isinstance(payload, dict) \
            or not payload.get("access_token"):
        return None, ["the platform did not issue a catalog token"]
    return payload["access_token"], []


def _spotify_get(http, token, path):
    _s, payload, _r = http("GET", SPOTIFY_API + path,
                           headers=_bearer_headers(token))
    return payload if isinstance(payload, dict) else None


def _spotify_track_item(track, account_fallback=None):
    artists = track.get("artists") or []
    artist = artists[0] if artists else {}
    album = track.get("album") or {}
    return _finalize_item({
        "platform": "spotify",
        "account_id": str(artist.get("id") or account_fallback or ""),
        "account_display_name": artist.get("name", ""),
        "external_id": str(track["id"]),
        "title": track.get("name", ""),
        "kind": "audio",
        "native_type": "track",
        "permalink": (track.get("external_urls") or {})
        .get("spotify", ""),
        "published_at": album.get("release_date"),
        "modified_at": None,
        "version_marker": None,
        "version_marker_kind": None,
        "platform_checksum": None,
        "byte_class": "metadata_only",
        "rendition": None,
        # The ISRC is adapter bookkeeping only (DESIGN.md): it
        # never enters the source object or the signed record.
        "extra": {"isrc": (track.get("external_ids") or {})
                  .get("isrc")},
    })


def _spotify_episode_item(episode):
    show = episode.get("show") or {}
    return _finalize_item({
        "platform": "spotify",
        "account_id": str(show.get("id", "")),
        "account_display_name": show.get("name", ""),
        "external_id": str(episode["id"]),
        "title": episode.get("name", ""),
        "kind": "audio",
        "native_type": "episode",
        "permalink": (episode.get("external_urls") or {})
        .get("spotify", ""),
        "published_at": episode.get("release_date"),
        "modified_at": None,
        "version_marker": None,
        "version_marker_kind": None,
        "platform_checksum": None,
        "byte_class": "metadata_only",
        "rendition": None,
        "extra": {"duration_ms": episode.get("duration_ms")},
    })


def _spotify_artist_items(http, token, artist_id):
    """Every track on an artist's albums, hydrated one by one
    (the platform's development mode no longer offers a batch
    track read), up to the catalog ceiling."""
    artist = _spotify_get(http, token, "/artists/" + artist_id)
    if artist is None:
        return None, False, ["the platform did not return that "
                             "artist"]
    items = []
    truncated = False
    offset = 0
    while True:
        page = _spotify_get(
            http, token, "/artists/%s/albums?include_groups="
            "album,single&limit=50&offset=%d" % (artist_id, offset))
        if page is None:
            break
        for album in page.get("items") or []:
            tracks = _spotify_get(
                http, token, "/albums/%s/tracks?limit=50"
                % album["id"])
            for stub in (tracks or {}).get("items") or []:
                track = _spotify_get(http, token,
                                      "/tracks/" + stub["id"])
                if track is None:
                    continue
                items.append(_spotify_track_item(
                    track, account_fallback=artist_id))
                if len(items) >= MAX_CATALOG_ITEMS:
                    truncated = True
                    break
            if truncated:
                break
        if truncated or not page.get("next"):
            break
        offset += 50
    return items, truncated, []


def _spotify_show_items(http, token, show_id):
    """Every episode of a show, hydrated one by one (same platform
    constraint as artist tracks), up to the catalog ceiling."""
    show = _spotify_get(http, token, "/shows/" + show_id)
    if show is None:
        return None, False, ["the platform did not return that "
                             "show"]
    items = []
    truncated = False
    offset = 0
    while True:
        page = _spotify_get(
            http, token, "/shows/%s/episodes?limit=50&offset=%d"
            % (show_id, offset))
        if page is None:
            break
        for stub in page.get("items") or []:
            episode = _spotify_get(http, token,
                                    "/episodes/" + stub["id"])
            if episode is None:
                continue
            episode.setdefault("show", {"id": show_id,
                                         "name": show.get("name", "")})
            items.append(_spotify_episode_item(episode))
            if len(items) >= MAX_CATALOG_ITEMS:
                truncated = True
                break
        if truncated or not page.get("next"):
            break
        offset += 50
    return items, truncated, []


def register_spotify_references(store, keys, email, creator_name,
                                client_ip, references, http,
                                now_iso):
    """Register works from owner-provided Spotify references:
    track and episode permalinks register directly; an artist or
    show reference enumerates its catalog in; an ISRC resolves to
    the track that carries it. Each reference resolves on its own:
    a bad one fails in the receipt, never the batch."""
    token, problems = spotify_app_token(http)
    if problems:
        return None, None, problems
    items = []
    extra_failures = []
    truncated = False
    for entry in references:
        value = entry.get("permalink") if isinstance(entry, dict) \
            else None
        if value is None and isinstance(entry, dict):
            value = entry.get("isrc")
        if value is None:
            value = entry
        parsed = parse_spotify_reference(value)
        if parsed is None:
            extra_failures.append({
                "external_id": str(value)[:256],
                "problems": ["not a Spotify permalink, URI, or "
                             "ISRC"]})
            continue
        kind, ref = parsed
        if kind == "track":
            track = _spotify_get(http, token, "/tracks/" + ref)
            if track is None:
                extra_failures.append({
                    "external_id": str(value)[:256],
                    "problems": ["the platform did not return that "
                                 "track"]})
                continue
            items.append(_spotify_track_item(track))
        elif kind == "episode":
            episode = _spotify_get(http, token, "/episodes/" + ref)
            if episode is None:
                extra_failures.append({
                    "external_id": str(value)[:256],
                    "problems": ["the platform did not return that "
                                 "episode"]})
                continue
            items.append(_spotify_episode_item(episode))
        elif kind == "isrc":
            found = _spotify_get(
                http, token, "/search?q=isrc:%s&type=track&limit=1"
                % urllib.parse.quote(ref, safe=":"))
            tracks = ((found or {}).get("tracks") or {}) \
                .get("items") or []
            if not tracks:
                extra_failures.append({
                    "external_id": ref,
                    "problems": ["no track in the public catalog "
                                 "carries this ISRC"]})
                continue
            items.append(_spotify_track_item(tracks[0]))
        elif kind == "artist":
            found, cut, problems = _spotify_artist_items(
                http, token, ref)
            if problems:
                extra_failures.append({
                    "external_id": str(value)[:256],
                    "problems": problems})
                continue
            items.extend(found)
            truncated = truncated or cut
        else:  # show
            found, cut, problems = _spotify_show_items(
                http, token, ref)
            if problems:
                extra_failures.append({
                    "external_id": str(value)[:256],
                    "problems": problems})
                continue
            items.extend(found)
            truncated = truncated or cut
    account_ids = {item["account_id"] for item in items
                   if item["account_id"]}
    detail_note = ""
    if truncated:
        detail_note = (" Enumeration stopped at the lane ceiling "
                       "of %d works; the rest were not read."
                       % MAX_CATALOG_ITEMS)
    batch, summary = register_items(
        store, keys, email, creator_name, client_ip, items,
        platform="spotify",
        account_id=account_ids.pop() if len(account_ids) == 1
        else None,
        enumerated_at=now_iso, enumerated_from="public_catalog",
        connection_id=None, now_iso=now_iso,
        extra_failures=extra_failures, detail_note=detail_note)
    summary["enumeration_truncated"] = truncated
    return batch, summary, []


# -- disconnect ---------------------------------------------------------------------
def _revoke_tokens(conn, http):
    """Best-effort revoke at the platform (grant hygiene). Returns
    "confirmed" when the platform accepted the revoke, else
    "not_confirmed": the local disconnect stands either way, and
    the outcome is reported, never hidden."""
    platform = conn["platform"]
    access = conn.get("access_token", "")
    try:
        if platform == "youtube":
            status, _p, _r = http("POST", GOOGLE_REVOKE_URL,
                                  form={"token": access})
        elif platform == "instagram":
            url = "%s/me/permissions?access_token=%s" % (
                instagram_api_base(),
                urllib.parse.quote(access, safe=""))
            status, _p, _r = http("DELETE", url)
        else:  # tiktok
            config = oauth_config("tiktok")
            if config is None:
                return "not_confirmed"
            status, _p, _r = http(
                "POST", TIKTOK_API + "/v2/oauth/revoke/", form={
                    "client_key": config[0],
                    "client_secret": config[1],
                    "token": access})
    except Exception:
        return "not_confirmed"
    return "confirmed" if status == 200 else "not_confirmed"


def disconnect(store, conn, http, now_iso):
    """Disconnect: revoke at the platform (best effort), blank the
    stored tokens, mark the connection disconnected, and drop its
    cached scans. The signed records the customer holds stay;
    disconnecting never unmakes a record."""
    revocation = _revoke_tokens(conn, http)
    store.disconnect_social_connection(conn["connection_id"],
                                       now_iso)
    store.delete_social_scans(conn["connection_id"])
    return {"connection_id": conn["connection_id"],
            "platform": conn["platform"],
            "status": "disconnected",
            "platform_revocation": revocation}
