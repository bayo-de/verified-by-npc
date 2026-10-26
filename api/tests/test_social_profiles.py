"""Social profiles content-registration lane tests (build pass 1).

The lane behind the registry's social `source` provenance
(integrations/DESIGN.md; npc_verify.social). These tests pin the
lane contract:

- everything stays behind NPC_SOCIAL_PROFILES=1; with the flag
  off the routes refuse with a clean 503 and a registration source
  carrying the lane's fields is stripped to exactly today's
  record (byte-identical behavior);
- a platform whose developer app is not configured refuses with a
  clean not-configured 503, never a fake success;
- connect is read-only OAuth: the authorize URL carries the exact
  redirect URI and the lane's minimum scopes, the callback
  consumes its single-use state before the token exchange, and no
  token ever appears in a response or a signed record;
- scan enumerates the connected account's works through the
  platform API and caches them; register classifies each work
  unchanged / new / new-version against the owner's index, mints
  one signed registration per work plus one signed batch receipt,
  and an item failure never fails the batch;
- a connected-account record states it was enumerated from the
  owner's connected account at a stated time and that the account
  controls this content on the platform, in those words; the
  status stays "registered, checks pending" (registration is
  never verification);
- owner-driven calls prove ownership by the connection's email
  hash behind attempts counted before the match: a wrong email
  and an unknown connection are the same signed 404;
- X permalinks and Spotify references register without a
  connection, per item, with the ISRC kept as bookkeeping only
  (never in a signed record);
- disconnect revokes (best effort), blanks the tokens, drops the
  cached scans, and leaves the signed records standing.

All external calls are fakes injected into the app. No test
touches the network.
"""
import base64
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

os.environ.setdefault("NPC_ALLOW_LOOPBACK_FETCH", "1")

from npc_verify import pact, registry, social  # noqa: E402
from npc_verify.canonical import canonicalize  # noqa: E402
from npc_verify import ed25519  # noqa: E402
from npc_verify.server import Handler, create_app  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from npc_verify.store import registration_email_hash  # noqa: E402

FLAG = registry.SOCIAL_PROFILES_ENV
ENV_KEYS = (FLAG,
            "NPC_YOUTUBE_CLIENT_ID", "NPC_YOUTUBE_CLIENT_SECRET",
            "NPC_INSTAGRAM_CLIENT_ID", "NPC_INSTAGRAM_CLIENT_SECRET",
            "NPC_TIKTOK_CLIENT_KEY", "NPC_TIKTOK_CLIENT_SECRET",
            "NPC_SPOTIFY_CLIENT_ID", "NPC_SPOTIFY_CLIENT_SECRET",
            "NPC_PUBLIC_BASE_URL")

CHANNEL_ID = "UCtestchannel123"
ARTIST_ID = "0TnOYISbd1XYRBk9myaseg"
TRACK1_ID = "4uLU6hMCjMI75M1A2tKUQC"
TRACK2_ID = "3nQHG4CzQKEbOoAJfDzSOF"
ALBUM_ID = "1ATL5GLyefJaxhQzSPVrLX"
EPISODE_ID = "512ojhOuo1ktJprKbVcKyQ"
SHOW_ID = "5CfCWKI5pZ28U0uOzXkDHe"
ISRC1 = "USRC12600001"


def _yt_video(vid, title, published):
    return {"id": vid,
            "snippet": {"title": title, "publishedAt": published},
            "contentDetails": {"duration": "PT1M30S"},
            "status": {"privacyStatus": "public"}}


def _sp_track(tid, name, isrc):
    return {"id": tid, "name": name,
            "artists": [{"id": ARTIST_ID, "name": "Bayo"}],
            "album": {"release_date": "2026-05-01"},
            "external_urls": {
                "spotify": "https://open.spotify.com/track/" + tid},
            "external_ids": {"isrc": isrc}}


class FakeSocialHttp:
    """Stands in for YouTube, Instagram, TikTok, and Spotify.
    Records every call; asserts the wire shapes it cares about."""

    def __init__(self):
        self.calls = []
        self.refresh_calls = 0

    def __call__(self, method, url, headers=None, form=None,
                 json_body=None, timeout=10):
        self.calls.append((method, url))
        # -- Google / YouTube --------------------------------------
        if url == social.GOOGLE_TOKEN_URL:
            if form["grant_type"] == "authorization_code":
                assert form["redirect_uri"] == \
                    "https://api.npclabs.xyz/v1/social/youtube/callback"
                return 200, {
                    "access_token": "yt-access-1",
                    "refresh_token": "yt-refresh-1",
                    "expires_in": 3600,
                    "scope": social.OAUTH_SCOPES["youtube"]}, ""
            if form["grant_type"] == "refresh_token":
                assert form["refresh_token"] == "yt-refresh-1"
                self.refresh_calls += 1
                return 200, {"access_token": "yt-access-2",
                             "expires_in": 3600}, ""
            raise AssertionError("bad google grant: %r" % (form,))
        if url == social.GOOGLE_REVOKE_URL:
            return 200, {}, ""
        if url.startswith(social.YOUTUBE_API + "/channels"):
            assert (headers or {}).get("Authorization", "") \
                .startswith("Bearer yt-access")
            if "part=snippet,contentDetails" in url:
                return 200, {"items": [{
                    "id": CHANNEL_ID,
                    "snippet": {"title": "Bayo Creates"},
                    "contentDetails": {"relatedPlaylists":
                                       {"uploads": "UUuploads"}}}]}, ""
            return 200, {"items": [{
                "id": CHANNEL_ID,
                "contentDetails": {"relatedPlaylists":
                                   {"uploads": "UUuploads"}}}]}, ""
        if url.startswith(social.YOUTUBE_API + "/playlistItems"):
            if "pageToken=p2" in url:
                return 200, {"items": [
                    {"contentDetails": {"videoId": "vid3"}}]}, ""
            return 200, {
                "items": [{"contentDetails": {"videoId": "vid1"}},
                          {"contentDetails": {"videoId": "vid2"}}],
                "nextPageToken": "p2"}, ""
        if url.startswith(social.YOUTUBE_API + "/videos"):
            videos = {
                "vid1": _yt_video("vid1", "First Video",
                                  "2026-01-02T03:04:05Z"),
                "vid2": _yt_video("vid2", "Second Video",
                                  "2026-02-03T04:05:06Z"),
                "vid3": _yt_video("vid3", "Third Video",
                                  "2026-03-04T05:06:07Z"),
            }
            ids = url.rsplit("id=", 1)[1].split(",")
            return 200, {"items": [videos[i] for i in ids]}, ""
        # -- Instagram ----------------------------------------------
        if url == "https://api.instagram.com/oauth/access_token":
            assert form["grant_type"] == "authorization_code"
            assert form["redirect_uri"] == (
                "https://api.npclabs.xyz/v1/social/instagram/callback")
            return 200, {"access_token": "ig-short",
                         "user_id": 998877}, ""
        if url.startswith(
                "https://graph.instagram.com/access_token?"):
            assert "grant_type=ig_exchange_token" in url
            return 200, {"access_token": "ig-long",
                         "expires_in": 5184000}, ""
        if "/me?fields=" in url:
            return 200, {"id": "998877", "username": "bayo.creates",
                         "account_type": "MEDIA_CREATOR"}, ""
        if "/me/media?" in url:
            return 200, {"data": [
                {"id": "ig1", "caption": "Sunset print",
                 "media_type": "IMAGE",
                 "media_url": "https://cdn.example/ig1.jpg",
                 "permalink": "https://www.instagram.com/p/AAA1/",
                 "timestamp": "2026-04-01T10:00:00+0000"},
                {"id": "ig2", "caption": "Studio session",
                 "media_type": "VIDEO",
                 "permalink": "https://www.instagram.com/reel/BBB2/",
                 "timestamp": "2026-04-02T11:00:00+0000"},
                {"id": "ig3", "caption": "Process shots",
                 "media_type": "CAROUSEL_ALBUM",
                 "media_url": "https://cdn.example/ig3.jpg",
                 "permalink": "https://www.instagram.com/p/CCC3/",
                 "timestamp": "2026-04-03T12:00:00+0000"},
            ], "paging": {}}, ""
        if "/me/permissions" in url:
            assert method == "DELETE"
            return 200, {"success": True}, ""
        # -- TikTok ---------------------------------------------------
        if url == social.TIKTOK_API + "/v2/oauth/token/":
            if form["grant_type"] == "authorization_code":
                assert form["redirect_uri"] == (
                    "https://api.npclabs.xyz/v1/social/tiktok/callback")
                return 200, {
                    "access_token": "tt-access-1",
                    "refresh_token": "tt-refresh-1",
                    "expires_in": 86400, "open_id": "tt-open-1",
                    "scope": "user.info.basic,video.list"}, ""
            if form["grant_type"] == "refresh_token":
                self.refresh_calls += 1
                return 200, {
                    "access_token": "tt-access-2",
                    "refresh_token": "tt-refresh-2",
                    "expires_in": 86400}, ""
            raise AssertionError("bad tiktok grant: %r" % (form,))
        if url == social.TIKTOK_API + "/v2/oauth/revoke/":
            return 200, {}, ""
        if url.startswith(social.TIKTOK_API + "/v2/user/info/"):
            return 200, {"data": {"user": {
                "open_id": "tt-open-1",
                "display_name": "Bayo Creates"}}}, ""
        if url.startswith(social.TIKTOK_API + "/v2/video/list/"):
            videos = {
                "tv1": {"id": "7300000000000000001",
                        "title": "First clip",
                        "create_time": 1767225600,
                        "share_url": "https://www.tiktok.com/@bayo/"
                                     "video/7300000000000000001",
                        "duration": 12},
                "tv2": {"id": "7300000000000000002",
                        "title": "Second clip",
                        "create_time": 1767312000,
                        "share_url": "https://www.tiktok.com/@bayo/"
                                     "video/7300000000000000002",
                        "duration": 30},
            }
            cursor = (json_body or {}).get("cursor")
            if cursor == 111:
                return 200, {"data": {"videos": [videos["tv2"]],
                                      "cursor": 222,
                                      "has_more": False}}, ""
            return 200, {"data": {"videos": [videos["tv1"]],
                                  "cursor": 111,
                                  "has_more": True}}, ""
        # -- Spotify ----------------------------------------------------
        if url == social.SPOTIFY_TOKEN_URL:
            assert (headers or {}).get("Authorization", "") \
                .startswith("Basic ")
            assert form["grant_type"] == "client_credentials"
            return 200, {"access_token": "sp-app-token",
                         "expires_in": 3600}, ""
        if url.startswith(social.SPOTIFY_API + "/tracks/"):
            tid = url.rsplit("/", 1)[1]
            tracks = {TRACK1_ID: _sp_track(TRACK1_ID, "Golden Hour",
                                           ISRC1),
                      TRACK2_ID: _sp_track(TRACK2_ID, "Silver Line",
                                           "USRC12600002")}
            return 200, tracks[tid], ""
        if url.startswith(social.SPOTIFY_API + "/search?"):
            return 200, {"tracks": {"items": [
                _sp_track(TRACK1_ID, "Golden Hour", ISRC1)]}}, ""
        if url == social.SPOTIFY_API + "/artists/" + ARTIST_ID:
            return 200, {"id": ARTIST_ID, "name": "Bayo"}, ""
        if "/artists/%s/albums" % ARTIST_ID in url:
            return 200, {"items": [{"id": ALBUM_ID}], "next": None}, ""
        if url.startswith(social.SPOTIFY_API + "/albums/"):
            return 200, {"items": [{"id": TRACK1_ID},
                                   {"id": TRACK2_ID}]}, ""
        if url.startswith(social.SPOTIFY_API + "/episodes/"):
            return 200, {
                "id": EPISODE_ID, "name": "Episode One",
                "release_date": "2026-06-01",
                "external_urls": {
                    "spotify": "https://open.spotify.com/episode/"
                               + EPISODE_ID},
                "show": {"id": SHOW_ID, "name": "The Show"}}, ""
        raise AssertionError("unexpected external call: %s %s"
                             % (method, url))



class SocialTestCase(unittest.TestCase):
    """An app with the social fakes injected, over real HTTP."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_social_test_")
        cls.fake_http = FakeSocialHttp()
        cls.app = create_app(
            os.path.join(cls.tmp, "t.db"),
            os.path.join(cls.tmp, "keys"),
            link_http=cls.fake_http)
        seed_all(cls.app.store, cls.app.keys)
        Handler.app = cls.app
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.app.store.close()

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ENV_KEYS}
        os.environ[FLAG] = "1"
        os.environ["NPC_YOUTUBE_CLIENT_ID"] = "test-yt-client-id"
        os.environ["NPC_YOUTUBE_CLIENT_SECRET"] = "test-yt-secret"
        os.environ["NPC_INSTAGRAM_CLIENT_ID"] = "test-ig-client-id"
        os.environ["NPC_INSTAGRAM_CLIENT_SECRET"] = "test-ig-secret"
        os.environ["NPC_TIKTOK_CLIENT_KEY"] = "test-tt-client-key"
        os.environ["NPC_TIKTOK_CLIENT_SECRET"] = "test-tt-secret"
        os.environ["NPC_SPOTIFY_CLIENT_ID"] = "test-sp-client-id"
        os.environ["NPC_SPOTIFY_CLIENT_SECRET"] = "test-sp-secret"
        os.environ["NPC_PUBLIC_BASE_URL"] = "https://api.npclabs.xyz"
        self.fake_http.refresh_calls = 0

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # -- HTTP plumbing (mirrors tests/test_identity_linking.py) -----
    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        payload = None
        headers = {}
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        out = (resp.status, dict(resp.getheaders()), data)
        conn.close()
        return out

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None):
        return self.request("POST", path, body=body)

    def check_signature(self, headers, body_bytes):
        sig_b64 = headers.get("X-NPC-Signature")
        key_id = headers.get("X-NPC-Key-ID")
        self.assertIsNotNone(sig_b64)
        status, _, kdata = self.get("/v1/keys")
        self.assertEqual(status, 200)
        keys_doc = json.loads(kdata)
        pub = None
        cur = keys_doc["api_signing"]["current"]
        if cur and cur["key_id"] == key_id:
            pub = base64.b64decode(cur["public_key"])
        else:
            for h in keys_doc["api_signing"]["history"]:
                if h["key_id"] == key_id:
                    pub = base64.b64decode(h["public_key"])
        parsed = json.loads(body_bytes)
        self.assertEqual(canonicalize(parsed), body_bytes)
        self.assertTrue(ed25519.verify(
            pub, body_bytes, base64.b64decode(sig_b64)))
        return parsed

    # -- domain helpers -------------------------------------------------
    _counter = [0]

    def fresh_email(self, tag):
        SocialTestCase._counter[0] += 1
        return "social-%s-%d@example.com" % (
            tag, SocialTestCase._counter[0])

    def connect(self, platform, email):
        """Run one full connect; returns the public connection."""
        status, _, data = self.post(
            "/v1/social/%s/connect/start" % platform,
            body={"email": email})
        self.assertEqual(status, 201, data)
        start = json.loads(data)
        status, _, data = self.get(
            "/v1/social/%s/callback?code=test-code&state=%s"
            % (platform, urllib.parse.quote(start["state"])))
        self.assertEqual(status, 201, data)
        return json.loads(data)["connection"], start

    def scan(self, conn, email):
        status, _, data = self.post(
            "/v1/social/connections/%s/scan" % conn["connection_id"],
            body={"email": email})
        self.assertEqual(status, 201, data)
        return json.loads(data)

    def register(self, conn, email, scan_id, external_ids=None):
        body = {"email": email, "creator_name": "Bayo",
                "scan_id": scan_id}
        if external_ids is not None:
            body["external_ids"] = external_ids
        status, _, data = self.post(
            "/v1/social/connections/%s/register"
            % conn["connection_id"], body=body)
        self.assertEqual(status, 201, data)
        return json.loads(data)

    def public_record(self, record_id):
        status, _, data = self.get("/v1/records/" + record_id)
        self.assertEqual(status, 200, data)
        return json.loads(data)

    # -- the flag ----------------------------------------------------
    def test_flag_off_routes_refuse(self):
        os.environ.pop(FLAG, None)
        email = self.fresh_email("off")
        for path, body in (
                ("/v1/social/youtube/connect/start",
                 {"email": email}),
                ("/v1/social/connections/list", {"email": email}),
                ("/v1/social/x/register",
                 {"email": email, "creator_name": "Bayo",
                  "permalinks": ["https://x.com/a/status/1"]}),
                ("/v1/social/spotify/register",
                 {"email": email, "creator_name": "Bayo",
                  "references": [ISRC1]}),
        ):
            status, _, data = self.post(path, body=body)
            self.assertEqual(status, 503, (path, data))
            self.assertEqual(json.loads(data)["error"],
                             "social_profiles_not_enabled")

    def test_flag_off_source_fields_dropped(self):
        """With the lane off, the three provenance fields are
        unknown fields: validation ignores them and normalization
        drops them, so records stay exactly as today."""
        os.environ.pop(FLAG, None)
        source = {
            "platform": "youtube", "external_id": "vid1",
            "permalink": "https://www.youtube.com/watch?v=vid1",
            "byte_class": "metadata_only",
            "account_id": CHANNEL_ID,
            "enumerated_at": "not-a-date",
            "enumerated_from": "connected_account",
        }
        self.assertEqual(registry.validate_source(source), [])
        out = registry.normalize_source(source)
        for name in ("account_id", "enumerated_at",
                     "enumerated_from"):
            self.assertNotIn(name, out)

    def test_flag_on_source_fields_validated(self):
        source = {
            "platform": "youtube", "external_id": "vid1",
            "permalink": "https://www.youtube.com/watch?v=vid1",
            "byte_class": "metadata_only",
            "account_id": CHANNEL_ID,
            "enumerated_at": "not-a-date",
            "enumerated_from": "connected_account",
        }
        problems = registry.validate_source(source)
        self.assertTrue(any("enumerated_at" in p for p in problems),
                        problems)
        source["enumerated_at"] = "2026-10-19T12:00:00+00:00"
        self.assertEqual(registry.validate_source(source), [])
        out = registry.normalize_source(source)
        self.assertEqual(out["account_id"], CHANNEL_ID)
        self.assertEqual(out["enumerated_from"], "connected_account")
        self.assertEqual(out["enumerated_at"],
                         "2026-10-19T12:00:00+00:00")
        source["enumerated_from"] = "invented"
        self.assertTrue(any("enumerated_from" in p
                            for p in registry.validate_source(source)))

    # -- connect --------------------------------------------------------
    def test_unconfigured_platform_refuses(self):
        os.environ.pop("NPC_YOUTUBE_CLIENT_ID", None)
        os.environ.pop("NPC_YOUTUBE_CLIENT_SECRET", None)
        status, _, data = self.post(
            "/v1/social/youtube/connect/start",
            body={"email": self.fresh_email("cfg")})
        self.assertEqual(status, 503, data)
        self.assertEqual(json.loads(data)["error"],
                         "social_profiles_not_configured")

    def test_youtube_authorize_url(self):
        status, _, data = self.post(
            "/v1/social/youtube/connect/start",
            body={"email": self.fresh_email("url")})
        self.assertEqual(status, 201, data)
        start = json.loads(data)
        self.assertEqual(
            start["redirect_uri"],
            "https://api.npclabs.xyz/v1/social/youtube/callback")
        parts = urllib.parse.urlparse(start["authorization_url"])
        self.assertEqual(parts.netloc, "accounts.google.com")
        query = urllib.parse.parse_qs(parts.query)
        self.assertEqual(query["client_id"], ["test-yt-client-id"])
        self.assertEqual(query["redirect_uri"],
                         [start["redirect_uri"]])
        self.assertEqual(
            query["scope"],
            ["https://www.googleapis.com/auth/youtube.readonly"])
        self.assertEqual(query["access_type"], ["offline"])
        self.assertEqual(query["state"], [start["state"]])

    def test_callback_unknown_state_fails_closed(self):
        status, _, data = self.get(
            "/v1/social/youtube/callback?code=x&state=bogus-state")
        self.assertEqual(status, 422, data)

    def test_instagram_and_tiktok_authorize_urls(self):
        for platform, netloc, scope in (
                ("instagram", "www.instagram.com",
                 "instagram_business_basic"),
                ("tiktok", "www.tiktok.com",
                 "user.info.basic,video.list")):
            status, _, data = self.post(
                "/v1/social/%s/connect/start" % platform,
                body={"email": self.fresh_email(platform)})
            self.assertEqual(status, 201, data)
            start = json.loads(data)
            self.assertEqual(
                start["redirect_uri"],
                "https://api.npclabs.xyz/v1/social/%s/callback"
                % platform)
            parts = urllib.parse.urlparse(start["authorization_url"])
            self.assertEqual(parts.netloc, netloc)
            query = urllib.parse.parse_qs(parts.query)
            self.assertEqual(query["scope"], [scope])
            self.assertEqual(query["redirect_uri"],
                             [start["redirect_uri"]])

    # -- YouTube: the full lane -----------------------------------------
    def test_youtube_full_flow(self):
        email = self.fresh_email("yt")
        conn, start = self.connect("youtube", email)
        self.assertEqual(conn["platform"], "youtube")
        self.assertEqual(conn["platform_account_id"], CHANNEL_ID)
        self.assertEqual(conn["account_display_name"], "Bayo Creates")
        self.assertNotIn("access_token", json.dumps(conn))
        self.assertNotIn("yt-access", json.dumps(conn))
        # The state is single-use: a replayed callback fails.
        status, _, data = self.get(
            "/v1/social/youtube/callback?code=test-code&state=%s"
            % urllib.parse.quote(start["state"]))
        self.assertEqual(status, 422, data)
        # Scan: both playlist pages, three videos.
        summary = self.scan(conn, email)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_kind"], {"video": 3})
        self.assertEqual(summary["by_byte_class"],
                         {"metadata_only": 3})
        self.assertFalse(summary["truncated"])
        # Register the whole scan.
        out = self.register(conn, email, summary["scan_id"])
        counts = out["summary"]["counts"]
        self.assertEqual(
            counts, {"total": 3, "registered": 3, "new_version": 0,
                     "unchanged": 0, "failed": 0, "deferred": 0})
        batch = out["batch"]
        self.assertEqual(batch["record_type"],
                         "npc.social.registration_batch")
        self.assertEqual(batch["platform"], "youtube")
        self.assertEqual(batch["account_id"], CHANNEL_ID)
        self.assertTrue(pact.verify_record(self.app.keys, batch))
        self.assertIn("does not stand in for any of them",
                      batch["detail"])
        # One record per video, carrying the lane's provenance.
        by_id = {i["external_id"]: i for i in out["summary"]["items"]}
        record = self.public_record(by_id["vid1"]["record_id"])
        self.assertEqual(record["status"],
                         "registered_checks_pending")
        source = record["source"]
        self.assertEqual(source["platform"], "youtube")
        self.assertEqual(source["account_id"], CHANNEL_ID)
        self.assertEqual(source["enumerated_from"],
                         "connected_account")
        self.assertEqual(source["enumerated_at"],
                         summary["enumerated_at"])
        self.assertEqual(source["permalink"],
                         "https://www.youtube.com/watch?v=vid1")
        self.assertEqual(source["published_at"],
                         "2026-01-02T03:04:05Z")
        self.assertTrue(pact.verify_record(self.app.keys, record))
        metadata = [c for c in record["checks_run"]
                    if c["check"] == "platform_metadata"]
        self.assertEqual(len(metadata), 1)
        self.assertIn("The account controls this content on the "
                      "platform.", metadata[0]["detail"])
        self.assertIn("is not verification of the work",
                      metadata[0]["detail"])
        # No token material anywhere in the signed record.
        self.assertNotIn("yt-access", json.dumps(record))
        self.assertNotIn("yt-refresh", json.dumps(record))

    def test_rescan_reregister_is_unchanged(self):
        email = self.fresh_email("yt2")
        conn, _ = self.connect("youtube", email)
        first = self.scan(conn, email)
        self.register(conn, email, first["scan_id"])
        second = self.scan(conn, email)
        out = self.register(conn, email, second["scan_id"])
        counts = out["summary"]["counts"]
        self.assertEqual(counts["registered"], 0)
        self.assertEqual(counts["new_version"], 0)
        self.assertEqual(counts["unchanged"], 3)
        email_hash = registration_email_hash(email)
        rows = self.app.store.list_social_registrations(email_hash)
        self.assertEqual(len(rows), 3)

    def test_register_selected_subset_and_unknown_id(self):
        email = self.fresh_email("yt3")
        conn, _ = self.connect("youtube", email)
        summary = self.scan(conn, email)
        out = self.register(conn, email, summary["scan_id"],
                            external_ids=["vid2", "nope"])
        counts = out["summary"]["counts"]
        self.assertEqual(counts["registered"], 1)
        self.assertEqual(counts["failed"], 1)
        failures = [i for i in out["summary"]["items"]
                    if i["action"] == "failed"]
        self.assertEqual(failures[0]["external_id"], "nope")

    def test_wrong_email_is_unknown_everywhere(self):
        email = self.fresh_email("owner")
        other = self.fresh_email("intruder")
        conn, _ = self.connect("youtube", email)
        summary = self.scan(conn, email)
        cid = conn["connection_id"]
        for path, body in (
                ("/v1/social/connections/%s/scan" % cid,
                 {"email": other}),
                ("/v1/social/connections/%s/register" % cid,
                 {"email": other, "creator_name": "Bayo",
                  "scan_id": summary["scan_id"]}),
                ("/v1/social/connections/%s/disconnect" % cid,
                 {"email": other}),
                ("/v1/social/connections/conn_missing/scan",
                 {"email": email}),
        ):
            status, _, data = self.post(path, body=body)
            self.assertEqual(status, 404, (path, data))
            self.assertEqual(json.loads(data)["verdict"], "unknown")
        # The connection still works for its owner afterwards.
        status, _, _ = self.post(
            "/v1/social/connections/list", body={"email": email})
        self.assertEqual(status, 200)

    def test_token_refresh_on_scan(self):
        email = self.fresh_email("refresh")
        conn, _ = self.connect("youtube", email)
        self.app.store.update_social_connection(
            conn["connection_id"],
            {"token_expires_at": "2020-01-01T00:00:00+00:00"})
        summary = self.scan(conn, email)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(self.fake_http.refresh_calls, 1)
        row = self.app.store.get_social_connection(
            conn["connection_id"])
        self.assertEqual(row["access_token"], "yt-access-2")

    def test_disconnect(self):
        email = self.fresh_email("bye")
        conn, _ = self.connect("youtube", email)
        summary = self.scan(conn, email)
        out = self.register(conn, email, summary["scan_id"])
        record_id = out["summary"]["items"][0]["record_id"]
        status, _, data = self.post(
            "/v1/social/connections/%s/disconnect"
            % conn["connection_id"], body={"email": email})
        self.assertEqual(status, 200, data)
        result = json.loads(data)
        self.assertEqual(result["status"], "disconnected")
        self.assertEqual(result["platform_revocation"], "confirmed")
        row = self.app.store.get_social_connection(
            conn["connection_id"])
        self.assertEqual(row["status"], "disconnected")
        self.assertEqual(row["access_token"], "")
        self.assertEqual(row["refresh_token"], "")
        self.assertIsNone(self.app.store.get_social_scan(
            summary["scan_id"]))
        status, _, data = self.post(
            "/v1/social/connections/list", body={"email": email})
        self.assertEqual(json.loads(data)["connections"], [])
        # The signed record stands.
        self.public_record(record_id)
        # And a scan against the dead connection is unknown.
        status, _, _ = self.post(
            "/v1/social/connections/%s/scan" % conn["connection_id"],
            body={"email": email})
        self.assertEqual(status, 404)

    def test_connections_list_never_shows_tokens(self):
        email = self.fresh_email("list")
        self.connect("youtube", email)
        self.connect("tiktok", email)
        status, _, data = self.post(
            "/v1/social/connections/list", body={"email": email})
        self.assertEqual(status, 200, data)
        body = json.loads(data)
        self.assertEqual(len(body["connections"]), 2)
        self.assertNotIn("access", data.decode())
        self.assertNotIn("refresh", data.decode())


    # -- Instagram ------------------------------------------------------
    def test_instagram_flow(self):
        email = self.fresh_email("ig")
        conn, _ = self.connect("instagram", email)
        self.assertEqual(conn["platform_account_id"], "998877")
        self.assertEqual(conn["account_display_name"], "bayo.creates")
        # The short-lived token was exchanged for the long-lived one.
        row = self.app.store.get_social_connection(
            conn["connection_id"])
        self.assertEqual(row["access_token"], "ig-long")
        summary = self.scan(conn, email)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_byte_class"],
                         {"bytes_fetchable": 2, "metadata_only": 1})
        self.assertEqual(summary["by_kind"],
                         {"image": 2, "video": 1})
        out = self.register(conn, email, summary["scan_id"])
        self.assertEqual(out["summary"]["counts"]["registered"], 3)
        record_id = {i["external_id"]: i["record_id"]
                     for i in out["summary"]["items"]}["ig2"]
        record = self.public_record(record_id)
        self.assertEqual(record["source"]["byte_class"],
                         "metadata_only")
        self.assertEqual(record["source"]["native_type"], "VIDEO")

    # -- TikTok ------------------------------------------------------------
    def test_tiktok_flow_two_pages(self):
        email = self.fresh_email("tt")
        conn, _ = self.connect("tiktok", email)
        self.assertEqual(conn["platform_account_id"], "tt-open-1")
        summary = self.scan(conn, email)
        self.assertEqual(summary["total"], 2)
        first = {i["external_id"]: i for i in summary["items"]}[
            "7300000000000000001"]
        self.assertEqual(first["published_at"],
                         "2026-01-01T00:00:00+00:00")
        out = self.register(conn, email, summary["scan_id"])
        self.assertEqual(out["summary"]["counts"]["registered"], 2)
        record = self.public_record(
            out["summary"]["items"][0]["record_id"])
        self.assertEqual(record["source"]["platform"], "tiktok")
        self.assertEqual(record["source"]["byte_class"],
                         "metadata_only")

    # -- X permalinks ---------------------------------------------------------
    def test_x_permalinks(self):
        email = self.fresh_email("x")
        status, _, data = self.post("/v1/social/x/register", body={
            "email": email, "creator_name": "Bayo",
            "permalinks": [
                "https://x.com/bayo_de/status/1234567890?s=20",
                {"url": "https://twitter.com/bayo_de/status/"
                        "2234567890"},
                "https://example.com/not-a-post",
                "https://x.com/bayo_de/status/1234567890",
            ]})
        self.assertEqual(status, 201, data)
        out = json.loads(data)
        counts = out["summary"]["counts"]
        self.assertEqual(counts["registered"], 2)
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(counts["failed"], 1)
        actions = {}
        for item in out["summary"]["items"]:
            actions.setdefault(item["external_id"],
                               []).append(item["action"])
        self.assertEqual(actions["1234567890"],
                         ["registered", "duplicate_in_batch"])
        self.assertEqual(actions["2234567890"], ["registered"])
        record_id = [i["record_id"] for i in out["summary"]["items"]
                     if i["external_id"] == "1234567890"
                     and i["action"] == "registered"][0]
        record = self.public_record(record_id)
        source = record["source"]
        self.assertEqual(source["enumerated_from"], "owner_supplied")
        self.assertEqual(source["byte_class"], "permalink_only")
        self.assertEqual(source["account_id"], "bayo_de")
        self.assertEqual(source["permalink"],
                         "https://x.com/bayo_de/status/1234567890")
        self.assertEqual(record["title"], "Post by @bayo_de on X")
        metadata = [c for c in record["checks_run"]
                    if c["check"] == "platform_metadata"][0]
        self.assertIn("NPC has not read the work from the "
                      "platform", metadata["detail"])

    # -- Spotify ----------------------------------------------------------------
    def test_spotify_track_isrc_and_artist(self):
        email = self.fresh_email("sp")
        status, _, data = self.post("/v1/social/spotify/register",
                                    body={
            "email": email, "creator_name": "Bayo",
            "references": [
                {"permalink": "https://open.spotify.com/track/"
                              + TRACK1_ID + "?si=abc"},
                {"isrc": ISRC1},
                "https://open.spotify.com/artist/" + ARTIST_ID,
                "not a reference",
            ]})
        self.assertEqual(status, 201, data)
        out = json.loads(data)
        counts = out["summary"]["counts"]
        self.assertEqual(counts["registered"], 2, out)
        self.assertEqual(counts["unchanged"], 2)
        self.assertEqual(counts["failed"], 1)
        batch = out["batch"]
        self.assertEqual(batch["enumerated_from"], "public_catalog")
        self.assertEqual(batch["account_id"], ARTIST_ID)
        self.assertTrue(pact.verify_record(self.app.keys, batch))
        record_id = [i["record_id"] for i in out["summary"]["items"]
                     if i["external_id"] == TRACK1_ID
                     and i["action"] == "registered"][0]
        record = self.public_record(record_id)
        self.assertEqual(record["source"]["account_id"], ARTIST_ID)
        self.assertEqual(record["source"]["published_at"],
                         "2026-05-01")
        # The ISRC is bookkeeping only: nowhere in the record.
        self.assertNotIn(ISRC1, json.dumps(record))
        self.assertNotIn("isrc", record["source"])

    def test_spotify_episode(self):
        email = self.fresh_email("sp2")
        status, _, data = self.post("/v1/social/spotify/register",
                                    body={
            "email": email, "creator_name": "Bayo",
            "references": ["spotify:episode:" + EPISODE_ID]})
        self.assertEqual(status, 201, data)
        out = json.loads(data)
        self.assertEqual(out["summary"]["counts"]["registered"], 1)
        record = self.public_record(
            out["summary"]["items"][0]["record_id"])
        self.assertEqual(record["source"]["native_type"], "episode")
        self.assertEqual(record["source"]["account_id"], SHOW_ID)

    def test_spotify_unconfigured(self):
        os.environ.pop("NPC_SPOTIFY_CLIENT_ID", None)
        os.environ.pop("NPC_SPOTIFY_CLIENT_SECRET", None)
        status, _, data = self.post("/v1/social/spotify/register",
                                    body={
            "email": self.fresh_email("sp3"), "creator_name": "Bayo",
            "references": [ISRC1]})
        self.assertEqual(status, 503, data)
        self.assertEqual(json.loads(data)["error"],
                         "social_profiles_not_configured")


    # -- planner semantics at the service level ----------------------
    def _versioned_item(self, marker):
        return social._finalize_item({
            "platform": "youtube", "account_id": CHANNEL_ID,
            "account_display_name": "Bayo Creates",
            "external_id": "vidX", "title": "Versioned Video",
            "kind": "video", "native_type": "video",
            "permalink": "https://www.youtube.com/watch?v=vidX",
            "published_at": "2026-01-01T00:00:00Z",
            "modified_at": None, "version_marker": marker,
            "version_marker_kind": "opaque",
            "platform_checksum": None,
            "byte_class": "metadata_only", "rendition": None,
            "extra": {}})

    def test_new_version_mints_linked_record(self):
        email = self.fresh_email("ver")
        now = social.utcnow_iso()
        batch1, summary1 = social.register_items(
            self.app.store, self.app.keys, email, "Bayo",
            "203.0.113.9", [self._versioned_item("v1")],
            platform="youtube", account_id=CHANNEL_ID,
            enumerated_at=now, enumerated_from="connected_account",
            connection_id=None, now_iso=now)
        self.assertEqual(summary1["counts"]["registered"], 1)
        first_id = summary1["items"][0]["record_id"]
        batch2, summary2 = social.register_items(
            self.app.store, self.app.keys, email, "Bayo",
            "203.0.113.9", [self._versioned_item("v2")],
            platform="youtube", account_id=CHANNEL_ID,
            enumerated_at=now, enumerated_from="connected_account",
            connection_id=None, now_iso=now)
        self.assertEqual(summary2["counts"]["new_version"], 1)
        second_id = summary2["items"][0]["record_id"]
        self.assertNotEqual(first_id, second_id)
        record = self.public_record(second_id)
        self.assertEqual(record["source"]["previous_record_id"],
                         first_id)
        # The earlier record is never edited.
        first = self.public_record(first_id)
        self.assertNotIn("previous_record_id", first["source"])
        self.assertEqual(first["source"]["version_marker"]["value"],
                         "v1")

    def test_flag_off_public_registration_byte_identical(self):
        """A public registration carrying the lane's source fields
        with the flag off produces exactly the source it produces
        without them."""
        os.environ.pop(FLAG, None)
        base_source = {
            "platform": "youtube", "external_id": "vidSame",
            "permalink": "https://www.youtube.com/watch?v=vidSame",
            "byte_class": "metadata_only",
        }
        enriched = dict(base_source, account_id=CHANNEL_ID,
                        enumerated_at="2026-10-19T12:00:00+00:00",
                        enumerated_from="connected_account")
        records = []
        for tag, source in (("plain", base_source),
                            ("enriched", enriched)):
            status, _, data = self.post("/v1/register/content", body={
                "title": "Same Video", "kind": "video",
                "locator": "https://www.youtube.com/watch?v=vidSame",
                "creator_name": "Bayo",
                "creator_email": self.fresh_email(tag),
                "source": source})
            self.assertEqual(status, 201, data)
            records.append(json.loads(data))
        self.assertEqual(records[0]["source"], records[1]["source"])
        metadata = [c for c in records[1]["checks_run"]
                    if c["check"] == "platform_metadata"]
        self.assertEqual(len(metadata), 1)
        self.assertNotIn("enumerated_from", metadata[0])


class SocialPhase15TestCase(unittest.TestCase):
    """Phase 1.5 tests on their own app instance: the lane caps
    count attempts per IP over the app's store, so these tests
    get a fresh store rather than sharing SocialTestCase's."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="npc_social15_test_")
        cls.fake_http = FakeSocialHttp()
        cls.app = create_app(
            os.path.join(cls.tmp, "t.db"),
            os.path.join(cls.tmp, "keys"),
            link_http=cls.fake_http)
        seed_all(cls.app.store, cls.app.keys)
        Handler.app = cls.app
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.app.store.close()

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ENV_KEYS}
        os.environ[FLAG] = "1"
        os.environ["NPC_YOUTUBE_CLIENT_ID"] = "test-yt-client-id"
        os.environ["NPC_YOUTUBE_CLIENT_SECRET"] = "test-yt-secret"
        os.environ["NPC_PUBLIC_BASE_URL"] = "https://api.npclabs.xyz"

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        payload = None
        headers = {}
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        out = (resp.status, dict(resp.getheaders()), data)
        conn.close()
        return out

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None):
        return self.request("POST", path, body=body)

    def check_signature(self, headers, body_bytes):
        sig_b64 = headers.get("X-NPC-Signature")
        key_id = headers.get("X-NPC-Key-ID")
        self.assertIsNotNone(sig_b64)
        status, _, kdata = self.get("/v1/keys")
        self.assertEqual(status, 200)
        keys_doc = json.loads(kdata)
        pub = None
        cur = keys_doc["api_signing"]["current"]
        if cur and cur["key_id"] == key_id:
            pub = base64.b64decode(cur["public_key"])
        else:
            for h in keys_doc["api_signing"]["history"]:
                if h["key_id"] == key_id:
                    pub = base64.b64decode(h["public_key"])
        parsed = json.loads(body_bytes)
        self.assertEqual(canonicalize(parsed), body_bytes)
        self.assertTrue(ed25519.verify(
            pub, body_bytes, base64.b64decode(sig_b64)))
        return parsed

    _counter = [0]

    def fresh_email(self, tag):
        SocialPhase15TestCase._counter[0] += 1
        return "social15-%s-%d@example.com" % (
            tag, SocialPhase15TestCase._counter[0])

    def connect(self, platform, email):
        status, _, data = self.post(
            "/v1/social/%s/connect/start" % platform,
            body={"email": email})
        self.assertEqual(status, 201, data)
        start = json.loads(data)
        status, _, data = self.get(
            "/v1/social/%s/callback?code=test-code&state=%s"
            % (platform, urllib.parse.quote(start["state"])))
        self.assertEqual(status, 201, data)
        return json.loads(data)["connection"], start

    def scan(self, conn, email):
        status, _, data = self.post(
            "/v1/social/connections/%s/scan" % conn["connection_id"],
            body={"email": email})
        self.assertEqual(status, 201, data)
        return json.loads(data)

    def register(self, conn, email, scan_id, external_ids=None):
        body = {"email": email, "creator_name": "Bayo",
                "scan_id": scan_id}
        if external_ids is not None:
            body["external_ids"] = external_ids
        status, _, data = self.post(
            "/v1/social/connections/%s/register"
            % conn["connection_id"], body=body)
        self.assertEqual(status, 201, data)
        return json.loads(data)


class BatchReceiptLookupTests(SocialPhase15TestCase):
    """Phase 1.5: a batch receipt resolves through the one record
    lookup while the lane is enabled, as the stored signed record;
    with the flag off its ID answers exactly as it did before the
    lane existed."""

    def test_receipt_resolves_flag_on_and_verifies(self):
        email = self.fresh_email("receipt")
        conn, _ = self.connect("youtube", email)
        summary = self.scan(conn, email)
        out = self.register(conn, email, summary["scan_id"])
        batch = out["batch"]
        status, headers, data = self.get(
            "/v1/records/" + batch["record_id"])
        self.assertEqual(status, 200, data)
        served = self.check_signature(headers, data)
        self.assertEqual(served, batch)
        self.assertEqual(served["record_type"],
                         "npc.social.registration_batch")
        self.assertTrue(pact.verify_record(self.app.keys, served))

    def test_receipt_unknown_with_flag_off(self):
        email = self.fresh_email("receiptoff")
        conn, _ = self.connect("youtube", email)
        summary = self.scan(conn, email)
        out = self.register(conn, email, summary["scan_id"])
        batch_id = out["batch"]["record_id"]
        record_id = out["summary"]["items"][0]["record_id"]
        os.environ.pop(FLAG, None)
        status, _, data = self.get("/v1/records/" + batch_id)
        self.assertEqual(status, 404, data)
        self.assertEqual(json.loads(data)["verdict"], "unknown")
        # Byte-identical to any unknown ID's answer: with the
        # flag off the receipt does not exist as far as the
        # lookup is concerned.
        _, _, unknown_data = self.get(
            "/v1/records/batch_ffffffffffffffffffffffff")
        self.assertEqual(data, unknown_data)
        # The registrations the receipt names still resolve with
        # the flag off: only the receipt's own resolution is gated.
        status, _, data = self.get("/v1/records/" + record_id)
        self.assertEqual(status, 200, data)

    def test_unknown_batch_id_still_unknown_flag_on(self):
        status, _, data = self.get(
            "/v1/records/batch_000000000000000000000000")
        self.assertEqual(status, 404, data)
        self.assertEqual(json.loads(data)["verdict"], "unknown")


class ConnectionOverviewTests(SocialPhase15TestCase):
    """Phase 1.5: the read-only per-connection overview behind the
    same ownership gate as scan and register."""

    def overview(self, conn, email):
        status, _, data = self.post(
            "/v1/social/connections/%s/overview"
            % conn["connection_id"], body={"email": email})
        self.assertEqual(status, 200, data)
        return json.loads(data)

    def test_overview_full_flow(self):
        email = self.fresh_email("overview")
        conn, _ = self.connect("youtube", email)
        # Before any scan: an honest empty overview.
        out = self.overview(conn, email)
        self.assertEqual(out["connection"]["platform_account_id"],
                         CHANNEL_ID)
        self.assertEqual(out["connection"]["status"], "active")
        self.assertEqual(out["provenance"],
                         "The account controls this content on the "
                         "platform.")
        self.assertIsNone(out["last_scan"])
        self.assertEqual(out["scan_count"], 0)
        self.assertEqual(out["batches"], [])
        self.assertEqual(out["totals"]["registered"], 0)
        self.assertNotIn("yt-access", json.dumps(out))
        # Scan and register: the overview reports both.
        summary = self.scan(conn, email)
        out_reg = self.register(conn, email, summary["scan_id"])
        out = self.overview(conn, email)
        self.assertEqual(out["scan_count"], 1)
        self.assertEqual(out["last_scan"]["scan_id"],
                         summary["scan_id"])
        self.assertEqual(out["last_scan"]["enumerated_at"],
                         summary["enumerated_at"])
        self.assertEqual(out["last_scan"]["item_count"],
                         summary["total"])
        self.assertEqual(len(out["batches"]), 1)
        self.assertEqual(out["batches"][0]["batch_id"],
                         out_reg["batch"]["record_id"])
        self.assertEqual(out["batches"][0]["counts"],
                         out_reg["summary"]["counts"])
        self.assertEqual(out["totals"]["registered"], 3)
        self.assertEqual(out["totals"]["failed"], 0)
        # A rescan and re-register: second scan counted, the
        # outcomes accumulate, nothing double-counted as new.
        second = self.scan(conn, email)
        self.register(conn, email, second["scan_id"])
        out = self.overview(conn, email)
        self.assertEqual(out["scan_count"], 2)
        self.assertEqual(out["last_scan"]["scan_id"],
                         second["scan_id"])
        self.assertEqual(len(out["batches"]), 2)
        self.assertEqual(out["totals"]["registered"], 3)
        self.assertEqual(out["totals"]["unchanged"], 3)

    def test_overview_ownership_gate(self):
        email = self.fresh_email("ovowner")
        other = self.fresh_email("ovintruder")
        conn, _ = self.connect("youtube", email)
        cid = conn["connection_id"]
        status, _, data = self.post(
            "/v1/social/connections/%s/overview" % cid,
            body={"email": other})
        self.assertEqual(status, 404, data)
        self.assertEqual(json.loads(data)["verdict"], "unknown")
        status, _, data = self.post(
            "/v1/social/connections/conn_nope/overview",
            body={"email": email})
        self.assertEqual(status, 404, data)
        self.assertEqual(json.loads(data)["verdict"], "unknown")

    def test_overview_flag_off_refuses(self):
        email = self.fresh_email("ovoff")
        conn, _ = self.connect("youtube", email)
        os.environ.pop(FLAG, None)
        status, _, data = self.post(
            "/v1/social/connections/%s/overview"
            % conn["connection_id"], body={"email": email})
        self.assertEqual(status, 503, data)
        self.assertEqual(json.loads(data)["error"],
                         "social_profiles_not_enabled")


class SocialStoreDDBTestCase(unittest.TestCase):
    """The DynamoDB mirror of the social store surface, against
    the fake boto3 table (no AWS calls)."""

    @classmethod
    def setUpClass(cls):
        fake_dir = os.path.join(BASE, "serverless", "lambda_v3",
                                "fake_boto3")
        if fake_dir not in sys.path:
            sys.path.insert(0, fake_dir)

    def setUp(self):
        import boto3 as fake_boto3
        from npc_verify.ddb_store import DynamoDBStore
        self.table = fake_boto3.FakeTable("npc-social-test")
        self.store = DynamoDBStore(table=self.table)

    def test_social_round_trip(self):
        store = self.store
        now = "2026-10-19T12:00:00+00:00"
        challenge = {"challenge_id": "schg_1", "platform": "youtube",
                     "email_hash": "hash1", "secret": "state-1",
                     "created_at": now, "expires_at": now}
        self.assertTrue(store.add_social_challenge(challenge))
        self.assertFalse(store.add_social_challenge(challenge))
        found = store.find_social_challenge("youtube", "state-1")
        self.assertEqual(found["challenge_id"], "schg_1")
        self.assertTrue(store.consume_social_challenge("schg_1", now))
        self.assertFalse(store.consume_social_challenge("schg_1", now))
        self.assertIsNone(store.find_social_challenge("youtube",
                                                      "state-1"))
        conn = {"connection_id": "conn_1", "platform": "youtube",
                "email_hash": "hash1",
                "platform_account_id": CHANNEL_ID,
                "account_display_name": "Bayo Creates",
                "access_token": "tok", "refresh_token": "rtok",
                "token_expires_at": "", "scopes": "s",
                "status": "active", "created_at": now,
                "updated_at": now}
        self.assertTrue(store.add_social_connection(conn))
        self.assertEqual(
            store.find_social_connection("youtube", "hash1",
                                         CHANNEL_ID)["connection_id"],
            "conn_1")
        self.assertEqual(
            len(store.list_social_connections("hash1")), 1)
        self.assertTrue(store.update_social_connection(
            "conn_1", {"access_token": "tok2"}))
        self.assertEqual(store.get_social_connection("conn_1")
                         ["access_token"], "tok2")
        item = {"external_id": "vid1", "idempotency_key": "k1",
                "title": "First"}
        self.assertTrue(store.add_social_scan(
            {"scan_id": "scan_1", "connection_id": "conn_1",
             "enumerated_at": now, "item_count": 1}))
        self.assertTrue(store.add_social_scan_item("scan_1", item))
        self.assertEqual(store.list_social_scan_items("scan_1"),
                         [item])
        reg = {"email_hash": "hash1",
               "identity_key": "youtube|%s|vid1" % CHANNEL_ID,
               "idempotency_key": "k1", "record_id": "reg_1",
               "batch_id": "batch_1", "platform": "youtube",
               "created_at": now}
        self.assertTrue(store.add_social_registration(reg))
        self.assertFalse(store.add_social_registration(reg))
        store.update_social_registration(
            "hash1", reg["identity_key"], "k2", "reg_2", "batch_2")
        got = store.get_social_registration("hash1",
                                            reg["identity_key"])
        self.assertEqual(got["record_id"], "reg_2")
        self.assertEqual(len(store.list_social_registrations(
            "hash1")), 1)
        batch = {"record_id": "batch_1",
                 "registered_at": now, "detail": "receipt"}
        self.assertTrue(store.add_social_batch(batch, "conn_1"))
        self.assertEqual(store.get_social_batch("batch_1")["detail"],
                         "receipt")
        # Phase 1.5 list reads: per connection, oldest first.
        self.assertEqual(
            [s["scan_id"] for s in store.list_social_scans("conn_1")],
            ["scan_1"])
        self.assertEqual(store.list_social_scans("conn_other"), [])
        self.assertEqual(
            [b["record_id"]
             for b in store.list_social_batches("conn_1")],
            ["batch_1"])
        self.assertEqual(store.list_social_batches("conn_other"),
                         [])
        self.assertTrue(store.add_social_batch(
            {"record_id": "batch_0", "registered_at": now,
             "detail": "no connection"}, None))
        self.assertEqual(
            [b["record_id"]
             for b in store.list_social_batches("")], ["batch_0"])
        store.record_social_attempt("conn_1", "a@example.com",
                                    "203.0.113.9", True, now)
        self.assertEqual(store.count_social_attempts_since(
            "email", "a@example.com", "2026-10-19T00:00:00+00:00"), 1)
        self.assertEqual(store.count_social_attempts_since(
            "ip", "203.0.113.9", "2026-10-19T00:00:00+00:00"), 1)
        # Disconnect: tokens blanked, scans tombstoned away.
        self.assertTrue(store.disconnect_social_connection(
            "conn_1", now))
        row = store.get_social_connection("conn_1")
        self.assertEqual(row["access_token"], "")
        store.delete_social_scans("conn_1")
        self.assertIsNone(store.get_social_scan("scan_1"))
        self.assertEqual(store.list_social_scan_items("scan_1"), [])
        self.assertEqual(store.list_social_scans("conn_1"), [])
        # The receipts stand: disconnect never unmakes a record.
        self.assertEqual(
            [b["record_id"]
             for b in store.list_social_batches("conn_1")],
            ["batch_1"])


if __name__ == "__main__":
    unittest.main()
