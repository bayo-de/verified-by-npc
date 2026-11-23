"""Staged media uploads (v6.11): one staging path for oversized media.

API requests are small JSON messages, so a video (cap 50 MB), an
audio file (cap 25 MB), or an image above the 750 KB inline cap
cannot ride inside a check request. Instead the client asks the
API for an upload slot (POST /v1/account/uploads), PUTs the file
to a private staging bucket through a short-lived presigned URL,
and then runs the account check with the upload id. The API reads
the staged bytes itself (no public URL is ever minted for staged
media, so this lane adds no SSRF surface), hashes and checks them
exactly like fetched media, and deletes the object when the check
attempt completes.

This module is the staging store seam, in the shape of the other
server seams (detector, media fetcher, mailer):

- S3StagingStore is the production store. boto3 is imported
  lazily, only when the store is constructed, so the package
  imports cleanly where boto3 is absent (the same discipline as
  ddb_store and mailer). The presigned PUT is bound to the object
  key, the content type, and the declared content length, and
  expires in PRESIGN_EXPIRES_SECONDS.
- MemoryStagingStore is the test and simulation store: the same
  interface over a dict. Its "presigned URL" is a memory:// URL
  that nothing can PUT to over HTTP; tests place bytes with
  put_bytes, which is exactly the state a completed S3 PUT leaves
  behind.
- staging_from_env builds the S3 store when NPC_STAGING_BUCKET is
  set and returns None otherwise, so an API without a bucket
  answers the uploads route honestly (503) instead of pretending.

Upload metadata (which account, which media kind, the declared
size, the claim state) does NOT live here: it lives in the API
store (account_uploads in npc_verify.store / npc_verify.ddb_store),
beside the account check history, so it survives execution
environment recycles. This module only moves bytes.
"""
import os

PRESIGN_EXPIRES_SECONDS = 900  # 15 minutes to complete the PUT
UPLOAD_TTL_HOURS = 24          # records (and, by lifecycle, objects)

# Media kinds and their byte caps. Video and audio reuse the URL
# lane's caps from npc_verify.server (kept here to avoid an import
# cycle; server asserts they agree). The image cap is new: the
# 750 KB inline cap is a transport cap (the 1 MiB JSON body), not a
# detector cap, and 10 MB covers ordinary phone photos while
# staying small enough to hold in memory and hand to the vendor in
# one request. It is a conservative operational cap of ours, not a
# vendor figure.
MEDIA_CAPS = {
    "video": 50 * 1000 * 1000,
    "audio": 25 * 1000 * 1000,
    "image": 10 * 1000 * 1000,
}

# The content type is derived from the filename extension, per
# kind, from this allowlist only: a client cannot invent a type,
# and the presigned PUT is signed for exactly this type.
CONTENT_TYPES = {
    "video": {
        "mp4": "video/mp4",
        "mov": "video/quicktime",
        "webm": "video/webm",
        "m4v": "video/x-m4v",
    },
    "audio": {
        "mp3": "audio/mpeg",
        "wav": "audio/wav",
        "m4a": "audio/mp4",
        "ogg": "audio/ogg",
        "flac": "audio/flac",
    },
    "image": {
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "webp": "image/webp",
        "gif": "image/gif",
        "bmp": "image/bmp",
    },
}


class StagingError(Exception):
    """The staging store could not complete an operation."""


def content_type_for(media_type, filename):
    """The allowlisted content type for (kind, filename), or None."""
    if not isinstance(filename, str) or "." not in filename:
        return None
    ext = filename.rsplit(".", 1)[1].strip().lower()
    return CONTENT_TYPES.get(media_type, {}).get(ext)


def object_key(account_id, upload_id):
    """The one key an upload may occupy: per-account namespace."""
    return "staging/%s/%s" % (account_id, upload_id)


class MemoryStagingStore:
    """In-memory staging store for tests and the bundle simulation.

    put_bytes stands in for the client's presigned PUT: after it,
    the store is in exactly the state the check lane reads.
    """

    def __init__(self):
        self.objects = {}

    def presign_put(self, key, content_type, size_bytes):
        return "memory://npc-staging/" + key

    def put_bytes(self, key, data):
        self.objects[key] = bytes(data)

    def get_bytes(self, key):
        try:
            return self.objects[key]
        except KeyError:
            raise StagingError("staged object is missing")

    def delete(self, key):
        self.objects.pop(key, None)


class S3StagingStore:
    """Staging store over one private S3 bucket (boto3, lazy)."""

    def __init__(self, bucket, client=None):
        self.bucket = bucket
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("s3")
        return self._client

    def presign_put(self, key, content_type, size_bytes):
        try:
            return self.client.generate_presigned_url(
                "put_object",
                Params={"Bucket": self.bucket, "Key": key,
                        "ContentType": content_type,
                        "ContentLength": int(size_bytes)},
                ExpiresIn=PRESIGN_EXPIRES_SECONDS)
        except Exception as exc:
            raise StagingError("could not sign the upload: %s" % exc)

    def get_bytes(self, key):
        try:
            resp = self.client.get_object(Bucket=self.bucket, Key=key)
            return resp["Body"].read()
        except Exception as exc:
            raise StagingError("staged object could not be read: %s"
                               % exc)

    def delete(self, key):
        # Deletion is best-effort by contract: the bucket lifecycle
        # rule (1 day on staging/) is the backstop, so a failed
        # delete must never fail the check that already completed.
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
        except Exception:
            pass


def staging_from_env(env=None):
    """The staging store from NPC_STAGING_BUCKET, or None.

    None means uploads are not configured on this API: the uploads
    route answers 503 and staged checks cannot resolve, honestly,
    the way an unconfigured detector answers 503.
    """
    env = os.environ if env is None else env
    bucket = env.get("NPC_STAGING_BUCKET")
    if bucket:
        return S3StagingStore(bucket)
    return None
