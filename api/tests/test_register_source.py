"""Integration source provenance tests (the `source` object).

POST /v1/register/content may carry an optional `source` object when
a registration arrives through a platform account the customer
connected (the integrations batch lane, integrations/DESIGN.md). The
source is provenance, not a verdict: it records which platform listed
the work and what the platform said about it. These tests pin the
contract:

- a valid source is normalized (known fields only) and signed into
  the record, which still verifies offline;
- the generic URL fetch does NOT run for a source registration (a
  platform permalink is a human page, not the work's bytes), and the
  byte fetch is honestly listed as not run;
- a record without a source has no `source` key at all, exactly the
  records this API has always minted;
- malformed sources fail validation with 422.
"""
import hashlib
import json
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import pact, registry  # noqa: E402
from tests.helpers import ApiTestCase  # noqa: E402

YOUTUBE_SOURCE = {
    "platform": "youtube",
    "external_id": "dQw4w9WgXcQ11",
    "permalink": "https://www.youtube.com/watch?v=dQw4w9WgXcQ11",
    "byte_class": "metadata_only",
    "account_display_name": "Harbor Lights Channel",
    "native_type": "video",
    "published_at": "2026-09-01T12:00:00+00:00",
    "metadata_hash": hashlib.sha256(b"fixture").hexdigest(),
}

BOX_SOURCE = {
    "platform": "box",
    "external_id": "987654321",
    "permalink": "https://app.box.com/file/987654321",
    "byte_class": "metadata_only",
    "native_type": "audio/vnd.wav",
    "platform_checksum": {
        "algorithm": "sha1",
        "value": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    },
    "version_marker": {"kind": "box_file_version", "value": "112233"},
}


def _checks(rec, name, bucket="checks_run"):
    return [c for c in rec[bucket] if c["check"] == name]


class SourceRegistrationTests(ApiTestCase):

    def register_with_source(self, source, email, kind="video",
                             title="Harbor lights, take two"):
        locator = source.get("permalink") if isinstance(source, dict) \
            else None
        body = {
            "title": title,
            "kind": kind,
            "locator": locator or "https://www.youtube.com/watch?v=x",
            "creator_name": "Test Maker",
            "creator_email": email,
            "source": source,
        }
        return self.post("/v1/register/content", body=body)

    def test_source_record_is_signed_and_normalized(self):
        source = dict(YOUTUBE_SOURCE)
        source["unexpected_field"] = "must not survive"
        status, headers, data = self.register_with_source(
            source, "yt-source@example.com")
        self.assertEqual(status, 201)
        rec = self.check_signature(headers, data)
        self.assertEqual(rec["status"], "registered_checks_pending")
        self.assertNotIn("verdict", rec)
        self.assertTrue(pact.verify_record(self.app.keys, rec))
        kept = rec["source"]
        self.assertEqual(kept["platform"], "youtube")
        self.assertEqual(kept["external_id"], "dQw4w9WgXcQ11")
        self.assertEqual(kept["byte_class"], "metadata_only")
        self.assertEqual(kept["metadata_hash"],
                         YOUTUBE_SOURCE["metadata_hash"])
        self.assertNotIn("unexpected_field", kept)

    def test_source_registration_does_not_fetch_the_permalink(self):
        status, _, data = self.register_with_source(
            dict(YOUTUBE_SOURCE), "yt-nofetch@example.com")
        self.assertEqual(status, 201)
        rec = json.loads(data)
        observed = _checks(rec, "platform_metadata")
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["status"], "observed")
        self.assertEqual(observed[0]["platform"], "youtube")
        # the permalink was never fetched: no content_fetch result,
        # and the byte fetch is honestly listed as not run
        self.assertEqual(_checks(rec, "content_fetch"), [])
        pending = _checks(rec, "content_fetch", "checks_not_run")
        self.assertEqual(len(pending), 1)
        self.assertIn("verification_decision",
                      {c["check"] for c in rec["checks_not_run"]})

    def test_platform_checksum_is_labeled_platform_supplied(self):
        status, _, data = self.register_with_source(
            dict(BOX_SOURCE), "box-source@example.com", kind="audio",
            title="Final mix, version three")
        self.assertEqual(status, 201)
        rec = json.loads(data)
        entries = _checks(rec, "platform_checksum")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "provided_by_platform")
        self.assertEqual(entries[0]["algorithm"], "sha1")
        self.assertEqual(rec["source"]["platform_checksum"]["value"],
                         BOX_SOURCE["platform_checksum"]["value"])
        self.assertEqual(
            rec["source"]["version_marker"],
            {"kind": "box_file_version", "value": "112233"})

    def test_record_without_source_has_no_source_key(self):
        body = {
            "title": "A plain registration",
            "kind": "text",
            "locator": "sha256:" + "ab" * 32,
            "creator_name": "Test Maker",
            "creator_email": "plain@example.com",
        }
        status, _, data = self.post("/v1/register/content", body=body)
        self.assertEqual(status, 201)
        rec = json.loads(data)
        self.assertNotIn("source", rec)
        self.assertTrue(pact.verify_record(self.app.keys, rec))

    def test_source_record_resolves_by_id(self):
        status, _, data = self.register_with_source(
            dict(YOUTUBE_SOURCE), "yt-resolve@example.com")
        self.assertEqual(status, 201)
        rec = json.loads(data)
        status, _, data = self.get("/v1/records/" + rec["record_id"])
        self.assertEqual(status, 200)
        got = json.loads(data)
        self.assertEqual(got["source"]["external_id"],
                         "dQw4w9WgXcQ11")

    def test_invalid_sources_are_422(self):
        bad_sources = [
            "not-an-object",
            dict(YOUTUBE_SOURCE, platform="myspace"),
            {k: v for k, v in YOUTUBE_SOURCE.items()
             if k != "external_id"},
            dict(YOUTUBE_SOURCE, byte_class="sometimes"),
            dict(YOUTUBE_SOURCE, permalink="ftp://example.com/x"),
            dict(YOUTUBE_SOURCE, metadata_hash="ABCD"),
            dict(YOUTUBE_SOURCE, published_at="last Tuesday"),
            dict(YOUTUBE_SOURCE,
                 platform_checksum={"algorithm": "sha512",
                                    "value": "aa"}),
            dict(YOUTUBE_SOURCE, version_marker={"kind": "etag"}),
            dict(YOUTUBE_SOURCE, previous_record_id="cred_123"),
        ]
        for i, source in enumerate(bad_sources):
            status, _, data = self.register_with_source(
                source, "bad-source-%d@example.com" % i)
            self.assertEqual(status, 422, data)


class SourceValidationUnitTests(unittest.TestCase):
    """Direct checks on the registry helpers (no HTTP)."""

    def test_validate_source_accepts_minimal(self):
        problems = registry.validate_source({
            "platform": "box",
            "external_id": "1",
            "permalink": "https://app.box.com/file/1",
            "byte_class": "metadata_only",
        })
        self.assertEqual(problems, [])

    def test_normalize_source_drops_unknown_and_trims(self):
        out = registry.normalize_source({
            "platform": "box",
            "external_id": " 42 ",
            "permalink": "https://app.box.com/file/42",
            "byte_class": "metadata_only",
            "account_display_name": "  ",
            "surprise": True,
        })
        self.assertEqual(out["external_id"], "42")
        self.assertNotIn("account_display_name", out)
        self.assertNotIn("surprise", out)

    def test_normalize_source_rejects_unusable(self):
        self.assertIsNone(registry.normalize_source(None))
        self.assertIsNone(registry.normalize_source("nope"))
        self.assertIsNone(registry.normalize_source({
            "platform": "myspace",
            "external_id": "1",
            "permalink": "https://example.com/1",
            "byte_class": "metadata_only",
        }))


if __name__ == "__main__":
    unittest.main()
