"""Media probe (v5.5 workstream 2): container facts read from the
file bytes alone. Fixtures are tiny ffmpeg-generated files (and the
C2PA-signed MP4 from the validation suite). The probe never decodes
frames; it parses headers, so every expectation here is a header
fact the fixture bytes carry.
"""
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import media_probe  # noqa: E402

FIXTURES = os.path.join(BASE, "tests", "fixtures")


def _fixture(name):
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


class ProbeVideoTest(unittest.TestCase):
    def test_mp4_video_facts(self):
        entry = media_probe.probe_media(_fixture("plain.mp4"), "video")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["check"], "media_probe")
        self.assertEqual(entry["container"], "mp4")
        self.assertEqual(entry["duration_ms"], 1000)
        self.assertEqual(entry["video_codec"], "H.264")
        self.assertEqual(entry["width"], 64)
        self.assertEqual(entry["height"], 48)
        self.assertEqual(entry["audio_codec"], "AAC")
        self.assertEqual(entry["audio_channels"], 1)
        self.assertEqual(entry["audio_sample_rate"], 44100)
        self.assertEqual(entry["detected_kind"], "video")
        self.assertTrue(entry["kind_match"])

    def test_signed_mp4_probes_the_same(self):
        entry = media_probe.probe_media(
            _fixture("signed-es256.mp4"), "video")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["duration_ms"], 1000)
        self.assertEqual(entry["video_codec"], "H.264")


class ProbeAudioTest(unittest.TestCase):
    def test_wav_facts(self):
        entry = media_probe.probe_media(_fixture("tone.wav"), "audio")
        self.assertEqual(entry["container"], "wav")
        self.assertEqual(entry["format"], "PCM")
        self.assertEqual(entry["channels"], 1)
        self.assertEqual(entry["sample_rate"], 44100)
        self.assertEqual(entry["duration_ms"], 2000)
        self.assertTrue(entry["kind_match"])

    def test_mp3_facts(self):
        entry = media_probe.probe_media(_fixture("tone.mp3"), "audio")
        self.assertEqual(entry["container"], "mp3")
        self.assertEqual(entry["codec"], "MP3")
        self.assertEqual(entry["sample_rate"], 44100)
        self.assertEqual(entry["channels"], 1)
        self.assertTrue(entry["kind_match"])

    def test_flac_facts(self):
        entry = media_probe.probe_media(_fixture("tone.flac"), "audio")
        self.assertEqual(entry["container"], "flac")
        self.assertEqual(entry["channels"], 1)
        self.assertEqual(entry["sample_rate"], 44100)
        self.assertEqual(entry["duration_ms"], 2000)

    def test_ogg_vorbis_facts(self):
        entry = media_probe.probe_media(_fixture("tone.ogg"), "audio")
        self.assertEqual(entry["container"], "ogg")
        self.assertEqual(entry["codec"], "Vorbis")
        self.assertEqual(entry["channels"], 1)
        self.assertEqual(entry["sample_rate"], 44100)

    def test_m4a_facts(self):
        entry = media_probe.probe_media(_fixture("tone.m4a"), "audio")
        self.assertEqual(entry["container"], "mp4")
        self.assertEqual(entry["brand"], "M4A")
        self.assertEqual(entry["audio_codec"], "AAC")
        self.assertEqual(entry["channels"], 1)
        self.assertEqual(entry["sample_rate"], 44100)
        self.assertEqual(entry["duration_ms"], 2000)


class ProbeHonestyTest(unittest.TestCase):
    def test_wrong_kind_bytes_return_none(self):
        # JPEG bytes are not a media container the probe knows, for
        # either declared kind: the probe must not invent a result.
        self.assertIsNone(
            media_probe.probe_media(_fixture("plain.jpg"), "video"))
        self.assertIsNone(
            media_probe.probe_media(_fixture("plain.jpg"), "audio"))

    def test_corrupt_and_garbage_return_none(self):
        self.assertIsNone(media_probe.probe_media(
            b"\x00\x00\x00\x18ftypisom" + b"\xff" * 10, "video"))
        self.assertIsNone(
            media_probe.probe_media(b"garbage bytes", "audio"))
        self.assertIsNone(media_probe.probe_media(b"", "audio"))

    def test_truncated_mp4_returns_none(self):
        data = _fixture("plain.mp4")
        self.assertIsNone(media_probe.probe_media(data[:60], "video"))


if __name__ == "__main__":
    unittest.main()
