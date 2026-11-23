"""Server-side AI-generation detection for video and music.

Mirrors npc_verify/detector.py (the Sightengine image client) in
structure, for the two media kinds the image check does not cover:

- Credentials live server-side only (SIGHTENGINE_API_USER /
  SIGHTENGINE_API_SECRET, the same pair the image detector uses).
- Transports are injectable, so tests replay recorded vendor
  response shapes with no network and no credentials.
- Failures raise DetectorError; an unconfigured server raises
  DetectorNotConfigured so endpoints answer an honest 503 instead of
  guessing. A score is never fabricated.

Vendor facts this module is built against (Sightengine official
docs, checked 2026-10-14):

- Video: POST https://api.sightengine.com/1.0/video/check-sync.json
  with models=genai analyzes a short video (< 1 minute) and returns
  per-frame scores under data.frames[].type.ai_generated, each frame
  carrying info.position in milliseconds. The async path for long
  videos is POST /1.0/video/check.json with a callback_url; results
  arrive at the callback in the same frames shape. Only the sync
  path is wired to a route today; the async submit helper and the
  callback parser are here for the long-video lane.
  https://sightengine.com/docs/ai-generated-video-detection
- Music: POST https://api.sightengine.com/1.0/audio/check.json with
  models=ai_music returns type.ai_music in [0, 1]. The vendor states
  the model works best on audio with no vocals and was trained on
  Suno / Udio / Riffusion output.
  https://sightengine.com/docs/ai-generated-music-detection

Detector contract:
- check_ai_video(video_bytes=..., interval_seconds=...) returns a
  VideoCheckResult: the per-frame probabilities plus their mean and
  peak. Aggregation policy belongs to the caller; the vendor scores
  are a signal with uncertainty, never a verdict by themselves.
- check_ai_music(audio_bytes=...) returns the ai_music probability
  as a float in [0, 1].
"""
import os

from .detector import (DetectorError, DetectorNotConfigured,
                       _urlopen_transport)

SIGHTENGINE_VIDEO_SYNC_ENDPOINT = \
    "https://api.sightengine.com/1.0/video/check-sync.json"
SIGHTENGINE_VIDEO_ASYNC_ENDPOINT = \
    "https://api.sightengine.com/1.0/video/check.json"
SIGHTENGINE_AUDIO_ENDPOINT = "https://api.sightengine.com/1.0/audio/check.json"
SIGHTENGINE_MODEL = "genai"
AUDIO_MODEL = "ai_music"
PROVIDER_NAME = "sightengine"

# Vendor-documented frame intervals for the video model (seconds).
VIDEO_INTERVALS = (0.5, 1, 2, 3, 4, 5)
DEFAULT_INTERVAL_SECONDS = 2


class VideoCheckResult:
    """Aggregated per-frame genai scores for one video."""

    def __init__(self, frame_scores, operations=None):
        # frame_scores: list of (position_ms:int, prob:float)
        self.frames = list(frame_scores)
        self.operations = operations
        probs = [p for _, p in self.frames]
        self.mean = sum(probs) / len(probs)
        self.peak = max(probs)
        self.flagged = sum(1 for p in probs if p >= 0.5)


def _parse_frames(payload):
    """Extract [(position_ms, ai_generated)] from a video response.

    Shared by the sync response and the async callback payload: both
    carry data.frames in the same shape. Raises DetectorError on any
    malformed or unsuccessful payload.
    """
    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise DetectorError("detection service returned an error")
    data = payload.get("data") or {}
    frames = data.get("frames")
    if not isinstance(frames, list) or not frames:
        raise DetectorError("detection service returned no frames")
    out = []
    for frame in frames:
        if not isinstance(frame, dict):
            raise DetectorError("detection service returned a bad frame")
        prob = (frame.get("type") or {}).get("ai_generated")
        if isinstance(prob, bool) or not isinstance(prob, (int, float)):
            raise DetectorError("detection service returned no score")
        prob = float(prob)
        if not (0.0 <= prob <= 1.0):
            raise DetectorError("detection service returned an "
                                "out-of-range score")
        pos = (frame.get("info") or {}).get("position")
        if isinstance(pos, bool) or not isinstance(pos, (int, float)):
            pos = 0
        out.append((int(pos), prob))
    operations = (payload.get("request") or {}).get("operations")
    if isinstance(operations, bool) \
            or not isinstance(operations, (int, float)):
        operations = None
    return out, operations


def parse_video_callback(payload):
    """Parse an async video-moderation callback payload.

    Returns a VideoCheckResult. Raises DetectorError when the
    callback does not carry a successful, complete result.
    """
    frames, operations = _parse_frames(payload)
    return VideoCheckResult(frames, operations=operations)


class SightengineVideoDetector:
    """Calls the Sightengine genai video model (sync path)."""

    provider = PROVIDER_NAME
    model = SIGHTENGINE_MODEL
    configured = True

    def __init__(self, api_user, api_secret, transport=None,
                 endpoint=SIGHTENGINE_VIDEO_SYNC_ENDPOINT, timeout=120):
        self._api_user = api_user
        self._api_secret = api_secret
        self._transport = transport or _urlopen_transport
        self._endpoint = endpoint
        self._timeout = timeout

    def check_ai_video(self, video_bytes=None,
                       interval_seconds=DEFAULT_INTERVAL_SECONDS):
        if not video_bytes:
            raise DetectorError("video bytes are required")
        if interval_seconds not in VIDEO_INTERVALS:
            raise DetectorError("unsupported frame interval")
        fields = {
            "models": SIGHTENGINE_MODEL,
            "api_user": self._api_user,
            "api_secret": self._api_secret,
            "interval": interval_seconds,
        }
        status, payload = self._transport(
            self._endpoint, fields, "media", "video", video_bytes,
            self._timeout)
        if status != 200:
            raise DetectorError("detection service returned an error")
        frames, operations = _parse_frames(payload)
        return VideoCheckResult(frames, operations=operations)

    def submit_ai_video_async(self, video_bytes=None, callback_url=None,
                              interval_seconds=DEFAULT_INTERVAL_SECONDS):
        """Submit a long video to the async path; returns the vendor
        request id. The result itself arrives later at callback_url
        and is parsed with parse_video_callback. Job persistence and
        the callback route are a separate lane, not wired to a route
        today."""
        if not video_bytes:
            raise DetectorError("video bytes are required")
        if not callback_url:
            raise DetectorError("callback_url is required")
        if interval_seconds not in VIDEO_INTERVALS:
            raise DetectorError("unsupported frame interval")
        fields = {
            "models": SIGHTENGINE_MODEL,
            "api_user": self._api_user,
            "api_secret": self._api_secret,
            "interval": interval_seconds,
            "callback_url": callback_url,
        }
        status, payload = self._transport(
            SIGHTENGINE_VIDEO_ASYNC_ENDPOINT, fields, "media", "video",
            video_bytes, self._timeout)
        if status != 200 or not isinstance(payload, dict) \
                or payload.get("status") != "success":
            raise DetectorError("detection service returned an error")
        request_id = (payload.get("request") or {}).get("id")
        if not request_id:
            raise DetectorError("detection service returned no "
                                "request id")
        return request_id


class SightengineAudioDetector:
    """Calls the Sightengine ai_music model."""

    provider = PROVIDER_NAME
    model = AUDIO_MODEL
    configured = True

    def __init__(self, api_user, api_secret, transport=None,
                 endpoint=SIGHTENGINE_AUDIO_ENDPOINT, timeout=120):
        self._api_user = api_user
        self._api_secret = api_secret
        self._transport = transport or _urlopen_transport
        self._endpoint = endpoint
        self._timeout = timeout

    def check_ai_music(self, audio_bytes=None):
        if not audio_bytes:
            raise DetectorError("audio bytes are required")
        fields = {
            "models": AUDIO_MODEL,
            "api_user": self._api_user,
            "api_secret": self._api_secret,
        }
        status, payload = self._transport(
            self._endpoint, fields, "audio", "audio", audio_bytes,
            self._timeout)
        if status != 200 or not isinstance(payload, dict) \
                or payload.get("status") != "success":
            raise DetectorError("detection service returned an error")
        prob = (payload.get("type") or {}).get("ai_music")
        if isinstance(prob, bool) or not isinstance(prob, (int, float)):
            raise DetectorError("detection service returned no score")
        prob = float(prob)
        if not (0.0 <= prob <= 1.0):
            raise DetectorError("detection service returned an "
                                "out-of-range score")
        return prob


class UnconfiguredVideoDetector:
    provider = PROVIDER_NAME
    model = SIGHTENGINE_MODEL
    configured = False

    def check_ai_video(self, video_bytes=None,
                       interval_seconds=DEFAULT_INTERVAL_SECONDS):
        raise DetectorNotConfigured("detection is not configured")

    def submit_ai_video_async(self, video_bytes=None, callback_url=None,
                              interval_seconds=DEFAULT_INTERVAL_SECONDS):
        raise DetectorNotConfigured("detection is not configured")


class UnconfiguredAudioDetector:
    provider = PROVIDER_NAME
    model = AUDIO_MODEL
    configured = False

    def check_ai_music(self, audio_bytes=None):
        raise DetectorNotConfigured("detection is not configured")


def av_detectors_from_env(env=None):
    """Build (video_detector, audio_detector) from the same env vars
    the image detector uses. Missing either value yields the
    unconfigured stand-ins, so endpoints answer honestly."""
    env = os.environ if env is None else env
    user = env.get("SIGHTENGINE_API_USER")
    secret = env.get("SIGHTENGINE_API_SECRET")
    if user and secret:
        return (SightengineVideoDetector(user, secret),
                SightengineAudioDetector(user, secret))
    return (UnconfiguredVideoDetector(), UnconfiguredAudioDetector())
