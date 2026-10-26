"""Server-side AI-generation detection (Sightengine genai).

The NPC Verify extension never holds detection-service credentials and
never calls the provider directly: credentials in shipped client code
are extractable by anyone. Instead the extension asks this API, and
this module calls Sightengine from the server side with credentials
read from the environment (SIGHTENGINE_API_USER /
SIGHTENGINE_API_SECRET). The result travels back inside the API's
normal signed response envelope, so the extension's signature check
covers it unchanged.

Detector contract: check_ai(image_bytes=..., image_url=...) returns
the provider's ai_generated probability as a float in [0, 1]. Exactly
one of image_bytes / image_url is given. Failures raise DetectorError;
a server with no credentials configured reports configured = False
and raises DetectorNotConfigured, so the endpoint can answer honestly
instead of guessing.
"""
import json
import os
import urllib.request
import uuid

SIGHTENGINE_ENDPOINT = "https://api.sightengine.com/1.0/check.json"
SIGHTENGINE_MODEL = "genai"
PROVIDER_NAME = "sightengine"
MODEL_NAME = "genai"


class DetectorError(Exception):
    """The detection service could not complete the check."""


class DetectorNotConfigured(DetectorError):
    """No detection credentials are configured on this server."""


def _multipart_body(fields, file_field, filename, file_bytes):
    """Build a multipart/form-data body. Returns (bytes, content_type)."""
    boundary = "npc" + uuid.uuid4().hex
    out = []
    for name, value in fields.items():
        out.append(f"--{boundary}\r\n".encode())
        out.append(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        out.append(str(value).encode() + b"\r\n")
    if file_bytes is not None:
        out.append(f"--{boundary}\r\n".encode())
        out.append(
            (f'Content-Disposition: form-data; name="{file_field}"; '
             f'filename="{filename}"\r\n').encode())
        out.append(b"Content-Type: application/octet-stream\r\n\r\n")
        out.append(file_bytes + b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


def _urlopen_transport(endpoint, fields, file_field, filename, file_bytes,
                       timeout):
    """Default transport: one HTTPS POST. Returns (status, parsed_json).

    Only parsed JSON comes back; anything else raises DetectorError.
    """
    body, content_type = _multipart_body(fields, file_field, filename,
                                         file_bytes)
    req = urllib.request.Request(endpoint, data=body, method="POST")
    req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        # Sightengine answers errors as JSON too; read what it sent.
        try:
            raw = exc.read()
        except Exception:
            raise DetectorError("detection service returned an error")
        status = exc.code
    except Exception:
        raise DetectorError("detection service could not be reached")
    try:
        return status, json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise DetectorError("detection service returned an unreadable "
                            "response")


class SightengineDetector:
    """Calls the Sightengine genai model with server-side credentials."""

    provider = PROVIDER_NAME
    model = MODEL_NAME
    configured = True

    def __init__(self, api_user, api_secret, transport=None,
                 endpoint=SIGHTENGINE_ENDPOINT, timeout=20):
        self._api_user = api_user
        self._api_secret = api_secret
        self._transport = transport or _urlopen_transport
        self._endpoint = endpoint
        self._timeout = timeout

    def check_ai(self, image_bytes=None, image_url=None):
        if (image_bytes is None) == (image_url is None):
            raise DetectorError("exactly one image source is required")
        fields = {
            "models": SIGHTENGINE_MODEL,
            "api_user": self._api_user,
            "api_secret": self._api_secret,
        }
        file_bytes = None
        filename = "image"
        if image_url is not None:
            fields["url"] = image_url
        else:
            file_bytes = image_bytes
        status, payload = self._transport(
            self._endpoint, fields, "media", filename, file_bytes,
            self._timeout)
        if status != 200 or not isinstance(payload, dict) \
                or payload.get("status") != "success":
            raise DetectorError("detection service returned an error")
        prob = (payload.get("type") or {}).get("ai_generated")
        if isinstance(prob, bool) or not isinstance(prob, (int, float)):
            raise DetectorError("detection service returned no score")
        prob = float(prob)
        if not (0.0 <= prob <= 1.0):
            raise DetectorError("detection service returned an "
                                "out-of-range score")
        return prob


class UnconfiguredDetector:
    """Stand-in when no credentials are configured: never guesses."""

    provider = PROVIDER_NAME
    model = MODEL_NAME
    configured = False

    def check_ai(self, image_bytes=None, image_url=None):
        raise DetectorNotConfigured("detection is not configured")


def detector_from_env(env=None):
    """Build the detector from SIGHTENGINE_API_USER / _SECRET.

    Missing either value yields an UnconfiguredDetector, so the API
    runs (and answers honestly) with detection switched off.
    """
    env = os.environ if env is None else env
    user = env.get("SIGHTENGINE_API_USER")
    secret = env.get("SIGHTENGINE_API_SECRET")
    if user and secret:
        return SightengineDetector(user, secret)
    return UnconfiguredDetector()
