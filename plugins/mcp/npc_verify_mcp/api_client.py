"""Thin client over the NPC Verification API v1.

Every response is Ed25519 signature-verified against the API's published
keys (``GET /v1/keys``) before it is returned. Any verification failure is
fail-closed: the caller gets an error, never the unverified data.

The signing primitives are REUSED from the API reference implementation
(``npc_verify.canonical`` / ``npc_verify.ed25519``). When the API tree
is not present (a standalone PyPI install), byte-identical vendored
copies under ``npc_verify_mcp._vendor`` are used instead; the test
suite asserts the copies never drift. The API package is located via
``NPC_VERIFY_API_PATH`` or by resolving ``../api`` relative to this
package's install location.
"""
import base64
import http.client
import json
import os
import sys
import urllib.parse


def _ensure_api_package():
    """Make the npc_verify API package importable. Returns its base dir."""
    try:
        import npc_verify  # noqa: F401
        import npc_verify.canonical  # noqa: F401
        import npc_verify.ed25519  # noqa: F401
        return os.path.dirname(npc_verify.__file__)
    except ImportError:
        pass
    override = os.environ.get("NPC_VERIFY_API_PATH")
    candidates = []
    if override:
        candidates.append(override)
    here = os.path.dirname(os.path.abspath(__file__))
    # <program>/plugins/mcp/npc_verify_mcp -> <program>/api
    candidates.append(os.path.normpath(
        os.path.join(here, "..", "..", "..", "api")))
    for cand in candidates:
        init = os.path.join(cand, "npc_verify", "__init__.py")
        if os.path.isfile(init) and cand not in sys.path:
            sys.path.insert(0, cand)
            import npc_verify  # noqa: F401
            return cand
    raise RuntimeError(
        "npc_verify API package not found. Set NPC_VERIFY_API_PATH to the "
        "directory containing the api/ tree (the one holding npc_verify/).")


def _load_primitives():
    """Return (canonicalize, ed25519 module).

    Prefers the API reference implementation itself; falls back to the
    vendored copies so a standalone install (no repo checkout) works.
    """
    try:
        _ensure_api_package()
        from npc_verify.canonical import canonicalize
        from npc_verify import ed25519
        return canonicalize, ed25519
    except Exception:
        from ._vendor import canonical as _vc
        from ._vendor import ed25519 as _ve
        return _vc.canonicalize, _ve


canonicalize, ed25519 = _load_primitives()


class ApiError(Exception):
    """Raised when the API call cannot be completed or trusted."""


class UnknownSubject(Exception):
    """The API has no record of the subject. Fail-closed: unknown, not false."""

    def __init__(self, payload):
        super().__init__("unknown")
        self.payload = payload


#: Public production API. Local development overrides via
#: NPC_VERIFY_API_URL (e.g. http://127.0.0.1:8787).
DEFAULT_API_URL = "https://api.npclabs.xyz"

#: Public read-only verifier key bundled with the client: the same demo
#: verifier key the Chrome extension ships
#: (plugins/chrome-extension/config.js). Verifier role only: it can read
#: records and verify claims; it cannot issue or administer. Developers
#: override with NPC_VERIFY_API_KEY.
DEFAULT_API_KEY = "npc_demo_HNL8-qoMjLTVvDCYog1scIZm4JgrganOI2RRFoTFI-E"


def _config():
    url = os.environ.get("NPC_VERIFY_API_URL", DEFAULT_API_URL).rstrip("/")
    key = os.environ.get("NPC_VERIFY_API_KEY", "") or DEFAULT_API_KEY
    return url, key


def _split(url):
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme or "https"
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, parts.hostname or "api.npclabs.xyz", port, parts.path or ""


class VerifiedClient:
    """HTTP client for API v1 with mandatory response-signature verification."""

    def __init__(self, base_url=None, api_key=None, timeout=10):
        env_url, env_key = _config()
        self.base_url = (base_url or env_url).rstrip("/")
        self.api_key = api_key if api_key is not None else env_key
        self.timeout = timeout
        self._keys_doc = None

    # -- seam for tests -------------------------------------------------
    def _http(self, method, path, body_bytes=None, extra_headers=None):
        scheme, host, port, prefix = _split(self.base_url)
        conn_cls = (http.client.HTTPSConnection if scheme == "https"
                    else http.client.HTTPConnection)
        conn = conn_cls(host, port, timeout=self.timeout)
        headers = dict(extra_headers or {})
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        conn.request(method, prefix + path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        headers_out = dict(resp.getheaders())
        status = resp.status
        conn.close()
        return status, headers_out, data

    # -- key management --------------------------------------------------
    def _signing_keys(self):
        """Fetch GET /v1/keys (unsigned bootstrap, TOFU on first connect)."""
        if self._keys_doc is None:
            try:
                status, _, data = self._http("GET", "/v1/keys")
            except OSError as exc:
                raise ApiError(f"NPC Verification API unreachable at "
                               f"{self.base_url}: {exc}") from exc
            if status != 200:
                raise ApiError(f"GET /v1/keys returned {status}")
            self._keys_doc = json.loads(data)
        return self._keys_doc

    def _public_key_for(self, key_id):
        doc = self._signing_keys()
        cur = doc["api_signing"]["current"]
        if cur and cur["key_id"] == key_id:
            return base64.b64decode(cur["public_key"])
        for hist in doc["api_signing"].get("history", []):
            if hist["key_id"] == key_id:
                return base64.b64decode(hist["public_key"])
        return None

    def _verify_response(self, status, headers, body_bytes):
        """Verify X-NPC-Signature. Returns parsed JSON. Raises on failure."""
        lowered = {k.lower(): v for k, v in headers.items()}
        sig_b64 = lowered.get("x-npc-signature")
        key_id = lowered.get("x-npc-key-id")
        if not sig_b64 or not key_id:
            raise ApiError("response missing X-NPC-Signature/X-NPC-Key-ID — "
                           "refusing to trust it")
        pub = self._public_key_for(key_id)
        if pub is None:
            raise ApiError(f"signing key {key_id!r} is not published by the "
                           f"API — refusing to trust the response")
        try:
            parsed = json.loads(body_bytes)
        except ValueError as exc:
            raise ApiError("response body is not valid JSON") from exc
        if canonicalize(parsed) != body_bytes:
            raise ApiError("response body is not canonical JSON — refusing "
                           "to trust it")
        try:
            sig = base64.b64decode(sig_b64)
        except ValueError as exc:
            raise ApiError("X-NPC-Signature is not valid base64") from exc
        if not ed25519.verify(pub, body_bytes, sig):
            raise ApiError("response signature verification FAILED — the "
                           "response may have been tampered with")
        return parsed

    # -- request ---------------------------------------------------------
    def request(self, method, path, body=None, auth=True):
        """Signed, verified API call. Returns parsed JSON.

        Raises UnknownSubject on 404 (fail-closed: unknown, never a guess),
        ApiError on transport, auth, rate-limit, or signature problems.
        """
        if auth and not self.api_key:
            raise ApiError("NPC_VERIFY_API_KEY is not set — cannot call "
                           "authenticated endpoints")
        payload = None
        headers = {}
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            status, resp_headers, data = self._http(
                method, path, body_bytes=payload, extra_headers=headers)
        except OSError as exc:
            raise ApiError(
                f"NPC Verification API unreachable at "
                f"{self.base_url}: {exc}") from exc
        if status == 404:
            # 404s are signed too — verify before trusting the unknown shape.
            parsed = self._verify_response(status, resp_headers, data)
            raise UnknownSubject(parsed)
        if status == 401:
            raise ApiError("API key rejected (401) — check NPC_VERIFY_API_KEY")
        if status == 403:
            raise ApiError("API key lacks the required role (403)")
        if status == 429:
            # The 429 body is signed like every other response; its
            # retry guidance is only trusted after verification.
            parsed = self._verify_response(status, resp_headers, data)
            retry = parsed.get("retry_after_seconds")
            if isinstance(retry, int) and not isinstance(retry, bool):
                raise ApiError(
                    "API rate limit hit (429) — slow down and retry "
                    f"after {retry} seconds")
            raise ApiError("API rate limit hit (429) — slow down and retry")
        if status >= 400:
            # Surface the API's own rejection detail (the validation
            # problems on a 422, a conflict on a 409) so the caller can
            # fix its request — but only from the signature-verified
            # body, never from an untrusted one.
            parsed = self._verify_response(status, resp_headers, data)
            detail = parsed.get("detail")
            if isinstance(detail, str) and detail:
                raise ApiError(f"API returned {status}: {detail}")
            raise ApiError(f"API returned {status}")
        return self._verify_response(status, resp_headers, data)

    # -- thin tool calls (no logic lives here) ---------------------------
    def verify_claim(self, claim_text=None, claim_hash=None):
        body = {}
        if claim_text:
            body["claim_text"] = claim_text
        if claim_hash:
            body["claim_hash"] = claim_hash
        return self.request("POST", "/v1/claims/verify", body=body)

    def verify_credential(self, credential_id):
        return self.request("GET", f"/v1/credentials/{credential_id}")

    def verify_product(self, tag_id):
        return self.request("GET", f"/v1/products/{tag_id}")

    def verify_agent(self, agent_id):
        return self.request("GET", f"/v1/agents/{agent_id}/attestation")

    # -- registration (public endpoints; no API key required) ------------
    # Registration is how verification starts: these endpoints are
    # deliberately unauthenticated on the API (registration is free
    # and open; the abuse minimums are the required email and the
    # per-email / per-IP submission caps the API counts itself). They
    # are called with auth=False so they work with no key configured;
    # when a key IS configured it is still sent, and the API ignores
    # it on these routes. Registration is NOT verification: the record
    # returned states "registered, checks pending" and carries no
    # verdict and no verification mark.
    def register_agent(self, agent_name, owner_name, owner_email,
                       homepage=None, description=None):
        body = {"agent_name": agent_name, "owner_name": owner_name,
                "owner_email": owner_email}
        if homepage:
            body["homepage"] = homepage
        if description:
            body["description"] = description
        return self.request("POST", "/v1/register/agent", body=body,
                            auth=False)

    def register_content(self, title, kind, locator, creator_name,
                         creator_email):
        body = {"title": title, "kind": kind, "locator": locator,
                "creator_name": creator_name,
                "creator_email": creator_email}
        return self.request("POST", "/v1/register/content", body=body,
                            auth=False)

    def health(self):
        return self.request("GET", "/v1/health", auth=False)
