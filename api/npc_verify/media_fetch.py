"""SSRF-guarded media fetcher for the AV check routes.

The video and audio check endpoints take a media URL (the API's
JSON body cap rules out inline media at these sizes, and the
vendor's video and audio endpoints take file uploads), so the
server fetches the media itself and forwards the bytes. A
server-side fetch of a caller-supplied URL is an SSRF surface, so
this fetcher is stricter than the registration intake fetcher in
registry.py:

- Only http(s) URLs, and the host must pass the same literal checks
  the intake guard applies (registry._url_fetch_permitted: no
  localhost names, no private / loopback / link-local / multicast /
  reserved / unspecified IP literals, including the legacy
  inet_aton forms).
- On top of that, the hostname is resolved here and EVERY resolved
  address must be public. The intake guard deliberately does not
  resolve names; this one does, because the fetched bytes leave for
  a vendor and the route answers to any verifier key.
- Redirects are followed manually through the same two checks at
  every hop; a refused hop ends the fetch.
- The body is read in chunks under a hard byte cap; oversize,
  empty, and any transport failure raise FetchError with a
  caller-safe message. Nothing is returned partially.

Residual, stated plainly: the connection itself is opened by
urllib against the hostname, so a DNS answer that changes between
this module's resolution check and the connect (rebinding) is not
fully excluded by stdlib means. The layered checks above (literal
screen, resolved-address screen, per-hop revalidation) are the
defense this lane ships with; the fetch runs in the API's Lambda,
which holds no VPC-internal targets.

Tests inject a fake resolver and a fake opener; production uses
socket.getaddrinfo and urllib.
"""
import ipaddress
import socket
import urllib.parse
import urllib.request

from . import registry as _registry

FETCH_TIMEOUT = 60
MAX_REDIRECTS = 3
_CHUNK = 65536


class FetchError(Exception):
    """The media URL could not be fetched within the caps."""


def _ip_is_public(ip, allow_loopback=False):
    if ip.is_loopback:
        return allow_loopback
    return not (ip.is_private or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)


def _default_resolver(host):
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return out


def host_permitted(hostname, resolver=None, allow_loopback=False):
    """True when a fetch (or a redirect hop) may connect to hostname:
    the registry literal screen plus a resolution screen."""
    if not hostname:
        return False
    host = hostname.strip().lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return False
    literal = _registry._ip_literal(host)
    if literal is not None:
        return _ip_is_public(literal, allow_loopback=allow_loopback)
    resolve = resolver or _default_resolver
    try:
        ips = resolve(host)
    except Exception:
        return False
    if not ips:
        return False
    return all(_ip_is_public(ip, allow_loopback=allow_loopback)
               for ip in ips)


def url_permitted(url, resolver=None, allow_loopback=False):
    """Full per-URL screen: scheme + registry literal guard + the
    resolution screen above."""
    if not _registry._url_fetch_permitted(
            url, allow_loopback=allow_loopback):
        return False
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return host_permitted(parts.hostname, resolver=resolver,
                          allow_loopback=allow_loopback)


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-run the full URL screen on every redirect target; a
    refused hop ends the fetch (urllib surfaces the 3xx)."""

    def __init__(self, resolver=None, allow_loopback=False):
        super().__init__()
        self.max_redirections = MAX_REDIRECTS
        self._resolver = resolver
        self._allow_loopback = allow_loopback

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        absolute = urllib.parse.urljoin(req.get_full_url(), newurl)
        if not url_permitted(absolute, resolver=self._resolver,
                             allow_loopback=self._allow_loopback):
            return None
        return super().redirect_request(req, fp, code, msg, headers,
                                        absolute)


def fetch_media_bytes(url, max_bytes, timeout=FETCH_TIMEOUT,
                      resolver=None, opener=None):
    """Fetch one media URL's bytes under the guard and the cap.

    Returns the bytes. Raises FetchError (never returns None or a
    partial body) on a refused URL, an unreachable host, an empty
    body, or a body over max_bytes.
    """
    if not isinstance(url, str) or not (
            url.startswith("https://") or url.startswith("http://")):
        raise FetchError("media could not be fetched")
    allow_loopback = _registry._loopback_fetch_allowed()
    if not url_permitted(url, resolver=resolver,
                         allow_loopback=allow_loopback):
        raise FetchError("media could not be fetched")
    if opener is None:
        opener = urllib.request.build_opener(_GuardedRedirectHandler(
            resolver=resolver, allow_loopback=allow_loopback))
    req = urllib.request.Request(
        url, headers={"User-Agent": "NPCVerify/1.0 "
                                    "(+https://verify.npclabs.xyz)"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            chunks = []
            total = 0
            while True:
                chunk = resp.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(
                        "media exceeds the size cap for this check")
                chunks.append(chunk)
    except FetchError:
        raise
    except Exception:
        raise FetchError("media could not be fetched")
    data = b"".join(chunks)
    if not data:
        raise FetchError("media URL returned no content")
    return data
