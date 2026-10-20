"""Netlify Python function: NPC Verification API v1 (demo).

Single entry point. The app is built once per cold start (see demoapp.py)
and every response is canonicalized + Ed25519-signed by the API itself,
exactly like the local server.
"""
import base64
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
# The bundle keeps demoapp.py and the npc_verify / npc_memory packages in
# the api_pkgs/ subdirectory next to this file (see build_bundle.py), so
# that directory must be importable too. Without this, a cold start in the
# real Netlify runtime fails with ModuleNotFoundError: demoapp. The local
# verifier masked this by adding api_pkgs to sys.path itself.
PKGS = os.path.join(HERE, "api_pkgs")
if os.path.isdir(PKGS) and PKGS not in sys.path:
    sys.path.insert(0, PKGS)

from demoapp import build_app  # noqa: E402

APP = build_app()

_FUNCTION_PREFIX = "/.netlify/functions/api"


def handler(event, context):
    method = (event.get("httpMethod") or "GET").upper()
    path = event.get("path") or "/"
    if path.startswith(_FUNCTION_PREFIX):
        path = path[len(_FUNCTION_PREFIX):] or "/"
    headers = {str(k).lower(): v
               for k, v in (event.get("headers") or {}).items()}
    # Gateway-reported source IP for the public registration caps;
    # set after the client's headers so it cannot be spoofed.
    source_ip = ((event.get("requestContext") or {}).get("identity")
                 or {}).get("sourceIp")
    if source_ip:
        headers["x-npc-peer"] = source_ip
    raw_body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body_bytes = base64.b64decode(raw_body)
    else:
        body_bytes = raw_body.encode("utf-8")

    code, out_headers, payload = APP.dispatch(method, path, headers,
                                             body_bytes)
    resp_headers = dict(out_headers)
    resp_headers["Cache-Control"] = "no-store"
    return {
        "statusCode": code,
        "headers": resp_headers,
        "body": payload.decode("utf-8"),
    }
