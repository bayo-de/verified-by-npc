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
