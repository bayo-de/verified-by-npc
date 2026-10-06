#!/usr/bin/env python3
"""Local verification of the staged Netlify function bundle.

Feeds synthetic Netlify events through the real handler (cold-start
bootstrap included) and checks: demo fixtures, fail-closed unknown,
stripped write endpoints, and Ed25519 signature validity of every
response against the published keys. Stdlib only.
"""
import base64
import json
import os
import sys

STAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stage")
FUNC = os.path.join(STAGE, "netlify", "functions")
sys.path.insert(0, FUNC)
sys.path.insert(0, os.path.join(FUNC, "api_pkgs"))

import api as function  # noqa: E402
from npc_verify import ed25519  # noqa: E402

DEMO_KEY = None  # filled from the staged demo_env.json
FAILURES = []


def event(method, path, body=None, auth=True):
    headers = {}
    if auth:
        headers["authorization"] = f"Bearer {DEMO_KEY}"
    raw = None
    if body is not None:
        raw = json.dumps(body)
    return {"httpMethod": method, "path": path, "headers": headers,
            "body": raw, "isBase64Encoded": False}


def check(name, cond, detail=""):
    print(("ok: " if cond else "FAIL: ") + name
          + (f" ({detail})" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def verify_signature(resp, keys):
    sig = base64.b64decode(resp["headers"]["X-NPC-Signature"])
    key_id = resp["headers"]["X-NPC-Key-ID"]
    pub = None
    for section in (keys["api_signing"]["current"],
                    *keys["api_signing"]["history"]):
        if section and section["key_id"] == key_id:
            pub = base64.b64decode(section["public_key"])
    if pub is None:
        return False
    return ed25519.verify(pub, resp["body"].encode("utf-8"), sig)


def main():
    global DEMO_KEY
    with open(os.path.join(FUNC, "api_pkgs", "demo_env.json"),
              encoding="utf-8") as f:
        DEMO_KEY = json.load(f)["demo_verifier_key"]

    # 1. health
    r = function.handler(event("GET", "/v1/health", auth=False), None)
    check("health 200", r["statusCode"] == 200, r["statusCode"])
    body = json.loads(r["body"])
    check("health ok", body.get("status") == "ok", body)

    # 2. keys
    r = function.handler(event("GET", "/v1/keys", auth=False), None)
    keys = json.loads(r["body"])
    check("keys 200", r["statusCode"] == 200)
    check("keys has demo api signing key",
          keys["api_signing"]["current"]["key_id"].startswith(
              "npc-demo-api-signing-"),
          keys["api_signing"]["current"]["key_id"])
    check("health signature valid", verify_signature(
        function.handler(event("GET", "/v1/health", auth=False), None),
        keys))
    check("keys signature valid", verify_signature(r, keys))

    # 3. product demo-tag-001
    r = function.handler(event("GET", "/v1/products/demo-tag-001"), None)
    body = json.loads(r["body"])
    check("product 200", r["statusCode"] == 200, r["statusCode"])
    check("product verdict verified",
          body.get("verdict") == "verified" and
          body.get("status") == "authentic", body.get("verdict"))
    check("product signature valid", verify_signature(r, keys))

    # 4. credential demo-cred-001
    r = function.handler(event("GET", "/v1/credentials/demo-cred-001"),
                         None)
    body = json.loads(r["body"])
    check("credential 200", r["statusCode"] == 200)
    check("credential valid", body.get("status") == "valid",
          body.get("status"))
    check("credential signature valid", verify_signature(r, keys))

    # 5. claim
    r = function.handler(
        event("POST", "/v1/claims/verify",
              {"claim_text": "the product shipped on demo date"}), None)
    body = json.loads(r["body"])
    check("claim 200", r["statusCode"] == 200, r["statusCode"])
    check("claim matched",
          body.get("matched") is True and
          body["attestation"]["verdict"] == "verified", body)
    check("claim signature valid", verify_signature(r, keys))

    # 6. agent demo-agent-001
    r = function.handler(
        event("GET", "/v1/agents/demo-agent-001/attestation"), None)
    body = json.loads(r["body"])
    check("agent 200", r["statusCode"] == 200)
    check("agent verified", body.get("verdict") == "verified",
          body.get("verdict"))
    check("agent signature valid", verify_signature(r, keys))

    # 7. unknown subject -> 404 unknown (fail-closed)
    r = function.handler(event("GET", "/v1/products/no-such-tag"), None)
    body = json.loads(r["body"])
    check("unknown 404", r["statusCode"] == 404, r["statusCode"])
    check("unknown verdict", body.get("verdict") == "unknown", body)
    check("unknown signature valid", verify_signature(r, keys))

    # 8. no auth -> 401
    r = function.handler(event("GET", "/v1/products/demo-tag-001",
                               auth=False), None)
    check("no-auth 401", r["statusCode"] == 401, r["statusCode"])

    # 9. write endpoints stripped
    r = function.handler(
        event("POST", "/v1/attestations", {"subject_type": "x"}), None)
    check("issuance stripped (404)", r["statusCode"] == 404,
          r["statusCode"])
    r = function.handler(
        event("POST", "/v1/memory/records", {"type": "x"}), None)
    check("memory stripped (404)", r["statusCode"] == 404,
          r["statusCode"])

    # 10. function-prefix path tolerance
    r = function.handler(
        event("GET", "/.netlify/functions/api/v1/health", auth=False),
        None)
    check("function prefix tolerated", r["statusCode"] == 200,
          r["statusCode"])

    print()
    if FAILURES:
        print(f"VERIFY FAILED: {len(FAILURES)} failure(s)")
        return 1
    print("VERIFY PASSED: demo API bundle is green (local simulation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
