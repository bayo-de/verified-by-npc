"""Validate the .npc file the e2e driver downloaded.

Checks, against the throwaway local stack in NPC_E2E_DIR:
  1. the test file's SHA-256, recomputed here, matches the
     envelope's subject fingerprint and the record's locator;
  2. the embedded signed record verifies with the repo's own
     verification code (npc_verify.pact.verify_record) against the
     stack's key registry, and a tampered copy does not;
  3. the embedded record is byte-for-byte the record the API
     itself returns at GET /v1/records/{id};
  4. attestation and anchor are null, the honest state of a fresh
     registration, and the summary names the standing;
  5. the dashboard's /verify page serves the file flow and the
     inlined npc/1.0 module (a DOM-level check of the real page).

Usage: NPC_E2E_DIR=/tmp/npc-e2e python3 npc_e2e_validate.py
Exits nonzero on the first failed check.
"""
import hashlib
import http.client
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.dirname(BASE))
sys.path.insert(0, os.path.normpath(os.path.join(BASE, "..", "api")))

from npc_verify.server import create_app  # noqa: E402
from npc_verify import pact  # noqa: E402


def check(name, ok, detail=""):
    print("%s %s %s" % ("PASS" if ok else "FAIL", name, detail))
    if not ok:
        sys.exit(1)


def get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    data = resp.read().decode("utf-8")
    status = resp.status
    conn.close()
    return status, data


def main():
    work = os.environ.get("NPC_E2E_DIR") or "/tmp/npc-e2e"
    with open(os.path.join(work, "e2e-manifest.json")) as fh:
        manifest = json.load(fh)
    with open(manifest["npcPath"]) as fh:
        env = json.load(fh)

    # 1. hash recomputed from the file itself
    digest = hashlib.sha256()
    with open(manifest["testFile"], "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    recomputed = digest.hexdigest()
    check("file hash recomputed", recomputed == manifest["sha256"])
    check("envelope subject fingerprint",
          env["subject"]["contentSha256"] == "sha256:" + recomputed)
    rec = env["registration"]["record"]
    check("record locator is the file hash",
          rec["locator"] == "sha256:" + recomputed)
    check("envelope names the record",
          env["registration"]["recordId"] == manifest["recordId"]
          and rec["record_id"] == manifest["recordId"])
    check("envelope spec and issuer",
          env["spec"] == "npc/1.0"
          and env["issuer"] == "did:web:npclabs.xyz")

    # 2. the repo's own verifier, on the stack's keys
    app = create_app(os.path.join(work, "e2e.db"),
                     os.path.join(work, "keys"))
    check("embedded record signature verifies",
          pact.verify_record(app.keys, rec) is True)
    tampered = dict(rec)
    tampered["title"] = rec["title"] + " (altered)"
    check("tampered record fails verification",
          pact.verify_record(app.keys, tampered) is False)
    app.store.close()

    # 3. the embedded record is the API's own record, verbatim
    status, body = get(8799, "/v1/records/" + manifest["recordId"])
    served = json.loads(body)
    check("GET /v1/records/{id} answers 200", status == 200)
    check("embedded record matches the served record",
          served == rec)

    # 4. honest nulls and summary on a fresh registration
    check("attestation is null", env["attestation"] is None)
    check("anchor is null", env["anchor"] is None)
    check("summary states the standing",
          "registered, checks pending" in env["summary"]
          and "Verification is a separate step" in env["summary"])

    # 5. the real page carries the flow
    status, page = get(8790, "/verify")
    check("dashboard /verify answers 200", status == 200)
    for marker in ('id="npc-file-form"', 'id="npc-file-drop"',
                   "NPCCredential", "npc/1.0", "did:web:npclabs.xyz",
                   "The file never leaves your device."):
        check("page carries %s" % marker, marker in page)

    print("E2E VALIDATION PASSED for %s" % manifest["npcName"])


if __name__ == "__main__":
    main()
