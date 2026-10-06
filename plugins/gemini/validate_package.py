"""End-to-end package validation for the Gemini CLI extension.

Checks, in order:
  1. Required files are present.
  2. No em-dashes in human-facing text (manifest, commands, GEMINI.md,
     README, operation descriptions).
  3. The operation mapping is read-only (no attestation issuance).
  4. The full unittest suite passes.

Exits 0 when everything passes, nonzero on the first failure.
"""
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))

REQUIRED_FILES = [
    "gemini-extension.json",
    "operations.json",
    "GEMINI.md",
    "README.md",
    "npc_verify_gemini/__init__.py",
    "npc_verify_gemini/client.py",
    "npc_verify_gemini/__main__.py",
    "commands/verify-product.toml",
    "commands/verify-credential.toml",
    "commands/verify-claim.toml",
    "commands/verify-agent.toml",
    "commands/explain-verification.toml",
    "tests/__init__.py",
    "tests/helpers.py",
    "tests/test_manifest.py",
    "tests/test_operations.py",
    "tests/test_client.py",
]

HUMAN_FACING_FILES = [
    "gemini-extension.json",
    "operations.json",
    "GEMINI.md",
    "README.md",
    "commands/verify-product.toml",
    "commands/verify-credential.toml",
    "commands/verify-claim.toml",
    "commands/verify-agent.toml",
    "commands/explain-verification.toml",
]

FAILURES = []


def check(name, ok, detail=""):
    status = "ok" if ok else "FAIL"
    print(f"[{status}] {name}" + (f": {detail}" if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def main():
    print("== Verified by NPC: Gemini extension package validation ==")

    for rel in REQUIRED_FILES:
        check(f"file present: {rel}",
              os.path.isfile(os.path.join(BASE, rel)))

    for rel in HUMAN_FACING_FILES:
        path = os.path.join(BASE, rel)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as f:
            text = f.read()
        check(f"no em-dashes: {rel}", "\u2014" not in text)

    ops_path = os.path.join(BASE, "operations.json")
    try:
        with open(ops_path, encoding="utf-8") as f:
            ops = json.load(f)
        names = {a["name"] for a in ops["actions"]}
        check("operations: five actions mapped",
              names == {"verify_product", "verify_credential", "verify_claim",
                        "verify_agent", "explain_verification"},
              f"found {sorted(names)}")
        mapped = {(a["method"], a["path"]) for a in ops["actions"]}
        check("operations: read-only (no issuance)",
              ("POST", "/v1/attestations") not in mapped
              and not any("attestations" in a["path"]
                          for a in ops["actions"]))
    except (OSError, ValueError, KeyError) as exc:
        check("operations.json parses", False, str(exc))

    print("-- running unittest suite --")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests",
         "-t", BASE, "-v"],
        cwd=BASE, capture_output=True, text=True)
    print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    check("unittest suite passes", proc.returncode == 0,
          f"exit {proc.returncode}")

    print("== "
          + ("ALL CHECKS PASSED" if not FAILURES
             else f"{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
          + " ==")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
