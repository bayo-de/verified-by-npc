"""End-to-end package validation for the Copilot plugin.

Checks, in order:
  1. Required files are present.
  2. No em-dashes in human-facing text (manifests, spec, README).
  3. The plugin manifest declares schema v2.2 with five functions.
  4. The OpenAPI spec maps all five actions and is read-only
     (no attestation issuance).
  5. The full unittest suite passes.

Exits 0 when everything passes, nonzero on the first failure.
"""
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "tests"))

REQUIRED_FILES = [
    "npc-verify-apiplugin.json",
    "declarative-agent.json",
    "npc-verify-openapi.yaml",
    "README.md",
    "npc_verify_copilot/__init__.py",
    "npc_verify_copilot/client.py",
    "npc_verify_copilot/__main__.py",
    "tests/__init__.py",
    "tests/helpers.py",
    "tests/_yaml_subset.py",
    "tests/test_manifest.py",
    "tests/test_openapi.py",
    "tests/test_client.py",
]

HUMAN_FACING_FILES = [
    "npc-verify-apiplugin.json",
    "declarative-agent.json",
    "npc-verify-openapi.yaml",
    "README.md",
]

EXPECTED_ACTIONS = {"verify_product", "verify_credential", "verify_claim",
                    "verify_agent", "explain_verification"}

FAILURES = []


def check(name, ok, detail=""):
    status = "ok" if ok else "FAIL"
    print(f"[{status}] {name}" + (f": {detail}" if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def main():
    print("== Verified by NPC: Copilot plugin package validation ==")

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

    manifest_path = os.path.join(BASE, "npc-verify-apiplugin.json")
    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        check("manifest: schema v2.2",
              manifest.get("schema_version") == "v2.2")
        check("manifest: five functions",
              len(manifest.get("functions", [])) == 5)
    except (OSError, ValueError) as exc:
        check("plugin manifest parses", False, str(exc))

    spec_path = os.path.join(BASE, "npc-verify-openapi.yaml")
    try:
        from _yaml_subset import parse as yaml_parse
        with open(spec_path, encoding="utf-8") as f:
            spec = yaml_parse(f.read())
        actions = set()
        for path_item in spec["paths"].values():
            for op in path_item.values():
                if isinstance(op, dict) and op.get("x-npc-action"):
                    actions.add(op["x-npc-action"])
        check("spec: five actions mapped", actions == EXPECTED_ACTIONS,
              f"found {sorted(actions)}")
        check("spec: read-only (no issuance)",
              not any("attestations" in p for p in spec["paths"]))
    except Exception as exc:  # noqa: BLE001 - validator reports, not raises
        check("openapi spec parses", False, str(exc))

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
