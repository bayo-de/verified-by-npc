#!/usr/bin/env python3
"""End-to-end package validation for the Verified by NPC OpenAI plugin.

Checks the whole package and exits nonzero on ANY failure:

1. The unittest suite passes (manifest, OpenAPI spec, signature,
   contracts).
2. Every file referenced by plugin.json exists inside the package
   (logo, composer icon, onboarding skill, skills directory).
3. Copy rules hold across all human-facing text: no em-dashes, no
   invented live URLs, no claims about funding or profitability.
4. The retired ai-plugin.json is not shipped (it fails the 2026
   submission scan).
5. A trial submission ZIP assembles with exactly the expected contents.

Stdlib only. Run from anywhere: python3 validate_package.py
"""
import io
import json
import os
import re
import subprocess
import sys
import zipfile

BASE = os.path.dirname(os.path.abspath(__file__))
EM_DASH = "—"
FAILURES = []


def fail(msg):
    FAILURES.append(msg)
    print(f"FAIL: {msg}")


def ok(msg):
    print(f"ok: {msg}")


# -- 1. unit tests ---------------------------------------------------------
def check_tests():
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=BASE, capture_output=True, text=True)
    tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
    if proc.returncode != 0:
        fail(f"unittest suite failed:\n" + "\n".join(tail))
    else:
        ok(f"unittest suite passed ({tail[-1].strip()})")


# -- 2. referenced files exist ---------------------------------------------
def check_references():
    with open(os.path.join(BASE, "plugin.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    iface = manifest["extensions"]["com.openai"]["interface"]
    refs = [iface["logo"], iface["composerIcon"],
            manifest["extensions"]["com.openai"]["onboardingSkill"]]
    for ref in refs:
        full = os.path.normpath(os.path.join(BASE, ref))
        if not os.path.isfile(full):
            fail(f"manifest reference missing: {ref}")
        elif not full.startswith(BASE):
            fail(f"manifest reference escapes package: {ref}")
        else:
            ok(f"manifest reference present: {ref}")
    skills_dir = os.path.join(BASE, "skills")
    found = []
    for root, _, files in os.walk(skills_dir):
        found += [os.path.join(root, n) for n in files]
    if not any(n.endswith("SKILL.md") for n in found):
        fail("skills/ contains no SKILL.md")
    else:
        ok(f"skills/ present ({len(found)} files)")


# -- 3. copy rules ----------------------------------------------------------
HUMAN_FILES = ["plugin.json", "openapi-plugin.yaml", "README.md",
               os.path.join("skills", "verified-by-npc", "SKILL.md")]


def check_copy_rules():
    for rel in HUMAN_FILES:
        path = os.path.join(BASE, rel)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if EM_DASH in text:
            fail(f"em-dash in human-facing text: {rel}")
        # invented live URLs: anything http(s) that is not the documented
        # API surface, the manifest schema, or the SVG namespace.
        for m in re.finditer(r"https?://[^\s\"')<>]+", text):
            url = m.group(0)
            allowed = url.startswith((
                "https://agent-plugins.org/",
                "https://api.npclabs.xyz/",
                "http://127.0.0.1:8787/",
                "http://www.w3.org/2000/svg",
            ))
            if not allowed:
                fail(f"unexpected live URL in {rel}: {url}")
        low = text.lower()
        # Assertion-like funding/earnings phrases (not meta discussion of
        # the rule itself).
        for phrase in ("$18m", "seed round", "series a", "series b",
                       "we raised", "raised funds", "has raised",
                       "profitable"):
            if phrase in low:
                fail(f"funding/profitability claim in {rel}: {phrase!r}")
    if not any("FAIL" in f for f in FAILURES):
        ok("copy rules hold (no em-dashes, no invented URLs, no funding claims)")


# -- 4. no legacy manifest --------------------------------------------------
def check_no_legacy():
    legacy = os.path.join(BASE, "ai-plugin.json")
    if os.path.exists(legacy):
        fail("ai-plugin.json is retired and fails the 2026 submission scan; "
             "remove it")
    else:
        ok("no retired ai-plugin.json shipped")


# -- 5. trial submission ZIP -----------------------------------------------
EXPECTED_ZIP = sorted([
    "plugin.json",
    "openapi-plugin.yaml",
    "README.md",
    "validate_package.py",
    "assets/icon.svg",
    "assets/logo.svg",
    "npc_verify_openai/__init__.py",
    "npc_verify_openai/client.py",
    "skills/verified-by-npc/SKILL.md",
    "tests/__init__.py",
    "tests/_yaml_subset.py",
    "tests/helpers.py",
    "tests/test_contracts.py",
    "tests/test_manifest.py",
    "tests/test_openapi_spec.py",
    "tests/test_signature.py",
])


def check_zip():
    # Working documents live next to the package but never ship in the
    # submission ZIP.
    EXCLUDE = {"SUBMISSION-RUNBOOK.md"}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(BASE):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in sorted(files):
                if name in EXCLUDE:
                    continue
                full = os.path.join(root, name)
                arc = os.path.relpath(full, BASE)
                zf.write(full, arc)
    names = sorted(zf.namelist())
    if names != EXPECTED_ZIP:
        missing = [n for n in EXPECTED_ZIP if n not in names]
        extra = [n for n in names if n not in EXPECTED_ZIP]
        fail(f"submission ZIP contents unexpected "
             f"(missing={missing}, extra={extra})")
    else:
        ok(f"submission ZIP assembles ({len(names)} files, "
           f"{len(buf.getvalue())} bytes)")


def main():
    print("== Verified by NPC / OpenAI plugin package validation ==")
    check_tests()
    check_references()
    check_copy_rules()
    check_no_legacy()
    check_zip()
    print()
    if FAILURES:
        print(f"PACKAGE INVALID: {len(FAILURES)} failure(s)")
        return 1
    print("PACKAGE VALID: submission-ready (submission itself is gated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
