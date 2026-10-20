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
5. Review test-case placement follows OpenAI's directory rule:
   plugin-level review.test_cases is allowed only when the package
   declares exactly one MCP server; with any other server count the
   cases must be declared inside each mcpServers entry instead, and
   the two placements never combine. (OpenAI returned exactly this
   finding on the 2026-10-14 upload.)
6. A trial submission ZIP assembles with exactly the expected contents.
7. The MCP declaration in mcp.json conforms to the documented portable
   (Agent Plugins) shape the portal parses: the $schema marker, remote
   server entries whose type is the schema constant "streamable-http"
   (or "sse") with an HTTPS URL, no keys outside the documented set,
   and the authentication declaration the portal reads from mcp.json
   (extensions.com.openai.auth) present on every remote entry. The
   Codex-compatibility spelling "http" belongs in .mcp.json files, not
   in portable mcp.json; an entry using it matches no server definition
   in the Agent Plugins MCP schema and the portal reports the plugin
   as referencing no MCP server at all (observed 2026-10-15).
8. Review information is complete for an MCP plugin: the submission
   field reference requires five positive and three negative test
   cases (placement checked by rule 5, counts by the unit suite) and
   a reviewer-accessible demo recording URL
   (review.demo_recording_url) for MCP review; the field is optional
   in the ZIP only in the sense that skills-only plugins do not need
   it. A package declaring an MCP server without it leaves the
   portal's "Incomplete review information" finding standing even
   when every dashboard form section reads complete (observed
   2026-10-15).

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
                "https://npclabs.xyz",
                "https://npclabs.xyz/",
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


# -- 5. review test-case placement ------------------------------------------
def declared_mcp_servers():
    """Server names declared in the package's MCP configuration."""
    path = os.path.join(BASE, "mcp.json")
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        return sorted(json.load(f).get("mcpServers", {}))


def check_test_case_placement():
    with open(os.path.join(BASE, "plugin.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    review = manifest["extensions"]["com.openai"].get("review", {})
    plugin_cases = review.get("test_cases")
    servers = declared_mcp_servers()
    per_server = {}
    path = os.path.join(BASE, "mcp.json")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            mcp = json.load(f)
        for name, entry in mcp.get("mcpServers", {}).items():
            cases = entry.get("review", {}).get("test_cases")
            if cases:
                per_server[name] = cases
    if plugin_cases and per_server:
        fail("review test cases declared both at plugin level and inside "
             "mcpServers entries; OpenAI forbids combining the placements")
    elif plugin_cases:
        if len(servers) != 1:
            fail(f"plugin-level review.test_cases requires exactly one MCP "
                 f"server; package declares {len(servers)} ({servers}). "
                 f"Declare the cases inside each mcpServers entry instead")
        else:
            ok("plugin-level test_cases with exactly one MCP server")
    elif per_server:
        missing = [n for n in servers if n not in per_server]
        if missing:
            fail(f"mcpServers entries without review test cases: {missing}")
        else:
            ok(f"test cases declared per-server ({len(per_server)} entries, "
               f"none at plugin level)")
    else:
        fail("no review test cases declared anywhere (plugin level or "
             "per-server); MCP review requires 5 positive + 3 negative")


# -- 6. MCP declaration conforms to the documented portable shape -----------
MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
# Keys the Agent Plugins MCP schema plus the portal's documented
# extensions allow on a remote (HTTP) server entry. "review" is the
# portal's per-server test-case carrier (submission field reference);
# its placement is governed by check_test_case_placement above.
REMOTE_ENTRY_KEYS = {"type", "url", "headers", "extensions", "review"}
REMOTE_TYPES = {"streamable-http", "sse"}
AUTH_TYPES = {"none", "oauth", "mixed", "api_key"}


def mcp_entry_problems(name, entry):
    """Problems with one mcpServers entry, per the documented shape.

    Pure function (no file access) so the unit suite can run negative
    controls against it, including the 2026-10-15 v2 defect.
    """
    problems = []
    if not isinstance(entry, dict):
        return [f"mcpServers.{name}: entry is not an object"]
    if "url" in entry:  # remote HTTP server
        extra = sorted(set(entry) - REMOTE_ENTRY_KEYS)
        if extra:
            problems.append(
                f"mcpServers.{name}: keys outside the documented remote "
                f"entry shape: {extra}")
        etype = entry.get("type")
        if etype not in REMOTE_TYPES:
            problems.append(
                f"mcpServers.{name}: type {etype!r} is not a portable "
                f"remote transport; the Agent Plugins MCP schema requires "
                f"one of {sorted(REMOTE_TYPES)} ('http' is the Codex "
                f".mcp.json spelling and matches no portable server "
                f"definition, so the portal detects no MCP server)")
        url = entry.get("url", "")
        if not url.startswith("https://"):
            problems.append(
                f"mcpServers.{name}: remote URL must be HTTPS for public "
                f"submission: {url!r}")
        ext = entry.get("extensions")
        auth = None
        if isinstance(ext, dict):
            namespaces = sorted(set(ext) - {"com.openai"})
            if namespaces:
                problems.append(
                    f"mcpServers.{name}: undeclared extension namespaces: "
                    f"{namespaces}")
            openai_ext = ext.get("com.openai", {})
            if isinstance(openai_ext, dict):
                unknown = sorted(set(openai_ext) - {"auth"})
                if unknown:
                    problems.append(
                        f"mcpServers.{name}: undocumented com.openai "
                        f"extension keys: {unknown}")
                auth = openai_ext.get("auth")
        if not isinstance(auth, dict) or auth.get("type") not in AUTH_TYPES:
            problems.append(
                f"mcpServers.{name}: missing the authentication "
                f"declaration the portal reads from mcp.json "
                f"(extensions.com.openai.auth with type one of "
                f"{sorted(AUTH_TYPES)}; declare 'none' for a public "
                f"no-auth server)")
        headers = entry.get("headers")
        if headers:
            problems.append(
                f"mcpServers.{name}: public submission rejects nonempty "
                f"server headers")
    elif entry.get("type") == "stdio":
        if not entry.get("command"):
            problems.append(
                f"mcpServers.{name}: stdio entry without a command")
    else:
        problems.append(
            f"mcpServers.{name}: entry is neither a remote server (no "
            f"url) nor a stdio server (type != 'stdio')")
    return problems


def check_mcp_declaration():
    path = os.path.join(BASE, "mcp.json")
    if not os.path.isfile(path):
        fail("mcp.json missing; the portal discovers MCP servers from "
             "the portable root mcp.json")
        return
    with open(path, encoding="utf-8") as f:
        mcp = json.load(f)
    if mcp.get("$schema") != MCP_SCHEMA:
        fail(f"mcp.json $schema must be {MCP_SCHEMA}")
    servers = mcp.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        fail("mcp.json declares no mcpServers entries")
        return
    problems = []
    for name, entry in servers.items():
        problems += mcp_entry_problems(name, entry)
    for p in problems:
        fail(p)
    if not problems:
        ok(f"MCP declaration conforms to the documented portable shape "
           f"({len(servers)} server(s): {', '.join(sorted(servers))})")


# -- 8. review information complete for MCP review --------------------------
def check_review_completeness():
    with open(os.path.join(BASE, "plugin.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    review = manifest["extensions"]["com.openai"].get("review", {})
    if not declared_mcp_servers():
        ok("no MCP server declared; demo recording not required")
        return
    url = review.get("demo_recording_url")
    if not url:
        fail("review.demo_recording_url missing; the field reference "
             "requires a reviewer-accessible video walkthrough URL "
             "for MCP review, and the portal holds an 'Incomplete "
             "review information' finding until it is supplied")
    elif not url.startswith("https://"):
        fail(f"review.demo_recording_url must be HTTPS: {url!r}")
    else:
        ok(f"review.demo_recording_url present: {url}")


# -- 7. trial submission ZIP -----------------------------------------------
EXPECTED_ZIP = sorted([
    "plugin.json",
    "mcp.json",
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
    check_test_case_placement()
    check_mcp_declaration()
    check_review_completeness()
    check_zip()
    print()
    if FAILURES:
        print(f"PACKAGE INVALID: {len(FAILURES)} failure(s)")
        return 1
    print("PACKAGE VALID: submission-ready (submission itself is gated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
