#!/usr/bin/env python3
"""Assemble the Netlify Drop bundle for the demo API (api.npclabs.xyz).

Generates fresh demo signing keys + a demo verifier API key, stages the
stdlib-only function bundle, and zips it for drag-drop deploy.

The zip contains demo key material (demo_env.json): it is the server's own
key material, needed for the deploy. Do not publish the zip. The demo
verifier key plaintext prints once: Bayo pastes it into the OpenAI plugin
portal auth config. Stdlib only.
"""
import base64
import json
import os
import secrets
import shutil
import sys
import zipfile
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(os.path.dirname(BASE))  # verified-by-npc/
SRC = os.path.join(BASE, "function_src")
STAGE_SRC = os.path.join(BASE, "stage_src")
STAGE = os.path.join(BASE, "stage")
ZIP_PATH = os.path.join(BASE, "npc-verify-api-netlify-drop.zip")


def _key_id(purpose: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"npc-demo-{purpose}-{stamp}-{secrets.token_hex(3)}"


def _copy_package(src_name: str, dest_root: str):
    src = os.path.join(PROJECT, src_name)
    dest = os.path.join(dest_root, os.path.basename(src_name))
    shutil.copytree(src, dest,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return dest


def main() -> int:
    if os.path.isdir(STAGE):
        shutil.rmtree(STAGE)
    os.makedirs(STAGE)

    # Static site config + landing page.
    for name in ("netlify.toml", "public"):
        src = os.path.join(STAGE_SRC, name)
        dest = os.path.join(STAGE, name)
        if os.path.isdir(src):
            shutil.copytree(src, dest)
        else:
            shutil.copy2(src, dest)

    # Function bundle.
    func_dir = os.path.join(STAGE, "netlify", "functions")
    pkgs_dir = os.path.join(func_dir, "api_pkgs")
    os.makedirs(pkgs_dir)
    shutil.copy2(os.path.join(SRC, "api.py"), func_dir)
    shutil.copy2(os.path.join(SRC, "demoapp.py"), pkgs_dir)
    _copy_package(os.path.join("api", "npc_verify"), pkgs_dir)
    _copy_package(os.path.join("memory", "npc_memory"), pkgs_dir)
    shutil.copy2(os.path.join(BASE, "seed_demo.py"), pkgs_dir)

    # Fresh demo key material for this bundle.
    demo_env = {
        "api_signing": {
            "key_id": _key_id("api-signing"),
            "seed_b64": base64.b64encode(
                secrets.token_bytes(32)).decode(),
        },
        "issuer": {
            "key_id": _key_id("issuer"),
            "seed_b64": base64.b64encode(
                secrets.token_bytes(32)).decode(),
        },
        "demo_verifier_key": "npc_demo_" + secrets.token_urlsafe(32),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "note": "DEMO key material. Read-only demo fixtures only.",
    }
    with open(os.path.join(pkgs_dir, "demo_env.json"), "w",
              encoding="utf-8") as f:
        json.dump(demo_env, f, indent=2)

    # Zip it (Netlify Drop layout).
    if os.path.exists(ZIP_PATH):
        os.remove(ZIP_PATH)
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(STAGE):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in sorted(files):
                full = os.path.join(root, name)
                arc = os.path.relpath(full, STAGE)
                zf.write(full, arc)

    size = os.path.getsize(ZIP_PATH)
    print(f"bundle: {ZIP_PATH} ({size} bytes)")
    print(f"api signing key id: {demo_env['api_signing']['key_id']}")
    print(f"issuer key id:      {demo_env['issuer']['key_id']}")
    print()
    print("DEMO VERIFIER API KEY (shown once - Bayo pastes this into the")
    print("OpenAI plugin portal auth config):")
    print(f"  {demo_env['demo_verifier_key']}")
    print()
    print("Deploy: drag this zip onto a NEW Netlify site (Netlify Drop),")
    print("then add custom domain api.npclabs.xyz + the GoDaddy DNS record.")
    print("The zip contains demo key material: do not publish it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
