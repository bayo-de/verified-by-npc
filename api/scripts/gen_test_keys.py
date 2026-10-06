#!/usr/bin/env python3
"""Generate local TEST signing keys (Ed25519) for the Verification API.

Writes seed files (mode 600) into the keys dir and registers the public
keys in the SQLite store. These keys are for LOCAL DEVELOPMENT ONLY —
they must never be used in production or published.

Usage:
    python3 scripts/gen_test_keys.py [--db PATH] [--keys DIR] [--rotate PURPOSE]
"""
import argparse
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify.store import Store  # noqa: E402
from npc_verify.keys import KeyRegistry, PURPOSES  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.path.join(BASE, ".local", "npc_verify.db"))
    ap.add_argument("--keys", default=os.path.join(BASE, ".local", "keys"))
    ap.add_argument("--rotate", choices=PURPOSES, default=None,
                    help="rotate this purpose instead of bootstrapping")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.db), exist_ok=True)
    store = Store(args.db)
    reg = KeyRegistry(store, args.keys)
    if args.rotate:
        info = reg.rotate(args.rotate)
        print(f"rotated {args.rotate}: {info['key_id']} (old key retired)")
    else:
        created = reg.ensure_bootstrap()
        if created:
            print("created test keys:")
            for kid in created:
                print(f"  {kid}")
        else:
            print("keys already exist; use --rotate to rotate")
    print("WARNING: local test keys only. Never production.")


if __name__ == "__main__":
    main()
