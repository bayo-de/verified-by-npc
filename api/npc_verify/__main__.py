"""Run the Verification API v1 locally.

Usage:
    python -m npc_verify [--port 8787] [--seed]

On first run, TEST signing keys are generated locally (clearly labeled,
stored under .local/keys with mode 600) and test fixtures are seeded.
Binds to 127.0.0.1 only — local-first, no public exposure.
"""
import argparse
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify.server import run  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-seed", action="store_true",
                    help="do not seed test fixtures")
    args = ap.parse_args()

    local = os.path.join(BASE, ".local")
    db_path = os.path.join(local, "npc_verify.db")
    keys_dir = os.path.join(local, "keys")
    os.makedirs(local, exist_ok=True)

    fresh = not os.path.exists(db_path)
    server, app = run(db_path, keys_dir, host=args.host, port=args.port)

    if fresh:
        print("First run: LOCAL TEST keys generated (api_signing + issuer).")
        pub = app.keys.publish()
        print(f"  api signing key: {pub['api_signing']['current']['key_id']}")
        for isk in pub["issuers"]:
            if isk["status"] == "active":
                print(f"  issuer key:      {isk['key_id']}")
    if fresh and not args.no_seed:
        seeded = seed_all(app.store, app.keys)
        print("Fixtures seeded (all fictional, test_ prefixed).")
        print()
        print("TEST API keys (shown once — save them):")
        print(f"  verifier: {seeded['verifier_key']}")
        print(f"  issuer:   {seeded['issuer_key']}")
        print()
        print("WARNING: test keys only. Never use these in production.")
        print()

    actual_port = server.server_address[1]
    print(f"NPC Verification API v1 listening on {args.host}:{actual_port}")
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
