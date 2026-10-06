"""Run the Verified by NPC dashboard locally.

Usage:
    python -m dashboard [--port 8790] [--api-url URL] [--api-key KEY]

Binds to 127.0.0.1 only (local-first, no public exposure). Points at the
NPC Verification API v1 (default http://127.0.0.1:8787); the verifier API
key can be passed with --api-key or NPC_VERIFY_API_KEY.

The API must be running first:
    cd ../api && python3 -m npc_verify
"""
import argparse
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(BASE))

from dashboard.server import run  # noqa: E402


def main():
    ap = argparse.ArgumentParser(
        description="Verified by NPC dashboard (local preview)")
    ap.add_argument("--port", type=int, default=8790)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--api-url", default=None,
                    help="API v1 base URL (or NPC_VERIFY_API_URL)")
    ap.add_argument("--api-key", default=None,
                    help="verifier API key (or NPC_VERIFY_API_KEY)")
    args = ap.parse_args()

    api_url = (args.api_url or os.environ.get("NPC_VERIFY_API_URL")
               or "http://127.0.0.1:8787").rstrip("/")
    api_key = args.api_key or os.environ.get("NPC_VERIFY_API_KEY", "")

    server = run(api_url, api_key, host=args.host, port=args.port)
    actual = server.server_address[1]
    print("Verified by NPC dashboard listening on %s:%d" % (args.host,
                                                             actual))
    print("Reading from API v1 at %s" % api_url)
    if not api_key:
        print("No API key configured: lookups will show as unavailable. "
              "Set NPC_VERIFY_API_KEY.")
    print("Open http://127.0.0.1:%d/ in a browser." % actual)
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
