"""Console entry point: run the Gemini extension helper directly.

Usage:
    python3 -m npc_verify_gemini verify_product --tag-id TAG
    python3 -m npc_verify_gemini verify_credential --credential-id ID
    python3 -m npc_verify_gemini verify_claim --claim-text TEXT
    python3 -m npc_verify_gemini verify_claim --claim-hash HASH
    python3 -m npc_verify_gemini verify_agent --agent-id ID
    python3 -m npc_verify_gemini explain_verification

The package directory itself is runnable too:
    python3 <path-to>/npc_verify_gemini verify_product --tag-id TAG

Prints the action result (JSON for verification answers) and exits 0 when
verification completed (including "unknown"), 1 on error.
"""
import argparse
import os
import sys


def _bootstrap():
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(pkg_dir)
    if root not in sys.path:
        sys.path.insert(0, root)


_bootstrap()
from npc_verify_gemini.client import make_client, run_action  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verified by NPC - Gemini extension helper")
    parser.add_argument("action", choices=[
        "verify_product", "verify_credential", "verify_claim",
        "verify_agent", "explain_verification"])
    parser.add_argument("--tag-id")
    parser.add_argument("--credential-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--claim-text")
    parser.add_argument("--claim-hash")
    args = parser.parse_args(argv)

    action_args = {
        "tag_id": args.tag_id,
        "credential_id": args.credential_id,
        "agent_id": args.agent_id,
        "claim_text": args.claim_text,
        "claim_hash": args.claim_hash,
    }
    client = make_client()
    is_error, text = run_action(client, args.action, action_args)
    print(text)
    return 1 if is_error else 0


if __name__ == "__main__":
    sys.exit(main())
