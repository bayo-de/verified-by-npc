"""Continuous monitoring: one scheduler pass, from the command line.

Usage:
    python -m npc_verify.monitoring_cli --db PATH [--keys-dir DIR]
        [--enroll GRANT_ID ...] [--cadence-hours H] [--now ISO]

This is the invocable shape the standing scheduler calls (an
EventBridge-scheduled Lambda in production, a cron or a hand run
locally): build the store, enroll any subjects named, run one
monitoring pass with the PACT-fed audit runner, and print the pass
result as JSON. The events in this command's output are UNSIGNED
payloads; the signed publishing path is the server's monitoring run
route (POST /v1/monitoring/run, wired 2026-11-15), which mints each
event as an npc.registry.monitoring_event record through
npc_verify.registry.mint_monitoring_event. This command stays the
dry-run/replay shape. Local runs use the SQLite store and local test
keys, exactly like `python -m npc_verify`.
"""
import argparse
import json
import os
import sys

from . import monitoring
from .keys import KeyRegistry
from .monitoring_pact import make_pact_audit_runner
from .store import Store


def main(argv=None):
    parser = argparse.ArgumentParser(prog="monitoring_cli")
    parser.add_argument("--db", required=True,
                        help="SQLite store path (local runs)")
    parser.add_argument("--keys-dir", default=None,
                        help="signing keys directory (default: <db>.keys)")
    parser.add_argument("--enroll", action="append", default=[],
                        metavar="GRANT_ID",
                        help="enroll a PACT grant as a monitoring subject")
    parser.add_argument("--cadence-hours", type=float, default=None,
                        help="re-audit cadence for enrolled subjects")
    parser.add_argument("--now", default=None,
                        help="pin the pass time (ISO-8601) for replays")
    args = parser.parse_args(argv)

    store = Store(args.db)
    try:
        keys_dir = args.keys_dir or (args.db + ".keys")
        os.makedirs(keys_dir, exist_ok=True)
        keys = KeyRegistry(store, keys_dir)
        keys.ensure_bootstrap()
        # Enrollment timestamps use the pass clock when pinned, else
        # the current UTC time; keep them honest and simple.
        from datetime import datetime, timezone
        stamp = args.now or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        for grant_id in args.enroll:
            store.upsert_monitoring_subject(
                grant_id, args.cadence_hours, None, stamp)
        now = args.now or stamp
        runner = make_pact_audit_runner(store, keys, now_fn=lambda: now)
        result = monitoring.run_once(store, now, runner)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
