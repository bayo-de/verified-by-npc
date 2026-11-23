#!/usr/bin/env python3
"""Grant an operator test comp to a signed-in account's balance.

An operator tool, run by hand against the store, never through a
route: it lands a grant under the ledger source "operator_comp" on
the account's own ledger row (see npc_verify.credits and the
stores' grant_account_comp), so the comped checks are always
distinguishable in the ledger from checks the account bought.
The grant spends like a bonus grant (the whole remainder can fund
an AI check) and expires under the standard one-rollover rule
(credits.grant_expiry). It is keyed by grant id, so re-running the
same command lands nothing twice; a second comp for the same
account needs an explicit new --grant-id, on purpose.

The store is selected the way production selects it:
NPC_STORE_BACKEND=dynamodb grants against the DynamoDB table
(NPC_DDB_TABLE, default "npc-verify-store"; region from
NPC_DDB_REGION or AWS_REGION). Without that variable it grants
against a local SQLite store file (--db), which is the staging
and rehearsal path only.

Run (production, at deploy time, inside the Lambda environment or
a shell carrying its role):

  NPC_STORE_BACKEND=dynamodb python3 scripts/grant_account_comp.py \
      --email bayo@npclabs.xyz --amount 25 \
      --grant-id operator-comp-v6.10-launch

Exit 0 = granted (or already granted under that id); exit 2 = the
email has no account; exit 1 = usage or store errors.
"""
import argparse
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import credits  # noqa: E402
from npc_verify.models import utcnow_iso  # noqa: E402


def open_store(db_path):
    if os.environ.get("NPC_STORE_BACKEND") == "dynamodb":
        from npc_verify.ddb_store import DynamoDBStore
        table = os.environ.get("NPC_DDB_TABLE") or "npc-verify-store"
        region = os.environ.get("NPC_DDB_REGION") \
            or os.environ.get("AWS_REGION")
        return DynamoDBStore(table_name=table, region=region)
    from npc_verify.store import Store
    return Store(db_path)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Grant an operator test comp to an account.")
    parser.add_argument("--email", required=True,
                        help="the account's email address")
    parser.add_argument("--amount", type=int, default=25,
                        help="checks to grant (default 25)")
    parser.add_argument(
        "--grant-id", default=None,
        help="ledger grant id; a replay under the same id grants "
             "nothing twice (default: operator-comp:<account_id>)")
    parser.add_argument(
        "--db", default=os.path.join(BASE, "npc_verify.sqlite3"),
        help="SQLite store path (non-DynamoDB runs only)")
    args = parser.parse_args(argv)
    if args.amount <= 0:
        parser.error("--amount must be positive")

    store = open_store(args.db)
    account = store.get_account_by_email(args.email.strip().lower())
    if account is None:
        print("no account for %s; nothing granted" % args.email)
        return 2
    now = utcnow_iso()
    grant_id = args.grant_id or ("operator-comp:"
                                 + account["account_id"])
    outcome = store.grant_account_comp(
        account["account_id"], account.get("email"), args.amount,
        grant_id, now, credits.grant_expiry(now))
    if outcome["outcome"] == "not_found":
        print("account vanished mid-grant; nothing granted")
        return 2
    row = outcome["code"] or {}
    balance = row.get("credits_total", 0) - row.get("credits_used", 0) \
        + row.get("grant_balance", 0)
    print("%s: %d checks under grant %s; balance now %s "
          "(AI checks %s), expiring %s"
          % (outcome["outcome"], args.amount, grant_id, balance,
             row.get("ai_balance", "?"),
             credits.grant_expiry(now)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
