#!/usr/bin/env python3
"""Export a day of Biblo chat transcripts as a Markdown review digest.

Spec: biblo-chat-SPEC-2026-10-15.md section 6. The digest leads with
the turns where Biblo had no answer (the corpus backlog) and the
thumbs-down turns (the quality backlog), then prints every
conversation in order with its feedback inline.

Sources:
  --db PATH     a SQLite store file (local dev / test stacks)
  --table NAME  a DynamoDB table (default npc-verify-store); reads
                with boto3, scanning the CHAT# / CHATFB# / CHATDAY#
                partitions for the day. Production use only.

Usage:
  python3 export_chat_digest.py --day 2026-10-15 [--db store.db]
  python3 export_chat_digest.py --day 2026-10-15 --table npc-verify-store

The digest is an internal review artifact. It contains visitor text;
handle it like any support transcript.
"""
import argparse
import datetime
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)


def _from_sqlite(db_path, day):
    from npc_verify.store import Store
    store = Store(db_path)
    try:
        threads = {}
        for tid in store.chat_threads_on(day):
            threads[tid] = {
                "turns": store.get_chat_turns(tid),
                "feedback": {f["turn"]: f
                             for f in store.get_chat_feedback(tid)},
            }
        return threads, store.get_chat_daily(day)
    finally:
        store.close()


def _from_dynamodb(table_name, day):
    import boto3
    from boto3.dynamodb.conditions import Key
    table = boto3.resource("dynamodb").Table(table_name)

    def rows(pk):
        out, kwargs = [], {"KeyConditionExpression": Key("pk").eq(pk)}
        while True:
            resp = table.query(**kwargs)
            out.extend(json.loads(it["data"])
                       for it in resp.get("Items", []))
            last = resp.get("LastEvaluatedKey")
            if not last:
                return out
            kwargs["ExclusiveStartKey"] = last

    threads = {}
    for idx in rows("CHATDAY#" + day):
        tid = idx["thread_id"]
        threads[tid] = {
            "turns": rows("CHAT#" + tid),
            "feedback": {f["turn"]: f for f in rows("CHATFB#" + tid)},
        }
    daily = {"conversations": 0, "turns": 0, "est_micro_usd": 0}
    item = table.get_item(Key={"pk": "CHATCAP", "sk": day}).get("Item")
    if item:
        daily = json.loads(item["data"])
    return threads, daily


def render(day, threads, daily):
    lines = ["# Biblo chat digest: %s" % day, ""]
    lines.append("Conversations: %d. Turns: %d. Estimated provider "
                 "spend: $%.2f."
                 % (daily.get("conversations", 0),
                    daily.get("turns", 0),
                    daily.get("est_micro_usd", 0) / 1_000_000.0))
    lines.append("")
    no_answers, downs = [], []
    for tid in sorted(threads):
        data = threads[tid]
        visitor_turn = 0
        for t in data["turns"]:
            if t["role"] == "visitor":
                visitor_turn += 1
                pending_q = t["text"]
            elif t.get("no_answer"):
                no_answers.append((tid, visitor_turn, pending_q,
                                   t["text"]))
        for turn_no, fb in sorted(data["feedback"].items()):
            if fb["rating"] == "down":
                downs.append((tid, turn_no, fb.get("comment", "")))
    lines.append("## No-answer turns (%d)" % len(no_answers))
    lines.append("")
    if no_answers:
        for tid, n, q, _a in no_answers:
            lines.append("- [%s turn %d] %s" % (tid, n, q))
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## Thumbs down (%d)" % len(downs))
    lines.append("")
    if downs:
        for tid, n, comment in downs:
            lines.append("- [%s turn %d] %s" % (tid, n, comment or ""))
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## Conversations")
    for tid in sorted(threads):
        data = threads[tid]
        lines.append("")
        lines.append("### %s" % tid)
        visitor_turn = 0
        for t in data["turns"]:
            if t["role"] == "visitor":
                visitor_turn += 1
                lines.append("")
                lines.append("**Visitor (turn %d, %s):** %s"
                             % (visitor_turn, t.get("page") or "",
                                t["text"]))
            else:
                mark = " [no answer]" if t.get("no_answer") else ""
                lines.append("")
                lines.append("**Biblo:** %s%s" % (t["text"], mark))
                fb = data["feedback"].get(visitor_turn)
                if fb:
                    lines.append("")
                    lines.append("Feedback: %s%s"
                                 % (fb["rating"],
                                    (" (" + fb["comment"] + ")")
                                    if fb.get("comment") else ""))
    lines.append("")
    return "\n".join(lines)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--day", default=datetime.date.today().isoformat(),
                    help="UTC day to export (YYYY-MM-DD)")
    ap.add_argument("--db", help="SQLite store path")
    ap.add_argument("--table", default=None,
                    help="DynamoDB table name (default npc-verify-store)")
    ap.add_argument("--out", help="write the digest here (default: "
                                  "stdout)")
    args = ap.parse_args(argv)
    if args.db:
        threads, daily = _from_sqlite(args.db, args.day)
    else:
        threads, daily = _from_dynamodb(args.table or "npc-verify-store",
                                        args.day)
    text = render(args.day, threads, daily)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print("wrote %s" % args.out)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
