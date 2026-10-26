#!/usr/bin/env python3
"""Grounding eval for the Biblo site chat (spec section 9.3).

Runs the spec's question set through the REAL chat pipeline
(retrieval, fixed system prompt, provider call, post-checks, store)
and asserts behavior per question: grounded answers with sources
for direct questions, the exact no-answer where the corpus cannot
speak, the scope decline out of scope, no record verdicts, no
methodology, no injection compliance, plain identity.

Modes:
  --mode live   The real model, called through the stored-key
                surrogate of the custom.legacy-gemini connector
                (the key never enters this process; authd
                substitutes it on egress). Model: gemini-flash-latest,
                the alias verified working on that key path.
  --mode mock   A parrot provider that echoes retrieved chunk text.
                Proves the harness mechanics ONLY; fixed-string and
                identity expectations will fail by design. Never
                report a mock run as a grounding result.
  --mode deployed
                Posts the same question set to the DEPLOYED
                endpoint (https://api.npclabs.xyz/v1/chat), so the
                gate measures the real endpoint, its real key, and
                its real governor (the Oct 18 diagnosis, fix 5c).
                Responses with state "off" and HTTP 429s are counted
                as ENVIRONMENT events, separate from grounding
                failures (fix 5b): a throttled or resting endpoint
                is not an answer-quality verdict. Paced at 200s
                between questions by default (--pace to override):
                the endpoint allows 20 served turns per hour per
                IP, and this run must not throttle itself.

Usage:
  python3 eval_chat_grounding.py [--mode live|mock|deployed]
                                 [--pace SECONDS]

Exit code 0 when every question passes (in deployed mode: with
zero environment events as well), 1 otherwise. One line per
question, then a summary. Replies are printed (truncated) so a
human can judge tone alongside the assertions.
"""
import argparse
import json
import os
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from npc_verify import chat as chat_mod  # noqa: E402
from npc_verify.store import Store  # noqa: E402

QUESTIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "chat_eval_questions.json")
FIXED = {"no_answer": chat_mod.NO_ANSWER,
         "scope_decline": chat_mod.SCOPE_DECLINE}


class SurrogateGeminiProvider(chat_mod.GeminiChatProvider):
    """The production provider, riding the connector's stored-key
    surrogate instead of an in-process key."""

    def __init__(self):
        super().__init__("", model="gemini-flash-latest")
        sys.path.insert(
            0, "/opt/muse/skills/custom-connector-setup/bin")
        from dynamic_credentials import (
            read_json_response, url_with_surrogate_query_param)
        self._read = read_json_response
        self._surrogate = url_with_surrogate_query_param

    def _call(self, payload):
        import time
        import urllib.request
        last_exc = None
        for attempt in range(3):
            url = self._surrogate(
                "https://generativelanguage.googleapis.com/v1beta/"
                "models/%s:generateContent" % self.model,
                "custom.gemini",
                allowed_hosts=["generativelanguage.googleapis.com"])
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST")
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return self._read(resp)
            except Exception as exc:  # free-tier throttling is real;
                last_exc = exc  # pace and retry rather than fail
                if attempt < 2:
                    time.sleep(5.0 * (attempt + 1))
        raise last_exc


class ParrotProvider:
    """Mock mode: echoes the top retrieved chunk, or the no-answer
    when nothing retrieved. Harness smoke only."""

    def complete(self, system_instruction, history, message):
        chunks = chat_mod.retrieve(message)
        if not chunks:
            return chat_mod.NO_ANSWER, 10, 10
        return chunks[0]["text"], 10, 10


def check(question, body):
    """Returns a list of failure strings (empty = pass)."""
    exp = question["expect"]
    reply = body.get("reply", "")
    low = reply.lower()
    fails = []
    if body.get("state") != "ok":
        fails.append("state is %r, want 'ok'" % body.get("state"))
    if exp.get("reply_is"):
        want = FIXED[exp["reply_is"]]
        if reply != want:
            fails.append("reply is not the exact %s" % exp["reply_is"])
        return fails
    if exp.get("fixed"):
        if reply not in (FIXED[name] for name in exp["fixed"]):
            fails.append("reply is not one of the fixed strings %s"
                         % (exp["fixed"],))
    if exp.get("allow_no_answer") and reply == chat_mod.NO_ANSWER:
        return fails
    for group in exp.get("must_contain_any", []):
        if not any(s.lower() in low for s in group):
            fails.append("reply lacks any of %s" % (group,))
    for s in exp.get("must_not_contain", []):
        if s.lower() in low:
            fails.append("reply contains forbidden %r" % s)
    if exp.get("must_not_regex"):
        import re
        if re.search(exp["must_not_regex"], reply):
            fails.append("reply matches forbidden regex %s"
                         % exp["must_not_regex"])
    if exp.get("sources_include"):
        titles = " ".join(s["title"].lower()
                          for s in body.get("sources", []))
        if exp["sources_include"].lower() not in titles:
            fails.append("sources lack %r (got: %s)"
                         % (exp["sources_include"], titles))
    return fails


def run_deployed(questions, pace):
    """POST each question to the deployed endpoint and grade the
    replies with the same check() as the in-process modes. State
    "off" replies and HTTP 429s are environment events, not
    grounding failures; every other non-200 is environment too
    (the endpoint's availability is not the corpus's fault)."""
    import time
    import urllib.error
    import urllib.request

    endpoint = "https://api.npclabs.xyz/v1/chat"
    print("MODE: deployed (POST %s; pace %.0fs between questions)"
          % (endpoint, pace))
    print("START: %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                      time.gmtime()))
    passed = failed = env = 0
    for i, q in enumerate(questions):
        if i:
            time.sleep(pace)
        req = urllib.request.Request(
            endpoint,
            data=json.dumps({"message": q["question"],
                             "page": "/help"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST")
        status = None
        body = {}
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                status = resp.status
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                body = json.loads(exc.read().decode("utf-8"))
            except Exception:
                body = {}
        except Exception as exc:
            print("[ENV ] %-10s %s" % (q["id"], q["question"]))
            print("       - network error: %s" % type(exc).__name__)
            env += 1
            continue
        if status == 200 and body.get("state") == "ok":
            fails = check(q, body)
            if fails:
                failed += 1
                print("[FAIL] %-10s %s" % (q["id"], q["question"]))
            else:
                passed += 1
                print("[PASS] %-10s %s" % (q["id"], q["question"]))
            print("       reply: %s"
                  % (body.get("reply", "")[:220].replace("\n", " ")))
            for f_ in fails:
                print("       - %s" % f_)
        else:
            env += 1
            print("[ENV ] %-10s %s" % (q["id"], q["question"]))
            print("       reply: %s"
                  % (body.get("reply", "")[:220].replace("\n", " ")))
            print("       - environment: HTTP %s, state %r "
                  "(not a grounding failure)"
                  % (status, body.get("state")))
    print("\n%d passed, %d grounding failures, %d environment, "
          "%d total" % (passed, failed, env, passed + failed + env))
    print("END: %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                    time.gmtime()))
    return 1 if (failed or env) else 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["live", "mock", "deployed"],
                    default="live")
    ap.add_argument("--pace", type=float, default=None,
                    help="seconds between questions (deployed mode; "
                         "default 200, sized to the endpoint's "
                         "per-IP served-turn cap)")
    args = ap.parse_args(argv)

    with open(QUESTIONS, encoding="utf-8") as f:
        questions = json.load(f)

    if args.mode == "deployed":
        return run_deployed(questions,
                            args.pace if args.pace is not None
                            else 200.0)

    if args.mode == "live":
        provider = SurrogateGeminiProvider()
        print("MODE: live (real model via the stored-key surrogate; "
              "model gemini-flash-latest)")
    else:
        provider = ParrotProvider()
        print("MODE: mock (parrot provider; harness smoke ONLY, not "
              "a grounding result)")

    tmp = tempfile.mkdtemp(prefix="npc_chat_eval_")
    store = Store(os.path.join(tmp, "eval.db"))
    svc = chat_mod.ChatService(store, provider=provider)

    passed = failed = 0
    for i, q in enumerate(questions):
        if args.mode == "live" and i:
            import time
            time.sleep(3.0)  # pace under the free tier's rate limits
        ip = "198.51.100.%d" % (i + 1)  # one IP per question: the
        # per-IP caps are production behavior, not eval signal.
        status, body = svc.post_chat({"message": q["question"],
                                      "page": "/help"}, ip)
        if status != 200:
            fails = ["HTTP %s" % status]
        else:
            fails = check(q, body)
        verdict = "PASS" if not fails else "FAIL"
        if fails:
            failed += 1
        else:
            passed += 1
        print("[%s] %-10s %s" % (verdict, q["id"], q["question"]))
        print("       reply: %s"
              % (body.get("reply", "")[:220].replace("\n", " ")))
        for f_ in fails:
            print("       - %s" % f_)
    print("\n%d passed, %d failed, %d total"
          % (passed, failed, passed + failed))
    store.close()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
