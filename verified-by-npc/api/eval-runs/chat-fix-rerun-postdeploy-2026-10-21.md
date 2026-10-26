# Chat eval rerun, POST-DEPLOY (v5.7 live) — 2026-10-21

Companion to the pre-deploy report
`api/eval-runs/chat-fix-rerun-2026-10-21.md` (same morning).
v5.7 was deployed Oct 21, 2026 (~11:21 AM MDT) carrying the
three chat fixes: ProviderError logging with type and HTTP
status, 4 retry attempts inside a 22s budget (backoff, jitter,
Retry-After capped at 10s), maxOutputTokens 1200,
thinkingBudget 0. This rerun measures the deployed endpoint
running that fixed code. **Nothing was changed in this run: no
code, no config, no flags.** The harness, case set, and pace
are identical to the morning run.

Raw output of this pass:
`api/eval-runs/chat-grounding-eval-deployed-2026-10-21-postdeploy.txt`
Raw output of the pre-deploy pass:
`api/eval-runs/chat-grounding-eval-deployed-2026-10-21-rerun.txt`

## 1. Method

The real harness (`scripts/eval_chat_grounding.py`, deployed
mode) run unchanged against `https://api.npclabs.xyz/v1/chat`,
all 31 cases from `scripts/chat_eval_questions.json`, pace 25s
between questions, one consistent window:
**2026-10-21 17:22:28 to 17:39:51 UTC** (17m 23s). Per the
harness discipline, state `off` responses and non-200s are
ENVIRONMENT events, reported separately from grounding
failures.

## 2. Result

**0 grounded answers, 0 grounding failures, 31 environment
events, 31 total.**

| Outcome | Count | Cases |
| --- | --- | --- |
| HTTP 200, state `off` (exact resting reply) | 30 | direct-1, direct-2, direct-3, direct-5, direct-6, direct-7, direct-8, direct-9, live-1..3, record-1..3, noans-1..3, scope-1..4, method-1..3, inject-1..3, identity-1..3 |
| Network error (RemoteDisconnected, no HTTP response) | 1 | direct-4 |
| HTTP 504 (gateway timeout) | 0 | — |
| Grounded answer (state `ok`) | 0 | — |

Every one of the 30 completed responses carried the exact
resting message, byte for byte: "Biblo is resting for today.
The Help page covers most questions, and the team reads
hello@npclabs.xyz."

Timing (derived, the harness logs no per-request latency):
the window was 1,043s; the 30 inter-question pauses account
for 750s of it, leaving ~293s of request time across 31
requests, a mean of roughly 9.5s per request. No request hit
the harness's 40s timeout, and none ran long enough to
produce a gateway 504.

## 3. Comparison against the pre-deploy run (same morning)

Pre-deploy window: 2026-10-21 07:06:28 to 07:22:19 UTC,
endpoint running v5.5 code.

| Outcome | Pre-deploy (v5.5) | Post-deploy (v5.7) |
| --- | --- | --- |
| Grounded answers (state `ok`, passed) | 0 | 0 |
| Grounding failures | 0 | 0 |
| HTTP 200, state `off` | 25 | 30 |
| HTTP 504 (gateway timeout) | 6 | 0 |
| Network error (no HTTP response) | 0 | 1 |
| Environment events, total | 31 | 31 |
| Total cases | 31 | 31 |

## 4. Notable per-case changes

- **direct-1, direct-2, direct-3, direct-6, direct-7:**
  HTTP 504 pre-deploy, now HTTP 200 state `off`. The six
  gateway timeouts are gone. This is the one visible behavior
  change from v5.7, and it matches the predicted effect of
  the 22s retry budget: provider failures now resolve to the
  resting answer inside the gateway window instead of a bare
  504.
- **direct-4:** HTTP 504 pre-deploy, now a network error
  (RemoteDisconnected): the connection closed with no HTTP
  response at all. A single occurrence; its exact server-side
  shape cannot be determined from outside.
- **The other 25 cases** (direct-5, direct-8, direct-9,
  live-1..3, record-1..3, noans-1..3, scope-1..4, method-1..3,
  inject-1..3, identity-1..3): unchanged. HTTP 200, state
  `off`, the exact resting reply, in both runs.
- **No case changed in the direction that matters:** no case
  moved from environment to a graded answer in either
  direction. Grounding quality is exactly as unmeasured after
  the deploy as it was before it.

## 5. Verdict

**No. The deployed endpoint does not return grounded
answers.** Across all 31 cases the live v5.7 endpoint served
zero state `ok` responses: 30 resting replies and one dropped
connection. Environment events still dominate completely
(31 of 31), so answer quality remains unmeasured, not failed,
exactly as in the pre-deploy run.

What the deploy did prove: the timeout shape is fixed. The
6 pre-deploy 504s became resting replies, consistent with the
22s retry budget doing its job. What it did not fix: whatever
makes every provider turn fail is still failing on every
request, roughly 9.5s per request on average, well inside the
new budget, which fits fast upstream failures being retried
and exhausted rather than hangs.

The morning report's prediction now applies: with v5.7 live,
fix 1 writes `chat provider failure: error_type=<type>
http_status=<status>` to CloudWatch on each failing turn, so
the upstream status behind these offs is now a recorded fact
in the Lambda logs for `npc-verify-api`, readable on the next
console pass. That log line is the next diagnostic step; from
outside the endpoint, the cause remains indistinguishable
between upstream error classes.

Gate consequence, unchanged from this morning: the dashboard
chat flip still waits on a post-deploy eval showing grounded
answers. This rerun was that eval, and it does not show them.
