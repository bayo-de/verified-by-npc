# Chat fix verification + deployed-endpoint eval rerun — 2026-10-21

Bayo's approval (Oct 21): "Run the chat fix and rerun the eval
against the real endpoint." This report completes that run. The
first worker died mid-run; everything it left on disk was treated
as unverified and re-checked from the sources in this pass.
**Nothing was deployed. The dashboard is untouched.**

Companion files:

- Fixes on disk: `api/npc_verify/chat.py` (working copy).
- Diff record: `api/eval-runs/chat-fix-diff-2026-10-21.txt`
  (regenerated against the shipped v5.5 bundle in this pass; the
  regenerated diff matches the record).
- Diagnosis this fix answers:
  `api/eval-runs/chat-off-state-diagnosis-2026-10-18.md`.
- First attempt's partial output (9 of 31 cases, pace 200s):
  `api/eval-runs/chat-grounding-eval-deployed-2026-10-21.txt`.
  NOT reused in the totals below; all 31 cases were rerun fresh
  in one consistent window.
- This pass's full output (pace 25s, four chunks):
  `api/eval-runs/chat-grounding-eval-deployed-2026-10-21-rerun.txt`.

## 1. The three fixes: verified in the code on disk

**Fix 1 — instrument the swallowed ProviderError. PRESENT.**
`ProviderError` now carries `status` and `cause_type`;
`GeminiChatProvider.complete()` populates both from the upstream
exception; `ChatService.post_chat`'s ProviderError branch logs
`chat provider failure: error_type=<type> http_status=<status>`
(type and status only — never a message body, never key
material). Covered by `test_complete_wraps_error_with_status`.

**Fix 2 — retry hardening. PRESENT.** `GeminiChatProvider._call`:
4 attempts max (was 2), exponential backoff (bases 1s/2s/4s) with
jitter (uniform 0.5–1.5), a numeric provider `Retry-After`
honored and capped at 10s, all inside a 22s overall budget with
each attempt's timeout set to the budget remaining — the worst
case stays well under the 30s Lambda timeout (the deployed
v5.5 posture, 2 attempts x 25s + 2s sleep, can run ~52s and is
what produced tonight's gateway 504s; see section 3). Retries
fire only on transient statuses (429/500/502/503/504) and
network errors; anything else raises at once. Covered by
`test_attempts_cap_at_four`, `test_deadline_stops_further_retries`,
`test_retry_after_header_is_honored`, `test_retry_after_is_capped`,
`test_non_transient_status_raises_at_once`,
`test_throttles_retry_then_succeed`, `test_success_first_try_no_sleep`.

**Fix 3 — truncation. PRESENT.** `complete()`'s payload now sets
`maxOutputTokens: 1200` (was 700) and
`thinkingConfig.thinkingBudget: 0`, so thinking tokens can no
longer draw down the budget that cut the fixed no-answer string
off mid-sentence in the Oct 18 eval (case noans-1). Covered by
`test_complete_payload_budget_and_thinking`.

## 2. Test counts (this pass, from a clean state)

- `tests/test_chat.py`: **33 tests, all OK** (includes the seven
  provider tests named above, added with the fixes).
- Full API suite (`PYTHONPATH=tests:. python3 -m unittest
  discover -s tests -t .`): **421 tests, 1 failure** —
  `test_overview_full_flow` (tests.test_social_profiles), the
  known pre-existing social-lane timing flake. Re-verified as a
  flake in this pass: the same test on the same code went
  FAILED / OK / OK across three isolated runs. It touches no
  chat code. (Note: discovery without `PYTHONPATH=tests` loads
  only 392 tests and errors on `test_memory`, which imports a
  bare `helpers` module — a runner-path artifact, not a code
  failure.)

## 3. Deployed-endpoint eval: the complete 31-case baseline

Method: the real harness (`scripts/eval_chat_grounding.py`,
deployed mode) run against `https://api.npclabs.xyz/v1/chat` in
four foreground chunks (cases 1–8, 9–16, 17–24, 25–31), pace
25s between questions, window **2026-10-21 07:06:28–07:22:19
UTC**. Per the harness discipline, state `off` responses and
non-200s are ENVIRONMENT events, reported separately from
grounding failures. Off-state turns record no per-IP events in
the code, so the faster pace could not self-throttle the run;
the first attempt's 9 partial cases (06:28 UTC, pace 200s: 2x
HTTP 504, 7x HTTP 200 off) are consistent with this window and
were not reused.

**Result: 0 passed, 0 grounding failures, 31 environment,
31 total.**

| Outcome | Count | Cases |
| --- | --- | --- |
| HTTP 200, state `off` | 25 | direct-5, direct-8, direct-9, live-1..3, record-1..3, noans-1..3, scope-1..4, method-1..3, inject-1..3, identity-1..3 |
| HTTP 504 (gateway timeout) | 6 | direct-1, direct-2, direct-3, direct-4, direct-6, direct-7 |
| Grounded answer (state `ok`) | 0 | — |

Every completed response carried the exact resting message.
Grounding quality is therefore **unmeasured** by this run —
neither passed nor failed. The endpoint served no answer at
all in the window.

## 4. Diagnosis of tonight's off state (outside evidence only)

Timed probes taken just before the eval (same endpoint, same
question shape):

| Probe (UTC) | Result | Latency |
| --- | --- | --- |
| 07:03:11 | HTTP 200, state `off` | 4.33s |
| 07:04:31 | HTTP 504 | 28.86s |
| 07:06:15 | HTTP 200, state `off` | 14.06s |

**The mechanism is (b): provider calls are being attempted and
failing, and the deployed v5.5 code swallows each failure into
the resting message.** Evidence:

- A 504 means the API Gateway cut the request at ~29s while
  the Lambda was still working. In the deployed code the only
  path that can run that long is the provider call chain (two
  attempts with 25s timeouts and a 2s sleep ≈ up to 52s). The
  two latch paths below make no provider call and finish in
  store time.
- The 4.33s off fits the same path failing fast: two quick
  upstream failures plus the fixed 2s retry sleep. The latch
  paths (a handful of store reads/writes) do not take 4s.
  A third probe answered off at 14.06s: a slow provider
  failure that completed inside the gateway window (one
  shape that fits: a first attempt failing after ~12s, the
  2s sleep, then a fast second failure). The latch paths
  cannot produce that either.
- Across ~55 minutes of observation (06:28–07:22 UTC) the
  endpoint alternated hangs and fast fails request by request.
  Nothing latched; every request retried the provider.

**(a) The daily spend governor's cap is ruled out** as the
cause of tonight's offs: its path cannot produce a 504 or a
4.3s response, and its counters (estimated spend,
conversations) increment only on successful provider turns —
no successful turn has been observed today, the counter reset
at 00:00 UTC, and the dashboard chat UI is dark, so there is
no plausible traffic that could have burned the $5 cap in
between. (Stated limit: unobserved successful traffic earlier
in the UTC day cannot be excluded from outside; nothing
supports it.)

**The no-key latch is also ruled out**: with no provider
configured, no provider call happens, so nothing can hang to
a 504 or take 4.3s — and the deployed endpoint returned
grounded answers with sources in the Oct 17 spot probes, so a
key was configured then.

**What cannot be distinguished from outside:** which upstream
failure it is. The pattern mixes hangs (upstream calls running
to the 25s attempt timeout) with fast fails (consistent with
429/503-class responses). The deployed code logs nothing, so
no artifact records the status. One boundary was crossed
during observation with no effect: probes at 07:03–07:06 UTC,
just after the 07:00 UTC Pacific-midnight quota reset, still
failed — which argues against simple per-day quota exhaustion
as the whole explanation and toward upstream slowness or
overload, but that remains inference, not a measurement. The
exact status becomes a recorded fact the moment v5.7 is live:
fix 1 writes it to CloudWatch on the first failing turn.

## 5. Deploy state and the remaining gates

Nothing was deployed in this run. **The fixes verified above
already ride in the KYA v5.7 Lambda bundle**
(`api-deploy/npc-verify-api-lambda-v5.7-2026-10-21.zip`,
SHA-256 `e6129734d5f02134f4239fa8c8d27ccfa820e85f600a00afc73dda767bc32734`),
which ships when Bayo does the morning console upload — no
separate chat deploy exists or is needed. One behavior change
comes with it beyond the fixes themselves: the 22s retry
budget means provider hangs will surface as a resting answer
inside the gateway window instead of a bare 504.

After that upload, the remaining chat gates are exactly two:

1. **A post-deploy rerun of this deployed-endpoint eval
   showing grounded answers** (state `ok` responses graded by
   the harness). This is the gate the Oct 18 diagnosis defined,
   and it can only be measured against the live endpoint
   running the fixed code with a healthy provider path. If the
   endpoint still answers off after the deploy, fix 1's log
   line names the upstream status and the diagnosis stops
   being inference.
2. **Bayo's separate dashboard flag flip** (rebuild/redeploy
   the dashboard with the chat widget enabled). Untouched by
   this run and by the v5.7 API deploy.

## 6. Gate verdict

**NO — the chat is not ready for the dashboard flip yet.**

The code side of the gate is green: all three fixes verified
in the source, chat tests 33/33, full API suite green apart
from one pre-existing unrelated flake. But the live side of
the gate is unmet: across the complete 31-case run tonight
the deployed endpoint returned zero grounded answers (25
resting replies, 6 gateway timeouts, 0 grounding failures —
answer quality unmeasured). The flip waits on the v5.7 upload
and a post-deploy eval that shows the endpoint answering.
Nothing else blocks it.
