# Chat OFF-state diagnosis — 2026-10-18

Scope: why the formal grounding eval (Oct 18, 2026, live mode) saw the
"Biblo is resting for today" fallback with state `off` on 16 of 31
questions, interleaved with grounded passes. Read-only diagnosis. No
deploys, no config changes were made.

Code examined: `api/npc_verify/chat.py` (working copy). Verified
byte-identical to the shipped bundle: `api_pkgs/npc_verify/chat.py`
inside `api-deploy/npc-verify-api-lambda-v5.5-2026-10-15.zip` diffs
clean against it, so everything below describes the deployed code
path as well as the eval's.

## 1. Every code path that produces state `off`

`OFF_MESSAGE` is defined at chat.py:51-53. `ChatService.post_chat`
(chat.py:405) returns it with state `"off"` from exactly three places:

1. **Spend governor** (chat.py:430-442). Before any provider call:
   if the day's stored counter shows `est_micro_usd >=
   daily_cap_micro` OR `conversations >= max_conversations_per_day`,
   the turn is answered with OFF_MESSAGE. Defaults
   (chat.py:336-337, from_env at 349-361): cap $5.00/day
   (5,000,000 micro-USD, env `NPC_CHAT_DAILY_CAP_USD`),
   1,000 conversations/day (env
   `NPC_CHAT_MAX_CONVERSATIONS_PER_DAY`). Production counter is the
   DynamoDB `CHATCAP` item (ddb_store.py:580-600); the eval used the
   SQLite equivalent (store.py:786-810). This state LATCHES: once
   tripped, every later request that day is off.
2. **No provider configured** (chat.py:468-477). If
   `self.provider is None` (in production: `provider_from_env`,
   chat.py:364, finds no `NPC_CHAT_LLM_API_KEY` in the Lambda env),
   every turn is OFF_MESSAGE. This state also LATCHES until the env
   is fixed.
3. **Provider failure** (chat.py:479-491). If
   `provider.complete(...)` raises `ProviderError`, the exception is
   swallowed (nothing is logged anywhere in this branch) and the
   turn is answered with OFF_MESSAGE. This state does NOT latch:
   the next request tries the provider again.
   `GeminiChatProvider.complete` (chat.py:299-334) converts ANY
   exception from `_call` into ProviderError, and also raises it
   when Gemini returns no text. Production `_call` (chat.py:270-297)
   makes 2 attempts total, sleeping 2.0s before the retry, retrying
   only on HTTP 429/500/502/503/504 or a network error (code None),
   with a 25s timeout per attempt.

No other path yields `off`. Per-IP limits return HTTP 429 errors
(`errors.rate_limited`), not the off body, and the thread-length cap
returns LONG_CONVERSATION with state `ok`.

## 2. Which path fired in the eval, and why the others are ruled out

Critical context: **the eval never called the deployed endpoint.**
`scripts/eval_chat_grounding.py` runs the production ChatService
in-process (line 152-153) with two substitutions:

- **A fresh, empty store per run**: `tempfile.mkdtemp` +
  `Store(.../eval.db)` (line 150-151). The governor therefore
  started at zero. The whole run's estimated spend is roughly
  31 turns x ~1,000-2,000 micro-USD = well under $0.10 against a
  $5.00 cap, and 31 conversations against a 1,000 cap. The governor
  (path 1) is mathematically impossible in this run, and its
  latching behavior contradicts the observed pattern anyway:
  passes occur AFTER offs (direct-2 after direct-1; scope-2 after
  a run of offs; identity-2 near the end, after ten straight
  failures). A tripped cap cannot un-trip mid-run.
- **A surrogate provider** (lines 47-82): the production
  GeminiChatProvider subclass, but the HTTP call rides the
  custom.legacy-gemini connector's stored-key surrogate (the AI
  Studio key in the Secure Vault; authd substitutes it on egress),
  model `gemini-flash-latest`. The provider was injected, not None,
  so path 2 is ruled out; and interleaved grounded passes (with 5
  retrieved sources) prove the surrogate path works.

That leaves **path 3, uniquely**: each eval `off` is a turn where
the surrogate `_call` raised on all 3 of its attempts (attempts at
lines 60-82: 60s timeout each, sleeps of 5s then 10s between them),
`complete()` wrapped the final exception in ProviderError, and
`post_chat` silently answered OFF_MESSAGE.

The pattern fits transient upstream failure, most probably
**free-tier throttling (HTTP 429)** on the AI Studio key:
- The eval script's own comments anticipate exactly this:
  "free-tier throttling is real; pace and retry rather than fail"
  (line 78-79) and the 3.0s inter-question sleep exists to "pace
  under the free tier's rate limits" (line 158). Free-tier
  `gemini-flash-latest` quotas are per-minute and small; every
  throttled question fires 3 requests, so retries themselves keep
  the per-minute bucket drained, which matches offs clustering in
  the back half of the run (9 of the last 11 questions off) while
  an occasional window clears enough for one pass (identity-2).
- Timing arithmetic supports fast HTTP rejections, not timeouts:
  the run took 544.7s for 31 questions. Fixed pacing accounts for
  90s (30 x 3.0s). If failures were 60s timeouts, a single failed
  question would burn ~195s (3 x 60s + 15s of sleeps); several such
  questions cannot fit in the remaining ~455s. Quick 429/503
  responses plus 15s of retry sleeps per failed question fit the
  budget. (Inference from the run duration, labeled as such.)
- Corroboration: the previous live run, Oct 15
  (`api-deploy/eval-live-run2-2026-10-15.log`), scored 3 passed /
  28 failed through the same surrogate path. The flicker predates
  Oct 18 and was worse then; Oct 17's handful of spaced spot probes
  passed because a few isolated calls do not drain a per-minute
  quota.

**What cannot be settled from the artifacts:** the exact upstream
status. Nothing records it: the surrogate stores `last_exc` and
re-raises it, `complete()` keeps only the exception's type name in
the ProviderError message, and `post_chat` logs nothing. 429
(throttle) vs 503 (model overloaded on the flash-latest alias) vs
a surrogate/authd egress error are indistinguishable in the eval
output. Evidence that would settle it, in order of directness:
(a) one instrumented re-run of the eval with the surrogate printing
`type(exc)` / `exc.code` per attempt (a script-only change, no
deploy); (b) the AI Studio quota/usage view for the surrogate key
around 23:48-23:57 UTC on Oct 18; (c) for the deployed endpoint
only, the DynamoDB `CHATCAP` item for 2026-10-18 (shows whether
production spend ever approached the cap) and, after fix option 1
below lands, CloudWatch logs from the Lambda (account 367429573265,
via Bayo's Builder ID session). Existing CloudWatch logs cannot
help retroactively: the current code logs nothing on this branch.

**Production implication, stated precisely:** the deployed
endpoint runs this identical code, so it will also answer `off`
on any double consecutive upstream failure, and its retry posture
is weaker than the eval's (2 attempts, 2s apart, 25s timeouts vs
the surrogate's 3 attempts over ~15s). But the eval's failure RATE
does not measure the deployed endpoint: production uses the
Lambda's own key and model from env (`NPC_CHAT_LLM_API_KEY`,
`NPC_CHAT_LLM_MODEL`, default gemini-2.5-flash) and the DynamoDB
governor, none of which the eval touched. The Oct 17 evening spot
probes remain the direct evidence about the deployed endpoint:
grounded answers, 5 sources, healthy that evening.

## 3. Reset behavior (per the code)

- Governor off: self-resets at **UTC midnight**. The day key is
  `now[:10]` from `utcnow_iso()` (chat.py:424), i.e. the UTC date;
  a new day reads a fresh counter starting at zero. No manual
  reset exists or is needed. (Note: UTC, not MDT — a cap tripped
  in the Las Cruces evening clears at 6 PM MDT the following day
  during daylight time... precisely: at 00:00 UTC, which is
  18:00 MDT the same local evening.)
- Provider-failure off: no latch at all. Every request re-attempts
  the provider; the state clears the moment upstream answers.
- No-key off: never self-resets; requires the env var to be set
  (console change) and a cold start.

## 4. The non-off failure: noans-1 (truncated fixed string)

Question: "When is the mobile app launching?" Expectation:
`reply_is: no_answer`, i.e. the reply must equal NO_ANSWER exactly.
The recorded reply is 92 characters and is an **exact prefix of
NO_ANSWER (157 characters)**, cut mid-sentence after "the
search,". The model was emitting the exact required string and
generation stopped early. This is therefore **not a corpus or
prompt wording problem** (the instruction already demands the
verbatim string, and the model complied) and **not an evaluator
strictness artifact** (exactness is the spec's design, section
9.3, and the sibling question noans-2 passed with the full
string). It is a generation-budget truncation: `complete()` sets
`maxOutputTokens: 700` (chat.py:313) and sends no thinking
config; on Gemini 2.5 Flash-class models, thinking tokens draw
from the same output budget, so a reply can be cut after ~90
visible characters when thinking runs long. The truncated text
passes `post_check` (no forbidden content), so it is shown as-is
instead of being replaced by the canonical NO_ANSWER.

## 5. Fix options, ranked

1. **Instrument the swallow (code change; Lambda redeploy for
   production, script-only for the eval).** Log the exception type
   and HTTP status in `post_chat`'s ProviderError branch
   (chat.py:483) and print it per attempt in the eval's surrogate
   `_call`. Changes nothing user-facing; converts every future
   off-flicker from inference into a recorded cause. Prerequisite
   for choosing confidently among options 2-3.
2. **Harden the production retry (code change; Lambda redeploy).**
   In `GeminiChatProvider._call`: raise attempts from 2 to 4 with
   exponential backoff and jitter (e.g. 2s/5s/10s) and honor a
   `Retry-After` header on 429. Directly targets the observed
   failure shape (bursts of quick 429s a 2s pause cannot clear).
   Watch the budget: worst case must stay well under the Lambda's
   configured timeout (4 attempts x 25s timeouts is the tail risk;
   consider lowering the per-attempt timeout to ~15s as part of
   the same change).
3. **Fix the quota, not the code (config only; NO redeploy).**
   Confirm which tier the Lambda's `NPC_CHAT_LLM_API_KEY` is on.
   If it is a free-tier AI Studio key, its per-minute caps make
   flicker structural under any real traffic; a paid-tier key (or
   a dedicated key for chat) removes most 429s. Console env/secret
   change by Bayo; the key value never enters a file. This also
   applies to the eval's surrogate key, which is the key the eval
   actually measures.
4. **Fix the fixed-string truncation (code change; Lambda
   redeploy).** In `complete()`'s payload: raise `maxOutputTokens`
   (700 to ~1200) and set `thinkingConfig.thinkingBudget` to 0 (or
   a small cap) for this fixed-format answerer. Targets the
   noans-1 class specifically; cheap and safe.
5. **Eval hygiene (no production change).** (a) Slow the pacing
   (3.0s to ~8-10s) and/or spread the run; (b) report
   ProviderError offs as an "environment" category separate from
   grounding failures in the summary, so a throttled surrogate
   cannot masquerade as a grounding verdict; (c) add a second eval
   mode that posts to the deployed `https://api.npclabs.xyz/v1/chat`
   so the launch gate measures the real endpoint, its real key,
   and its real governor. Until (c) exists, an eval "not clean
   pass" verdict conflates surrogate throttling with answer
   quality.
6. **Optional, spec-level (skip unless wanted).** Split the API
   state so a transient provider failure reports distinctly from
   the daily-cap rest (e.g. `busy` vs `off`) with matching visitor
   copy. Helps visitors and the dashboard tell a flicker from a
   full stop, but it changes the spec's fixed strings and the
   dashboard contract; not needed to fix the gate.

Note on what NOT to do: raising `NPC_CHAT_DAILY_CAP_USD` would
change nothing for this incident. The governor never fired in the
eval (fresh store, ~$0.10 of ~$5.00), and a cap change cannot
produce or cure an interleaved pattern.
