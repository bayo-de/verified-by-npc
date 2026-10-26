"""Biblo chat endpoints (biblo-chat-SPEC-2026-10-15.md).

Two layers:
- HTTP shape tests through the live loopback stack (unsigned
  responses, validation, idempotent replay, quiet feedback).
- Service-level tests with a fresh store and a fake provider per
  test: grounding, post-check replacement, the spend governor
  (state "off" with NO provider call), per-IP limits, the thread
  cap, TTL fields, transcript hygiene, and the DynamoDB backend's
  chat round-trip over the fake table.
No real provider is ever called from tests.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
FAKE_DIR = os.path.join(BASE, "serverless", "lambda_v5_4", "fake_boto3")
sys.path.insert(0, FAKE_DIR)

from tests.helpers import ApiTestCase  # noqa: E402
from npc_verify import chat as chat_mod  # noqa: E402
from npc_verify.store import Store  # noqa: E402
import boto3 as fake_boto3  # noqa: E402
from npc_verify.ddb_store import DynamoDBStore  # noqa: E402


class FakeProvider:
    """Scripted provider: replies from a function, counts calls."""

    def __init__(self, fn=None):
        self.calls = 0
        self.fn = fn or (lambda sys_ins, hist, msg:
                         ("Registration is free, and it takes about "
                          "a minute.", 120, 12))

    def complete(self, system_instruction, history, message):
        self.calls += 1
        self.last_system = system_instruction
        self.last_history = history
        return self.fn(system_instruction, history, message)


class ExplodingProvider:
    def complete(self, system_instruction, history, message):
        raise chat_mod.ProviderError("boom")


def _service(provider, config=None):
    tmp = tempfile.mkdtemp(prefix="npc_chat_test_")
    store = Store(os.path.join(tmp, "t.db"))
    return chat_mod.ChatService(store, provider=provider,
                                config=config), store


class TestChatService(unittest.TestCase):
    def test_grounded_answer_with_sources(self):
        svc, _store = _service(FakeProvider())
        status, body = svc.post_chat(
            {"message": "How do I register my own work?",
             "page": "/help"}, "203.0.113.7")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "ok")
        self.assertTrue(body["thread_id"].startswith("cht_"))
        self.assertIn("Registration is free", body["reply"])
        self.assertTrue(body["sources"], "grounded answer has sources")
        for s in body["sources"]:
            self.assertIn("title", s)
            self.assertIn("path", s)

    def test_thread_continues(self):
        svc, store = _service(FakeProvider())
        _s, b1 = svc.post_chat({"message": "What does unknown mean?"},
                               "203.0.113.7")
        _s, b2 = svc.post_chat(
            {"message": "And the two check colors?",
             "thread_id": b1["thread_id"]}, "203.0.113.7")
        self.assertEqual(b1["thread_id"], b2["thread_id"])
        self.assertEqual(len(store.get_chat_turns(b1["thread_id"])), 4)

    def test_validation(self):
        svc, _store = _service(FakeProvider())
        self.assertEqual(svc.post_chat({}, "1.2.3.4")[0], 422)
        self.assertEqual(svc.post_chat({"message": "  "}, "1.2.3.4")[0],
                         422)
        self.assertEqual(
            svc.post_chat({"message": "x" * 1001}, "1.2.3.4")[0], 422)
        self.assertEqual(
            svc.post_chat({"message": "hi", "thread_id": "nope"},
                          "1.2.3.4")[0], 422)

    def test_post_check_failure_becomes_no_answer(self):
        bad = FakeProvider(lambda s, h, m: (
            "Sure, see https://example.com/steal and write to "
            "someone@other.example for details.", 50, 20))
        svc, store = _service(bad)
        status, body = svc.post_chat(
            {"message": "How do I register my own work?"}, "203.0.113.7")
        self.assertEqual(status, 200)
        self.assertEqual(body["reply"], chat_mod.NO_ANSWER)
        self.assertEqual(body["sources"], [])
        turns = store.get_chat_turns(body["thread_id"])
        self.assertTrue(turns[-1]["no_answer"])

    def test_verdict_language_is_replaced(self):
        bad = FakeProvider(lambda s, h, m: (
            "Yes, demo-tag-001 is verified and authentic.", 50, 10))
        svc, _store = _service(bad)
        _s, body = svc.post_chat(
            {"message": "Is demo-tag-001 genuine?"}, "203.0.113.7")
        self.assertEqual(body["reply"], chat_mod.NO_ANSWER)

    def test_overlong_reply_is_replaced(self):
        bad = FakeProvider(lambda s, h, m: ("word " * 400, 50, 800))
        svc, _store = _service(bad)
        _s, body = svc.post_chat(
            {"message": "How do I register my own work?"}, "203.0.113.7")
        self.assertEqual(body["reply"], chat_mod.NO_ANSWER)

    def test_cap_governor_rests_without_calling_provider(self):
        provider = FakeProvider()
        config = chat_mod.ChatConfig(daily_cap_micro=1)  # one micro
        svc, store = _service(provider, config)
        _s, b1 = svc.post_chat({"message": "What does unknown mean?"},
                               "203.0.113.7")
        self.assertEqual(b1["state"], "ok")
        self.assertEqual(provider.calls, 1)
        # Estimated spend now exceeds the one-micro cap: the next
        # turn rests, and the provider is NOT called again.
        _s, b2 = svc.post_chat({"message": "What does unknown mean?"},
                               "203.0.113.8")
        self.assertEqual(b2["state"], "off")
        self.assertEqual(b2["reply"], chat_mod.OFF_MESSAGE)
        self.assertEqual(provider.calls, 1)

    def test_unconfigured_provider_rests(self):
        svc, _store = _service(None)
        status, body = svc.post_chat({"message": "Hello"}, "203.0.113.7")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "off")
        self.assertEqual(body["reply"], chat_mod.OFF_MESSAGE)

    def test_provider_failure_rests(self):
        svc, _store = _service(ExplodingProvider())
        _s, body = svc.post_chat({"message": "Hello"}, "203.0.113.7")
        self.assertEqual(body["state"], "off")
        self.assertEqual(body["reply"], chat_mod.OFF_MESSAGE)

    def test_provider_failure_is_logged_with_status(self):
        # The Oct 21 instrumentation: a swallowed ProviderError now
        # leaves a trace carrying the type and HTTP status (and
        # nothing else: no message body, no key material).
        class StatusProvider:
            def complete(self, system_instruction, history, message):
                raise chat_mod.ProviderError(
                    "gemini call failed: HTTPError", status=429,
                    cause_type="HTTPError")

        svc, _store = _service(StatusProvider())
        with self.assertLogs("npc_verify.chat", level="WARNING") as cm:
            _s, body = svc.post_chat({"message": "Hello"},
                                     "203.0.113.7")
        self.assertEqual(body["state"], "off")
        line = " ".join(cm.output)
        self.assertIn("error_type=HTTPError", line)
        self.assertIn("http_status=429", line)

    def test_provider_failure_logged_when_no_status(self):
        svc, _store = _service(ExplodingProvider())
        with self.assertLogs("npc_verify.chat", level="WARNING") as cm:
            svc.post_chat({"message": "Hello"}, "203.0.113.7")
        line = " ".join(cm.output)
        self.assertIn("error_type=ProviderError", line)
        self.assertIn("http_status=None", line)

    def test_per_ip_hour_limit(self):
        svc, _store = _service(FakeProvider())
        for i in range(chat_mod.IP_PER_HOUR):
            status, _b = svc.post_chat(
                {"message": "What does unknown mean?"}, "198.51.100.3")
            self.assertEqual(status, 200, "turn %d" % i)
        status, body = svc.post_chat(
            {"message": "What does unknown mean?"}, "198.51.100.3")
        self.assertEqual(status, 429)
        self.assertEqual(body["error"], "rate_limited")
        # A different IP is unaffected.
        status, _b = svc.post_chat(
            {"message": "What does unknown mean?"}, "198.51.100.4")
        self.assertEqual(status, 200)

    def test_thread_cap(self):
        svc, _store = _service(FakeProvider())
        tid = None
        for i in range(chat_mod.MAX_TURNS_PER_THREAD):
            # Rotate IPs: the thread cap is per thread, and one IP
            # would hit the per-hour limit first (by design).
            _s, body = svc.post_chat(
                {"message": "What does unknown mean?", "thread_id": tid},
                "203.0.113.%d" % (10 + i))
            tid = body["thread_id"]
        provider_calls = svc.provider.calls
        _s, body = svc.post_chat(
            {"message": "One more?", "thread_id": tid}, "203.0.113.7")
        self.assertEqual(body["reply"], chat_mod.LONG_CONVERSATION)
        self.assertEqual(svc.provider.calls, provider_calls)

    def test_feedback_round_trip_and_quiet_unknowns(self):
        svc, store = _service(FakeProvider())
        _s, b = svc.post_chat({"message": "What does unknown mean?"},
                              "203.0.113.7")
        tid = b["thread_id"]
        status, fb = svc.post_feedback(
            {"thread_id": tid, "turn": 1, "rating": "up",
             "comment": "clear"})
        self.assertEqual((status, fb), (200, {"recorded": True}))
        rows = store.get_chat_feedback(tid)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["rating"], "up")
        # Unknown thread / bad turn / bad rating: quiet, not errors.
        for payload in (
                {"thread_id": "cht_unknown0", "turn": 1,
                 "rating": "up"},
                {"thread_id": tid, "turn": 99, "rating": "up"},
                {"thread_id": tid, "turn": 1, "rating": "meh"},
                {"thread_id": tid, "turn": "1", "rating": "up"},
                {}):
            status, fb = svc.post_feedback(payload)
            self.assertEqual((status, fb), (200, {"recorded": False}),
                             payload)

    def test_ttl_fields_are_90_days(self):
        svc, store = _service(FakeProvider())
        _s, b = svc.post_chat({"message": "What does unknown mean?"},
                              "203.0.113.7")
        turns = store.get_chat_turns(b["thread_id"])
        now = time.time()
        for t in turns:
            self.assertGreater(t["ttl_epoch"], now + 89 * 86400)
            self.assertLess(t["ttl_epoch"], now + 91 * 86400)
        svc.post_feedback({"thread_id": b["thread_id"], "turn": 1,
                           "rating": "down"})
        fb = store.get_chat_feedback(b["thread_id"])[0]
        self.assertGreater(fb["ttl_epoch"], now + 89 * 86400)

    def test_transcripts_hold_no_secrets_or_prompt(self):
        svc, store = _service(FakeProvider())
        _s, b = svc.post_chat({"message": "What does unknown mean?"},
                              "203.0.113.7")
        blob = json.dumps(store.get_chat_turns(b["thread_id"]))
        for forbidden in ("NPC_CHAT_LLM_API_KEY", "system prompt",
                          "MATERIALS FOR THIS ANSWER", "x-goog-api-key"):
            self.assertNotIn(forbidden, blob)

    def test_history_window_and_delimiting(self):
        provider = FakeProvider()
        svc, _store = _service(provider)
        _s, b = svc.post_chat({"message": "What does unknown mean?"},
                              "203.0.113.7")
        svc.post_chat({"message": "And the check colors?",
                       "thread_id": b["thread_id"]}, "203.0.113.7")
        self.assertEqual(len(provider.last_history), 2)
        self.assertIn("MATERIALS FOR THIS ANSWER",
                      provider.last_system)


class _HttpStub(Exception):
    """Stands in for urllib.error.HTTPError: _call reads only
    .code and .headers."""

    def __init__(self, code, headers=None):
        super().__init__("HTTP %s" % code)
        self.code = code
        self.headers = headers or {}


class _FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self._body


class _FakeTime:
    """chat module time stand-in: the real monotonic clock, with
    sleeps recorded instead of taken."""

    def __init__(self):
        self.sleeps = []

    def monotonic(self):
        return time.monotonic()

    def sleep(self, seconds):
        self.sleeps.append(seconds)


class TestGeminiProvider(unittest.TestCase):
    """The Oct 21 retry hardening and generation budget (fixes
    b and c from the Oct 18 off-state diagnosis). No network: the
    urlopen and the clock are fakes."""

    def _provider(self):
        return chat_mod.GeminiChatProvider("test-key")

    def _run_call(self, provider, outcomes):
        calls = {"n": 0}

        def fake_urlopen(req, timeout=None):
            outcome = outcomes[min(calls["n"], len(outcomes) - 1)]
            calls["n"] += 1
            if isinstance(outcome, Exception):
                raise outcome
            return _FakeResponse(outcome)

        fake_time = _FakeTime()
        with mock.patch.object(chat_mod.urllib.request, "urlopen",
                               fake_urlopen), \
                mock.patch.object(chat_mod, "time", fake_time):
            try:
                result = provider._call({"contents": []})
            except Exception as exc:
                return None, exc, calls["n"], fake_time.sleeps
        return result, None, calls["n"], fake_time.sleeps

    def test_success_first_try_no_sleep(self):
        result, exc, n, sleeps = self._run_call(
            self._provider(), [{"ok": True}])
        self.assertIsNone(exc)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(n, 1)
        self.assertEqual(sleeps, [])

    def test_throttles_retry_then_succeed(self):
        result, exc, n, sleeps = self._run_call(
            self._provider(),
            [_HttpStub(429), _HttpStub(503), {"ok": True}])
        self.assertIsNone(exc)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(n, 3)
        self.assertEqual(len(sleeps), 2)
        # Exponential bases 1s then 2s, jittered by 0.5x-1.5x.
        self.assertTrue(0.5 <= sleeps[0] <= 1.5)
        self.assertTrue(1.0 <= sleeps[1] <= 3.0)

    def test_non_transient_status_raises_at_once(self):
        result, exc, n, sleeps = self._run_call(
            self._provider(), [_HttpStub(400)])
        self.assertIsNone(result)
        self.assertIsInstance(exc, _HttpStub)
        self.assertEqual(exc.code, 400)
        self.assertEqual(n, 1)
        self.assertEqual(sleeps, [])

    def test_attempts_cap_at_four(self):
        result, exc, n, sleeps = self._run_call(
            self._provider(), [_HttpStub(429)] * 6)
        self.assertIsNone(result)
        self.assertIsInstance(exc, _HttpStub)
        self.assertEqual(n, 4)
        self.assertEqual(len(sleeps), 3)

    def test_retry_after_header_is_honored(self):
        result, exc, n, sleeps = self._run_call(
            self._provider(),
            [_HttpStub(429, {"Retry-After": "7"}), {"ok": True}])
        self.assertIsNone(exc)
        self.assertEqual(sleeps, [7.0])

    def test_retry_after_is_capped(self):
        result, exc, n, sleeps = self._run_call(
            self._provider(),
            [_HttpStub(503, {"Retry-After": "60"}), {"ok": True}])
        self.assertIsNone(exc)
        self.assertEqual(sleeps, [chat_mod.GeminiChatProvider
                                  ._RETRY_AFTER_CAP_S])

    def test_deadline_stops_further_retries(self):
        provider = self._provider()
        provider._OVERALL_BUDGET_S = 0.2
        provider._BACKOFF_BASE_S = (5.0, 5.0, 5.0)
        result, exc, n, sleeps = self._run_call(
            provider, [_HttpStub(429)] * 4)
        self.assertIsNone(result)
        self.assertIsInstance(exc, _HttpStub)
        self.assertEqual(n, 1)
        self.assertEqual(sleeps, [])

    def test_complete_payload_budget_and_thinking(self):
        captured = {}

        class CapturingProvider(chat_mod.GeminiChatProvider):
            def _call(self, payload):
                captured.update(payload)
                return {"candidates": [{"content": {"parts": [
                    {"text": " hello "}]}}],
                    "usageMetadata": {"promptTokenCount": 11,
                                      "candidatesTokenCount": 7}}

        reply, tok_in, tok_out = CapturingProvider(
            "test-key").complete("sys", [], "hi")
        self.assertEqual((reply, tok_in, tok_out), ("hello", 11, 7))
        cfg = captured["generationConfig"]
        self.assertEqual(cfg["maxOutputTokens"], 1200)
        self.assertEqual(cfg["thinkingConfig"]["thinkingBudget"], 0)

    def test_complete_wraps_error_with_status(self):
        class FailingProvider(chat_mod.GeminiChatProvider):
            def _call(self, payload):
                raise _HttpStub(503)

        with self.assertRaises(chat_mod.ProviderError) as ctx:
            FailingProvider("test-key").complete("sys", [], "hi")
        self.assertEqual(ctx.exception.status, 503)
        self.assertEqual(ctx.exception.cause_type, "_HttpStub")


class TestCorpus(unittest.TestCase):
    def test_corpus_shape(self):
        chunks = chat_mod.load_corpus()
        self.assertGreaterEqual(len(chunks), 40)
        self.assertLessEqual(len(chunks), 70)
        hosts = set()
        for c in chunks:
            self.assertTrue(c["title"])
            self.assertTrue(c["text"])
            self.assertNotIn("—", c["text"])
            hosts.add(c["source"].split("/")[2])
        self.assertEqual(hosts, {"verify.npclabs.xyz", "npclabs.xyz",
                                 "paragraph.com"})

    def test_retrieval_finds_the_right_pages(self):
        top = chat_mod.retrieve("Where can I use the plugins?")
        self.assertTrue(top)
        self.assertTrue(any("plugin" in c["title"].lower()
                            for c in top))
        top = chat_mod.retrieve("How do I register my own work?")
        self.assertTrue(any("register" in c["title"].lower()
                            for c in top))


class TestChatDynamoDB(unittest.TestCase):
    def setUp(self):
        self.table = fake_boto3.FakeTable("npc-verify-store-chat")
        self.store = DynamoDBStore(table=self.table)

    def test_chat_round_trip_with_ttl_attribute(self):
        svc = chat_mod.ChatService(self.store, provider=FakeProvider())
        status, body = svc.post_chat(
            {"message": "What does unknown mean?"}, "203.0.113.7")
        self.assertEqual(status, 200)
        turns = self.store.get_chat_turns(body["thread_id"])
        self.assertEqual(len(turns), 2)
        # The raw item carries the ttl_epoch attribute DynamoDB TTL
        # reads (next to the data envelope).
        item = self.table.get_item(
            Key={"pk": "CHAT#" + body["thread_id"], "sk": "000001"})
        self.assertIn("ttl_epoch", item["Item"])
        self.assertGreater(item["Item"]["ttl_epoch"],
                           int(time.time()) + 89 * 86400)
        # Daily counter, feedback, and the day index all land.
        from npc_verify.models import utcnow_iso
        day = utcnow_iso()[:10]
        self.assertEqual(
            self.store.get_chat_daily(day)["conversations"], 1)
        self.assertIn(body["thread_id"], self.store.chat_threads_on(day))
        svc.post_feedback({"thread_id": body["thread_id"], "turn": 1,
                           "rating": "up"})
        self.assertEqual(
            len(self.store.get_chat_feedback(body["thread_id"])), 1)
        cap_item = self.table.get_item(Key={"pk": "CHATCAP", "sk": day})
        self.assertIn("ttl_epoch", cap_item["Item"])


class TestChatHTTP(ApiTestCase):
    def setUp(self):
        self.app.chat.provider = FakeProvider()

    def _post(self, path, body, headers=None):
        return self.request("POST", path, body=body, headers=headers)

    def test_chat_answer_is_unsigned(self):
        status, headers, data = self._post(
            "/v1/chat", {"message": "What does unknown mean?",
                         "page": "/help"})
        self.assertEqual(status, 200)
        self.assertNotIn("X-NPC-Signature", headers)
        self.assertNotIn("X-NPC-Key-ID", headers)
        body = json.loads(data)
        self.assertEqual(body["state"], "ok")
        self.assertTrue(body["thread_id"].startswith("cht_"))
        # A signed endpoint still signs, for contrast.
        status, headers, _d = self.get("/v1/health")
        self.assertIn("X-NPC-Signature", headers)

    def test_chat_validation_over_http(self):
        status, _h, _d = self._post("/v1/chat", {})
        self.assertEqual(status, 422)
        status, _h, _d = self._post(
            "/v1/chat", {"message": "x" * 1001})
        self.assertEqual(status, 422)

    def test_feedback_over_http_is_quiet(self):
        _s, _h, data = self._post(
            "/v1/chat", {"message": "What does unknown mean?"})
        tid = json.loads(data)["thread_id"]
        status, headers, data = self._post(
            "/v1/chat/feedback",
            {"thread_id": tid, "turn": 1, "rating": "down"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data), {"recorded": True})
        self.assertNotIn("X-NPC-Signature", headers)
        status, _h, data = self._post(
            "/v1/chat/feedback",
            {"thread_id": "cht_nope000", "turn": 1, "rating": "up"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data), {"recorded": False})

    def test_idempotent_replay_is_unsigned_and_identical(self):
        headers = {"Idempotency-Key": "chat-test-key-1"}
        s1, h1, d1 = self._post(
            "/v1/chat", {"message": "What does unknown mean?"},
            headers=headers)
        calls = self.app.chat.provider.calls
        s2, h2, d2 = self._post(
            "/v1/chat", {"message": "What does unknown mean?"},
            headers=headers)
        self.assertEqual((s1, d1), (s2, d2))
        self.assertNotIn("X-NPC-Signature", h2)
        self.assertEqual(self.app.chat.provider.calls, calls)


if __name__ == "__main__":
    unittest.main()
