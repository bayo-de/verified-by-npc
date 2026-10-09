"""Tool tests: get_canon, speak, voice_check.

Exercises the real handlers through the MCP dispatch layer.
"""
import json

from tests.helpers import McpTestCase


class TestGetCanon(McpTestCase):
    def test_returns_canon_with_version(self):
        is_error, text = self.call_tool("get_canon", {})
        self.assertFalse(is_error)
        payload = json.loads(text)
        self.assertEqual(payload["character"], "biblo")
        self.assertEqual(payload["canon_version"], "0.1")
        self.assertIn("Biblo", payload["canon"])
        self.assertIn("owl librarian", payload["canon"].lower())


class TestSpeak(McpTestCase):
    def test_empty_draft_is_error(self):
        is_error, text = self.call_tool("speak", {"draft": ""})
        self.assertTrue(is_error)
        self.assertIn("draft", text.lower())

    def test_removes_em_dash(self):
        is_error, text = self.call_tool(
            "speak", {"draft": "The work is done \u2014 finally."})
        self.assertFalse(is_error)
        payload = json.loads(text)
        self.assertNotIn("\u2014", payload["rewritten"])
        self.assertTrue(any("em dash" in t for t in
                            payload["transforms_applied"]))

    def test_removes_owl_emoji(self):
        is_error, text = self.call_tool(
            "speak", {"draft": "Well said \U0001F989"})
        self.assertFalse(is_error)
        payload = json.loads(text)
        self.assertNotIn("\U0001F989", payload["rewritten"])
        self.assertTrue(any("owl emoji" in t for t in
                            payload["transforms_applied"]))

    def test_strips_leading_opener(self):
        is_error, text = self.call_tool(
            "speak", {"draft": "Great question! Here is the answer."})
        self.assertFalse(is_error)
        payload = json.loads(text)
        self.assertEqual(payload["rewritten"], "Here is the answer.")
        self.assertTrue(any("opener" in t for t in
                            payload["transforms_applied"]))

    def test_clean_draft_passes_through(self):
        draft = "The work is on track. I will check back Thursday."
        is_error, text = self.call_tool("speak", {"draft": draft})
        self.assertFalse(is_error)
        payload = json.loads(text)
        self.assertEqual(payload["rewritten"], draft)
        self.assertEqual(payload["transforms_applied"], [])

    def test_notes_honesty(self):
        is_error, text = self.call_tool("speak", {"draft": "Hello."})
        self.assertFalse(is_error)
        payload = json.loads(text)
        self.assertTrue(any("Mechanical pass only" in n for n in
                            payload["notes"]))


class TestVoiceCheck(McpTestCase):
    def test_empty_text_is_error(self):
        is_error, text = self.call_tool("voice_check", {"text": "  "})
        self.assertTrue(is_error)
        self.assertIn("text", text.lower())

    def test_clean_text_scores_100(self):
        is_error, text = self.call_tool(
            "voice_check",
            {"text": "The work is on track. I will check back Thursday."})
        self.assertFalse(is_error)
        payload = json.loads(text)
        self.assertEqual(payload["score"], 100)
        self.assertEqual(payload["violations"], [])

    def test_em_dash_violation(self):
        is_error, text = self.call_tool(
            "voice_check", {"text": "Done \u2014 finally."})
        self.assertFalse(is_error)
        payload = json.loads(text)
        self.assertLess(payload["score"], 100)
        rules = [v["rule"] for v in payload["violations"]]
        self.assertIn("no_em_dash", rules)
        self.assertTrue(all(v["excerpt"] and v["suggestion"]
                            for v in payload["violations"]))

    def test_owl_emoji_violation(self):
        is_error, text = self.call_tool(
            "voice_check", {"text": "Well said \U0001F989"})
        self.assertFalse(is_error)
        payload = json.loads(text)
        rules = [v["rule"] for v in payload["violations"]]
        self.assertIn("no_owl_emoji", rules)

    def test_ai_slop_violation(self):
        is_error, text = self.call_tool(
            "voice_check",
            {"text": "Great question, let us delve into it."})
        self.assertFalse(is_error)
        payload = json.loads(text)
        rules = [v["rule"] for v in payload["violations"]]
        self.assertIn("no_ai_slop", rules)
        self.assertEqual(payload["score"], 100 - 10 - 10)

    def test_score_floors_at_zero(self):
        is_error, text = self.call_tool(
            "voice_check", {"text": "\U0001F989" * 10})
        self.assertFalse(is_error)
        payload = json.loads(text)
        self.assertEqual(payload["score"], 0)

    def test_long_sentences_are_notes_not_violations(self):
        long_text = ("This is a deliberately overlong sentence that keeps "
                     "going well past any reasonable notion of brevity, "
                     "piling clause upon clause without mercy, because it "
                     "wants to trigger the subtraction note and prove the "
                     "point about radical editing.")
        is_error, text = self.call_tool("voice_check", {"text": long_text})
        self.assertFalse(is_error)
        payload = json.loads(text)
        self.assertEqual(payload["violations"], [])
        self.assertTrue(any("subtraction" in n for n in payload["notes"]))
