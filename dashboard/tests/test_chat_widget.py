"""Biblo chat widget on the dashboard (biblo-chat spec section 2).

- The floating button and panel ride every page; /help also carries
  the inline Ask Biblo section.
- The visitor notice is part of the panel, word for word.
- The widget talks to the chat endpoints and the feedback endpoint,
  renders the opening message, and has a resting path that disables
  only itself.
- The privacy policy describes the chat in the same change.
- The icon assets exist, are real images, and ship in the export.
"""
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)                       # dashboard package contents
sys.path.insert(0, os.path.dirname(BASE))      # the `dashboard` package itself

from tests.helpers import DashTestCase  # noqa: E402
from dashboard import export_static, views  # noqa: E402

NOTICE = ("Conversations may be read by the NPC team to improve "
          "these answers. Please do not share private details here.")
OPENING = ("Hello. I am Biblo, the assistant here at NPC Labs.")


class TestChatWidget(DashTestCase):
    def test_widget_on_every_page(self):
        for path in ("/", "/records", "/search", "/plugins", "/api",
                     "/privacy", "/help", "/verify", "/archive"):
            status, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn('id="npc-chat-btn"', body, path)
            self.assertIn('id="npc-chat-float"', body, path)
            self.assertIn("/assets/biblo-chat-icon-112.png", body, path)
            self.assertIn(NOTICE, body, path)
            self.assertIn("AI assistant for NPC Labs", body, path)
            for q in views.CHAT_STARTERS:
                self.assertIn('data-q="%s"' % q, body, path)

    def test_help_carries_the_inline_ask_biblo_section(self):
        status, body = self.get("/help")
        self.assertEqual(status, 200)
        self.assertIn("<h2>Ask Biblo</h2>", body)
        # Two panels on /help: the inline section and the floating one.
        self.assertEqual(body.count('class="npc-chat-panel'), 2)
        self.assertIn("It cannot look a record up", body)

    def test_widget_script_wires_chat_and_feedback(self):
        _status, body = self.get("/")
        self.assertIn(OPENING, body)
        self.assertIn("/v1/chat", body)
        self.assertIn("/v1/chat/feedback", body)
        self.assertIn("Biblo is not reachable right now", body)
        self.assertIn("That is a lot of questions for now", body)

    def test_widget_never_blocks_the_verify_form(self):
        _status, body = self.get("/verify")
        # The registration forms are present and not wrapped/disabled
        # by the widget; the panel starts hidden.
        self.assertIn('id="npc-content-form"', body)
        self.assertIn('id="npc-chat-float" hidden', body)

    def test_privacy_policy_describes_the_chat(self):
        _status, body = self.get("/privacy")
        self.assertIn("Talking with Biblo on this site", body)
        self.assertIn("kept for 90 days", body)
        self.assertIn("may be read by the NPC team", body)
        self.assertIn("Please do not share private details", body)

    def test_icon_assets_are_real_images(self):
        for rel in export_static.ASSET_FILES:
            path = os.path.join(BASE, rel)
            self.assertTrue(os.path.exists(path), rel)
            with open(path, "rb") as f:
                head = f.read(16)
            if rel.endswith(".png"):
                self.assertTrue(head.startswith(b"\x89PNG"), rel)
            else:
                self.assertTrue(head.startswith(b"RIFF")
                                and b"WEBP" in head, rel)

    def test_csp_allows_the_button_image(self):
        csp = dict(export_static.SECURITY_HEADERS)[
            "Content-Security-Policy"]
        self.assertIn("img-src 'self'", csp)
        self.assertIn("connect-src https://api.npclabs.xyz", csp)


if __name__ == "__main__":
    unittest.main()
