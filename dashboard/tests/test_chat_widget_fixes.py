"""Chat widget fixes (2026-11-23): string-level pins.

The DOM-level behaviour (close collapses the panel, a fresh load
starts closed or restores the saved state, internal source labels
never render) is exercised by tests/chat_widget.test.js under
Node/jsdom. These pins cover the shipped text the behaviour
depends on: the [hidden] display rule that makes toggling the
panel visible at all, the complete placeholder, the storage key,
the Escape handler, and the source-label filter.
"""
import unittest

try:
    from tests import helpers  # noqa: F401  (puts the package on path)
except ImportError:  # pragma: no cover - direct invocation
    import helpers  # noqa: F401

from dashboard import views  # noqa: E402


class ChatWidgetFixPins(unittest.TestCase):

    def test_hidden_panels_are_display_none(self):
        # .npc-chat-panel sets display:flex, which overrides the
        # hidden attribute's built-in display:none. Without this
        # rule the panel shows on every load and neither the
        # launcher nor the close button can ever hide it.
        self.assertIn(".npc-chat-panel[hidden]{display:none}",
                      views.CSS)

    def test_placeholder_is_complete_and_short(self):
        html = views.chat_panel_html("https://api.example", True)
        self.assertIn(
            'placeholder="Ask about records or verification"', html)
        self.assertNotIn("registering, the checks", html)

    def test_open_state_is_remembered_and_escape_closes(self):
        js = views.CHAT_JS
        self.assertIn("npc-chat-open", js)
        self.assertIn("localStorage", js)
        self.assertIn('"Escape"', js)
        self.assertIn("setOpen(false, false)", js)

    def test_source_labels_are_filtered(self):
        js = views.CHAT_JS
        self.assertIn("safeSources", js)
        self.assertIn("unable to verify", js)
        self.assertIn("srcs-label", js)
        self.assertIn(".npc-chat-msg .srcs a{display:block",
                      views.CSS)

    def test_panel_starts_hidden(self):
        html = views.chat_panel_html("https://api.example", True)
        self.assertIn('id="npc-chat-float" hidden', html)


if __name__ == "__main__":
    unittest.main()
