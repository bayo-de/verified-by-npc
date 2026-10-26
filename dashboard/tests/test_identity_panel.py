"""Identity panel (federated identity signals, phase 1): the
dashboard half.

Pins: the server-side renderer prints the API panel payload's own
heading, labels, and boundary line, and renders nothing when
nothing is linked; a registration card carries the panel container
for the live loader; the live-lookup scripts ship the loader and
invoke it for the looked-up record. The words come from the API
payload, so this suite checks structure and wiring, not copy.
"""
import unittest

try:
    from tests import helpers  # noqa: F401  (puts the package on path)
except ImportError:  # pragma: no cover - direct invocation
    import helpers  # noqa: F401

from dashboard import views  # noqa: E402


PANEL = {
    "record_id": "reg_test",
    "record_status": "registered_checks_pending",
    "record_status_label": "Registered, checks pending",
    "panel": {
        "heading": "Identity the owner has linked",
        "intro": "These checks were run by the services named.",
        "boundary": "Linked checks show what the services named "
                    "confirmed about the owner.",
        "groups": [{
            "assurance_class": "account_control",
            "heading": "Accounts the owner controls",
            "signals": [{
                "provider": "github", "signal": "account",
                "assurance_class": "account_control",
                "label": "GitHub: the owner controls a GitHub "
                         "account.",
                "subject_ref": "88342117", "state": "current",
            }],
        }],
        "not_current": [{
            "provider": "coinbase", "signal": "verified_account",
            "assurance_class": "kyc_backed_account",
            "label": "Coinbase: this wallet belongs to a Coinbase "
                     "customer.",
            "subject_ref": "0x" + "12" * 20, "state": "revoked",
            "reason": "The service withdrew this confirmation.",
        }],
        "not_current_note": "A link below is no longer confirmed.",
        "signals_current": 1,
        "signals_not_current": 1,
    },
}


class IdentityPanelHtmlTests(unittest.TestCase):

    def test_renders_payload_words(self):
        html = views.identity_panel_html(PANEL)
        self.assertIn("Identity the owner has linked", html)
        self.assertIn("Accounts the owner controls", html)
        self.assertIn("GitHub: the owner controls a GitHub account.",
                      html)
        self.assertIn("No longer confirmed", html)
        self.assertIn("The service withdrew this confirmation.",
                      html)
        self.assertIn("Linked checks show what the services named "
                      "confirmed about the owner.", html)

    def test_renders_nothing_when_nothing_linked(self):
        empty = {"panel": {"heading": "Identity the owner has "
                            "linked", "groups": [],
                            "not_current": []}}
        self.assertEqual(views.identity_panel_html(empty), "")
        self.assertEqual(views.identity_panel_html(None), "")
        self.assertEqual(views.identity_panel_html({}), "")

    def test_escapes_payload_text(self):
        hostile = {"panel": {
            "heading": "<script>alert(1)</script>", "intro": "x",
            "boundary": "y",
            "groups": [{"heading": "h", "signals": [
                {"label": "<b>bold</b>"}]}],
            "not_current": []}}
        html = views.identity_panel_html(hostile)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<b>bold</b>", html)


class PanelWiringTests(unittest.TestCase):

    def test_registration_card_carries_the_container(self):
        rec = {
            "record_type": "npc.registry.agent_registration",
            "record_id": "reg_abc",
            "kind": "agent", "agent_name": "Harbor Helper",
            "owner_name": "Test Owner",
            "registered_at": "2026-10-19T00:00:00+00:00",
            "key_id": "k1", "checks_run": [], "checks_not_run": [],
        }
        html = views.registration_result(rec)
        self.assertIn('class="npc-identity-panel"', html)
        self.assertIn('data-record-id="reg_abc"', html)

    def test_live_lookup_ships_the_loader(self):
        html = views.live_lookup_marker("https://api.example")
        self.assertIn("npcIdentityPanel", html)
        self.assertIn("/identity-panel", html)

    def test_lookup_flow_invokes_the_loader(self):
        self.assertIn("window.npcIdentityPanel(id, base)",
                      views.LIVE_LOOKUP_JS)


if __name__ == "__main__":
    unittest.main()
