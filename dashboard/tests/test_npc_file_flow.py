"""Register a file (the .npc flow) on the Verify yours page.

The browser side of this flow hashes the visitor's file on the
device, registers the fingerprint with the API, and builds the
downloadable .npc credential with the shared npc_credential.js
module. These tests pin the page wiring and the honest copy; the
module itself is unit tested in Node (npc_credential.test.js), and
the full local round trip (register a file, download the .npc,
verify its hash and signature) runs in the e2e driver beside this
file (npc_e2e_driver.mjs + npc_e2e_validate.py).
"""
import unittest

try:
    from tests.helpers import DashTestCase
except ImportError:  # pragma: no cover - direct invocation
    from helpers import DashTestCase

try:
    from tests import helpers  # noqa: F401  (puts the package on path)
except ImportError:  # pragma: no cover - direct invocation
    import helpers  # noqa: F401


class NpcFileFlowPageTest(DashTestCase):
    def test_verify_page_renders_the_file_flow(self):
        status, body = self.get("/verify")
        self.assertEqual(status, 200)
        self.assertIn("Register a file", body)
        for marker in ('id="npc-file-register"', 'id="npc-file-drop"',
                       'id="npc-file-input"', 'id="npc-file-form"',
                       'id="npc-file-hashline"',
                       'id="npc-file-progress"', 'id="npc-file-result"',
                       'id="npc-file-error"', 'id="npc-file-submit"'):
            self.assertIn(marker, body)
        # the file form, field for field
        for field_id in ('id="npc-f-title"', 'id="npc-f-kind"',
                         'id="npc-f-name"', 'id="npc-f-email"'):
            self.assertIn(field_id, body)
        for name in ("title", "kind", "creator_name", "creator_email"):
            self.assertIn('name="%s"' % name, body)
        # the kind choices a file can be registered under
        for value in ("image", "audio", "video", "text", "other"):
            self.assertIn('<option value="%s">' % value, body)

    def test_module_and_wiring_are_inlined(self):
        status, body = self.get("/verify")
        self.assertEqual(status, 200)
        # the npc/1.0 exporter module, inlined from npc_credential.js
        self.assertIn("NPCCredential", body)
        self.assertIn("npc/1.0", body)
        self.assertIn("did:web:npclabs.xyz", body)
        self.assertIn("buildCredential", body)
        self.assertIn("credentialFilename", body)
        # the wiring: hash locally, register by hash, never upload
        self.assertIn('"/v1/register/content"', body)
        self.assertIn('"sha256:" + state.hash', body)
        # the register lane points at the same API base as the page
        self.assertIn('id="npc-file-register" data-api-base="%s"'
                      % self.api_url, body)

    def test_copy_is_honest_about_registration(self):
        status, body = self.get("/verify")
        self.assertEqual(status, 200)
        self.assertIn("The file never leaves your device.", body)
        self.assertIn("Registration is the signed starting record, "
                      "not verification.", body)
        self.assertIn("no verification mark comes with registration",
                      body)
        self.assertNotIn(" — ", body)

    def test_existing_forms_still_render(self):
        # the file flow is an addition, not a replacement
        status, body = self.get("/verify")
        self.assertEqual(status, 200)
        self.assertIn('id="npc-content-form"', body)
        self.assertIn('id="npc-agent-form"', body)
        self.assertIn("Register a piece of work", body)
        self.assertIn("Register an agent", body)


if __name__ == "__main__":
    unittest.main()
