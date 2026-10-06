# Post-publish smoke test: npc-verify Gemini CLI extension

Run AFTER `bayo-de/npc-verify-gemini` is created AND the Gemini CLI gallery
crawler has indexed it. Indexing is roughly daily: the crawler auto-indexes
public repos carrying the `gemini-cli-extension` topic, and the listing appears
once the extension passes the crawler's validation. There is no manual
submission form. If `gemini extensions install` cannot find the extension, the
crawler has not indexed it yet: wait for the next cycle (check after 24-48h).

Requires: a machine with the Gemini CLI installed.
NOTE: `gemini` is NOT installed on this VM as of 2026-10-06, so this runs on a
scratch machine or after installing Gemini CLI here.

```bash
# 1. Install from the public repo
gemini extensions install github.com/bayo-de/npc-verify-gemini
# EXPECT: install succeeds

# 2. Confirm the extension is registered
gemini extensions list | grep -i npc
# EXPECT: npc-verify listed

# 3. Confirm the manifest and helper resolve at the expected install path
ls ~/.gemini/extensions/npc-verify/gemini-extension.json
python3 ~/.gemini/extensions/npc-verify/npc_verify_gemini explain_verification
# EXPECT: manifest listed; the explainer prints and exits 0 (no API key needed)

# 4. Live verification against a reachable API (needs API URL + verifier key)
export NPC_VERIFY_API_URL="http://127.0.0.1:8787"
export NPC_VERIFY_API_KEY='<your-verifier-key>'
python3 ~/.gemini/extensions/npc-verify/npc_verify_gemini verify_product --tag-id <known-tag-id>
# EXPECT: JSON verdict, signature checked, exit 0
# Then try a bogus tag id to confirm fail-closed behavior:
python3 ~/.gemini/extensions/npc-verify/npc_verify_gemini verify_product --tag-id no-such-tag
# EXPECT: "unknown", exit 0, never presented as verified
```

If step 1 fails before indexing: the repo, topic, and manifest are the
things to check (`gh repo view bayo-de/npc-verify-gemini --json topics`,
`gemini-extension.json` valid JSON at the repo root).
