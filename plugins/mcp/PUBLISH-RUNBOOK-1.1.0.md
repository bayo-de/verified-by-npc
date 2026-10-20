# Publish Runbook — npc-verify-mcp 1.1.0 to PyPI

Prepared: 2026-10-18. Bayo gave the GO on Oct 18, 2026.
Status: **READY, waiting only on Bayo's fresh project-scoped PyPI token.**
Nothing in this runbook has been executed against PyPI yet. No token has been requested, received, or stored.

## Artifacts (verified on disk, 2026-10-18)

Directory: `~/workspace/grand-fleet/verified-by-npc/plugins/mcp/dist/`

| File | Size (bytes) | SHA-256 |
|---|---|---|
| `npc_verify_mcp-1.1.0-py3-none-any.whl` | 21,284 | `05842bec3ff9e45194f512a9ce12e6d29abc964ab35de72bf35d49634d4fc8d3` |
| `npc_verify_mcp-1.1.0.tar.gz` | 30,712 | `7f962067693c233942cbf6655242a0ad860624ef59c1492026845e1531d22656` |

Version confirmed as 1.1.0 in three places: `pyproject.toml` (`version = "1.1.0"`),
`npc_verify_mcp/__init__.py` (`__version__ = "1.1.0"`), and `server.json`.

Twine check (run 2026-10-18 with twine in an isolated venv, see Step 0): **both artifacts PASSED**.

Live PyPI state at prep time: latest published version is **1.0.1** (uploaded 2026-10-15).
1.1.0 is not on PyPI yet. Project: https://pypi.org/project/npc-verify-mcp/ (owner: npc-labs).

## Token rules (hard limits)

- Bayo creates a **fresh API token scoped to the single project `npc-verify-mcp`** at
  https://pypi.org/manage/account/token/ (account: npc-labs). Not an account-wide token.
- The token is used **transiently, via an environment variable in one shell session only**.
- It is **never** written to a file, a `.pypirc`, shell history, this runbook, memory, or chat logs.
- It is **revoked immediately after the upload verifies** (Step 4).

## Step 0 — Tooling (isolated venv; system Python has no twine)

```bash
cd /tmp
rm -rf twinecheck
python3 -m venv twinecheck
./twinecheck/bin/pip install -q twine
TWINE=/tmp/twinecheck/bin/twine
```

## Step 1 — Pre-flight (no token needed)

```bash
cd ~/workspace/grand-fleet/verified-by-npc/plugins/mcp

# Artifacts unchanged since prep?
sha256sum dist/npc_verify_mcp-1.1.0-py3-none-any.whl dist/npc_verify_mcp-1.1.0.tar.gz
# Expect:
# 05842bec3ff9e45194f512a9ce12e6d29abc964ab35de72bf35d49634d4fc8d3  dist/npc_verify_mcp-1.1.0-py3-none-any.whl
# 7f962067693c233942cbf6655242a0ad860624ef59c1492026845e1531d22656  dist/npc_verify_mcp-1.1.0.tar.gz

# Metadata still clean?
$TWINE check dist/npc_verify_mcp-1.1.0-py3-none-any.whl dist/npc_verify_mcp-1.1.0.tar.gz
# Expect: PASSED for both.

# 1.1.0 still unpublished? (info.version should read 1.0.1)
curl -s https://pypi.org/pypi/npc-verify-mcp/json | python3 -c "import sys,json; print(json.load(sys.stdin)['info']['version'])"
```

If any check fails, STOP and report. Do not upload.

## Step 2 — Receive the token (transient, no echo, no history)

Bayo hands over the token through the secure channel he chooses. In the publish shell:

```bash
# set +o history keeps the session out of shell history files where supported
set +o history 2>/dev/null || true
read -rsp "Paste the npc-verify-mcp PyPI token, then Enter: " PYPI_TOKEN; echo
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="$PYPI_TOKEN"
unset PYPI_TOKEN
```

Never print `TWINE_PASSWORD`. Never paste the token into any other command.

## Step 3 — Upload (exactly these two files, nothing else)

```bash
cd ~/workspace/grand-fleet/verified-by-npc/plugins/mcp
$TWINE upload --non-interactive \
  dist/npc_verify_mcp-1.1.0-py3-none-any.whl \
  dist/npc_verify_mcp-1.1.0.tar.gz
```

Expect twine to report both files uploaded to https://pypi.org/project/npc-verify-mcp/1.1.0/.

## Step 4 — Verify live, then revoke

```bash
# 1.1.0 is the live version and both files are listed?
curl -s https://pypi.org/pypi/npc-verify-mcp/json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['info']['version']); print(sorted(d['releases'].get('1.1.0',[{}])[0].get('filename') for _ in [0])); print([u['filename'] for u in d['urls']])"
pip index versions npc-verify-mcp 2>/dev/null || pip install npc-verify-mcp== 2>&1 | head -2
```

Then, immediately:

1. **Clear the session:** `unset TWINE_PASSWORD TWINE_USERNAME`
2. **Revoke the token** at https://pypi.org/manage/account/ (API tokens list, remove the
   token created for this publish). A project-scoped token that has served its one upload
   should not live on.
3. Spot-check the project page renders the 1.1.0 README correctly:
   https://pypi.org/project/npc-verify-mcp/1.1.0/
4. Report back: upload timestamps, the live version read-back, and confirmation the token was revoked.

## Notes

- If the upload errors midway (one file lands, the other fails): do NOT rebuild or re-version.
  Re-run Step 3 as-is; twine/PyPI will skip or reject the already-uploaded file, and the
  missing one can be uploaded alone with the same command naming only that file.
- A failed upload with an unknown outcome is not retried blindly: check the JSON API first
  (Step 4 read-back) to see what actually landed.
- The MCP registry `server.json` in this directory already carries version 1.1.0; the separate
  registry publish, if wanted, is a different step and is not part of this runbook.
