# Verified by NPC - Gemini CLI extension: publish commands

One-shot publish to the public repo `bayo-de/npc-verify-gemini`.
Bayo approved 2026-10-06. Runbook: `PUBLISH-RUNBOOK.md`.

How to run:
1. Ask Bayo for the classic PAT (repo scope, 7-day expiry).
2. Replace `<PASTE-PAT-HERE>` below with the real token.
3. Run the whole block in one go (`bash` a saved copy, or paste into a fresh terminal).
   The token lives in shell memory only and is shredded at the end.

```bash
STG=~/workspace/grand-fleet/verified-by-npc/plugins/gemini/public-repo

# 0. Confirm the staged package is the validated one (36/36 green, scans clean)
cd "$STG"
find . -type f -not -path "./.git/*" | sort

# 1. Stop this shell from saving history (token hygiene)
set +o history

# 2. TRANSIENT token: shell memory only, never written to disk or logs
export GH_TOKEN='<PASTE-PAT-HERE>'
if [[ "$GH_TOKEN" == *"<PASTE-PAT-HERE>"* ]]; then
  echo "STOP: replace <PASTE-PAT-HERE> with Bayo's real token first."
  exit 1
fi
echo "$GH_TOKEN" | gh auth login --with-token
gh auth status
# EXPECT: "Logged in to github.com account bayo-de". STOP if it says anyone else.

# 3. Init local git, commit, create the public repo, push in one move
git init -b main
git add -A
git -c user.name="bayo-de" -c user.email="bayo-de@users.noreply.github.com" \
  commit -m "Initial release: Verified by NPC Gemini CLI extension v1.0.0"
gh repo create bayo-de/npc-verify-gemini --public \
  --description "Verified by NPC for Gemini CLI. Ask 'is this real?' to check products, credentials, claims, and agents against NPC Labs verification records." \
  --source=. --push

# 4. Add the gallery topic so the Gemini CLI crawler indexes it
gh repo edit bayo-de/npc-verify-gemini --add-topic gemini-cli-extension
gh repo view bayo-de/npc-verify-gemini --json name,url,isPrivate,topics
# EXPECT: isPrivate false, topics includes "gemini-cli-extension"

# 5. Tag v1.0.0 and create the GitHub release with the drafted notes
git tag -a v1.0.0 -m "Verified by NPC for Gemini CLI v1.0.0"
git push origin v1.0.0
gh release create v1.0.0 \
  --title "v1.0.0" \
  --notes-file ~/workspace/grand-fleet/verified-by-npc/plugins/gemini/RELEASE-NOTES-v1.0.0.md

# 6. Sanity: the private monorepo stays private (no step above touches it)
gh repo view bayo-de/npc-grand-fleet --json isPrivate
# EXPECT: true

# 7. Shred the token: log out, unset, clear history
gh auth logout
unset GH_TOKEN
history -c
```

If `gh repo create` fails with 401: the token is wrong or lacks the `repo`
scope. Generate a new classic PAT. Rollback (only with Bayo's explicit
go-ahead): `gh repo delete bayo-de/npc-verify-gemini --yes`.
