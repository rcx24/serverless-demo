#!/usr/bin/env bash
# Publishes harness/ to the orphan `harness` branch, and nothing else.
#
# The harness clones this repo at `revision: harness`, shallow and single-branch,
# so whatever is on that branch is the entire universe the agent sees. main -- with
# soar.py's deliberate gap, the contracts README, the artifact generator, every
# statement of where the orphaned key is -- must never reach it. This script is the
# boundary, so it is deliberately explicit about what it copies.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree is dirty. Commit or stash before publishing." >&2
  exit 1
fi

current="$(git rev-parse --abbrev-ref HEAD)"
staging="$(mktemp -d)"

# Exactly the harness-facing content. AGENTS.md at the root of the branch, because
# that is where the runtime's own AGENTS.md generation looks and where Pi walks to.
cp harness/AGENTS.md "$staging/AGENTS.md"
cp -r harness/runbooks "$staging/runbooks"

git checkout --orphan harness-tmp
git rm -rf --quiet . >/dev/null 2>&1 || true
cp "$staging/AGENTS.md" AGENTS.md
cp -r "$staging/runbooks" runbooks
git add AGENTS.md runbooks
git commit --quiet -m "Publish runbooks $(git rev-parse --short "$current")"

# Replace the harness branch with what we just built.
git branch -M harness-tmp harness
git checkout --quiet "$current"
rm -rf "$staging"

echo "Published harness/ to the 'harness' branch."
echo "Push it with: git push -f origin harness"
echo "The frame clones this repo at revision: harness."
