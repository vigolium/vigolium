#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEST_BASE="$HOME/Desktop/external"
GIT_ORG="git@github.com:vigolium"

PLATFORMS=(
  jsscan
  vigolium-workbench
  vigolium-console
  static-reports
)

for name in "${PLATFORMS[@]}"; do
  src="$REPO_ROOT/platform/$name"
  dest="$DEST_BASE/$name"

  if [ ! -d "$src" ]; then
    echo "SKIP: $src does not exist"
    continue
  fi

  echo "==> Syncing $name"

  # Clone if destination doesn't exist
  if [ ! -d "$dest" ]; then
    echo "    Cloning $GIT_ORG/$name.git -> $dest"
    git clone -q "$GIT_ORG/$name.git" "$dest"
  fi

  # Sync files (preserve destination .git)
  rsync -a --delete --exclude='.git' "$src/" "$dest/"

  # Commit and push if there are changes
  cd "$dest"
  if [ -n "$(git status --porcelain)" ]; then
    git add -A
    git commit -q -m "sync: update from vigolium monorepo ($(date +%Y-%m-%d))"
    git push -q origin
    echo "    Pushed changes for $name"
  else
    echo "    No changes for $name"
  fi

  cd "$REPO_ROOT"
done

echo "==> Done"
