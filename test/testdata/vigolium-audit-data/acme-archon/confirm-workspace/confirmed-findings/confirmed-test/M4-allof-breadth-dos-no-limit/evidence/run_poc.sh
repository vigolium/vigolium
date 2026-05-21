#!/usr/bin/env bash
# Wrapper: run the PoC from the repo root so ts-node resolves src/ imports.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../../../" && pwd)"
cd "$REPO_ROOT"
exec npx ts-node --project tsconfig.json --transpile-only \
  archon/findings/M4-allof-breadth-dos-no-limit/evidence/poc_root.ts "$@"
