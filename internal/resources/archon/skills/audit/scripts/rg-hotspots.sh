#!/usr/bin/env bash
set -euo pipefail

# Fast, noisy-first security hotspot discovery.
# Goal: find review starting points (sinks and risky APIs), not prove vulns.
#
# Usage:
#   scripts/rg-hotspots.sh            # scan repo from cwd
#   scripts/rg-hotspots.sh path/      # scan a subdir
#
# Tips:
# - Pipe into a pager: `... | less -R`
# - Narrow scope for signal: `... api/` or `... src/auth/`

root="${1:-.}"

if ! command -v rg >/dev/null 2>&1; then
  echo "error: rg (ripgrep) not found in PATH" >&2
  exit 2
fi

rg_base=(
  --no-heading
  --line-number
  --hidden
  --follow
  --smart-case
  --glob '!.git/**'
  --glob '!**/node_modules/**'
  --glob '!**/dist/**'
  --glob '!**/build/**'
  --glob '!**/target/**'
  --glob '!**/.next/**'
  --glob '!**/vendor/**'
  --glob '!**/.venv/**'
  --glob '!**/venv/**'
)

section() {
  echo
  echo "== $1"
}

run() {
  local label="$1"
  shift
  section "$label"
  # `|| true` because some sections will have no matches (not an error).
  rg "${rg_base[@]}" "$@" "$root" || true
}

section "RG Hotspots"
echo "root: $root"

run "Command Execution / Dangerous Eval" \
  -e 'Runtime\.getRuntime\(\)\.exec' \
  -e 'ProcessBuilder\s*\(' \
  -e '\bexec(ute)?\s*\(' \
  -e '\bsystem\s*\(' \
  -e '\bpopen\s*\(' \
  -e 'child_process\.(exec|execSync|spawn|spawnSync)\b' \
  -e '\bos\.system\b' \
  -e '\bsubprocess\.(run|Popen|call|check_output)\b' \
  -e '\beval\s*\(' \
  -e '\bFunction\s*\(' \
  -e 'vm\.run(In(New)?Context|InThisContext)\b'

run "Deserialization / Template Injection Primitives" \
  -e '\bpickle\.loads\b' \
  -e '\byaml\.load\s*\(' \
  -e '\bObjectInputStream\b' \
  -e '\breadObject\s*\(' \
  -e '\bunserialize\s*\(' \
  -e '\bMarshal\.load\b' \
  -e '\bERB\.new\b' \
  -e '\bnew\s+Template\b' \
  -e '\bMustache\.' \
  -e '\bHandlebars\.' \
  -e '\bEJS\b'

run "SSRF / URL Fetching / HTTP Clients (review call sites)" \
  -e '\brequests\.(get|post|put|delete|head|patch)\b' \
  -e '\burllib\.(request|parse)\b' \
  -e '\bhttpx\.(get|post|Client)\b' \
  -e '\baxios\.' \
  -e '\bfetch\s*\(' \
  -e '\bgot\s*\(' \
  -e '\bnew\s+URL\s*\(' \
  -e '\bnet/http\b' \
  -e '\bhttp\.NewRequest\b' \
  -e '\bhttp\.Client\b'

run "SQL / Query Construction (review interpolation/concatenation)" \
  -e '\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b' \
  -e '\bquery(Raw)?\s*\(' \
  -e '\bexecute\s*\(' \
  -e '\bprepare\s*\('

run "File & Path Handling (review traversal/allowlists)" \
  -e '\bopen\s*\(' \
  -e '\bos\.path\.join\b|\bpath\.join\b|\bfilepath\.Join\b' \
  -e '\bread(File|FileSync)\s*\(' \
  -e '\bwrite(File|FileSync)\s*\(' \
  -e '\bcreate(Read|Write)Stream\s*\(' \
  -e '\bSendFile\b|\bsendFile\s*\('

run "AuthN/AuthZ Signals (review enforcement points)" \
  -e '\bauthori[sz]e\b' \
  -e '\bpermission(s)?\b' \
  -e '\brole(s)?\b' \
  -e '\bisAdmin\b|\badminOnly\b' \
  -e '\bRBAC\b|\bABAC\b'

run "Secrets (high false positives; prioritize obvious tokens/keys)" \
  -e 'AKIA[0-9A-Z]{16}' \
  -e 'ASIA[0-9A-Z]{16}' \
  -e '-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----' \
  -e 'xox[baprs]-[0-9A-Za-z-]+' \
  -e 'ghp_[0-9A-Za-z]{30,}' \
  -e 'AIza[0-9A-Za-z\-_]{35}' \
  -e '\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*["'\''][^"'\'']{8,}["'\'']'
