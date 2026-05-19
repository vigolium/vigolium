#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path.cwd()
INVENTORY_PATH = ROOT / "piolium/confirm-workspace/findings-inventory.json"
ENV_PATH = ROOT / "piolium/confirm-workspace/env-connection.json"
RESULTS_PATH = ROOT / "piolium/confirm-workspace/poc-results.json"
AUDIT_STATE_PATH = ROOT / "piolium/audit-state.json"
SESSION = os.environ.get("PIGOLIUM_SESSION_UUID", "")

NETWORK_CLASSES = {"network-exploitable"}
LOCAL_CLASSES = {"local-exploitable"}
NON_EXPLOITABLE_CLASSES = {"non-exploitable"}

# User-requested report statuses plus developer-compatible fallbacks.
STRUCTURED_RE = re.compile(r"^\s*\{.*\"status\".*\}\s*$")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_slug() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")
    tmp.replace(path)


def run_cmd(cmd: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None, timeout_s: int = 30) -> dict[str, Any]:
    started = time.time()
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = proc.communicate()
        return {
            "cmd": cmd,
            "cwd": str(cwd),
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "duration_s": round(time.time() - started, 3),
            "stdout": stdout or "",
            "stderr": stderr or "",
        }
    except FileNotFoundError as e:
        return {
            "cmd": cmd,
            "cwd": str(cwd),
            "exit_code": None,
            "timed_out": False,
            "duration_s": round(time.time() - started, 3),
            "stdout": "",
            "stderr": str(e),
            "missing_interpreter": cmd[0],
        }


def shell_quote(cmd: list[str]) -> str:
    import shlex
    return " ".join(shlex.quote(x) for x in cmd)


def detect_command(poc_path: Path) -> tuple[list[str] | None, str | None]:
    ext = poc_path.suffix.lower()
    if ext == ".py":
        interp = shutil.which("python3")
        return ([interp or "python3", str(poc_path)] if interp else None, "python3")
    if ext == ".js":
        interp = shutil.which("node")
        return ([interp or "node", str(poc_path)] if interp else None, "node")
    if ext == ".sh":
        interp = shutil.which("bash") or shutil.which("sh")
        return ([interp or "bash", str(poc_path)] if interp else None, "bash")
    if ext == ".rb":
        interp = shutil.which("ruby")
        return ([interp or "ruby", str(poc_path)] if interp else None, "ruby")
    if ext == ".go":
        interp = shutil.which("go")
        return ([interp or "go", "run", str(poc_path)] if interp else None, "go")
    return None, ext.lstrip(".") or "unknown"


def parse_structured(stdout: str, stderr: str = "") -> dict[str, Any] | None:
    # Contract says stdout; include combined stream as a defensive fallback for old wrappers.
    candidates: list[dict[str, Any]] = []
    for line in (stdout + "\n" + stderr).splitlines():
        s = line.strip()
        if STRUCTURED_RE.match(s):
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and "status" in obj:
                candidates.append(obj)
    return candidates[-1] if candidates else None


def list_state(path: Path) -> str:
    if not path.exists():
        return f"{path} does not exist\n"
    lines: list[str] = []
    max_files = 160
    count = 0
    for p in sorted(path.rglob("*")):
        try:
            rel = p.relative_to(path)
        except Exception:
            rel = p
        if p.is_file():
            try:
                size = p.stat().st_size
            except OSError:
                size = -1
            lines.append(f"file {rel} size={size}")
            count += 1
        elif p.is_dir():
            # Keep directory list useful without exploding too much.
            depth = len(rel.parts) if isinstance(rel, Path) else 0
            if depth <= 3:
                lines.append(f"dir  {rel}/")
        if count >= max_files:
            lines.append(f"... truncated after {max_files} files ...")
            break
    return "\n".join(lines) + ("\n" if lines else "(empty)\n")


def read_text_if_exists(path: Path, max_bytes: int = 120_000) -> str:
    if not path.exists() or not path.is_file():
        return f"[missing] {path}\n"
    data = path.read_bytes()
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    text = data.decode("utf-8", errors="replace")
    if truncated:
        text += f"\n[truncated at {max_bytes} bytes from {path}]\n"
    return text


def append_confirmation(report_path: Path, fields: dict[str, str]) -> None:
    existing = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    marker = "\n## Confirmation (V4)\n"
    if marker in existing:
        existing = existing.split(marker, 1)[0].rstrip() + "\n"
    if not existing.endswith("\n"):
        existing += "\n"
    lines = ["## Confirmation (V4)", ""]
    order = [
        "Confirm-Status",
        "Confirm-Timestamp",
        "Confirm-Evidence",
        "Confirm-Variant-Count",
        "Confirm-FpCheck",
        "Confirm-Notes",
    ]
    for k in order:
        if k in fields:
            lines.append(f"{k}: {fields[k]}")
    for k, v in fields.items():
        if k not in order:
            lines.append(f"{k}: {v}")
    report_path.write_text(existing + "\n" + "\n".join(lines) + "\n", encoding="utf-8")


def write_block_evidence(evidence_file: Path, finding: dict[str, Any], status: str, reason: str, reachability: dict[str, Any], variant_count: int = 0) -> None:
    evidence_file.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Piolium V4 PoC Execution Evidence",
        f"Finding: {finding.get('finding_key')}",
        f"Status: {status}",
        f"Reason: {reason}",
        f"Timestamp: {utc_now()}",
        f"Session: {SESSION}",
        f"Protocol: {finding.get('protocol')}",
        f"Exploitability-Class: {finding.get('exploitability_class')}",
        f"PoC: {finding.get('poc_script_path')}",
        f"Variant-Count: {variant_count}",
        "",
        "## Reachability / target check",
        json.dumps(reachability, indent=2),
        "",
        "## Notes",
        reason,
        "",
    ]
    evidence_file.write_text("\n".join(lines), encoding="utf-8")


def perform_reachability(env_conn: dict[str, Any]) -> dict[str, Any]:
    base_url = env_conn.get("base_url")
    method = env_conn.get("method_used")
    now = utc_now()
    if base_url:
        curl = shutil.which("curl") or "curl"
        cmd = [curl, "-sf", "-o", "/dev/null", "--max-time", "5", str(base_url)]
        res = run_cmd(cmd, timeout_s=7)
        return {
            "timestamp": now,
            "mode": "base_url",
            "base_url": base_url,
            "command": shell_quote(cmd),
            "reachable": (res.get("exit_code") == 0 and not res.get("timed_out")),
            "exit_code": res.get("exit_code"),
            "timed_out": res.get("timed_out"),
            "stdout": res.get("stdout", ""),
            "stderr": res.get("stderr", ""),
        }
    # The target is a CLI in this audit. There is no base_url to curl, so keep the precheck
    # explicit and use the V3-discovered healthcheck as the target-liveness gate.
    health_cmd_str = env_conn.get("healthcheck_endpoint") or env_conn.get("cli_command") or "node ./bin/cli.mjs --version"
    if isinstance(health_cmd_str, str) and health_cmd_str.startswith("cli:"):
        health_cmd_str = health_cmd_str[4:]
    cmd = ["/bin/bash", "-lc", str(health_cmd_str)]
    res = run_cmd(cmd, timeout_s=7)
    return {
        "timestamp": now,
        "mode": "cli-healthcheck-base-url-null",
        "base_url": None,
        "method_used": method,
        "command": shell_quote(cmd),
        "reachable": (res.get("exit_code") == 0 and not res.get("timed_out")),
        "exit_code": res.get("exit_code"),
        "timed_out": res.get("timed_out"),
        "stdout": res.get("stdout", ""),
        "stderr": res.get("stderr", ""),
        "notes": "env-connection.json has base_url=null because this repository is a local CLI target; no persistent HTTP app is expected.",
    }


def poc_env_for_variant(base_env: dict[str, str], finding: dict[str, Any], variant_idx: int) -> dict[str, str]:
    env = base_env.copy()
    env.update({
        "CI": "1",
        "NO_COLOR": "1",
        "FORCE_COLOR": "0",
        "DISABLE_TELEMETRY": "1",
        "DO_NOT_TRACK": "1",
        "PIGOLIUM_SESSION_UUID": SESSION,
        "PIOLIUM_CONFIRM_VARIANT": str(variant_idx),
    })
    # Variant knobs for PoCs that support alternate payload sizes.
    key = finding.get("finding_key", "")
    if variant_idx == 2:
        env["PIOLIUM_VARIANT_NOTE"] = "variant-2-rerun-with-smaller-or-alternate-payload-where-supported"
        if key == "p10-004-unbounded-well-known-fetch-and-frontmatter-parse":
            env["POC_YAML_BYTES"] = str(512 * 1024)
            env["POC_AUX_COUNT"] = "2"
            env["POC_AUX_BYTES"] = str(64 * 1024)
    return env


def summarize_relevant_env(env: dict[str, str], finding: dict[str, Any]) -> dict[str, str]:
    keys = [
        "CI", "NO_COLOR", "FORCE_COLOR", "DISABLE_TELEMETRY", "DO_NOT_TRACK",
        "PIGOLIUM_SESSION_UUID", "PIOLIUM_CONFIRM_VARIANT", "PIOLIUM_VARIANT_NOTE",
        "POC_YAML_BYTES", "POC_AUX_COUNT", "POC_AUX_BYTES", "SKILLS_DOWNLOAD_URL",
        "SKILLS_API_URL", "GITHUB_TOKEN", "GH_TOKEN", "HOME", "XDG_CONFIG_HOME", "CODEX_HOME",
        "PATH",
    ]
    out: dict[str, str] = {}
    for k in keys:
        if k in env:
            if k in {"GITHUB_TOKEN", "GH_TOKEN"} and env[k]:
                out[k] = "[set-redacted]"
            elif k == "PATH":
                out[k] = env[k]
            else:
                out[k] = env[k]
    return out


def run_network_poc(finding: dict[str, Any], reachability: dict[str, Any], ts: str) -> dict[str, Any]:
    finding_dir = ROOT / finding["dir"].rstrip("/")
    evidence_dir = ROOT / finding.get("evidence_dir", str(finding_dir / "evidence")).rstrip("/")
    report_path = ROOT / finding["report_path"]
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = evidence_dir / f"confirmed-{ts}.log"
    poc_rel = finding.get("poc_script_path")
    poc_path = ROOT / poc_rel if poc_rel else None

    if not poc_path or not poc_path.exists():
        reason = "no-poc-script-found"
        write_block_evidence(evidence_file, finding, "blocked", reason, reachability)
        append_confirmation(report_path, {
            "Confirm-Status": "blocked",
            "Confirm-Timestamp": utc_now(),
            "Confirm-Evidence": str(evidence_file.relative_to(ROOT)),
            "Confirm-Variant-Count": "0",
            "Confirm-FpCheck": "not-run",
            "Confirm-Notes": reason,
        })
        return {"finding_key": finding.get("finding_key"), "status": "blocked", "notes": reason, "evidence": str(evidence_file.relative_to(ROOT)), "variant_count": 0}

    cmd, interp = detect_command(poc_path)
    if cmd is None:
        reason = f"missing-interpreter-{interp}"
        write_block_evidence(evidence_file, finding, "blocked", reason, reachability)
        append_confirmation(report_path, {
            "Confirm-Status": "blocked",
            "Confirm-Timestamp": utc_now(),
            "Confirm-Evidence": str(evidence_file.relative_to(ROOT)),
            "Confirm-Variant-Count": "0",
            "Confirm-FpCheck": "not-run",
            "Confirm-Notes": reason,
        })
        return {"finding_key": finding.get("finding_key"), "status": "blocked", "notes": reason, "evidence": str(evidence_file.relative_to(ROOT)), "variant_count": 0}

    attempts: list[dict[str, Any]] = []
    final_structured: dict[str, Any] | None = None
    final_status = "failed"
    final_notes = "no structured PoC success marker observed"
    max_attempts = 2

    before_state = list_state(evidence_dir)
    log_parts: list[str] = [
        "# Piolium V4 PoC Execution Evidence",
        f"Finding: {finding.get('finding_key')}",
        f"Title: {finding.get('title')}",
        f"Timestamp: {utc_now()}",
        f"Session: {SESSION}",
        f"Protocol: {finding.get('protocol')}",
        f"Exploitability-Class: {finding.get('exploitability_class')}",
        f"PoC: {poc_path}",
        f"Per-variant-timeout-s: 30",
        "",
        "## Reachability / target check",
        json.dumps(reachability, indent=2),
        "",
        "## Before state (evidence directory)",
        before_state,
        "",
    ]

    for variant_idx in range(1, max_attempts + 1):
        env = poc_env_for_variant(os.environ, finding, variant_idx)
        log_parts.extend([
            f"## Variant {variant_idx}",
            f"Started: {utc_now()}",
            f"Command: {shell_quote(cmd)}",
            f"CWD: {ROOT}",
            "Relevant-Env:",
            json.dumps(summarize_relevant_env(env, finding), indent=2),
            "",
        ])
        res = run_cmd(cmd, cwd=ROOT, env=env, timeout_s=30)
        structured = parse_structured(res.get("stdout", ""), res.get("stderr", ""))
        attempt = {
            "variant": variant_idx,
            "command": shell_quote(cmd),
            "cwd": str(ROOT),
            "exit_code": res.get("exit_code"),
            "timed_out": res.get("timed_out"),
            "duration_s": res.get("duration_s"),
            "structured": structured,
        }
        attempts.append(attempt)
        log_parts.extend([
            f"Exit-Code: {res.get('exit_code')}",
            f"Timed-Out: {res.get('timed_out')}",
            f"Duration-s: {res.get('duration_s')}",
            "",
            "### stdout",
            res.get("stdout", ""),
            "",
            "### stderr",
            res.get("stderr", ""),
            "",
            "### Structured PoC Output",
            json.dumps(structured, indent=2) if structured is not None else "[none]",
            "",
        ])
        # Write partial evidence after each attempt in case a later attempt hangs unexpectedly.
        evidence_file.write_text("\n".join(log_parts), encoding="utf-8")

        if structured is not None:
            final_structured = structured
            s = str(structured.get("status", "")).lower()
            if s == "confirmed":
                final_status = "confirmed-live"
                final_notes = str(structured.get("evidence") or "structured PoC status=confirmed")
                break
            if s == "inconclusive":
                final_status = "inconclusive"
                final_notes = str(structured.get("notes") or structured.get("evidence") or "structured PoC status=inconclusive")
                # Try a second variant if available.
                continue
            if s == "failed":
                final_status = "failed"
                final_notes = str(structured.get("notes") or structured.get("evidence") or "structured PoC status=failed")
                # Try second variant.
                continue
        else:
            if res.get("timed_out"):
                final_status = "blocked"
                final_notes = "PoC wrapper timed out after 30s before emitting structured output"
                # Try second variant.
                continue
            # Legacy fallback: inspect stdout/stderr for clear confirmation markers.
            combined = (res.get("stdout", "") + "\n" + res.get("stderr", "")).lower()
            if "confirmed" in combined and ("marker" in combined or "installed" in combined or "persist" in combined):
                final_status = "confirmed-live"
                final_notes = "legacy-poc-format confirmation marker observed"
                break
            final_status = "failed" if res.get("exit_code") not in (0, None) else "inconclusive"
            final_notes = "legacy-poc-format no structured status line"
            continue

    variant_count = len(attempts)
    # If the last emitted status was inconclusive due an environment/liveness issue, leave it as
    # inconclusive (developer contract) rather than false-positive. Timed-out harness is blocked.
    after_state = list_state(evidence_dir)
    generated_files = [
        "env-info.txt",
        "setup.log",
        "healthcheck.log",
        "exploit.log",
        "impact.log",
        "poc-error.log",
        "http-git-access.log",
        "poc-run.stdout",
        "skills-lock.before.json",
        "skills-lock.after.json",
    ]
    log_parts.extend([
        "## After state (evidence directory)",
        after_state,
        "",
        "## Generated PoC Evidence Files",
        "The following sections inline the PoC-produced logs when present, so this single file contains command/stdout/stderr plus request/response/state evidence for replay.",
        "",
    ])
    for name in generated_files:
        p = evidence_dir / name
        if p.exists() and p.resolve() != evidence_file.resolve():
            log_parts.extend([f"### {name}", read_text_if_exists(p), ""])
    # Include one level of runtime state/important files if they exist.
    for sub in ["runtime", "workdir", "runtime-project", "home", "work"]:
        p = evidence_dir / sub
        if p.exists():
            log_parts.extend([f"### State tree: {sub}/", list_state(p), ""])

    log_parts.extend([
        "## Final Verdict",
        f"Confirm-Status: {final_status}",
        f"Confirm-Variant-Count: {variant_count}",
        f"Confirm-Notes: {final_notes}",
        "Final-Structured-Output:",
        json.dumps(final_structured, indent=2) if final_structured else "[none]",
        "",
    ])
    evidence_file.write_text("\n".join(log_parts), encoding="utf-8")

    append_confirmation(report_path, {
        "Confirm-Status": final_status,
        "Confirm-Timestamp": utc_now(),
        "Confirm-Evidence": str(evidence_file.relative_to(ROOT)),
        "Confirm-Variant-Count": str(variant_count),
        "Confirm-FpCheck": "not-run",
        "Confirm-Notes": final_notes.replace("\n", " ")[:500],
    })

    return {
        "finding_key": finding.get("finding_key"),
        "id": finding.get("id"),
        "slug": finding.get("slug"),
        "status": final_status,
        "notes": final_notes,
        "evidence": str(evidence_file.relative_to(ROOT)),
        "variant_count": variant_count,
        "attempts": attempts,
        "structured": final_structured,
        "queued_for_v5": final_status not in {"confirmed-live", "analytical-only", "false-positive", "confirmed-fp"},
    }


def update_audit_state(results: dict[str, Any]) -> None:
    if not AUDIT_STATE_PATH.exists():
        return
    try:
        state = load_json(AUDIT_STATE_PATH)
        audits = state.get("audits") if isinstance(state, dict) else None
        if isinstance(audits, list) and audits:
            audit = audits[0]
            phases = audit.setdefault("phases", {})
            p = phases.setdefault("P16:V4", {})
            p.update({
                "status": "complete",
                "completed_at": utc_now(),
                "results_path": str(RESULTS_PATH.relative_to(ROOT)),
                "total_findings": results.get("total"),
                "network_attempted": results.get("summary", {}).get("network_attempted"),
                "confirmed_live": results.get("summary", {}).get("confirmed-live"),
                "blocked": results.get("summary", {}).get("blocked"),
                "inconclusive": results.get("summary", {}).get("inconclusive"),
            })
            phases.setdefault("P16", {})["last_completed_subphase"] = "V4"
            phases.setdefault("P16", {})["last_event_at"] = utc_now()
            write_json(AUDIT_STATE_PATH, state)
    except Exception as exc:
        # Do not fail confirmation if state bookkeeping fails; record beside results.
        (ROOT / "piolium/confirm-workspace/audit-state-update-error.log").write_text(repr(exc), encoding="utf-8")


def main() -> int:
    inventory = load_json(INVENTORY_PATH)
    env_conn = load_json(ENV_PATH)
    ts = timestamp_slug()
    reachability = perform_reachability(env_conn)

    findings = inventory.get("findings", [])
    results: list[dict[str, Any]] = []
    summary: dict[str, int] = {
        "confirmed-live": 0,
        "failed": 0,
        "blocked": 0,
        "analytical-only": 0,
        "false-positive": 0,
        "inconclusive": 0,
        "no-poc": 0,
        "local-routed-to-v5": 0,
        "network_attempted": 0,
    }

    network_block_reason = None
    if not reachability.get("reachable"):
        if env_conn.get("base_url"):
            network_block_reason = f"app-unreachable-at-poc-start ({env_conn.get('base_url')})"
        else:
            network_block_reason = "target CLI healthcheck failed with base_url=null"

    for finding in findings:
        finding_dir = ROOT / finding["dir"].rstrip("/")
        evidence_dir = ROOT / finding.get("evidence_dir", str(finding_dir / "evidence")).rstrip("/")
        report_path = ROOT / finding["report_path"]
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_file = evidence_dir / f"confirmed-{ts}.log"
        exp_class = (finding.get("exploitability_class") or "").lower()
        protocol = (finding.get("protocol") or "http").lower()
        existing_confirm = (finding.get("confirm_status") or "").lower()

        if existing_confirm == "confirmed-live":
            # Keep prior confirmation; still include in aggregate.
            results.append({"finding_key": finding.get("finding_key"), "status": "confirmed-live", "notes": "already confirmed-live before V4 run", "evidence": finding.get("evidence_dir"), "variant_count": 0, "skipped": True})
            summary["confirmed-live"] += 1
            continue

        if exp_class in NON_EXPLOITABLE_CLASSES or protocol == "non-exploitable":
            reason = "non-exploitable analytical finding; no live PoC execution applicable"
            write_block_evidence(evidence_file, finding, "analytical-only", reason, reachability)
            append_confirmation(report_path, {
                "Confirm-Status": "analytical-only",
                "Confirm-Timestamp": utc_now(),
                "Confirm-Evidence": str(evidence_file.relative_to(ROOT)),
                "Confirm-Variant-Count": "0",
                "Confirm-FpCheck": "not-run",
                "Confirm-Notes": reason,
            })
            results.append({"finding_key": finding.get("finding_key"), "status": "analytical-only", "notes": reason, "evidence": str(evidence_file.relative_to(ROOT)), "variant_count": 0, "queued_for_v5": False})
            summary["analytical-only"] += 1
            continue

        if exp_class in LOCAL_CLASSES or protocol.startswith("local"):
            reason = "local-only finding routed to V5; V4 executes only network-exploitable PoCs for this run"
            write_block_evidence(evidence_file, finding, "blocked", reason, reachability)
            append_confirmation(report_path, {
                "Confirm-Status": "blocked",
                "Confirm-Timestamp": utc_now(),
                "Confirm-Evidence": str(evidence_file.relative_to(ROOT)),
                "Confirm-Variant-Count": "0",
                "Confirm-FpCheck": "not-run",
                "Confirm-Notes": reason,
            })
            results.append({"finding_key": finding.get("finding_key"), "status": "blocked", "notes": reason, "evidence": str(evidence_file.relative_to(ROOT)), "variant_count": 0, "queued_for_v5": True, "route": "V5-local"})
            summary["blocked"] += 1
            summary["local-routed-to-v5"] += 1
            continue

        # Network-exploitable.
        if network_block_reason:
            reason = network_block_reason
            write_block_evidence(evidence_file, finding, "blocked", reason, reachability)
            append_confirmation(report_path, {
                "Confirm-Status": "blocked",
                "Confirm-Timestamp": utc_now(),
                "Confirm-Evidence": str(evidence_file.relative_to(ROOT)),
                "Confirm-Variant-Count": "0",
                "Confirm-FpCheck": "not-run",
                "Confirm-Notes": reason,
            })
            results.append({"finding_key": finding.get("finding_key"), "status": "blocked", "notes": reason, "evidence": str(evidence_file.relative_to(ROOT)), "variant_count": 0, "queued_for_v5": True})
            summary["blocked"] += 1
            continue

        result = run_network_poc(finding, reachability, ts)
        results.append(result)
        status = result.get("status", "failed")
        summary[status] = summary.get(status, 0) + 1
        summary["network_attempted"] += 1

    aggregate = {
        "session": SESSION,
        "timestamp": utc_now(),
        "inventory_path": str(INVENTORY_PATH.relative_to(ROOT)),
        "env_connection_path": str(ENV_PATH.relative_to(ROOT)),
        "target": inventory.get("target"),
        "base_url": env_conn.get("base_url"),
        "method_used": env_conn.get("method_used"),
        "reachability": reachability,
        "total": len(findings),
        "summary": summary,
        "results": results,
        "notes": [
            "base_url was null for this CLI target, so V4 used the discovered CLI healthcheck before running network-shaped PoCs that start local attacker-controlled servers.",
            "local-exploitable findings were not executed in V4 and are marked blocked/queued_for_v5 as requested.",
            "A confirmed-live result is based only on structured PoC output plus inline command/stdout/stderr and generated impact logs in each evidence file.",
        ],
    }
    write_json(RESULTS_PATH, aggregate)
    update_audit_state(aggregate)
    print(json.dumps({"results_path": str(RESULTS_PATH), "summary": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
