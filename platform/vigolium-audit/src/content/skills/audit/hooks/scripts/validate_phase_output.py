#!/usr/bin/env python3
"""Validate durable vigolium-results output without editing audit state.

The TypeScript engine owns per-phase artifact gates. This helper is the final
cross-artifact consistency pass used by report-composer after both finding
buckets have been materialized.

Usage:
    validate_phase_output.py all <results_dir>

Exit 0: validation passed
Exit 1: validation failed (one reason per line on stderr)
Exit 2: usage error
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

FINDING_DIR_RE = re.compile(r"^([CHML][1-9][0-9]*)(?:-.+)?$")
FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _-]*):\s*(.*)$")
REPORT_MIN_BYTES = 501
FINAL_REPORT_MIN_BYTES = 200
FINAL_REPORT_MODES = {"balanced", "deep", "merge", "revisit"}


def safe_file(path: Path, min_bytes: int = 1) -> bool:
    try:
        return not path.is_symlink() and path.is_file() and path.stat().st_size >= min_bytes
    except OSError:
        return False


def load_json(path: Path) -> tuple[Optional[Any], Optional[str]]:
    if not safe_file(path):
        return None, f"{path}: missing or not a safe regular file"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"{path}: invalid JSON ({exc})"


def read_last_field(path: Path, name: str) -> str:
    if not safe_file(path):
        return ""
    value = ""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = FIELD_RE.match(line)
            if match and match.group(1).strip().lower() == name.lower():
                value = match.group(2).strip()
    except (OSError, UnicodeError):
        return ""
    return value


def finding_dirs(results_dir: Path) -> tuple[dict[str, tuple[str, Path]], list[str]]:
    findings: dict[str, tuple[str, Path]] = {}
    errors: list[str] = []
    for bucket in ("findings", "findings-theoretical"):
        root = results_dir / bucket
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            errors.append(f"{bucket}/ is not a safe directory")
            continue
        for entry in sorted(root.iterdir()):
            match = FINDING_DIR_RE.match(entry.name)
            if not match or entry.is_symlink() or not entry.is_dir():
                continue
            finding_id = match.group(1)
            if finding_id in findings:
                prior_bucket = findings[finding_id][0]
                errors.append(
                    f"duplicate finding ID {finding_id} across {prior_bucket}/ and {bucket}/"
                )
                continue
            findings[finding_id] = (bucket, entry)
    return findings, errors


def validate_finding(
    finding_id: str,
    bucket: str,
    directory: Path,
) -> list[str]:
    errors: list[str] = []
    if finding_id.startswith("L"):
        errors.append(f"{bucket}/{directory.name}: Low-severity finding leaked into final output")

    draft = directory / "draft.md"
    report = directory / "report.md"
    if not safe_file(draft):
        errors.append(f"{bucket}/{directory.name}/draft.md is missing or unsafe")
    if not safe_file(report, REPORT_MIN_BYTES):
        size = report.stat().st_size if report.exists() and report.is_file() else 0
        errors.append(
            f"{bucket}/{directory.name}/report.md is incomplete "
            f"({size} bytes; requires at least {REPORT_MIN_BYTES})"
        )

    poc_status = read_last_field(draft, "PoC-Status").lower()
    if bucket == "findings":
        if poc_status != "executed":
            errors.append(
                f"{bucket}/{directory.name}: confirmed bucket requires PoC-Status: executed"
            )
        poc_files = [
            path
            for path in directory.glob("poc.*")
            if path.name != "poc.theoretical.md" and safe_file(path)
        ]
        if not poc_files:
            errors.append(f"{bucket}/{directory.name}: confirmed finding has no executable PoC artifact")
    elif poc_status == "executed":
        errors.append(
            f"{bucket}/{directory.name}: executed PoC belongs in findings/, not findings-theoretical/"
        )
    return errors


def manifest_ids(results_dir: Path) -> tuple[set[str], list[str]]:
    path = results_dir / "findings-draft" / "consolidation-manifest.json"
    if not path.exists():
        return set(), []
    manifest, error = load_json(path)
    if error:
        return set(), [error]
    if not isinstance(manifest, dict):
        return set(), [f"{path}: root must be an object"]

    ids: set[str] = set()
    errors: list[str] = []
    for list_name in ("findings", "theoretical"):
        entries = manifest.get(list_name)
        if not isinstance(entries, list):
            errors.append(f"{path}: {list_name} must be an array")
            continue
        for index, entry in enumerate(entries):
            finding_id = entry.get("id") if isinstance(entry, dict) else None
            if not isinstance(finding_id, str) or not re.fullmatch(r"[CHM][1-9][0-9]*", finding_id):
                errors.append(f"{path}: {list_name}[{index}] has no safe Medium+ finding ID")
                continue
            ids.add(finding_id)
    return ids, errors


def latest_mode(results_dir: Path) -> tuple[Optional[str], list[str]]:
    path = results_dir / "audit-state.json"
    if not path.exists():
        return None, []
    state, error = load_json(path)
    if error:
        return None, [error]
    if not isinstance(state, dict) or state.get("schema_version", 1) != 1:
        return None, [f"{path}: expected schema_version 1 object"]
    audits = state.get("audits")
    if not isinstance(audits, list) or not audits:
        return None, [f"{path}: audits must be a non-empty array"]
    latest = audits[-1]
    mode = latest.get("mode") if isinstance(latest, dict) else None
    return mode if isinstance(mode, str) else None, []


def validate_final_report(
    results_dir: Path,
    mode: Optional[str],
    finding_ids: set[str],
) -> list[str]:
    report = results_dir / "final-audit-report.md"
    if not report.exists() and mode not in FINAL_REPORT_MODES:
        return []
    if not safe_file(report, FINAL_REPORT_MIN_BYTES):
        return [
            f"final-audit-report.md is missing or below {FINAL_REPORT_MIN_BYTES} bytes"
        ]
    try:
        content = report.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"final-audit-report.md is unreadable: {exc}"]
    return [
        f"final-audit-report.md does not reference finalized finding {finding_id}"
        for finding_id in sorted(finding_ids)
        if re.search(rf"(?<![A-Za-z0-9]){re.escape(finding_id)}(?![0-9])", content) is None
    ]


def lint_all(results_dir: Path) -> list[str]:
    if results_dir.is_symlink() or not results_dir.is_dir():
        return [f"results directory is missing or unsafe: {results_dir}"]

    errors: list[str] = []
    mode, state_errors = latest_mode(results_dir)
    errors.extend(state_errors)

    findings, discovery_errors = finding_dirs(results_dir)
    errors.extend(discovery_errors)
    for finding_id, (bucket, directory) in findings.items():
        errors.extend(validate_finding(finding_id, bucket, directory))

    expected_ids, manifest_errors = manifest_ids(results_dir)
    errors.extend(manifest_errors)
    for finding_id in sorted(expected_ids - set(findings)):
        errors.append(f"consolidation manifest finding {finding_id} has no finalized directory")

    errors.extend(validate_final_report(results_dir, mode, set(findings)))
    return errors


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] != "all":
        print("usage: validate_phase_output.py all <results_dir>", file=sys.stderr)
        sys.exit(2)

    results_dir = Path(sys.argv[2]).absolute()
    errors = lint_all(results_dir)
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
    print("PASS: durable audit output is internally consistent")


if __name__ == "__main__":
    main()
