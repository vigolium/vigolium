#!/usr/bin/env python3
"""
Walk the target repository, hash every source file, and write
vigolium-results/file-state.json — a per-file lattice that records which audit IDs
have touched which file. Run this as a side-effect of the final phase of
any audit (balanced Phase B9, deep Phase D12) so the next audit can compute
an incremental scope (changed/new/deleted files) against the prior state.

The state file is additive across runs: a re-run merges the new audit_id
into each file's `last_audits[]` rather than overwriting.

Usage:
    stamp_file_state.py [--target <path>] [--results-dir <path>] [--audit-id <id>] [--phases <id,id,...>]

Defaults:
    --target       cwd
    --results-dir   <target>/vigolium-results
    --audit-id     read from <results-dir>/audit-state.json's last entry
    --phases       all string keys from the last audit's `phases` map

Excludes:
    Standard noise (.git/, node_modules/, vendor/, __pycache__/, dist/,
    build/, .venv/, target/, .vigolium-audit-merge-staging-*/) and the vigolium-results/
    directory itself. Only text-readable files smaller than
    DEFAULT_MAX_BYTES (~512KB) are stored in the incremental hash index.

Exit codes:
    0  success
    1  no audit_id available (no prior audit-state.json and none provided)
    2  usage error / target missing
    3  I/O failure during walk or write
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional

DEFAULT_MAX_BYTES = 512 * 1024  # 512 KB cap per file before we skip hashing

EXCLUDED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    "target",
    ".next",
    ".nuxt",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".gradle",
    ".idea",
    ".vscode",
    "vigolium-results",
}

EXCLUDED_DIR_PREFIXES = (".vigolium-audit-merge-staging-", "bak-vigolium-audit-")

# Hashed only — extensions are intentionally broad. If a file has no
# extension we still hash it as long as it's not obviously a binary blob
# (we sniff the first chunk for null bytes).
TEXT_HINT_EXTENSIONS = {
    # source
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".rb", ".go", ".rs", ".java", ".kt", ".scala",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".mm",
    ".cs", ".fs", ".vb", ".swift", ".dart",
    ".php", ".pl", ".pm", ".lua", ".r", ".jl", ".ex", ".exs",
    ".erl", ".hrl", ".clj", ".cljs", ".elm", ".purs",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".sql", ".graphql", ".gql", ".proto", ".thrift", ".avsc",
    # config / infra
    ".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".conf",
    ".tf", ".hcl", ".tfvars", ".dockerfile",
    # docs
    ".md", ".mdx", ".rst", ".txt",
}


def is_excluded_dir(name: str) -> bool:
    if name in EXCLUDED_DIR_NAMES:
        return True
    return any(name.startswith(p) for p in EXCLUDED_DIR_PREFIXES)


def looks_like_text(path: Path, sniff_bytes: int = 4096) -> bool:
    """Cheap binary sniff. We hash anything that has a text-y extension or
    that doesn't trip the null-byte heuristic in its first chunk."""
    if path.suffix.lower() in TEXT_HINT_EXTENSIONS:
        return True
    # No extension or unfamiliar extension — sniff content.
    try:
        with path.open("rb") as f:
            chunk = f.read(sniff_bytes)
    except OSError:
        return False
    if not chunk:
        return True  # empty file is fine
    return b"\x00" not in chunk


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for buf in iter(lambda: f.read(64 * 1024), b""):
            h.update(buf)
    return h.hexdigest()


def walk_target(target: Path) -> list[Path]:
    out: list[Path] = []
    target = target.resolve()
    for root, dirs, files in os.walk(target):
        # Prune in place — modifying `dirs` skips them entirely.
        dirs[:] = [d for d in dirs if not is_excluded_dir(d)]
        root_path = Path(root)
        for name in files:
            full = root_path / name
            if not full.is_file():
                continue
            try:
                if full.is_symlink():
                    continue
            except OSError:
                continue
            out.append(full)
    return sorted(out)


def load_prior(state_path: Path) -> dict:
    if not state_path.is_file():
        return {"audits": [], "files": {}}
    try:
        return json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError):
        return {"audits": [], "files": {}}


def detect_audit_id(results_dir: Path) -> Optional[tuple[str, list[str]]]:
    """Pull the most recent audit's id + phase keys from audit-state.json.
    Returns (audit_id, phase_ids) or None if the file is unreadable.
    """
    audit_state = results_dir / "audit-state.json"
    if not audit_state.is_file():
        return None
    try:
        data = json.loads(audit_state.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    audits = data.get("audits") or []
    if not audits:
        return None
    last = audits[-1]
    audit_id = (last.get("audit_id") or "").strip()
    if not audit_id:
        return None
    phase_map = last.get("phases") or {}
    phases = sorted(str(key) for key in phase_map.keys())
    return audit_id, phases


def stamp(
    target: Path,
    results_dir: Path,
    audit_id: str,
    phases: list[str],
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict:
    state_path = results_dir / "file-state.json"
    state = load_prior(state_path)
    prior_files: dict = state.get("files") or {}
    files: dict = {}
    large_skipped = 0
    binary_skipped = 0

    target = target.resolve()
    paths = walk_target(target)
    for full in paths:
        try:
            rel = str(full.relative_to(target))
        except ValueError:
            continue
        try:
            stat = full.stat()
        except OSError:
            continue

        large = stat.st_size > max_bytes
        text = looks_like_text(full) if not large else False
        if large:
            large_skipped += 1
            continue
        if not text:
            binary_skipped += 1
            continue

        try:
            sha256 = hash_file(full)
        except OSError:
            continue

        prior = prior_files.get(rel) or {}
        prior_audits = list(prior.get("last_audits") or [])
        if audit_id not in prior_audits:
            prior_audits.append(audit_id)
        last_audits = [str(value) for value in prior_audits][-5:]

        prior_phases = [str(value) for value in list(prior.get("last_phases") or [])]
        merged_phases = list(dict.fromkeys(prior_phases + phases))[-5:]
        files[rel] = {
            "sha256": sha256,
            "last_audits": last_audits,
            "last_phases": merged_phases,
        }

    state = {"schema_version": 1, "files": files}

    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")

    counts = {
        "tracked": len(files),
        "with_hash": len(files),
        "large_skipped": large_skipped,
        "binary_skipped": binary_skipped,
    }
    return counts


def parse_phases_arg(raw: str) -> list[str]:
    if not raw:
        return []
    out: list[str] = []
    for piece in raw.split(","):
        piece = piece.strip()
        if not piece:
            continue
        out.append(piece)
    return list(dict.fromkeys(out))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=".", help="Target repository path (default: cwd)")
    parser.add_argument("--results-dir", default=None, help="Vigolium-Audit data dir (default: <target>/vigolium-results)")
    parser.add_argument("--audit-id", default=None, help="Override the audit id to stamp (default: read from audit-state.json)")
    parser.add_argument("--phases", default=None, help="Comma-separated phase IDs to mark on each file (default: all phases from current audit)")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="Skip hashing for files larger than this many bytes")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"error: target is not a directory: {target}", file=sys.stderr)
        sys.exit(2)

    results_dir = Path(args.results_dir) if args.results_dir else target / "vigolium-results"
    results_dir.mkdir(parents=True, exist_ok=True)

    audit_id = args.audit_id
    phases: list[str] = parse_phases_arg(args.phases or "")

    if not audit_id or not phases:
        detected = detect_audit_id(results_dir)
        if detected is None and not audit_id:
            print(
                "error: no audit_id provided and audit-state.json is unreadable",
                file=sys.stderr,
            )
            sys.exit(1)
        if detected is not None:
            det_id, det_phases = detected
            if not audit_id:
                audit_id = det_id
            if not phases:
                phases = det_phases

    try:
        counts = stamp(target, results_dir, audit_id, phases, max_bytes=args.max_bytes)
    except OSError as exc:
        print(f"error: I/O failure during stamp: {exc}", file=sys.stderr)
        sys.exit(3)

    state_path = results_dir / "file-state.json"
    print(
        f"file-state stamped at {state_path}: "
        f"{counts['tracked']} tracked "
        f"({counts['with_hash']} hashed, "
        f"{counts['large_skipped']} large-skipped, "
        f"{counts['binary_skipped']} binary-skipped)"
    )


if __name__ == "__main__":
    main()
