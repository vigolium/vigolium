#!/usr/bin/env python3
"""
Route confirmed vs theoretical findings AFTER poc-author has run.

`consolidate_drafts.py` puts every actionable finding in
`<archon_dir>/findings/<ID>-<slug>/`. poc-author then attempts a PoC for
each and writes `PoC-Status: executed | theoretical | blocked` back into the
finding's `draft.md`. This script reads that field and demotes any finding
that did NOT reach `PoC-Status: executed` into
`<archon_dir>/findings-theoretical/<ID>-<slug>/` (same directory shape, IDs
unchanged so cross-references stay stable).

Bucket contract:
    findings/              -> confirmed, PoC executed (the actionable bucket)
    findings-theoretical/  -> no PoC / theoretical / blocked, plus the
                              triage-skipped findings consolidate_drafts.py
                              already placed there.

The script is idempotent: re-running it never moves an already-`executed`
finding, and a re-demoted finding overwrites any stale same-ID directory in
the theoretical bucket. It is a no-op for modes that never build PoCs
(nothing is `executed`, but those modes simply don't invoke this script).

Usage:
    partition_findings.py [archon_dir]

archon_dir defaults to "archon". Exit codes:
    0  success (including "nothing to move")
    2  usage error / archon_dir missing
    3  I/O error during partition
"""

import json
import os
import re
import shutil
import sys
from pathlib import Path

FINDING_DIR_RE = re.compile(r"^[CHM]\d+-")
# Same shape as consolidate_drafts.py's KV_RE, intentionally duplicated:
# every vendored script under skills/audit/scripts/ is standalone (copied
# verbatim at install time, no cross-script imports). Keep the two in sync.
KV_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _-]*):\s*(.*)$")


def read_poc_status(draft_path: Path) -> str:
    """Return the lowercased PoC-Status value from a finding draft, or "" if
    absent.

    poc-author writes `PoC-Status:` back into an already-materialised
    `draft.md` *after* consolidation, so it does not always land inside the
    strict leading `Key: Value` block (which terminates at the first blank
    line or `## ` heading). Demoting a genuinely confirmed finding because
    the field sat one line outside that block is the costly failure
    direction, so scan the WHOLE file for a `PoC-Status:` line and take the
    last occurrence (re-runs append an updated value). This matches how
    finding-writer and merge mode read the field loosely.
    """
    if not draft_path.is_file():
        return ""
    found = ""
    try:
        with draft_path.open() as f:
            for line in f:
                m = KV_RE.match(line.rstrip("\n"))
                if m and m.group(1).strip().lower() == "poc-status":
                    found = m.group(2).strip().lower()
    except OSError:
        pass
    return found


def move_into(src: Path, dest_dir: Path) -> Path:
    """Move `src` directory into `dest_dir`, replacing any same-named target
    so the operation is idempotent. Returns the destination path.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / src.name
    if target.exists():
        shutil.rmtree(target)
    shutil.move(str(src), str(target))
    return target


def partition(archon_dir: Path) -> int:
    findings_dir = archon_dir / "findings"
    theoretical_dir = archon_dir / "findings-theoretical"

    kept: list[str] = []
    moved: list[dict] = []

    if findings_dir.is_dir():
        for entry in sorted(os.listdir(findings_dir)):
            folder = findings_dir / entry
            if not folder.is_dir() or not FINDING_DIR_RE.match(entry):
                continue
            status = read_poc_status(folder / "draft.md")
            if status == "executed":
                kept.append(entry)
                continue
            dest = move_into(folder, theoretical_dir)
            moved.append(
                {
                    "id": entry.split("-", 1)[0],
                    "dir": entry,
                    "poc_status": status or "missing",
                    "to": str(dest),
                }
            )

    manifest = {
        "archon_dir": str(archon_dir),
        "kept": kept,
        "moved": moved,
        "counts": {"kept": len(kept), "moved": len(moved)},
    }
    (archon_dir / "findings-draft").mkdir(parents=True, exist_ok=True)
    (archon_dir / "findings-draft" / "partition-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )
    print(json.dumps(manifest, indent=2))
    print(
        f"partition: {len(kept)} confirmed stay in findings/, "
        f"{len(moved)} demoted to findings-theoretical/ "
        f"(no PoC / theoretical / blocked)",
        file=sys.stderr,
    )
    return 0


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    if len(argv) > 1:
        print("usage: partition_findings.py [archon_dir]", file=sys.stderr)
        sys.exit(2)
    archon_dir = Path(argv[0]) if argv else Path("archon")
    if not archon_dir.is_dir():
        print(f"error: archon dir not found: {archon_dir}", file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(partition(archon_dir))
    except OSError as e:
        print(f"error: I/O failure during partition: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
