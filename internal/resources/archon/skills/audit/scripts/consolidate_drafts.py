#!/usr/bin/env python3
"""
Consolidate finding drafts into per-finding directories under archon/findings/.

Reads every *.md file in <archon_dir>/findings-draft/, parses its frontmatter,
keeps only Verdict: VALID drafts with Severity-Original in {CRITICAL, HIGH,
MEDIUM}, assigns deterministic severity-prefixed IDs (C1, C2..., H1, H2...,
M1, M2...), creates <archon_dir>/findings/<ID>-<slug>/evidence/ for each,
copies the draft plus any adversarial review and chamber debate transcript,
writes metadata.json for variant findings, and emits a manifest JSON to both
stdout and <archon_dir>/findings-draft/consolidation-manifest.json.

The manifest is the hand-off to the orchestrator: it lists each finding's
assigned ID, slug, folder, and original draft path so the orchestrator can
dispatch one poc-builder per entry without having to parse frontmatter itself.

Usage:
    consolidate_drafts.py [archon_dir]

archon_dir defaults to "archon". Exit codes:
    0  success
    1  no VALID Medium-or-higher drafts to consolidate
    2  usage error / archon_dir missing
    3  I/O error during consolidation
"""

import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM"]
SEVERITY_PREFIX = {"CRITICAL": "C", "HIGH": "H", "MEDIUM": "M"}

FILENAME_RE = re.compile(r"^([a-z]+\d*)-(\d+)(?:-(.+))?\.md$")
KV_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _-]*):\s*(.*)$")


@dataclass
class Draft:
    source_path: Path
    filename: str
    phase: str = ""
    sequence: str = ""
    slug: str = ""
    verdict: str = ""
    severity: str = ""
    debate_path: str = ""
    origin_finding: str = ""
    origin_pattern: str = ""
    assigned_id: str = ""
    origin_resolved_id: str = ""
    folder: Optional[Path] = field(default=None)

    @property
    def is_variant(self) -> bool:
        return bool(self.origin_finding)


def parse_frontmatter(path: Path) -> dict:
    """Parse the draft's Key: value header.

    The finding-draft template begins with '# [Title]' followed by a blank
    line, then Key: value lines, then a blank line, then '## Summary'. We
    skip leading blanks and the '#' title line, collect Key: value pairs
    until either a blank line or a '##' section heading appears.
    """
    out: dict = {}
    try:
        with path.open() as f:
            in_fm = False
            for line in f:
                s = line.rstrip("\n")
                if not in_fm:
                    if not s.strip():
                        continue  # leading blank lines
                    if s.startswith("# ") and not s.startswith("## "):
                        continue  # title line
                    if s.startswith("## "):
                        break  # no frontmatter at all
                    m = KV_RE.match(s)
                    if m:
                        out[m.group(1).strip()] = m.group(2).strip()
                        in_fm = True
                    continue
                # inside frontmatter
                if not s.strip():
                    break
                if s.startswith("## "):
                    break
                m = KV_RE.match(s)
                if m:
                    out[m.group(1).strip()] = m.group(2).strip()
    except OSError:
        pass
    return out


def parse_filename(filename: str) -> tuple[str, str, str]:
    m = FILENAME_RE.match(filename)
    if not m:
        base = filename[:-3] if filename.endswith(".md") else filename
        return "", "", base
    return m.group(1), m.group(2), m.group(3) or ""


def slugify(text: str) -> str:
    s = (text or "").lower().strip()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s[:60] or "unknown"


def load_drafts(draft_dir: Path) -> list[Draft]:
    drafts: list[Draft] = []
    if not draft_dir.is_dir():
        return drafts
    for entry in sorted(os.listdir(draft_dir)):
        if not entry.endswith(".md"):
            continue
        if entry == "consolidation-manifest.json":
            continue
        path = draft_dir / entry
        if not path.is_file():
            continue
        fm = parse_frontmatter(path)
        phase_prefix, seq_from_name, slug_from_name = parse_filename(entry)
        d = Draft(source_path=path, filename=entry)
        d.phase = (fm.get("Phase") or phase_prefix or "").strip()
        d.sequence = (fm.get("Sequence") or seq_from_name or "").strip()
        slug_source = fm.get("Slug") or slug_from_name or path.stem
        d.slug = slugify(slug_source)
        d.verdict = (fm.get("Verdict") or "").strip().upper()
        d.severity = (fm.get("Severity-Original") or "").strip().upper()
        d.debate_path = (fm.get("Debate") or "").strip()
        d.origin_finding = (fm.get("Origin-Finding") or "").strip()
        d.origin_pattern = (fm.get("Origin-Pattern") or "").strip()
        drafts.append(d)
    return drafts


def assign_ids(drafts: list[Draft]) -> tuple[list[Draft], list[dict]]:
    kept: list[Draft] = []
    dropped: list[dict] = []
    for d in drafts:
        if d.verdict != "VALID":
            dropped.append(
                {"file": d.filename, "reason": f"verdict={d.verdict or 'MISSING'}"}
            )
            continue
        if d.severity not in SEVERITY_PREFIX:
            dropped.append(
                {"file": d.filename, "reason": f"severity={d.severity or 'MISSING'}"}
            )
            continue
        kept.append(d)

    def sort_key(d: Draft):
        sev_rank = SEVERITY_ORDER.index(d.severity)
        # variants sort after non-variants of the same severity so the parent
        # exists in the id map by the time variant resolution runs.
        variant_rank = 1 if d.is_variant else 0
        try:
            seq_num = int(d.sequence)
        except (TypeError, ValueError):
            seq_num = 0
        return (sev_rank, variant_rank, d.phase, seq_num, d.filename)

    kept.sort(key=sort_key)

    counters = {sev: 0 for sev in SEVERITY_PREFIX}
    for d in kept:
        counters[d.severity] += 1
        d.assigned_id = f"{SEVERITY_PREFIX[d.severity]}{counters[d.severity]}"
    return kept, dropped


def resolve_variants(kept: list[Draft]) -> None:
    path_to_id: dict[str, str] = {}
    for d in kept:
        if d.is_variant:
            continue
        path_to_id[str(d.source_path)] = d.assigned_id
        path_to_id[d.source_path.name] = d.assigned_id
        path_to_id[f"archon/findings-draft/{d.source_path.name}"] = d.assigned_id
        path_to_id[f"findings-draft/{d.source_path.name}"] = d.assigned_id

    for d in kept:
        if not d.is_variant:
            continue
        origin = d.origin_finding.strip()
        if not origin:
            continue
        if origin in path_to_id:
            d.origin_resolved_id = path_to_id[origin]
            continue
        basename = os.path.basename(origin)
        if basename in path_to_id:
            d.origin_resolved_id = path_to_id[basename]


def copy_if_exists(src: Path, dest: Path) -> bool:
    if src.is_file():
        shutil.copy2(src, dest)
        return True
    return False


def resolve_debate_path(raw: str, archon_dir: Path) -> Optional[Path]:
    if not raw:
        return None
    p = Path(raw)
    candidates = [p]
    if not p.is_absolute():
        candidates.append(Path.cwd() / p)
        # Tolerate drafts that stored an archon-relative path.
        if raw.startswith("archon/"):
            candidates.append(archon_dir.parent / p)
        else:
            candidates.append(archon_dir / p)
    for c in candidates:
        if c.is_file():
            return c
    return None


def consolidate(archon_dir: Path) -> int:
    draft_dir = archon_dir / "findings-draft"
    findings_dir = archon_dir / "findings"
    adv_dir = archon_dir / "adversarial-reviews"

    drafts = load_drafts(draft_dir)
    if not drafts:
        print(f"error: no draft files found in {draft_dir}", file=sys.stderr)
        return 1

    kept, dropped = assign_ids(drafts)
    if not kept:
        manifest = {
            "archon_dir": str(archon_dir),
            "findings": [],
            "dropped": dropped,
            "counts": {"critical": 0, "high": 0, "medium": 0, "total": 0, "dropped": len(dropped)},
        }
        _write_manifest(draft_dir, manifest)
        print(json.dumps(manifest, indent=2))
        print(
            "warning: no VALID Medium-or-higher drafts to consolidate",
            file=sys.stderr,
        )
        return 1

    resolve_variants(kept)
    findings_dir.mkdir(parents=True, exist_ok=True)

    findings_out: list[dict] = []
    for d in kept:
        folder = findings_dir / f"{d.assigned_id}-{d.slug}"
        evidence = folder / "evidence"
        evidence.mkdir(parents=True, exist_ok=True)
        d.folder = folder

        shutil.copy2(d.source_path, folder / "draft.md")

        if adv_dir.is_dir():
            for candidate in (
                adv_dir / f"{d.slug}-review.md",
                adv_dir / f"{d.source_path.stem}-review.md",
            ):
                if copy_if_exists(candidate, folder / "adversarial-review.md"):
                    break

        debate = resolve_debate_path(d.debate_path, archon_dir)
        if debate is not None:
            shutil.copy2(debate, folder / "debate.md")

        if d.is_variant:
            meta = {
                "is_variant": True,
                "origin_finding_id": d.origin_resolved_id,
                "origin_finding_draft": d.origin_finding,
                "origin_pattern": d.origin_pattern,
            }
            (folder / "metadata.json").write_text(
                json.dumps(meta, indent=2) + "\n"
            )

        findings_out.append(
            {
                "id": d.assigned_id,
                "slug": d.slug,
                "severity": d.severity,
                "folder": str(folder),
                "draft_path": str(d.source_path),
                "is_variant": d.is_variant,
                "origin_finding_id": d.origin_resolved_id if d.is_variant else "",
            }
        )

    counts = {
        "critical": sum(1 for d in kept if d.severity == "CRITICAL"),
        "high": sum(1 for d in kept if d.severity == "HIGH"),
        "medium": sum(1 for d in kept if d.severity == "MEDIUM"),
        "total": len(kept),
        "dropped": len(dropped),
    }
    manifest = {
        "archon_dir": str(archon_dir),
        "findings": findings_out,
        "dropped": dropped,
        "counts": counts,
    }
    _write_manifest(draft_dir, manifest)
    print(json.dumps(manifest, indent=2))
    print(
        f"consolidated {counts['total']} findings "
        f"(C:{counts['critical']} H:{counts['high']} M:{counts['medium']}), "
        f"dropped {counts['dropped']}",
        file=sys.stderr,
    )
    return 0


def _write_manifest(draft_dir: Path, manifest: dict) -> None:
    draft_dir.mkdir(parents=True, exist_ok=True)
    path = draft_dir / "consolidation-manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    if len(argv) > 1:
        print("usage: consolidate_drafts.py [archon_dir]", file=sys.stderr)
        sys.exit(2)
    archon_dir = Path(argv[0]) if argv else Path("archon")
    if not archon_dir.is_dir():
        print(f"error: archon dir not found: {archon_dir}", file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(consolidate(archon_dir))
    except OSError as e:
        print(f"error: I/O failure during consolidation: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
