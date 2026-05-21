#!/usr/bin/env python3
"""
Consolidate finding drafts into per-finding directories under vigolium-results/findings/.

Reads every *.md file in <results_dir>/findings-draft/, parses its frontmatter,
keeps only Verdict: VALID drafts with Severity-Original in {CRITICAL, HIGH,
MEDIUM}, and assigns deterministic severity-prefixed IDs (C1, C2..., H1,
H2..., M1, M2...) from one global per-severity counter so IDs are unique and
stable across both buckets.

Every promoted draft becomes a directory `<ID>-<slug>/` containing the draft
plus any adversarial review, chamber debate transcript, and variant
metadata.json. The destination bucket depends on the triager's verdict:

- drafts NOT marked `Triage-Priority: skip` -> `<results_dir>/findings/`
  (the actionable bucket; a poc-author is dispatched per entry, and a
  post-PoC routing step later demotes any that did not reach
  `PoC-Status: executed` into findings-theoretical/).
- drafts marked `Triage-Priority: skip` -> `<results_dir>/findings-theoretical/`
  directly (no PoC build; finding-writer still authors report.md).

The manifest emitted to stdout and
<results_dir>/findings-draft/consolidation-manifest.json carries `findings`
(actionable, for poc-author fan-out), `theoretical` (reporter-only, no
PoC), and `dropped`. There is no longer a `findings-deferred/` folder —
triage-skipped findings are folded into the theoretical bucket.

Revisit mode: pass --continue-ids to seed the severity counters from the
max existing ID already present in <results_dir>/findings/. New finding
directories created in this mode also receive a metadata.json stamped with
round / revisit_id / model / agent_sdk (pulled from env vars the
orchestrator sets) so future revisits can attribute each finding to the
pass that produced it.

Env vars read in continuation mode:
    VIGOLIUM_AUDIT_REVISIT_ROUND     integer round number (2 = first revisit)
    VIGOLIUM_AUDIT_REVISIT_ID        ISO timestamp identifying the revisit
    VIGOLIUM_AUDIT_REVISIT_MODEL     model string (e.g. opus-4.7)
    VIGOLIUM_AUDIT_REVISIT_AGENT_SDK platform string (e.g. claude-code)

Usage:
    consolidate_drafts.py [results_dir] [--continue-ids]

results_dir defaults to "vigolium-results". Exit codes:
    0  success
    1  no VALID Medium-or-higher drafts to consolidate
    2  usage error / results_dir missing
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
EXISTING_FOLDER_RE = re.compile(r"^([CHM])(\d+)-")


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
    triage_priority: str = ""
    is_theoretical: bool = False
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
        d.triage_priority = (fm.get("Triage-Priority") or "").strip().lower()
        drafts.append(d)
    return drafts


def scan_existing_ids(*findings_dirs: Path) -> dict[str, int]:
    """Return the max existing ID number per severity prefix across the given
    finding buckets.

    Scans directory names matching `<C|H|M><number>-...` under every passed
    directory (e.g. findings/ AND findings-theoretical/) and returns a dict
    like {"C": 2, "H": 4, "M": 0} so a revisit run can seed its counters
    from that floor without colliding with IDs already used in either bucket.
    """
    maxes = {"C": 0, "H": 0, "M": 0}
    for findings_dir in findings_dirs:
        if not findings_dir.is_dir():
            continue
        for entry in os.listdir(findings_dir):
            m = EXISTING_FOLDER_RE.match(entry)
            if not m:
                continue
            prefix = m.group(1)
            try:
                num = int(m.group(2))
            except ValueError:
                continue
            if num > maxes.get(prefix, 0):
                maxes[prefix] = num
    return maxes


def assign_ids(
    drafts: list[Draft],
    seed_counters: Optional[dict[str, int]] = None,
) -> tuple[list[Draft], list[dict]]:
    """Partition drafts into (promoted, dropped) and assign global IDs.

    `promoted` is every draft that passed the verdict + severity gates. Each
    promoted draft receives a deterministic severity-prefixed ID from ONE
    per-severity counter, regardless of bucket, so IDs stay unique and stable
    even if a finding is later moved from findings/ to findings-theoretical/
    by the post-PoC routing step.

    A promoted draft tagged `Triage-Priority: skip` by the finding-grader is
    flagged `is_theoretical=True`: it still gets an ID and a directory, but
    `consolidate()` writes it straight into findings-theoretical/ (no PoC
    build). `dropped` drafts failed verdict/severity and are discarded.
    """
    promoted: list[Draft] = []
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
        d.is_theoretical = d.triage_priority == "skip"
        promoted.append(d)

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

    promoted.sort(key=sort_key)

    # Seed counters from existing findings/ + findings-theoretical/ when
    # running in revisit continuation mode so new IDs don't collide with
    # round-1 folders in either bucket.
    counters = {sev: 0 for sev in SEVERITY_PREFIX}
    if seed_counters:
        for sev, prefix in SEVERITY_PREFIX.items():
            counters[sev] = seed_counters.get(prefix, 0)
    for d in promoted:
        counters[d.severity] += 1
        d.assigned_id = f"{SEVERITY_PREFIX[d.severity]}{counters[d.severity]}"
    return promoted, dropped


def resolve_variants(promoted: list[Draft]) -> None:
    # Build the parent path->ID map across BOTH buckets: a variant in
    # findings/ may point at a parent that was triage-skipped into
    # findings-theoretical/ (or vice versa), and IDs share one namespace.
    path_to_id: dict[str, str] = {}
    for d in promoted:
        if d.is_variant:
            continue
        path_to_id[str(d.source_path)] = d.assigned_id
        path_to_id[d.source_path.name] = d.assigned_id
        path_to_id[f"vigolium-results/findings-draft/{d.source_path.name}"] = d.assigned_id
        path_to_id[f"findings-draft/{d.source_path.name}"] = d.assigned_id

    for d in promoted:
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


def resolve_debate_path(raw: str, results_dir: Path) -> Optional[Path]:
    if not raw:
        return None
    p = Path(raw)
    candidates = [p]
    if not p.is_absolute():
        candidates.append(Path.cwd() / p)
        # Tolerate drafts that stored an vigolium-audit-relative path.
        if raw.startswith("vigolium-results/"):
            candidates.append(results_dir.parent / p)
        else:
            candidates.append(results_dir / p)
    for c in candidates:
        if c.is_file():
            return c
    return None


def _materialize_finding(
    d: Draft,
    dest_dir: Path,
    results_dir: Path,
    adv_dir: Path,
    revisit_meta: Optional[dict],
) -> dict:
    """Create `<dest_dir>/<ID>-<slug>/`, copy the draft + sibling artefacts +
    metadata.json into it, and return the manifest entry. Shared by both the
    actionable (findings/) and theoretical (findings-theoretical/) buckets so
    a triage-skipped finding has the exact same on-disk shape as an
    actionable one — finding-writer can author report.md for either.
    """
    folder = dest_dir / f"{d.assigned_id}-{d.slug}"
    (folder / "evidence").mkdir(parents=True, exist_ok=True)
    d.folder = folder

    shutil.copy2(d.source_path, folder / "draft.md")

    if adv_dir.is_dir():
        for candidate in (
            adv_dir / f"{d.slug}-review.md",
            adv_dir / f"{d.source_path.stem}-review.md",
        ):
            if copy_if_exists(candidate, folder / "adversarial-review.md"):
                break

    debate = resolve_debate_path(d.debate_path, results_dir)
    if debate is not None:
        shutil.copy2(debate, folder / "debate.md")

    is_revisit = bool(revisit_meta and revisit_meta.get("round"))
    meta: dict = {}
    if d.is_variant:
        meta.update(
            {
                "is_variant": True,
                "origin_finding_id": d.origin_resolved_id,
                "origin_finding_draft": d.origin_finding,
                "origin_pattern": d.origin_pattern,
            }
        )
    elif is_revisit:
        # Non-revisit non-variants emit no metadata.json (the report-composer
        # treats its absence as "round 1"); a revisit round still needs the
        # is_variant: False marker so the round stamp below has a home.
        meta["is_variant"] = False
    if is_revisit:
        meta.update(
            {
                "round": revisit_meta["round"],
                "revisit_id": revisit_meta.get("revisit_id"),
                "model": revisit_meta.get("model"),
                "agent_sdk": revisit_meta.get("agent_sdk"),
            }
        )
    if meta:
        (folder / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")

    return {
        "id": d.assigned_id,
        "slug": d.slug,
        "severity": d.severity,
        "folder": str(folder),
        "draft_path": str(d.source_path),
        "is_variant": d.is_variant,
        "origin_finding_id": d.origin_resolved_id if d.is_variant else "",
    }


_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}


def consolidate(results_dir: Path, continue_ids: bool = False) -> int:
    draft_dir = results_dir / "findings-draft"
    findings_dir = results_dir / "findings"
    theoretical_dir = results_dir / "findings-theoretical"
    adv_dir = results_dir / "adversarial-reviews"

    drafts = load_drafts(draft_dir)
    if not drafts:
        print(f"error: no draft files found in {draft_dir}", file=sys.stderr)
        return 1

    seed_counters: Optional[dict[str, int]] = None
    if continue_ids:
        seed_counters = scan_existing_ids(findings_dir, theoretical_dir)
        print(
            f"continue-ids: seeding counters from existing findings/ + "
            f"findings-theoretical/: C={seed_counters.get('C', 0)} "
            f"H={seed_counters.get('H', 0)} M={seed_counters.get('M', 0)}",
            file=sys.stderr,
        )

    revisit_meta: Optional[dict] = None
    if continue_ids:
        round_raw = os.environ.get("VIGOLIUM_AUDIT_REVISIT_ROUND", "").strip()
        try:
            round_int = int(round_raw) if round_raw else 0
        except ValueError:
            round_int = 0
        revisit_meta = {
            "round": round_int or None,
            "revisit_id": os.environ.get("VIGOLIUM_AUDIT_REVISIT_ID", "") or None,
            "model": os.environ.get("VIGOLIUM_AUDIT_REVISIT_MODEL", "") or None,
            "agent_sdk": os.environ.get("VIGOLIUM_AUDIT_REVISIT_AGENT_SDK", "") or None,
        }

    promoted, dropped = assign_ids(drafts, seed_counters=seed_counters)
    if not promoted:
        manifest = {
            "results_dir": str(results_dir),
            "findings": [],
            "theoretical": [],
            "dropped": dropped,
            "counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "total": 0,
                "dropped": len(dropped),
                "theoretical": 0,
            },
        }
        _write_manifest(draft_dir, manifest)
        print(json.dumps(manifest, indent=2))
        print(
            "warning: no VALID Medium-or-higher drafts to consolidate",
            file=sys.stderr,
        )
        return 1

    resolve_variants(promoted)

    findings_out: list[dict] = []
    theoretical_out: list[dict] = []
    for d in promoted:
        dest = theoretical_dir if d.is_theoretical else findings_dir
        entry = _materialize_finding(d, dest, results_dir, adv_dir, revisit_meta)
        (theoretical_out if d.is_theoretical else findings_out).append(entry)

    counts = {
        "critical": sum(1 for d in promoted if d.severity == "CRITICAL"),
        "high": sum(1 for d in promoted if d.severity == "HIGH"),
        "medium": sum(1 for d in promoted if d.severity == "MEDIUM"),
        "total": len(promoted),
        "dropped": len(dropped),
        "theoretical": len(theoretical_out),
    }
    # findings/ feeds the poc-author fan-out so it sorts P0-first; theoretical/
    # is reporter-only (no PoC budget to spend) so plain severity order suffices.
    findings_out = _sort_by_triage_priority(findings_out, promoted)
    theoretical_out.sort(
        key=lambda e: (_SEVERITY_RANK.get(e.get("severity", ""), 9), e.get("id", ""))
    )
    manifest = {
        "results_dir": str(results_dir),
        "findings": findings_out,
        "theoretical": theoretical_out,
        "dropped": dropped,
        "counts": counts,
    }
    _write_manifest(draft_dir, manifest)
    print(json.dumps(manifest, indent=2))
    msg = (
        f"consolidated {counts['total']} findings "
        f"(C:{counts['critical']} H:{counts['high']} M:{counts['medium']}); "
        f"{len(findings_out)} actionable -> findings/, "
        f"{len(theoretical_out)} triage-skip -> findings-theoretical/"
    )
    msg += f", dropped {counts['dropped']}"
    print(msg, file=sys.stderr)
    return 0


# Order in which P-priorities are processed by downstream poc-author fan-out.
# Lower index = higher priority; unknown / missing priorities sort after P2 so
# the orchestrator still builds them but only after the explicitly-prioritized
# set has consumed its budget.
TRIAGE_PRIORITY_RANK = {"p0": 0, "p1": 1, "p2": 2, "": 3}


def _sort_by_triage_priority(
    findings_out: list[dict], promoted: list[Draft]
) -> list[dict]:
    """Return findings_out sorted so triage P0 entries come first, then P1,
    then P2, then anything without a triage marker. Within each priority
    bucket the existing severity ordering is preserved (CRITICAL → HIGH →
    MEDIUM as already established by `assign_ids`).
    """
    by_id: dict[str, str] = {}
    for d in promoted:
        by_id[d.assigned_id] = (d.triage_priority or "").lower()

    def key(entry: dict):
        prio = by_id.get(entry.get("id", ""), "")
        prio_rank = TRIAGE_PRIORITY_RANK.get(prio, 3)
        sev_rank = _SEVERITY_RANK.get(entry.get("severity", ""), 9)
        return (prio_rank, sev_rank, entry.get("id", ""))

    return sorted(findings_out, key=key)


def _write_manifest(draft_dir: Path, manifest: dict) -> None:
    draft_dir.mkdir(parents=True, exist_ok=True)
    path = draft_dir / "consolidation-manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    continue_ids = False
    positional: list[str] = []
    for arg in argv:
        if arg == "--continue-ids":
            continue_ids = True
        else:
            positional.append(arg)
    if len(positional) > 1:
        print(
            "usage: consolidate_drafts.py [results_dir] [--continue-ids]",
            file=sys.stderr,
        )
        sys.exit(2)

    results_dir = Path(positional[0]) if positional else Path("vigolium-results")
    if not results_dir.is_dir():
        print(f"error: vigolium-audit dir not found: {results_dir}", file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(consolidate(results_dir, continue_ids=continue_ids))
    except OSError as e:
        print(f"error: I/O failure during consolidation: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
