#!/usr/bin/env python3
"""
Validate phase output before marking complete in audit-state.json.

Usage: validate_phase_output.py <phase_number> <security_dir>
Exit 0: validation passed
Exit 1: validation failed (prints reasons)
Exit 2: usage error
"""

import os
import sys

# All phase outputs write into security/knowledge-base-report.md (phases 1-7) or
# security/final-audit-report.md (phase 10). Checks verify KB sections and CodeQL artifacts.
#
# "kb_sections" entries are literal strings that must appear in knowledge-base-report.md.
# "files" entries are non-KB artifact files that must exist.
KB_FILE = "knowledge-base-report.md"

PHASE_REQUIREMENTS = {
    1: {
        "files": [KB_FILE],
        "kb_sections": ["Advisory Intelligence"],
    },
    2: {
        "files": [KB_FILE],
        "kb_sections": ["Bypass Analysis"],
    },
    3: {
        "files": [KB_FILE],
        "kb_sections": [
            "Project Classification",
            "Trust Boundaries",
            "DFD",
            "Threat Model",
            "Attack Surface",
            "Domain Attack Research",
        ],
    },
    4: {
        "files": [
            KB_FILE,
            "codeql-artifacts/entry-points.json",
            "codeql-artifacts/sinks.json",
            "codeql-artifacts/call-graph-slices.json",
            "codeql-artifacts/flow-paths-all-severities.md",
        ],
        "kb_sections": ["Static Analysis Summary", "CodeQL Structural Analysis"],
    },
    5: {
        # Phase 5 updates the KB in-place; Phase 5 Enrichment Notes section must be present
        "files": [KB_FILE],
        "kb_sections": ["Phase 5 Enrichment Notes"],
    },
    6: {
        # Spec Gap Analysis section must exist (may be "None identified" if no specs found)
        "files": [KB_FILE],
        "kb_sections": ["Spec Gap Analysis"],
    },
    7: {
        "files": [],
        "kb_sections": [],
        "findings_draft_required": True,
        "kb_addendum_required": True,
        "chamber_workspace_required": True,
        "attack_pattern_registry_required": True,
    },
    8: {
        "files": [],
        "kb_sections": [],
        "verdict_in_drafts_required": True,
        "adversarial_review_required": True,  # P8-LITE: only for CRITICAL/HIGH
    },
    9: {
        "files": [],
        "kb_sections": [],
        "findings_draft_required": True,
    },
    10: {
        "files": ["final-audit-report.md"],
        "kb_sections": [],
        "sections": {
            "final-audit-report.md": [
                "Executive Summary",
                "Methodology",
                "Summary of Findings",
                "Conclusion",
            ],
        },
    },
}

# Files that must NOT exist in security/ (consolidated into knowledge-base-report.md)
STALE_FILES = [
    "advisory-hunter-report.md",
    "bypass-analysis-report.md",
    "threat-model-report.md",
    "attack-surface-report.md",
    "static-analysis-report.md",
    "actions-audit-report.md",
    "spec-gaps-report.md",
    "final-findings-report.md",
]

VERDICT_MARKERS = ("VALID", "FALSE POSITIVE", "BY DESIGN", "OUT OF SCOPE", "FALSE POSITIVE (adversarial)")


def check_findings_draft(security_dir: str) -> tuple[bool, str]:
    draft_dir = os.path.join(security_dir, "findings-draft")
    if not os.path.isdir(draft_dir):
        return False, "findings-draft/ directory does not exist"
    entries = [f for f in os.listdir(draft_dir) if f.endswith(".md")]
    if not entries:
        return False, "findings-draft/ is empty — no findings were persisted to disk"
    return True, ""


def check_kb_addendum(security_dir: str) -> tuple[bool, str]:
    kb_path = os.path.join(security_dir, "knowledge-base-report.md")
    if not os.path.isfile(kb_path):
        return False, "knowledge-base-report.md not found for addendum check"
    try:
        content = open(kb_path).read()
    except OSError as e:
        return False, f"Could not read knowledge-base-report.md: {e}"
    if "Phase 7 Addendum" not in content:
        return False, "knowledge-base-report.md missing '## Phase 7 Addendum' section"
    return True, ""


def check_chamber_workspace(security_dir: str) -> tuple[bool, str]:
    """Verify chamber-workspace/ exists with at least one chamber containing a CLOSED debate."""
    workspace = os.path.join(security_dir, "chamber-workspace")
    if not os.path.isdir(workspace):
        return False, "chamber-workspace/ directory does not exist — Phase 7 Review Chambers required"
    chambers = [d for d in os.listdir(workspace) if os.path.isdir(os.path.join(workspace, d))]
    if not chambers:
        return False, "chamber-workspace/ is empty — no Review Chambers were created"
    for chamber in chambers:
        debate_path = os.path.join(workspace, chamber, "debate.md")
        if not os.path.isfile(debate_path):
            return False, f"chamber-workspace/{chamber}/debate.md does not exist"
        try:
            content = open(debate_path).read()
        except OSError as e:
            return False, f"Could not read debate.md for {chamber}: {e}"
        if "CLOSED" not in content:
            return False, f"chamber-workspace/{chamber}/debate.md Status is not CLOSED"
    return True, ""


def check_attack_pattern_registry(security_dir: str) -> tuple[bool, str]:
    """Verify attack-pattern-registry.json exists and is valid JSON."""
    import json
    registry_path = os.path.join(security_dir, "attack-pattern-registry.json")
    if not os.path.isfile(registry_path):
        return False, "attack-pattern-registry.json does not exist"
    try:
        data = json.loads(open(registry_path).read())
    except (OSError, json.JSONDecodeError) as e:
        return False, f"attack-pattern-registry.json is invalid: {e}"
    if "patterns" not in data:
        return False, "attack-pattern-registry.json missing 'patterns' key"
    return True, ""


def check_adversarial_reviews(security_dir: str) -> tuple[bool, str]:
    """P8-LITE: adversarial reviews required only for CRITICAL and HIGH VALID findings.
    Medium findings skip Stage 2 (already challenged by Devil's Advocate in chamber debate)."""
    draft_dir = os.path.join(security_dir, "findings-draft")
    reviews_dir = os.path.join(security_dir, "adversarial-reviews")

    if not os.path.isdir(draft_dir):
        return True, ""  # No drafts to check

    # Find VALID findings that are CRITICAL or HIGH (these need cold verification)
    critical_high_valid = []
    for fname in os.listdir(draft_dir):
        if not fname.endswith(".md"):
            continue
        fpath = os.path.join(draft_dir, fname)
        try:
            content = open(fpath).read()
        except OSError:
            continue
        if "Verdict: VALID" in content:
            # Check if CRITICAL or HIGH severity
            content_upper = content.upper()
            if "SEVERITY-ORIGINAL: CRITICAL" in content_upper or "SEVERITY-ORIGINAL: HIGH" in content_upper:
                critical_high_valid.append(fname)

    if not critical_high_valid:
        return True, ""  # No CRITICAL/HIGH VALID findings, Stage 2 not required

    # Check that adversarial-reviews/ directory exists and has review files
    if not os.path.isdir(reviews_dir):
        return False, (
            "CRITICAL/HIGH VALID findings exist but security/adversarial-reviews/ is missing. "
            "P8-LITE Stage 2 cold verification is required for CRITICAL and HIGH findings."
        )
    review_files = [f for f in os.listdir(reviews_dir) if f.endswith(".md")]
    if not review_files:
        return False, (
            "CRITICAL/HIGH VALID findings exist but security/adversarial-reviews/ is empty. "
            "P8-LITE Stage 2 cold verification is required for CRITICAL and HIGH findings."
        )

    # Check each CRITICAL/HIGH VALID draft has an Adversarial-Verdict: line
    missing_verdict = []
    for fname in critical_high_valid:
        fpath = os.path.join(draft_dir, fname)
        try:
            content = open(fpath).read()
        except OSError:
            continue
        if "Adversarial-Verdict:" not in content:
            missing_verdict.append(fname)

    if missing_verdict:
        return False, (
            f"CRITICAL/HIGH VALID findings missing Adversarial-Verdict: {', '.join(missing_verdict)}. "
            "P8-LITE Stage 2 cold verification must write verdicts back into CRITICAL/HIGH drafts."
        )

    return True, ""


def check_verdict_in_drafts(security_dir: str) -> tuple[bool, str]:
    draft_dir = os.path.join(security_dir, "findings-draft")
    if not os.path.isdir(draft_dir):
        return False, "findings-draft/ directory does not exist"
    for fname in os.listdir(draft_dir):
        if not fname.endswith(".md"):
            continue
        try:
            content = open(os.path.join(draft_dir, fname)).read()
        except OSError:
            continue
        if any(marker in content for marker in VERDICT_MARKERS):
            return True, ""
    return False, (
        "No verdict found in any findings-draft/ file. "
        "FP elimination verdicts (VALID / FALSE POSITIVE / BY DESIGN / OUT OF SCOPE) "
        "must be written back into draft files during Phase 8."
    )


def validate_phase(phase: int, security_dir: str) -> tuple[bool, list[str]]:
    errors: list[str] = []
    req = PHASE_REQUIREMENTS.get(phase)
    if req is None:
        return True, []

    # Required files must exist and be non-empty
    for fname in req.get("files", []):
        fpath = os.path.join(security_dir, fname)
        if not os.path.isfile(fpath):
            errors.append(f"Missing required output file: {fname}")
            continue
        if os.path.getsize(fpath) == 0:
            errors.append(f"Output file is empty: {fname}")

    # KB section checks — verify knowledge-base-report.md contains expected section headers
    kb_sections = req.get("kb_sections", [])
    if kb_sections:
        kb_path = os.path.join(security_dir, KB_FILE)
        try:
            kb_content = open(kb_path).read()
        except OSError as e:
            errors.append(f"Could not read {KB_FILE}: {e}")
            kb_content = ""
        for section in kb_sections:
            if section not in kb_content:
                errors.append(f"{KB_FILE}: missing required section '{section}'")

    # Structural content checks for non-KB files (Phase 10 final-audit-report)
    for fname, markers in req.get("sections", {}).items():
        fpath = os.path.join(security_dir, fname)
        if not os.path.isfile(fpath):
            continue  # already reported above
        try:
            content = open(fpath).read()
        except OSError as e:
            errors.append(f"Could not read {fname}: {e}")
            continue
        for marker in markers:
            if marker not in content:
                errors.append(f"{fname}: missing required content '{marker}'")

    # findings-draft presence check
    if req.get("findings_draft_required"):
        ok, msg = check_findings_draft(security_dir)
        if not ok:
            errors.append(msg)

    # KB addendum check (Phase 7 only)
    if req.get("kb_addendum_required"):
        ok, msg = check_kb_addendum(security_dir)
        if not ok:
            errors.append(msg)

    # Verdict-in-drafts check (Phase 8)
    if req.get("verdict_in_drafts_required"):
        ok, msg = check_verdict_in_drafts(security_dir)
        if not ok:
            errors.append(msg)

    # Adversarial review check (Phase 8 Stage 2 — P8-LITE: CRITICAL/HIGH only)
    if req.get("adversarial_review_required"):
        ok, msg = check_adversarial_reviews(security_dir)
        if not ok:
            errors.append(msg)

    # Chamber workspace check (Phase 7 Review Chambers)
    if req.get("chamber_workspace_required"):
        ok, msg = check_chamber_workspace(security_dir)
        if not ok:
            errors.append(msg)

    # Attack pattern registry check (Phase 7)
    if req.get("attack_pattern_registry_required"):
        ok, msg = check_attack_pattern_registry(security_dir)
        if not ok:
            errors.append(msg)

    return len(errors) == 0, errors


def lint_all(security_dir: str) -> tuple[bool, list[str]]:
    """Full-audit consistency checks across the security/ directory."""
    import json

    errors: list[str] = []

    # 1. Load audit-state.json — history format: {"audits": [...]}
    state_path = os.path.join(security_dir, "audit-state.json")
    current_audit: dict = {}
    if os.path.isfile(state_path):
        try:
            data = json.loads(open(state_path).read())
            audits = data.get("audits", [])
            if audits:
                current_audit = audits[-1]  # most recent entry is the current audit
            else:
                errors.append("audit-state.json has an empty 'audits' array")
        except (OSError, json.JSONDecodeError) as e:
            errors.append(f"audit-state.json unreadable: {e}")

    # 2. State vs artifact alignment: completed phases must have their KB sections and files
    phases_state = current_audit.get("phases", {})
    kb_path = os.path.join(security_dir, KB_FILE)
    kb_content = ""
    if os.path.isfile(kb_path):
        try:
            kb_content = open(kb_path).read()
        except OSError:
            pass

    for phase_str, info in phases_state.items():
        if info.get("status") != "complete":
            continue
        try:
            phase_num = int(phase_str)
        except ValueError:
            continue
        req = PHASE_REQUIREMENTS.get(phase_num, {})
        for fname in req.get("files", []):
            fpath = os.path.join(security_dir, fname)
            if not os.path.isfile(fpath):
                errors.append(
                    f"Phase {phase_num} marked complete but output missing: {fname}"
                )
        for section in req.get("kb_sections", []):
            if kb_content and section not in kb_content:
                errors.append(
                    f"Phase {phase_num} marked complete but KB missing section '{section}'"
                )

    # 3. KB addendum: if Phase 7 is complete, addendum must be present
    p7_info = phases_state.get("7", {})
    if p7_info.get("status") == "complete":
        ok, msg = check_kb_addendum(security_dir)
        if not ok:
            errors.append(f"Phase 7 complete but KB addendum missing: {msg}")

    # 4. Finding ID cross-reference: IDs in final-audit-report.md must have findings/ dirs
    final_report = os.path.join(security_dir, "final-audit-report.md")
    if os.path.isfile(final_report):
        import re
        content = open(final_report).read()
        ids_in_report = re.findall(r"\b([CH ML][0-9]+)-[\w-]+", content)
        findings_dir = os.path.join(security_dir, "findings")
        if os.path.isdir(findings_dir):
            existing = set(os.listdir(findings_dir))
            for fid in set(ids_in_report):
                matches = [d for d in existing if d.startswith(fid + "-") or d.startswith(fid.replace(" ", ""))]
                if not matches:
                    errors.append(
                        f"final-audit-report.md references {fid} but no matching directory in security/findings/"
                    )

    # 5. Findings-draft cleanup: VALID drafts must have corresponding findings/ dirs
    draft_dir = os.path.join(security_dir, "findings-draft")
    findings_dir = os.path.join(security_dir, "findings")
    if os.path.isdir(draft_dir):
        for fname in os.listdir(draft_dir):
            if not fname.endswith(".md"):
                continue
            fpath = os.path.join(draft_dir, fname)
            try:
                content = open(fpath).read()
            except OSError:
                continue
            if "Verdict: VALID" in content:
                slug = fname.replace(".md", "")
                if os.path.isdir(findings_dir):
                    matches = [d for d in os.listdir(findings_dir) if slug in d]
                    if not matches:
                        errors.append(
                            f"findings-draft/{fname} has Verdict: VALID but was not promoted to security/findings/"
                        )

    # 6. Stale separate report files must not exist (consolidated into knowledge-base-report.md)
    for stale in STALE_FILES:
        if os.path.isfile(os.path.join(security_dir, stale)):
            errors.append(
                f"Stale report file exists: {stale} — this has been consolidated into "
                f"{KB_FILE} and should be removed."
            )

    # 7. Orphan detection: files in security/ root not in the known output set
    known_outputs: set[str] = {KB_FILE, "final-audit-report.md", "audit-state.json", "bounty-scope.md",
                               "attack-pattern-registry.json"}
    known_dirs = {
        "findings", "findings-draft", "codeql-artifacts", "codeql-queries", "semgrep-rules",
        "adversarial-reviews", "real-env-evidence", "chamber-workspace",
    }
    for entry in os.listdir(security_dir):
        entry_path = os.path.join(security_dir, entry)
        if os.path.isdir(entry_path):
            if entry not in known_dirs:
                errors.append(f"Unexpected directory in security/: {entry}/")
        elif entry.endswith(".md") or entry.endswith(".json"):
            if entry not in known_outputs:
                errors.append(f"Orphaned file in security/ (not in any phase output map): {entry}")

    return len(errors) == 0, errors


def main() -> None:
    if len(sys.argv) < 3:
        print(
            "Usage: validate_phase_output.py <phase_number|all> <security_dir>",
            file=sys.stderr,
        )
        sys.exit(2)

    phase_arg = sys.argv[1]
    security_dir = sys.argv[2]

    if not os.path.isdir(security_dir):
        print(f"Security directory not found: {security_dir}", file=sys.stderr)
        sys.exit(2)

    if phase_arg == "all":
        passed, errors = lint_all(security_dir)
        label = "Full audit lint"
    else:
        try:
            phase = int(phase_arg)
        except ValueError:
            print(f"Invalid phase number: {phase_arg}", file=sys.stderr)
            sys.exit(2)
        passed, errors = validate_phase(phase, security_dir)
        label = f"Phase {phase} validation"

    if passed:
        print(f"{label} passed.")
        sys.exit(0)
    else:
        print(f"{label} FAILED:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
