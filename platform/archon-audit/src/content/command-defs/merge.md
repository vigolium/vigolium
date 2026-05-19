---
description: Agent-driven post-merge normalization of an `archon/` directory that the CLI has just pre-merged from two-or-more inputs via `archon-audit merge`. Validates every finding against the standard format, semantically deduplicates by root cause, auto-fixes safe issues, quarantines unfixable ones, renumbers per severity, regenerates summaries, and writes `archon/merge-report.md`.
argument-hint: "(no positional args — input dirs come from --dir on the CLI)"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
mode: merge
phases:
  - id: M1
    title: Validate Every Finding
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: []
  - id: M2
    title: Semantic Dedup by Root Cause
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: [M1]
  - id: M3
    title: Auto-Fix Safe Issues
    agent: finding-writer
    requires_git: false
    parallel_with: []
    depends_on: [M2]
  - id: M4
    title: Quarantine Unfixable
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: [M3]
  - id: M5
    title: Renumber + Rebuild References
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: [M4]
  - id: M6
    title: Regenerate Summaries
    agent: report-composer
    requires_git: false
    parallel_with: []
    depends_on: [M5]
  - id: M7
    title: Cleanup + merge-report.md
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: [M6]
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat archon/audit-context.md 2>/dev/null || echo "(none)"`
- Audit state: !`cat archon/audit-state.json 2>/dev/null | head -200 || echo "NO archon/audit-state.json — abort"`
- Findings present: !`ls -1 archon/findings/ 2>/dev/null | wc -l | tr -d ' '`
- Existing quarantine dir: !`ls -1 archon/quarantine/ 2>/dev/null | wc -l | tr -d ' '`
- Merge metadata present: !`grep -q '"merge_metadata"' archon/audit-state.json 2>/dev/null && echo "yes" || echo "no"`

## Your Task

The CLI has already run the deterministic file-merge step (`archon-audit merge`) and dropped the result at `archon/`. Your job is the LLM-only work: enforce the standard finding format, dedupe semantically by root cause, repair what's repairable, quarantine what isn't, renumber per severity, regenerate summaries, and document everything in `archon/merge-report.md`.

You operate in **autonomous mode** by default — do not pause for confirmation on individual decisions; surface every choice in `merge-report.md` at the end. Pause and ask only if a structural blocker is hit (e.g., audit-state.json is corrupt, no findings exist).

### Pre-Flight Check

1. **Merge context**: `archon/audit-state.json` MUST contain a top-level `merge_metadata` object — that's how you confirm the CLI's pre-merge step actually ran. If absent, abort with: "Not in merge context. Run `archon-audit run --mode merge --dir A --dir B` instead of invoking this command directly."
2. **Findings exist**: `archon/findings/` OR `archon/findings-theoretical/` MUST contain at least one directory. If both are empty, write a stub `archon/merge-report.md` noting "no findings to normalize", then exit cleanly.
3. **Lock file**: if `archon/.merge-lock` exists, check whether the recorded PID is alive. If alive → abort. If stale → delete and reclaim. Then write a new lock with the current PID and an ISO timestamp.

### Setup

```bash
mkdir -p archon/quarantine/ archon/merge-workspace/

cat > archon/.merge-lock <<EOF
{"pid": $$, "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF

cleanup_merge() {
  rm -rf archon/merge-workspace/
  rm -f archon/.merge-lock
}
trap cleanup_merge EXIT INT TERM
```

### Standard Finding Contract (the rubric you enforce)

Findings live in two buckets: `archon/findings/` (confirmed — PoC executed) and `archon/findings-theoretical/` (theoretical/unconfirmed — no PoC / theoretical / blocked / triage-skipped). IDs share one namespace across both. A finding directory `<ID>-<slug>/` in **either** bucket is **standard** iff all of these hold:

1. `draft.md` exists and its leading frontmatter carries the required fields: `Phase`, `Sequence`, `Slug`, `Severity-Original`, `Severity-Final`, `Verdict`. `PoC-Status` is required for `archon/findings/` entries (must be `executed`); for `archon/findings-theoretical/` entries it is optional and, when present, is `theoretical`/`blocked` (triage-skipped findings have no `PoC-Status` at all — that is valid). (Frontmatter format is bare `Key: Value` lines at the top of the file, terminated by a blank line or the first `## ` section.)
2. `report.md` exists and contains all nine required H2 sections, exactly: `## Summary`, `## Severity, Confidence, Vulnerability Type`, `## Impact`, `## Affected Component`, `## Source to Sink Flow`, `## Vulnerable Code`, `## Proof of concept & Evidence`, `## Preconditions`, `## Remediation`. File size > 500 bytes.
3. (Confirmed bucket only) If `poc.{py,sh,js,rb,go}` exists, its **last stdout line when executed** is contractually a JSON object `{"status":"confirmed|failed|inconclusive","evidence":"...","notes":"..."}`. Static check: the script's source contains a final `print`/`echo`/`console.log` of that JSON shape. (Don't actually execute scripts during merge — static check only.) Theoretical-bucket findings have no `poc.*` and must NOT be flagged for its absence.
4. (Confirmed bucket only) If `Severity-Final` is `CRITICAL` or `HIGH`, `evidence/` exists and is non-empty. Theoretical-bucket findings legitimately have an empty `evidence/`.
5. Directory name matches `<Severity><N>-<slug>` where Severity ∈ {C,H,M,L} and matches the prefix derived from the frontmatter's `Severity-Final` (`CRITICAL`→C, `HIGH`→H, `MEDIUM`→M, `LOW`→L).
6. If `metadata.json` exists with `"is_variant": true`, its `origin_finding_id` MUST resolve to another finding directory present in either bucket.

### Task List

Create tasks via `TaskCreate`:

| Task | Pass | Depends on |
|------|------|-----------|
| M1 | Validate every finding | — |
| M2 | Semantic dedup by root cause | M1 |
| M3 | Auto-fix safe issues | M2 |
| M4 | Quarantine unfixable | M3 |
| M5 | Renumber + rebuild references | M4 |
| M6 | Regenerate summaries | M5 |
| M7 | Cleanup + merge-report.md | M6 |

---

## Pass M1 — Validate Every Finding

Walk **both** `archon/findings/*/` and `archon/findings-theoretical/*/`. For each directory, record which bucket it is in, check the rubric above (bucket-aware), and produce a normalized index entry. Write the full index to `archon/merge-workspace/findings-index.json`:

```json
{
  "findings": [
    {
      "id": "C1",
      "dir": "archon/findings/C1-sqli-login/",
      "bucket": "findings",
      "slug": "sqli-login",
      "severity_dir": "C",
      "severity_frontmatter": "CRITICAL",
      "frontmatter": {
        "Phase": "8", "Sequence": "001", "Slug": "sqli-login",
        "Severity-Original": "CRITICAL", "Severity-Final": "CRITICAL",
        "Verdict": "VALID", "PoC-Status": "executed"
      },
      "root_cause": {"file": "src/auth/login.py", "line": 42, "sink": "execute(query)", "class": "SQLi"},
      "files": {
        "draft_md": true, "report_md": true, "poc": "poc.py",
        "evidence_dir": true, "metadata_json": false,
        "debate_md": true, "adversarial_review_md": false
      },
      "completeness_score": 7,
      "issues": []
    }
  ]
}
```

**Issue codes** (bake these into the `issues` array — used by M3/M4):

| Code | Meaning | M3 fix? | M4 quarantine? |
|------|---------|---------|----------------|
| `missing-report-md` | `report.md` absent or <500 bytes or missing required H2 sections | yes (call finding-writer) | only if finding-writer fails |
| `missing-draft-md` | `draft.md` absent | no — synthesize stub from report.md if possible | yes if no report.md either |
| `missing-frontmatter-field` | `draft.md` exists but lacks one of the required fields (6 always; `PoC-Status` also required when bucket = `findings`) | yes (infer from filename + report.md and patch frontmatter) | no |
| `severity-mismatch` | Dir-name severity prefix ≠ Severity-Final | yes (rename dir; M5 will reassign N) | no |
| `severity-original-vs-final-divergent` | Severity-Original ≠ Severity-Final | flag only — do NOT auto-pick | no |
| `poc-malformed-json-trailer` | PoC script does not emit `{"status":...}` last line | yes (append the JSON-trailer) | no |
| `missing-evidence-critical-high` | bucket = `findings`, `Severity-Final ∈ {C,H}` and `evidence/` empty/missing | no — cannot synthesize without re-running PoC | yes |
| `orphaned-variant` | `metadata.json.is_variant && origin_finding_id` not present in **either** bucket | yes if origin_finding_id can be remapped via M5 rename map; else convert to standalone | yes only if neither remap nor standalone works |
| `dir-name-non-conformant` | Dir name doesn't match `<C\|H\|M\|L>\d+-<slug>` | yes (rename) | no |

Compute `completeness_score` = count of present files (draft.md, report.md, poc.*, evidence/, debate.md, adversarial-review.md, metadata.json) — used as the dedup tie-breaker in M2.

Mark M1 complete.

---

## Pass M2 — Semantic Dedup by Root Cause

Two findings are **semantic duplicates** when ALL of:
- Same `root_cause.file` (case-insensitive, normalized to repo-relative)
- Same `root_cause.sink` token OR sink line within ±2 lines
- Same vulnerability `class` (e.g., both "SQLi", both "SSRF") — accept fuzzy matches if one says "SQL Injection" and the other says "SQLi"

Extracting `root_cause`: parse the `## Root Cause` and `## Proof of Concept` sections from `report.md`. Look for the first file-path-and-line citation (formats: `path/to/file.py:42`, `` `src/foo.py` line 42 ``, etc.). If `report.md` is missing, fall back to draft.md's `## Location` or `## Evidence` sections. If neither yields a citation, mark `root_cause: null` and SKIP this finding from dedup (it can't be safely merged).

For each duplicate group:

1. **Pick the canonical finding** = highest `completeness_score`. Ties broken by lexicographic dir name.
2. **Preserve losers' artifacts**: copy each loser's `poc.*` to `<canonical>/alt-poc-<orig-id>.{ext}` and its `evidence/` to `<canonical>/alt-evidence-<orig-id>/`. Do NOT copy draft.md / report.md (canonical already has them).
3. **Append a "Merged Variants" note** to canonical's `report.md` listing the merged-in IDs and where their alt-poc/alt-evidence live.
4. **Delete the loser directories** with `rm -rf`.
5. **Record in the rename map** (used by M5): `loser-id → canonical-id` so cross-references in other reports update correctly.

Edge case — **slug collision without root-cause match**: if two findings share a slug but differ in root cause, do NOT merge. Re-slug the lower-completeness one with a discriminator (e.g., `sqli-login` → `sqli-login-v2`) and rename its dir.

Write `archon/merge-workspace/dedup-decisions.json`:
```json
{
  "merged": [{"canonical": "C1-sqli-login", "absorbed": ["C3-login-sqli"], "reason": "same root_cause src/auth/login.py:42 SQLi"}],
  "reslug": [{"original": "M2-xss-form", "renamed": "M2-xss-form-v2", "reason": "slug collision, different root cause"}],
  "skipped_no_root_cause": ["M5-misc-finding"]
}
```

Mark M2 complete.

---

## Pass M3 — Auto-Fix Safe Issues

For each finding with fixable issues from M1, apply these fixes IN ORDER:

1. **`missing-frontmatter-field`** — read the existing draft.md frontmatter, the directory name, and the report.md if present, then patch the missing field via Edit:
   - `Phase` → infer from `Sequence` filename pattern (e.g., `p6-*` → 6, `p7-*` → 7, `p10-*` → 10) or default to `merge`
   - `Sequence` → derive from current dir-name N (e.g., `C3` → `003`)
   - `Slug` → from dir-name slug part
   - `Severity-Final` / `Severity-Original` → from dir-name severity prefix (C→CRITICAL etc.). If both are missing, set them equal.
   - `Verdict` → `VALID` (any finding that survived to a final dir was already validated)
   - `PoC-Status` → for `findings/` bucket entries: `executed` if `evidence/` is non-empty, else `theoretical`. For `findings-theoretical/` bucket entries: leave absent (triage-skipped) or keep the existing `theoretical`/`blocked` — never fabricate `executed` for a theoretical-bucket finding.

2. **`missing-report-md`** — spawn `archon:finding-writer` for that single finding directory (use its actual bucket path — `archon/findings/<ID>-<slug>/` or `archon/findings-theoretical/<ID>-<slug>/`):
   > Prompt: `"Author report.md for finding <ID>-<slug>. Input: <bucket-dir>/<ID>-<slug>/. Output: <bucket-dir>/<ID>-<slug>/report.md. This is a merge-mode normalization run; the directory was assembled from a prior audit and may have an incomplete report.md."`

   After it returns, re-validate. If the reporter could not produce a >500-byte report.md with all nine required sections, leave the issue in place — M4 will quarantine.

3. **`severity-mismatch`** — rename the directory so the prefix matches Severity-Final. Example: `C3-login-bypass/` with Severity-Final HIGH → `H<next-H>-login-bypass/`. Do NOT pick the new N here; emit a placeholder `_PENDING_<orig-id>` and let M5 assign the final N during the global renumber.

4. **`poc-malformed-json-trailer`** — append the missing JSON contract line to the script. For Python: `print(json.dumps({"status": "<inferred>", "evidence": "<short summary from evidence/exploit.log>", "notes": "trailer added by merge normalization"}))`. For bash: `echo '{"status":"<inferred>",...}'`. Infer status from existing evidence: confirmed if `evidence/exploit.log` shows success markers, failed if it shows the exploit didn't trigger, else inconclusive.

5. **`dir-name-non-conformant`** — rename dir to match `<Severity><N>-<slug>` pattern using inferred severity + sluggified title.

After all fixes, re-walk findings and rebuild `findings-index.json`. Mark M3 complete.

---

## Pass M4 — Quarantine Unfixable

For findings still carrying these issues after M3, move them to `archon/quarantine/<orig-id>-<slug>/`:

- `missing-evidence-critical-high` (cannot synthesize evidence in merge context)
- `missing-report-md` AND finding-writer failed
- `missing-draft-md` AND `missing-report-md` (no recoverable content)
- `orphaned-variant` AND no remap in dedup-decisions AND cannot stand alone (e.g., variant whose draft just says "see parent")

For each quarantined finding, write `archon/quarantine/<orig-id>-<slug>/QUARANTINE.md` with:
- Original ID, slug, severity (best-known)
- List of issues that triggered quarantine
- Brief explanation of what's missing
- Suggested remediation (e.g., "re-run /archon:confirm against a live target to populate evidence/")

Append the quarantine list to `merge-workspace/quarantine.json`.

Mark M4 complete.

---

## Pass M5 — Renumber + Rebuild References

Build a deterministic global renumber map:

1. List all surviving directories under `archon/findings/`. Group by Severity-Final (C, H, M, L).
2. Within each severity, sort by `(Phase, Sequence, slug)` lexicographically — so the order is stable across re-runs.
3. Assign new IDs starting at 1 per severity bucket: `C1, C2, C3, …; H1, H2, …; M1, M2, …; L1, L2, …`.
4. Build `archon/merge-workspace/rename-map.json`:
   ```json
   {
     "C1-sqli-login": "C1-sqli-login",
     "C3-login-bypass": "C2-login-bypass",
     "H2-xss-search":   "H1-xss-search"
   }
   ```
   Include the **identity entries** (unchanged IDs) too — downstream search-and-replace uses this as the authoritative map.

Then update **every cross-reference** in the tree:

a. **Rename directories** under `archon/findings/` per the map.
b. **Patch `draft.md` frontmatter** in each renamed dir: update `Sequence` to the new N (zero-padded to 3 digits).
c. **Patch `metadata.json`** for variants: rewrite `origin_finding_id` per the map. If the origin disappeared in M2/M4 and no remap exists, demote `is_variant` to false.
d. **Patch cross-references in `report.md`** files: search for patterns like `\b[CHML]\d+-[a-z0-9-]+\b` and `\b[CHML]\d+\b` (severity-id alone) and rewrite to the new ID. Fold dedup-decisions.json's `merged` map in too — losers' IDs map to their canonical.
e. **Patch `audit-state.json`**: walk every audit entry's `findings`, `phases`, and any nested `id` references; rewrite per the map. Add a `merge_metadata.rename_map` field referencing `merge-workspace/rename-map.json`.
f. **Patch any `confirmation-report.md`** if present.

Use Grep with `-l` to find all files containing each old ID before editing — prevents silent miss.

Mark M5 complete.

---

## Pass M6 — Regenerate Summaries

Spawn `archon:report-composer` (foreground):

> Prompt: `"Regenerate the consolidated audit report after a merge normalization. Read BOTH archon/findings/ (confirmed) and archon/findings-theoretical/ (theoretical/unconfirmed) as the source of truth (IDs and slugs are now post-renumber, see archon/merge-workspace/rename-map.json). Render confirmed findings in the main report and theoretical ones in the dedicated Theoretical / Unconfirmed Findings section, kept out of the Summary-of-Findings table. Read archon/audit-state.json for merge_metadata. Output: archon/final-audit-report.md, archon/README.md. Note in the report header that this is a merged audit (list source dirs from merge_metadata.sources). Findings have already been semantically deduplicated and renumbered — do not re-dedupe."`

If `archon/attack-surface/knowledge-base-report.md` is present, append a `## Merge Normalization Addendum` section with one line per source dir listed in merge_metadata.sources, plus the dedup/quarantine/renumber counts.

Mark M6 complete.

---

## Pass M7 — Cleanup + merge-report.md

1. Remove transient working dirs: `rm -rf archon/probe-workspace archon/chamber-workspace archon/findings-draft archon/adversarial-reviews archon/codeql-artifacts archon/semgrep-res` — but ONLY if they were left behind from the source audits and contain no in-progress work (check for empty/stale state). When in doubt, leave them and note in merge-report.md.
2. Remove any `*.conflict` files at top level of `archon/`.
3. Compose `archon/merge-report.md` summarizing the entire pass:

```markdown
# Merge Normalization Report

**Generated:** <ISO timestamp>
**Source dirs:** (from merge_metadata.sources)
- /path/to/run-1/archon
- /path/to/run-2/archon

## Validation (Pass M1)
- Findings inspected: N
- Standard-conformant on entry: X
- Issues detected (by code): { missing-report-md: 3, severity-mismatch: 1, ... }

## Semantic Dedup (Pass M2)
| Canonical | Absorbed | Reason |
| --- | --- | --- |
| C1-sqli-login | C3-login-sqli | same root_cause src/auth/login.py:42 SQLi |
- Re-slugged (slug collisions, different root cause): list
- Skipped (no extractable root cause): list

## Auto-Fixes (Pass M3)
- Frontmatter patched: N
- report.md authored via finding-writer: N (succeeded), N (failed → quarantined)
- PoC JSON trailer appended: N
- Severity-mismatch dir renames: N

## Quarantine (Pass M4)
| ID | Slug | Reason |
| --- | --- | --- |
| C2-mystery-finding | mystery-finding | missing-evidence-critical-high |
- Total quarantined: N

## Renumber (Pass M5)
- Rename map: see `archon/merge-workspace/rename-map.json` (also embedded in audit-state.json under `merge_metadata.rename_map`).
- Cross-references rewritten in: report.md (X files), metadata.json (Y files), audit-state.json, ...

## Summary Regeneration (Pass M6)
- final-audit-report.md: regenerated
- README.md: regenerated
- knowledge-base-report.md: addendum appended

## Manual-Review Items
Anything that needs the user's attention — severity-original vs final divergence, fuzzy dedup matches the agent was unsure about, quarantined CRITICAL/HIGH findings.

## Final Counts
- Findings (post-merge): C=N, H=N, M=N, L=N
- Quarantined: N
```

4. Remove the workspace dir: `rm -rf archon/merge-workspace/` (you've copied everything important into merge-report.md and rename-map.json is already mirrored into audit-state.json).
5. Print a one-line completion summary to stdout: `[✔] Merge normalized: X findings (was Y), Z quarantined, see archon/merge-report.md`.

Mark M7 complete. The EXIT trap removes the lock automatically.

---

## Error Recovery

- If finding-writer fails for a single finding in M3: leave `missing-report-md` in place, M4 will quarantine.
- If report-composer fails in M6: write a stub `final-audit-report.md` with the merge metadata header and a note "report-composer failed during merge — see merge-report.md and individual findings/", then continue to M7. Surface in merge-report.md's manual-review items.
- If audit-state.json patch in M5 fails (e.g., malformed JSON): back up the original to `archon/audit-state.json.pre-merge.bak` and write a fresh minimal one referencing `merge_metadata.sources`. Surface in manual-review items.
- Always run M7 (write merge-report.md) regardless of upstream failures, so the user has a complete record.
