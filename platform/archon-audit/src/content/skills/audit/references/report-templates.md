# Security Report Templates

Consistent output formats only.
Do not use this file for triage rules or analysis methodology.

## audit-state.json Schema

`archon/audit-state.json` is an append-only audit history. Each audit run is appended as a new
entry in the `audits` array. Earlier entries are never overwritten — they form the permanent record
of every audit cycle against this repository. The current (in-progress or most recently completed)
audit is always the last entry.

```json
{
  "audits": [
    {
      "audit_id": "<YYYY-MM-DDTHH:MM:SSZ>",
      "commit": "<git SHA>",
      "branch": "<branch name>",
      "repository": "<org/repo or folder name>",
      "started_at": "<ISO 8601 timestamp>",
      "completed_at": "<ISO 8601 timestamp or null if in progress>",
      "status": "complete | in_progress | failed",
      "phases": {
        "1": {
          "status": "complete | in_progress | failed | skipped",
          "started_at": "<ISO 8601 timestamp>",
          "completed_at": "<ISO 8601 timestamp>",
          "metrics": {
            "findings_count": 0,
            "reports_generated": ["knowledge-base-report.md"],
            "validation_passed": true,
            "error": null
          }
        }
      }
    }
  ]
}
```

Field notes:
- `audit_id`: ISO 8601 timestamp of when the audit started; unique identifier for the run
- `commit`: HEAD commit SHA at audit start; used for incremental re-audit diffing
- `repository`: org/repo slug from git remote origin (e.g. `org/reponame`), or working directory basename if no remote is configured
- `status` (audit-level): overall status of the audit run
- `findings_count`: number of candidate findings at phase completion (0 for phases that do not generate findings)
- `reports_generated`: list of KB sections or artifact files written during this phase
- `validation_passed`: result of running `validate_phase_output.py` for this phase
- `error`: validation error message if `validation_passed` is false; null otherwise

**Appending a new audit**: before starting a new audit run, read the existing file, append a new
entry to the `audits` array with `status: "in_progress"`, and write the file back. Never replace
the array or remove existing entries. If the file does not exist, create it with a single-entry
array.

**Re-audit detection**: to determine whether this is a re-audit, compare the current HEAD SHA
against `audits[-1].commit` (the most recent completed entry). If they differ, this is a re-audit;
load the KB sections from `archon/attack-surface/knowledge-base-report.md` as the starting knowledge base.

For Phase 4, `reports_generated` must include `archon/codeql-artifacts/entry-points.json`,
`archon/codeql-artifacts/sinks.json`, `archon/codeql-artifacts/call-graph-slices.json`, and
`archon/codeql-artifacts/flow-paths-all-severities.md`, plus the `## Static Analysis Summary`
section written to `archon/attack-surface/knowledge-base-report.md`. Missing any causes `validation_passed: false`.

Phase 4 `metrics` must include a `codeql_structural` sub-object:

```json
"codeql_structural": {
  "entry_points_count": 0,
  "sinks_count": 0,
  "slices_reachable": 0,
  "slices_not_reachable": 0,
  "informational_results_count": 0,
  "db_path": "archon/codeql-artifacts/db/"
}
```

## Finding Draft Template

Used for `archon/findings-draft/<phase>-<NNN>-<slug>.md` files written incrementally during Phases 7-9.

```markdown
# [Finding Title]

Phase: 7 | 8 | 9
Sequence: NNN
Slug: <slug>
Verdict: PENDING | VALID | FALSE POSITIVE | BY DESIGN | OUT OF SCOPE | FALSE POSITIVE (adversarial)
Rationale: <one-sentence explanation tied to the threat model — fill in during Phase 11>
Adversarial-Verdict: PENDING | CONFIRMED | DISPROVED
Adversarial-Rationale: <one sentence citing the decisive evidence — fill in during Phase 11 Stage 2>
Severity-Original: <severity assigned during Phase 10/8 Stage 1>
Severity-Final: <severity after adversarial challenge — lower severity wins>
PoC-Status: executed | theoretical | blocked
Pre-FP-Flag: <none | check-N-ambiguous — set by chamber Synthesizer if quality gate was ambiguous>
Debate: <path to chamber debate transcript, e.g., archon/chamber-workspace/chamber-01/debate.md>

## Summary

[One-sentence description of the vulnerability.]

## Location

File: <path>
Function/Method: <name>
Line: <number>

## Attacker Control

[What input does the attacker control, and how does it reach the vulnerable code?]

## Trust Boundary Crossed

[Which trust boundary is violated?]

## Impact

[Concrete attacker gain: what can the attacker do?]

## Evidence

[Code snippet or logic trace showing the vulnerable path.]

## Reproduction Steps

[Minimal steps to trigger the issue.]
```

## PoC Quality Requirements

Apply these requirements to every PoC produced in Phase 15 and Phase 11 Stage 2:

- **Prove the vulnerability, do not manufacture it.** The PoC must demonstrate the actual exploit path through the real application stack — not a stripped-down harness that bypasses the security controls under test. Bug bounty triagers reject PoCs that call the vulnerable function directly while skipping the auth layer, middleware, or sandbox that would normally gate access.
- **Minimize the PoC to its essential steps.** Remove all scaffolding, retry loops, verbose logging, and diagnostic output that are not necessary to trigger the vulnerability. The finished script should read like a CTF exploit: tight, purposeful, and self-contained.
- **Demonstrate the security effect.** The PoC must show the concrete attacker gain — data exfiltration, code execution, authentication bypass, privilege escalation — not merely that an error occurs.
- **Capture evidence.** For Critical and High findings, save execution output to `archon/findings/<ID>-<slug>/evidence/` (screenshots, response captures, or log snippets).
- **Label PoC-Status accurately.** Use `executed` only if the PoC ran successfully against a real environment. Use `theoretical` if only code-level analysis was performed. Use `blocked` with a `PoC-Block-Reason:` if environment provisioning failed.

## Adversarial Review Template

Used for `archon/adversarial-reviews/<slug>-review.md` files written during Phase 11 Stage 2.

```markdown
# Adversarial Review: [Finding Title]

Finding-Ref: archon/findings-draft/<phase>-<NNN>-<slug>.md
Reviewer-Agent: fresh (isolated — did not see Phase 10 reasoning)
Date: <ISO date>

## Independent Restatement

[Restate the vulnerability claim in your own words without copying the original description.]

## Sub-claim Decomposition

- Sub-claim A (attacker controls X): [assessment]
- Sub-claim B (X reaches Y without blocking controls): [assessment]
- Sub-claim C (Y causes security effect Z): [assessment]

Sub-claim result: all coherent | failure on <sub-claim> — <reason>

## Independent Code Path Trace

Entry point: <file:line>
Sink: <file:line>

[Step-by-step trace of the code path. Document every validation, sanitization, and transformation encountered.]

## Protections Checked

| Layer | Protection Found | Blocks Attack? |
|-------|-----------------|----------------|
| Language | | |
| Framework | | |
| Middleware | | |
| Application | | |
| Documentation | | |

## Real-Environment Reproduction

Environment type: web app | library | CLI | protocol | infrastructure
Provisioning method: Docker | VM (DigitalOcean) | VM (Azure) | local install | blocked

Setup commands: see `archon/real-env-evidence/<slug>/setup.sh`
Healthcheck result: pass | fail
Attempt 1: [payload/method] — [result]
Attempt 2 (if needed): [payload/method] — [result]
Attempt 3 (if needed): [payload/method] — [result]
Evidence: archon/real-env-evidence/<slug>/

PoC-Status: executed | theoretical | blocked
Block reason (if blocked): <specific reason>

## Prosecution Brief

[Strongest possible argument that this is a genuine, exploitable vulnerability. Cite code locations and evidence.]

## Defense Brief

[Strongest possible argument that this is a false positive or unexploitable. Cite protections, reproduction failures, and realistic preconditions.]

## Severity Challenge

Severity-Original: <from finding draft>
Severity-Challenge: MEDIUM | HIGH | CRITICAL
Justification: <one sentence with evidence>

## Verdict

Adversarial-Verdict: CONFIRMED | DISPROVED
Adversarial-Rationale: <one sentence citing the decisive evidence>
```

## Pentest-Style Final Report Template (`archon/final-audit-report.md`)

```markdown
# Security Audit Report: [Project Name]
=========================================

## Executive Summary
---------------------
[Concise high-level summary of the overall security posture. Identify the most critical risks and the general impact on the business or project stakeholders. Aim for a one-paragraph summary for non-technical audiences.]

## Methodology Summary
-----------------------
[Briefly describe the audit process (Phases 1-9) to establish technical depth.]
- **Intelligence Gathering:** Identified published advisories, architecture, and dependency risks.
- **Threat Modeling:** Documented trust boundaries, attacker entry points, and high-risk flows.
- **Static Analysis:** Executed CodeQL, Semgrep Pro, and custom architecture-driven rules.
- **Structural Extraction:** CodeQL structural artifacts (entry points, sinks, call graph slices,
  informational flow nodes, machine-generated DFD/CFD diagrams) were extracted and used to validate
  Phase 3 DFD/CFD slices, guide manual review in Phase 10, and drive AST-level variant hunting in
  Phase 12.
- **Deep Manual Review:** Targeted bug hunting focusing on logic, bypasses, and spec compliance.
- **Verification:** All findings were validated for exploitability within the project's threat model.

## Summary of Findings
----------------------

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| [C1] | [Vulnerability Title] | CRITICAL | VALID |
| [H1] | [Vulnerability Title] | HIGH | VALID |
| [M1] | [Vulnerability Title] | MEDIUM | VALID |

## Technical Findings Detail
---------------------------

### [[ID]] [Finding Title]
- **Severity:** [CRITICAL/HIGH/MEDIUM]
- **Summary:** [One-sentence summary of the vulnerability.]
- **Impact:** [How this impacts the system/user and what the attacker gains.]
- **Detailed Report:** [archon/findings/[ID]-[slug]/report.md]
- **Proof of Concept:** [archon/findings/[ID]-[slug]/poc.py]

[Repeat for each finding...]

## Conclusion
-------------
[Final assessment and professional recommendations for improving the overall security baseline.]
```

## Audit Report Template

```
Security Audit Report
===================

Scope: [full codebase | specific area | file path]

Method: static analysis [+ runtime verification if runnable]

Summary: CRITICAL: N, HIGH: N [or NONE]

Findings
--------

[C1/H1] Finding Title
- Severity: CRITICAL/HIGH/MEDIUM
- Prerequisites: [attacker position and required capabilities]
- Evidence: [source → sink chain with file references]
- Reproduction: [minimal safe steps]
- Impact: [concrete attacker gain]
- Discussion inputs: [key technical facts/questions for the dev team; do not propose a fix unless asked]

[Repeat for each finding...]

Noise Skipped (optional)
------------------------
- [Issue]: [reason for exclusion]
[Only include if needed to prevent confusion]
```

## Verification Report Template

```
Security Fix Verification
========================

Scope: [what was tested]
Changes: [what code/behavior changed]
Status: PASS/FAIL

Re-tested Findings
------------------

[C1/H1] Finding Title: FIXED/NOT FIXED
- Repro re-run: [steps taken]
- Evidence: [proof of fix or continued vulnerability]

[Repeat for each previous finding...]

Regressions
-----------
- [Test/Build]: [failure description]
[Include any test failures or build issues introduced by changes]
```

## Consistency Check: Phase 4 CodeQL Artifacts

Required files after Phase 4 (must exist and be non-empty):

```
archon/codeql-artifacts/entry-points.json
archon/codeql-artifacts/sinks.json
archon/codeql-artifacts/call-graph-slices.json
archon/codeql-artifacts/flow-paths-all-severities.md
```

Git-ignored but must exist on disk during Phases 5-9:

```
archon/codeql-artifacts/db/
archon/codeql-artifacts/flow-paths-raw.sarif
```

Spot checks:

```bash
jq 'length' archon/codeql-artifacts/entry-points.json
jq 'length' archon/codeql-artifacts/sinks.json
jq '[.[] | select(.reachable == true)] | length' archon/codeql-artifacts/call-graph-slices.json
jq '.runs[0].results | length' archon/codeql-artifacts/flow-paths-raw.sarif
```

## RFC Gaps Report Template

```
RFC Implementation Gaps Report
==============================

Scope: [protocol/module]
RFCs Reviewed: [RFC number(s) and sections]

Gap Summary
-----------
- Implemented correctly: N
- Partially implemented: N
- Missing: N
- Potentially bypassable: N

Per-Gap Detail
--------------

[G1] Gap Title
- RFC Clause: [RFC XXXX §Y.Z]
- Code Path: [file/function]
- Gap Type: implemented-correctly | partial | missing | bypassable
- Attack Vector: [threat-model-relevant vector]
- Exploit Conditions: [prerequisites]
- Impact: [concrete attacker gain]
- Evidence: [code path and reasoning]

[Repeat for each gap...]
```

## Attack Pattern Registry Schema

File: `archon/attack-pattern-registry.json`

Created during Phase 10 Review Chamber debates. Each confirmed vulnerability pattern is added
with detection signatures for automated variant hunting in Phase 12.

```json
{
  "patterns": [
    {
      "id": "AP-001",
      "title": "Unsafe ObjectInputStream deserialization",
      "bug_class": "deserialization",
      "root_cause": "ObjectInputStream.readObject() without ObjectInputFilter on attacker-reachable path",
      "detection_signature": {
        "codeql": "<QL query fragment for variant search>",
        "grep": "<regex pattern for codebase-wide search>",
        "semgrep": "<semgrep pattern for structural match>"
      },
      "confirmed_instances": [
        {"finding_ref": "p7-003-admin-deser.md", "file": "src/admin/AdminService.java:142"}
      ],
      "untested_candidates": [
        {"file": "src/backup/BackupRestoreService.java:201", "reason": "Uses ObjectInputStream in unaudited slice"}
      ],
      "severity": "CRITICAL",
      "added_at": "<ISO 8601 timestamp>",
      "added_by": "<chamber-id>"
    }
  ]
}
```

## Chamber Debate Transcript Template

File: `archon/chamber-workspace/<chamber-id>/debate.md`

See `references/chamber-protocol.md` for the complete format specification. The transcript is
append-only with structured round markers and role-tagged sections.
