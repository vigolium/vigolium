---
description: Show the current audit status including completed phases, findings count, and drift from last audited commit
allowed-tools: Bash(git log:*), Bash(git diff:*), Bash(ls:*), Bash(wc:*), Bash(du:*), Bash(cat:*), Read, Glob
---

## Context

- Audit state: !`cat security/audit-state.json 2>/dev/null || echo "No audit in progress"`
- Latest commit: !`git log --oneline -1`
- Security directory contents: !`ls security/ 2>/dev/null || echo "No security directory"`

## Your Task

Display a comprehensive audit status report. Do not modify any files.

### Status Report

1. **Phase Progress**: Read `audits[-1].phases` from `security/audit-state.json`. For each phase (1-10), show status (pending/in_progress/complete/failed) and completion timestamp if available.

2. **Commit Drift**: Compare `audits[-1].commit` from the state file with current HEAD. If they differ, show the number of commits and changed files since last audit.

3. **Findings Count**: Count files in `security/findings/` grouped by severity prefix:
   - `C*` -- Critical
   - `H*` -- High
   - `M*` -- Medium

4. **Reports Generated**: List whether these two report files exist in `security/`:
   - `knowledge-base-report.md`
   - `final-audit-report.md`

5. **Disk Usage**: Show total size of `security/` directory.

Format the output as a clean, readable summary.
