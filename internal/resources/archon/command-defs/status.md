---
description: Show the current audit status including completed phases, findings count, and drift from last audited commit
allowed-tools: Bash(git log:*), Bash(git diff:*), Bash(ls:*), Bash(wc:*), Bash(du:*), Bash(cat:*), Read, Glob
---

## Context

- Audit state: !`cat archon/audit-state.json 2>/dev/null || echo "No audit in progress"`
- Latest commit: !`git log --oneline -1`
- Security directory contents: !`ls archon/ 2>/dev/null || echo "No security directory"`

## Your Task

Display a comprehensive audit status report. Do not modify any files.

### Status Report

1. **Audit Metadata**: Read `audits[-1]` from `archon/audit-state.json`. Display:
   - Repository (`repository` field: e.g. org/repo)
   - Mode (`mode` field: lite/scan/deep)
   - Model (`model` field: e.g. opus-4.6, gpt-5.3-codex)
   - Coding Agent (`agent_sdk` field: e.g. claude-code, codex, bytesec)
   - Started at / Completed at timestamps

2. **Phase Progress**: For each phase in `audits[-1].phases`, show status (pending/in_progress/complete/failed) and completion timestamp if available.

3. **Commit Drift**: Compare `audits[-1].commit` from the state file with current HEAD. If they differ, show the number of commits and changed files since last audit.

4. **Findings Count**: Count files in `archon/findings/` grouped by severity prefix:
   - `C*` -- Critical
   - `H*` -- High
   - `M*` -- Medium

5. **Reports Generated**: List whether these two report files exist in `archon/`:
   - `knowledge-base-report.md`
   - `final-audit-report.md`

6. **Disk Usage**: Show total size of `archon/` directory.

Format the output as a clean, readable summary.
