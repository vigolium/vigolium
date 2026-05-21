---
description: Show the current audit status including completed phases, findings count, and drift from last audited commit
allowed-tools: Bash(git log:*), Bash(git diff:*), Bash(ls:*), Bash(wc:*), Bash(du:*), Bash(cat:*), Read, Glob
mode: status
phases: []
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat vigolium-results/audit-context.md 2>/dev/null || echo "(none)"`
- Audit state: !`cat vigolium-results/audit-state.json 2>/dev/null || echo "No audit in progress"`
- Latest commit: !`git log --oneline -1 2>/dev/null || echo "No git history available"`
- Security directory contents: !`ls vigolium-results/ 2>/dev/null || echo "No security directory"`

## Your Task

Display a comprehensive audit status report. Do not modify any files.

### Status Report

1. **Audit Metadata**: Read `audits[-1]` from `vigolium-results/audit-state.json`. Display:
   - Repository (`repository` field: e.g. org/reponame or folder name)
   - Mode (`mode` field: lite/balanced/deep)
   - Model (`model` field: e.g. opus-4.6, gpt-5.3-codex)
   - Coding Agent (`agent_sdk` field: e.g. claude-code, codex)
   - Started at / Completed at timestamps

2. **Phase Progress**: For each phase in `audits[-1].phases`, show status (pending/in_progress/complete/failed) and completion timestamp if available.

3. **Commit Drift**: Compare `audits[-1].commit` from the state file with current HEAD. If they differ, show the number of commits and changed files since last audit.

4. **Findings Count**: Count files in `vigolium-results/findings/` grouped by severity prefix:
   - `C*` -- Critical
   - `H*` -- High
   - `M*` -- Medium

5. **Reports Generated**: List whether these two report files exist in `vigolium-results/`:
   - `knowledge-base-report.md`
   - `final-audit-report.md`

6. **Disk Usage**: Show total size of `vigolium-results/` directory.

Format the output as a clean, readable summary.
