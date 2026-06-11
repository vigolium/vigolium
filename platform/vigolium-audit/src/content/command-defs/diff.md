---
description: Run an incremental audit on changes since the last audited commit
argument-hint: "Optional commit range"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch
mode: diff
phases:
  - id: "1"
    title: Diff-based Phase Selection
    agent: null
    requires_git: true
    parallel_with: []
    depends_on: []
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat vigolium-results/audit-context.md 2>/dev/null || echo "(none)"`
- Audit state: !`cat vigolium-results/audit-state.json 2>/dev/null || echo "No audit state found"`
- Git availability: !`git rev-parse --is-inside-work-tree >/dev/null 2>&1 && echo "Git worktree detected" || echo "No git worktree (diff mode unavailable)"`
- Current branch: !`git branch --show-current 2>/dev/null || echo "No git branch (plain directory target)"`
- Latest commit: !`git log --oneline -1 2>/dev/null || echo "No git history available"`

## Your Task

Run an incremental audit covering only changes since the last audited commit.

### Process

1. Verify Git history is available with `git rev-parse --is-inside-work-tree >/dev/null 2>&1`.
2. If Git is unavailable, stop and tell the user incremental diff mode is unsupported for plain source folders. Direct them to `/vigolium-audit:lite`, `/vigolium-audit:balanced`, or `/vigolium-audit:deep` instead.
3. Read `audits[-1].commit` from `vigolium-results/audit-state.json`. If no state file exists, direct the user to `/vigolium-audit:deep`.
4. If `audits[-1].history_available` is `false`, stop and tell the user the previous audit ran without local history, so there is no reliable diff base. Direct them to run a fresh audit.
5. If `$ARGUMENTS` contains a commit range, use that instead.
6. Compute the diff: `git diff <audits[-1].commit>..HEAD --stat` plus the full patch for the changed files.
7. Classify the changed files by **security risk**, not just file type. Delegate to the `differential-review` skill over the diff range — it assigns each changed file a HIGH/MEDIUM/LOW risk level, computes blast radius, and surfaces regression red-flags from git history (see that skill's Quick Reference and Red Flags sections for the risk triggers and red-flag catalog). Its per-file risk is the authoritative signal for phase selection — a two-line change that removes a validation guard is HIGH even though file-type matching would call it "core source".
8. Map each changed file's risk level **and** change type to the phases to re-run, taking the union across all changed files:

| Signal | Phases to Re-Run |
|--------|-----------------|
| differential-review HIGH risk, or any regression red-flag | D4 (Threat Model), D5 (Code Scan), D6 (Deep Probe) |
| Auth/security module changed | D4 (Threat Model), D5, D6 |
| Core source code (MEDIUM/LOW risk) | D5 (Code Scan), D6 (Deep Probe) |
| Dependencies (lockfiles, manifests) | D1/D2 (Intelligence Pass), D4, D5 |
| Workflow files (.github/) | D5 (Code Scan — Actions audit) |
| Config files | D5 (Code Scan — inline enrichment) |
| Documentation only | None |
| Test files only | None |

9. Re-run only the affected phases in order, following the full methodology for each. Seed each re-run with the differential-review report so the phases focus on the changed surface (and the HIGH-risk files first) rather than re-auditing the whole tree.
10. Set `audits[-1].completed_at` to current timestamp and `audits[-1].status` to `complete` after all affected phases finish. Append a new audit entry via the same schema if this diff audit constitutes a full re-audit.
11. Update phase timestamps in `audits[-1].phases`.
