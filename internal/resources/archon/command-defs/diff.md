---
description: Run an incremental audit on changes since the last audited commit
argument-hint: "Optional commit range"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch
---

## Context

- Audit state: !`cat archon/audit-state.json 2>/dev/null || echo "No audit state found"`
- Current branch: !`git branch --show-current`
- Latest commit: !`git log --oneline -1`

## Your Task

Run an incremental audit covering only changes since the last audited commit.

### Process

1. Read `audits[-1].commit` from `archon/audit-state.json`. If no state file exists, direct the user to `/archon:deep`.
2. If `$ARGUMENTS` contains a commit range, use that instead.
3. Compute the diff: `git diff <audits[-1].commit>..HEAD --stat`
4. Map changed files to affected phases:

| Change Type | Phases to Re-Run |
|-------------|-----------------|
| Core source code | 4 (SAST), 7 (Deep Bug Hunting) |
| Auth/security modules | 3 (Knowledge Base), 4, 7 |
| Dependencies (lockfiles, manifests) | 1 (Intelligence), 3, 4 |
| Workflow files (.github/) | 4 (Actions audit) |
| Config files | 5 (Enrichment) |
| Documentation only | None |
| Test files only | None |

5. Re-run only the affected phases in order, following the full methodology for each.
6. Set `audits[-1].completed_at` to current timestamp and `audits[-1].status` to `complete` after all affected phases finish. Append a new audit entry via the same schema if this diff audit constitutes a full re-audit.
7. Update phase timestamps in `audits[-1].phases`.
