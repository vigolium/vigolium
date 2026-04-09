---
description: Run a post-audit confirmation pass that boots the target application (or connects to a remote target), executes existing PoC scripts against it, falls back to generated test cases for unconfirmed findings, and produces a confirmation report with per-finding verdicts.
argument-hint: "Optional: --target URL to skip environment discovery and execute PoCs against a remote endpoint"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
---

## Context

- Current branch: !`git branch --show-current`
- Existing audit state: !`cat archon/audit-state.json 2>/dev/null || echo "No existing audit state"`
- Findings directory: !`ls archon/findings/ 2>/dev/null || echo "No findings directory"`
- Target argument: $ARGUMENTS

## Your Task

Run a post-audit confirmation pass that verifies findings by executing PoCs against a live environment.

### Pre-Flight Check

1. **Verify audit exists**: `archon/audit-state.json` MUST exist with at least one completed audit. If not, abort with: "No completed audit found. Run an audit first (`/archon:deep`, `/archon:scan`, or `/archon:lite`)."

2. **Verify findings exist**: `archon/findings/` MUST contain at least one finding directory with a `report.md`. If not, abort with: "No findings to confirm. The audit produced no findings."

3. **Check for previous confirmation**: if `archon/confirmation-report.md` exists, ask the user:
   - "A confirmation report already exists. What would you like to do?"
     - "Re-run confirmation (overwrites previous results)"
     - "Cancel"

4. **Parse target argument**: check if `$ARGUMENTS` contains a URL (starts with `http://` or `https://`):
   - **Yes** → set `REMOTE_TARGET=<URL>`, skip V2 and V3
   - **No** → set `REMOTE_TARGET=null`, run full V1-V6

### Setup

```bash
mkdir -p archon/confirm-workspace/
```

Initialize confirmation state in `archon/audit-state.json` — add a `confirmation` object to the latest audit entry:
```json
{
  "confirmation": {
    "started_at": "<ISO timestamp>",
    "status": "in_progress",
    "target": "<REMOTE_TARGET or 'local'>",
    "phases": {
      "V1": {"status": "pending"},
      "V2": {"status": "pending"},
      "V3": {"status": "pending"},
      "V4": {"status": "pending"},
      "V5": {"status": "pending"},
      "V6": {"status": "pending"}
    }
  }
}
```

If `REMOTE_TARGET` is set, mark V2 and V3 as `skipped`.

### Task List

Create tasks using `TaskCreate`:

| Task | Phase | Depends on | Skip if |
|------|-------|-----------|---------|
| T1 | V1 — Findings Inventory | — | — |
| T2 | V2 — Environment Discovery | T1 | `REMOTE_TARGET` set |
| T3 | V3 — Environment Provisioning | T2 | `REMOTE_TARGET` set |
| T4 | V4 — PoC Execution | T3 (or T1 if remote) | — |
| T5 | V5 — Test-Based Fallback | T4 (or T3 failure) | `REMOTE_TARGET` set |
| T6 | V6 — Confirmation Report | T4 + T5 | — |

---

## Phase V1 — Findings Inventory

Scan `archon/findings/` and build an inventory:

```bash
# List all findings
ls -d archon/findings/*/
```

For each finding directory:
1. Read `report.md` — extract: ID, slug, severity, vulnerability class, PoC-Status
2. Check for PoC scripts: `poc.{py,sh,js,rb,go}` or `exploit.{py,sh}`
3. Check for existing confirmation results (`Confirm-Status` field)

Write inventory to `archon/confirm-workspace/findings-inventory.json`:
```json
{
  "findings": [
    {
      "id": "C1",
      "slug": "sql-injection-user-input",
      "dir": "archon/findings/C1-sql-injection-user-input/",
      "severity": "CRITICAL",
      "vuln_class": "SQL Injection",
      "poc_script": "poc.py",
      "poc_status": "executed",
      "confirm_status": null
    }
  ],
  "total": 5,
  "with_poc": 4,
  "without_poc": 1,
  "by_severity": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2}
}
```

Sort findings by severity (CRITICAL first, then HIGH, then MEDIUM). Mark V1 complete.

---

## Phase V2 — Environment Discovery (skip if REMOTE_TARGET)

Spawn `archon:env-detective` (foreground):

> Prompt: "Discover how to build and run the application in this repository. Target directory: <abs_target>. Write results to archon/confirm-workspace/env-strategies.json. Findings inventory: archon/confirm-workspace/findings-inventory.json."

Mark V2 complete.

---

## Phase V3 — Environment Provisioning (skip if REMOTE_TARGET)

Spawn `archon:env-provisioner` (foreground):

> Prompt: "Start the target application using strategies from archon/confirm-workspace/env-strategies.json. Target directory: <abs_target>. Write connection details to archon/confirm-workspace/env-connection.json."

Read `archon/confirm-workspace/env-connection.json`:
- If `status: "running"` → mark V3 complete, proceed to V4
- If `status: "failed"` → mark V3 as `failed`, set all findings to `mode: full` for V5 (test-only), skip V4

---

## Phase V4 — PoC Execution

If `REMOTE_TARGET` is set, write a synthetic connection file:
```json
{
  "status": "remote",
  "base_url": "<REMOTE_TARGET>",
  "method_used": "remote-target",
  "healthcheck_passed": null,
  "cleanup_cmd": null
}
```

For each finding WITH a PoC script (from findings-inventory.json), spawn `archon:poc-executor` with `run_in_background: true`:

> Prompt: "Execute the PoC for finding <ID>-<slug>. Finding directory: archon/findings/<ID>-<slug>/. Connection: archon/confirm-workspace/env-connection.json. Timeout: 30s."

Wait for all poc-executor agents to complete.

Collect results: read each finding's `Confirm-Status`. Build two lists:
- `confirmed`: findings with `Confirm-Status: confirmed-live`
- `unconfirmed`: findings with `Confirm-Status: failed | error`
- `no-poc`: findings without PoC scripts

Mark V4 complete.

---

## Phase V5 — Test-Based Fallback (skip if REMOTE_TARGET)

**Determine which findings need test-based verification:**
- If V3 failed (no app): ALL findings (mode: `full`)
- If V3 succeeded but some PoCs failed: only `unconfirmed` + `no-poc` findings (mode: `fallback`)

If no findings need test-based verification, mark V5 as `skipped`.

For each finding needing test verification, spawn `archon:test-mapper` with `run_in_background: true`:

> Prompt: "Generate and run a reproducer test for finding <ID>-<slug>. Finding directory: archon/findings/<ID>-<slug>/. Test strategies: archon/confirm-workspace/env-strategies.json. Mode: <full|fallback>. Target directory: <abs_target>."

Wait for all test-mapper agents to complete. Mark V5 complete.

---

## Phase V6 — Confirmation Report

Spawn `archon:confirm-reporter` (foreground):

> Prompt: "Compile the confirmation report. Findings directory: archon/findings/. Confirm workspace: archon/confirm-workspace/. Audit state: archon/audit-state.json."

Mark V6 complete.

---

## Cleanup

After V6 completes:

1. **Environment cleanup**: read `archon/confirm-workspace/env-connection.json`. If `cleanup_cmd` is set:
   ```bash
   eval "<cleanup_cmd>" 2>&1 | tee archon/confirm-workspace/cleanup.log
   ```
   Also kill any process recorded in `archon/confirm-workspace/app.pid`:
   ```bash
   if [ -f archon/confirm-workspace/app.pid ]; then
     kill $(cat archon/confirm-workspace/app.pid) 2>/dev/null || true
     rm archon/confirm-workspace/app.pid
   fi
   ```

2. **Update audit state**: set `confirmation.status` to `complete` and `confirmation.completed_at` to current timestamp.

3. **Print summary**: display the confirmation rate and a one-line-per-finding result table.

---

## Error Recovery

- If V2 fails: skip V3, set all findings to test-only mode for V5
- If V3 fails: skip V4, set all findings to test-only mode for V5
- If a single poc-executor fails: mark that finding as `error`, continue with others
- If a single test-mapper fails: mark that finding as `blocked`, continue with others
- If V5 fails completely: proceed to V6 with whatever results are available
- Always run V6 (confirmation report) regardless of upstream failures
- Always run cleanup regardless of any failures
