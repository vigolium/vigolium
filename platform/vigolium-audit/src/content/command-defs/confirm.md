---
description: Run a confirmation pass for existing findings that boots the target application (or connects to a remote target), executes existing PoC scripts against it, falls back to generated test cases for findings the PoC could not reproduce, and produces a confirmation report with per-finding verdicts.
argument-hint: "Optional: --target URL to skip environment discovery and execute PoCs against a remote endpoint"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
mode: confirm
phases:
  - id: V1
    title: Findings Inventory
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: []
  - id: V1.5
    title: Intent Cross-Check
    agent: context-reviewer
    requires_git: false
    parallel_with: []
    depends_on: [V1]
  - id: V2
    title: Environment Discovery
    agent: env-profiler
    requires_git: false
    parallel_with: []
    depends_on: [V1.5]
  - id: V3
    title: Environment Provisioning
    agent: env-builder
    requires_git: false
    parallel_with: []
    depends_on: [V2]
  - id: V4
    title: PoC Execution
    agent: poc-runner
    requires_git: false
    parallel_with: []
    depends_on: [V3]
  - id: V5
    title: Test-Based Fallback
    agent: test-locator
    requires_git: false
    parallel_with: []
    depends_on: [V4]
  - id: V6
    title: Confirmation Report
    agent: confirm-writer
    requires_git: false
    parallel_with: []
    depends_on: [V4, V5]
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat vigolium-results/audit-context.md 2>/dev/null || echo "(none)"`
- Current branch: !`git branch --show-current 2>/dev/null || echo "No git branch (plain directory target)"`
- Existing audit metadata: !`cat vigolium-results/audit-state.json 2>/dev/null || echo "No audit-state.json present (standalone confirmation is allowed)"`
- Findings directory: !`ls vigolium-results/findings/ 2>/dev/null || echo "No findings directory"`
- Target argument: $ARGUMENTS

## Your Task

Run a confirmation pass that verifies existing findings by executing PoCs against a live environment.

### Pre-Flight Check

1. **Verify findings exist**: `vigolium-results/findings/` MUST contain at least one finding directory with a `report.md`. If not, abort with: "No findings to confirm. Expected `vigolium-results/findings/*/report.md`."

   **Scope**: confirm mode operates ONLY on `vigolium-results/findings/` (the confirmed bucket — findings whose PoC already executed). `vigolium-results/findings-theoretical/` is intentionally out of scope: those have no PoC to re-validate against a live target. Do not scan, confirm, or move theoretical findings here.

2. **Audit metadata is optional**: if `vigolium-results/audit-state.json` exists, use it only as supplemental metadata and update the latest audit entry's `confirmation` object. If it does not exist, continue in standalone confirmation mode.

3. **Workspace lock check**: if `vigolium-results/confirm-workspace/.lock` exists, read its `pid` and check whether the process is alive. If alive → abort with: "A confirmation run is already in progress (PID <pid>, started <ts>, session <uuid>). Wait for it to finish or remove the lock file." If stale (process gone) → remove and reclaim.

4. **Check for previous confirmation**: if `vigolium-results/confirmation-report.md` exists, ask the user:
   - "A confirmation report already exists. What would you like to do?"
     - "Re-run confirmation (overwrites previous results)"
     - "Cancel"

5. **Parse target argument**: check if `$ARGUMENTS` contains a URL (starts with `http://` or `https://`):
   - **Yes** → set `REMOTE_TARGET=<URL>`, skip V2 and V3
   - **No** → set `REMOTE_TARGET=null`, run full V1-V6

### Setup

```bash
mkdir -p vigolium-results/confirm-workspace/

# Generate a stable session UUID — propagated to every agent prompt and used for
# label-based cleanup (containers / processes are stamped with this value).
VIGOLIUM_AUDIT_SESSION_UUID=$(uuidgen 2>/dev/null || python3 -c 'import uuid;print(uuid.uuid4())')
export VIGOLIUM_AUDIT_SESSION_UUID

# Write workspace lock so concurrent confirm runs against the same target abort early.
cat > vigolium-results/confirm-workspace/.lock <<EOF
{"pid": $$, "session": "${VIGOLIUM_AUDIT_SESSION_UUID}", "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF

# Always-run cleanup trap: even on Ctrl-C, kill leaked containers/processes by session
# label and remove the lock. The trap calls the same cleanup logic as the post-V6 step.
cleanup_session() {
  echo "[cleanup] session ${VIGOLIUM_AUDIT_SESSION_UUID}" >> vigolium-results/confirm-workspace/cleanup.log 2>&1
  # Kill any container labelled with this session.
  if command -v docker >/dev/null 2>&1; then
    docker ps -aq --filter "label=vigolium-audit.session=${VIGOLIUM_AUDIT_SESSION_UUID}" | xargs -r docker rm -f >> vigolium-results/confirm-workspace/cleanup.log 2>&1
  fi
  # Kill any process recorded under this session.
  if [ -f vigolium-results/confirm-workspace/app.pid ]; then
    kill "$(cat vigolium-results/confirm-workspace/app.pid)" 2>/dev/null || true
    rm -f vigolium-results/confirm-workspace/app.pid
  fi
  # Run the env-builder-recorded cleanup_cmd if present (best-effort).
  if [ -f vigolium-results/confirm-workspace/env-connection.json ] && command -v jq >/dev/null 2>&1; then
    cmd=$(jq -r '.cleanup_cmd // empty' vigolium-results/confirm-workspace/env-connection.json)
    [ -n "$cmd" ] && eval "$cmd" >> vigolium-results/confirm-workspace/cleanup.log 2>&1 || true
  fi
  rm -f vigolium-results/confirm-workspace/.lock
}
trap cleanup_session EXIT INT TERM
```

If `vigolium-results/audit-state.json` exists, initialize confirmation state there by adding a `confirmation` object to the latest audit entry:
```json
{
  "confirmation": {
    "started_at": "<ISO timestamp>",
    "status": "in_progress",
    "target": "<REMOTE_TARGET or 'local'>",
    "phases": {
      "V1": {"status": "pending"},
      "V1.5": {"status": "pending"},
      "V2": {"status": "pending"},
      "V3": {"status": "pending"},
      "V4": {"status": "pending"},
      "V5": {"status": "pending"},
      "V6": {"status": "pending"}
    }
  }
}
```

If `vigolium-results/audit-state.json` does not exist, do not create it just for confirmation.

If `REMOTE_TARGET` is set, mark V2 and V3 as `skipped` when writing optional confirmation metadata.

### Task List

Create tasks using `TaskCreate`:

| Task | Phase | Depends on | Skip if |
|------|-------|-----------|---------|
| T1 | V1 — Findings Inventory | — | — |
| T1b | V1.5 — Intent Cross-Check | T1 | — (best-effort; skip-and-continue on failure) |
| T2 | V2 — Environment Discovery | T1b | `REMOTE_TARGET` set |
| T3 | V3 — Environment Provisioning | T2 | `REMOTE_TARGET` set |
| T4 | V4 — PoC Execution | T3 (or T1b if remote) | — |
| T5 | V5 — Test-Based Fallback | T4 (or T3 failure) | `REMOTE_TARGET` set |
| T6 | V6 — Confirmation Report | T4 + T5 | — |

---

## Phase V1 — Findings Inventory

Scan `vigolium-results/findings/` and build an inventory:

```bash
# List all findings
ls -d vigolium-results/findings/*/
```

For each finding directory:
1. Read `report.md` — this is the source of truth. Extract: ID, slug, severity, vulnerability class, title, PoC-Status
2. Check for PoC scripts: `poc.{py,sh,js,rb,go}` or `exploit.{py,sh}`
3. Check for existing confirmation results (`Confirm-Status` field)
4. Read `Protocol:` and `Auth-Required:` fields if present (poc-author writes them in deep mode)
5. **Classify exploitability** based on vuln_class and Protocol field:
   - `network-exploitable`: SQL/NoSQL injection, command injection, XSS, SSRF, IDOR/BOLA, auth bypass, path traversal, deserialization served over HTTP/RPC, file-upload abuse, request smuggling — any class where a remote PoC can be fired against a live endpoint
   - `local-exploitable`: TOCTOU on local files, privilege escalation in CLI tools, unsafe deserialization in offline parsers, race conditions requiring shell access
   - `non-exploitable`: weak random, hardcoded debug flag, missing security header in isolation, crypto algorithm misuse, supply-chain dependency advisories without a reachable trigger — analytically valid findings whose verification is structural, not behavioural
   When unsure, default to `network-exploitable` so V4 still gets a chance.

Write inventory to `vigolium-results/confirm-workspace/findings-inventory.json`:
```json
{
  "session": "${VIGOLIUM_AUDIT_SESSION_UUID}",
  "findings": [
    {
      "id": "C1",
      "slug": "sql-injection-user-input",
      "dir": "vigolium-results/findings/C1-sql-injection-user-input/",
      "severity": "CRITICAL",
      "vuln_class": "SQL Injection",
      "poc_script": "poc.py",
      "poc_status": "executed",
      "protocol": "http",
      "auth_required": "yes",
      "exploitability_class": "network-exploitable",
      "confirm_status": null
    }
  ],
  "total": 5,
  "with_poc": 4,
  "without_poc": 1,
  "by_severity": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2},
  "by_class": {"network-exploitable": 4, "local-exploitable": 0, "non-exploitable": 1}
}
```

Sort findings by severity (CRITICAL first, then HIGH, then MEDIUM). Mark V1 complete.

**Routing implications for later phases:**
- `non-exploitable` findings skip V4 entirely and are reported by V6 in an `analytical` section — confirmation is by structural agreement, not by live verification.
- `local-exploitable` findings skip V4 (no live HTTP target) and proceed straight to V5 test generation.
- `network-exploitable` findings flow through V4 → V5 fallback as today.

---

## Phase V1.5 — Intent Cross-Check

Spawn `vigolium-audit:context-reviewer` (foreground) under its **confirm contract**:

> Prompt: "CONFIRM CONTRACT (V1.5) — strictly annotate-only. Scan the target repository for documented security intent. Target directory: <abs_target>. Findings inventory: vigolium-results/confirm-workspace/findings-inventory.json (this presence selects the confirm contract). Output corpus to vigolium-results/confirm-workspace/intent-corpus.json. Cross-check each finding by reading its report.md (and a bounded read of ONLY the file:line it cites) — write per-finding verdicts to vigolium-results/confirm-workspace/intent-verdicts.json and annotate each finding's report.md with Documented-Intent / Documented-Intent-Source / Documented-Intent-Quote fields. Annotate ONLY — do NOT change Severity-Final, Confirm-Status, or Triage-Priority, and do NOT cause V4/V5 to be skipped. Session: ${VIGOLIUM_AUDIT_SESSION_UUID}."

**Failure policy: skip-and-continue.** If the agent fails, errors out, or produces no corpus, log the failure and proceed to V2 without intent context. Downstream phases (V4, V5, V6) must handle the absence of `intent-corpus.json` / `intent-verdicts.json` gracefully — V6 simply omits the "Documented-Intent Matches" section in that case.

**Annotate-only contract**: V1.5 NEVER auto-skips V4 or V5 and never routes a finding. A `Documented-Intent: yes` verdict is recorded for the human reviewer's benefit but the PoC still runs. The rationale is that documented intent can be wrong — running the PoC against a live target either confirms the documented behavior is what actually happens, or surfaces a contradiction worth reporting. (`context-reviewer`'s soft-influence routing only applies under its audit contract in balanced/deep — it is disabled here by the confirm contract.)

Mark V1.5 complete (or `failed` with `policy: skip-and-continue` recorded in the optional confirmation metadata).

---

## Phase V2 — Environment Discovery (skip if REMOTE_TARGET)

Spawn `vigolium-audit:env-profiler` (foreground):

> Prompt: "Discover how to build and run the application in this repository. Target directory: <abs_target>. Session: ${VIGOLIUM_AUDIT_SESSION_UUID}. Write env strategies to vigolium-results/confirm-workspace/env-strategies.json AND, if the project has any auth scaffolding (registration endpoint, login endpoint, role mechanism, or seed scripts that create users), write vigolium-results/confirm-workspace/auth-spec.json describing how to seed test identities. Findings inventory: vigolium-results/confirm-workspace/findings-inventory.json."

Mark V2 complete.

---

## Phase V3 — Environment Provisioning (skip if REMOTE_TARGET)

Spawn `vigolium-audit:env-builder` (foreground):

> Prompt: "Start the target application using strategies from vigolium-results/confirm-workspace/env-strategies.json. Auth spec (optional): vigolium-results/confirm-workspace/auth-spec.json — if present, seed the listed test identities and write their tokens to env-connection.json under test_identities[]. Target directory: <abs_target>. Session: ${VIGOLIUM_AUDIT_SESSION_UUID} (stamp every container/process with label vigolium-audit.session=<UUID>). Honour env vars IMAGE_PULL_TIMEOUT (default 300), SERVICE_BOOT_TIMEOUT (default 120), HEALTHCHECK_TIMEOUT (default 60), and SKIP_ISOLATION (default unset; when unset, snapshot the database after seeding). Write connection details to vigolium-results/confirm-workspace/env-connection.json."

Read `vigolium-results/confirm-workspace/env-connection.json`:
- If `status: "running"` → mark V3 complete, proceed to V4
- If `status: "failed"` → mark V3 as `failed`, set all findings to `mode: full` for V5 (test-only), skip V4
- If V3 fails, the V3 agent must emit `vigolium-results/confirm-workspace/healthcheck-failure.log` with the last 50 lines of relevant logs (compose logs, container logs, app stderr) so V5/V6 can surface the root cause to the user.

---

## Phase V4 — PoC Execution

If `REMOTE_TARGET` is set, write a synthetic connection file:
```json
{
  "status": "remote",
  "base_url": "<REMOTE_TARGET>",
  "method_used": "remote-target",
  "healthcheck_passed": null,
  "cleanup_cmd": null,
  "session": "${VIGOLIUM_AUDIT_SESSION_UUID}"
}
```

**Class-based routing (read findings-inventory.json):**
- `non-exploitable` findings → skip V4 entirely. Mark `Confirm-Status: analytical` directly in their `report.md` and continue.
- `local-exploitable` findings → skip V4. Pass straight to V5 with mode `local`.
- `network-exploitable` findings (with a PoC) → spawn poc-runner as below.

**Reachability gate**: before spawning ANY poc-runner, hit `base_url` once with a 5s timeout (`curl -sf -o /dev/null --max-time 5 "$base_url"`). If unreachable, mark every queued finding `Confirm-Status: blocked` with reason `app-unreachable-at-V4-start` and skip the per-finding spawns. Saves N×30s of wasted PoC timeouts.

For each remaining finding WITH a PoC script, spawn `vigolium-audit:poc-runner` with `run_in_background: true`:

> Prompt: "Execute the PoC for finding <ID>-<slug>. Finding directory: vigolium-results/findings/<ID>-<slug>/. Connection: vigolium-results/confirm-workspace/env-connection.json. Per-variant timeout: 30s (max 2 variants → 60s wall clock). Session: ${VIGOLIUM_AUDIT_SESSION_UUID}. Honour structured PoC output contract: parse the final JSON line `{\"status\":\"confirmed|failed|inconclusive\",\"evidence\":\"...\",\"notes\":\"...\"}` rather than heuristic log-scraping."

Wait for all poc-runner agents to complete.

Collect results by re-reading each finding's `report.md`. Build the lists:
- `live-verified`: findings with `Confirm-Status: live-verified`
- `not-reproduced`: findings with `Confirm-Status: not-reproduced | errored`
- `blocked`: findings flagged unreachable above
- `analytical`: non-exploitable findings (already finalized)
- `no-poc`: findings without PoC scripts (will go to V5)

Mark V4 complete.

---

## Phase V5 — Test-Based Fallback (skip if REMOTE_TARGET)

**Determine which findings need test-based verification:**
- If V3 failed (no app): ALL findings (mode: `full`)
- If V3 succeeded but some PoCs didn't reproduce: only `not-reproduced` + `no-poc` findings (mode: `fallback`)

If no findings need test-based verification, mark V5 as `skipped`.

For each finding needing test verification, spawn `vigolium-audit:test-locator` with `run_in_background: true`:

> Prompt: "Generate and run a reproducer test for finding <ID>-<slug>. Finding directory: vigolium-results/findings/<ID>-<slug>/. Test strategies: vigolium-results/confirm-workspace/env-strategies.json. Connection (for auth identities): vigolium-results/confirm-workspace/env-connection.json. Mode: <full|fallback|local>. Target directory: <abs_target>. Session: ${VIGOLIUM_AUDIT_SESSION_UUID}. Enforce per-test runtime cap of 60s (pytest --timeout=60, jest --testTimeout=60000, go test -timeout 60s, rspec --timeout 60). On timeout, mark Confirm-Status: blocked with Confirm-Notes: test-timeout."

Wait for all test-locator agents to complete. Mark V5 complete.

---

## Phase V6 — Confirmation Report

Spawn `vigolium-audit:confirm-writer` (foreground):

> Prompt: "Compile the confirmation report. Findings directory: vigolium-results/findings/. Confirm workspace: vigolium-results/confirm-workspace/. Audit state: vigolium-results/audit-state.json (optional). Session: ${VIGOLIUM_AUDIT_SESSION_UUID}. Stage findings into report-ready/{live-verified,test-verified,analytical,false-positive} and needs-review/{not-reproduced,flaky,blocked,no-poc,errored}. Group non-exploitable findings into the report-ready/analytical section rather than treating them as failed verifications. Dedupe findings confirmed by multiple methods. Append to audits[-1].confirmation_history[] (do NOT overwrite the previous confirmation object)."

Mark V6 complete.

---

## Cleanup

After V6 completes successfully, the EXIT trap installed during Setup invokes
`cleanup_session` automatically — that's the source of truth for cleanup. It
covers:

1. **Container teardown by session label**: `docker rm -f` every container with
   label `vigolium-audit.session=${VIGOLIUM_AUDIT_SESSION_UUID}` (works even when the original
   `cleanup_cmd` is missing or the previous session crashed mid-run).
2. **Process teardown**: kill any PID in `vigolium-results/confirm-workspace/app.pid`.
3. **Best-effort `cleanup_cmd`**: if `env-connection.json` recorded one, run it.
4. **Lock release**: remove `vigolium-results/confirm-workspace/.lock`.

Then, in the orchestrator (post-trap):

5. **Update audit state if present**: append a new entry to
   `audits[-1].confirmation_history[]` with `session`, `started_at`,
   `completed_at`, `target`, and the per-class result counts. Set
   `audits[-1].confirmation.status` to `complete` (latest run summary).

6. **Print summary**: display the confirmation rate broken down by
   exploitability class plus a one-line-per-finding result table.

---

## Error Recovery

- If V2 fails: skip V3, set all findings to test-only mode for V5
- If V3 fails: skip V4, set all findings to test-only mode for V5
- If a single poc-runner fails: mark that finding as `error`, continue with others
- If a single test-locator fails: mark that finding as `blocked`, continue with others
- If V5 fails completely: proceed to V6 with whatever results are available
- Always run V6 (confirmation report) regardless of upstream failures
- Always run cleanup regardless of any failures
