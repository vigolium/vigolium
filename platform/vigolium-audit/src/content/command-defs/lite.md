---
description: Run a super-quick 3-phase security audit — quick recon, secrets scan + SAST pass (parallel), then PoC building. Produces a flat findings list with severity, location, and PoCs.
argument-hint: "Optional: target path/scope"
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebSearch, WebFetch, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
mode: lite
phases:
  - id: L1
    title: Recon Pass
    agent: null
    requires_git: false
    parallel_with: []
    depends_on: []
  - id: L2
    title: Secrets Scan
    agent: null
    requires_git: false
    parallel_with: [L3]
    depends_on: [L1]
  - id: L3
    title: Fast Code Scan
    agent: null
    requires_git: false
    parallel_with: [L2]
    depends_on: [L1]
---

## Context

- Audit context (orchestrator-supplied directives + user prose, if any): !`cat vigolium-results/audit-context.md 2>/dev/null || echo "(none)"`
- Git availability: !`git rev-parse --is-inside-work-tree >/dev/null 2>&1 && echo "Git worktree detected" || echo "No git worktree (plain directory target)"`
- Current branch: !`git branch --show-current 2>/dev/null || echo "No git branch (plain directory target)"`
- Existing audit state: !`cat vigolium-results/audit-state.json 2>/dev/null || echo "No existing audit state"`
- Security directory: !`ls vigolium-results/ 2>/dev/null || echo "No security directory"`

## Your Task

Run a **lite** (super-quick) security audit of the current repository. Target scope: $ARGUMENTS

This is a minimal 3-phase pipeline designed for speed. It answers one question: **"what would blow up if this shipped right now?"** It produces the same output format as deeper audits (`/vigolium-audit:balanced`, `/vigolium-audit:deep`) so findings are compatible with `/vigolium-audit:diff` and `/vigolium-audit:status`.

This mode supports auditing a plain source folder with no `.git` directory or local history.

### What Lite Mode Covers

| Phase | What It Does |
|-------|-------------|
| L1 — Recon Pass | Detect languages, frameworks, entry points, and deployment model from file structure + package manifests |
| L2 — Secrets Scan | Hardcoded keys, tokens, passwords, credentials in source (runs parallel with L3) |
| L3 — Fast Code Scan | Single run of built-in security suites, scoped by L1 recon (runs parallel with L2) |

### What Lite Mode Skips

Everything else: intelligence gathering, knowledge base, deep probe, spec gap analysis, review chambers, FP elimination, variant analysis, and narrative report generation.

### Pre-Flight Check

If `vigolium-results/audit-state.json` exists, use `AskUserQuestion` to gate the next action:

- **Incomplete phases**: ask "An audit is already in progress. What would you like to do?" with options:
  - "Resume from last checkpoint"
  - "Start fresh (clears existing state)"
  - "Cancel"

- **All phases complete**: ask "A completed audit exists for this repository. What would you like to do?" with options:
  - "Run a fresh lite audit (clears existing state)"
  - "Upgrade to balanced mode (/vigolium-audit:balanced)"
  - "Upgrade to deep mode (/vigolium-audit:deep)"
  - "Cancel"

If the user chooses **Resume**: find the first phase not marked `complete` in the state file and continue from there.

If the user chooses **Start fresh**: delete `vigolium-results/audit-state.json` and proceed with Pre-Audit Setup.

Do not proceed past the pre-flight check without an explicit user choice.

### Pre-Audit Setup

1. Detect whether Git history is available:
   ```bash
   if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
     export VIGOLIUM_AUDIT_GIT_AVAILABLE=true
   else
     export VIGOLIUM_AUDIT_GIT_AVAILABLE=false
   fi
   ```
2. **Do NOT switch branches.** Stay on the current branch for the entire audit. Do NOT run `git checkout`, `git switch`, `git branch`, `git commit`, `git add`, or `git push` against the target repo at any point. The audit writes all artifacts under `vigolium-results/` (untracked) — the user controls staging and commits. If `VIGOLIUM_AUDIT_GIT_AVAILABLE=false`, continue auditing the directory in place; do NOT initialize a new repo just for the audit.
3. Create output directory: `mkdir -p vigolium-results/`
4. Initialize `vigolium-results/audit-state.json` by appending a new entry (or creating the file):
   ```json
   {
     "audits": [
       {
         "audit_id": "<ISO timestamp>",
         "commit": "<HEAD SHA from: git rev-parse HEAD, or null / \"nogit\" when Git is unavailable>",
         "branch": "<current branch, or \"nogit\">",
         "repository": "<value of $VIGOLIUM_AUDIT_REPOSITORY env var, pre-computed by the CLI from git remote / package manifests / basename — substitute the literal string before writing>",
         "history_available": "<true if Git worktree detected, else false>",
         "mode": "lite",
         "model": "<model name, e.g. opus-4.6, gpt-5.3-codex, sonnet-4.6>",
         "agent_sdk": "<platform name, e.g. claude-code, codex>",
         "started_at": "<ISO timestamp>",
         "completed_at": null,
         "status": "in_progress",
         "phases": {
           "L1": {"status": "pending"},
           "L2": {"status": "pending"},
           "L3": {"status": "pending"}
         }
       }
     ]
   }
   ```
   If the file already exists, read it and append a new entry to the `audits` array rather than replacing the file. Never remove earlier entries.

---

## Lite Pipeline

```
L1 (Recon Pass) → [L2 (Secrets Scan) + L3 (Fast Code Scan)] parallel → Output
```

### Phase L1: Recon Pass

Build a lightweight project context block by reading file structure and package manifests. No agents — just file reads. This phase should complete in seconds.

1. **Language detection**: scan file extensions across the target scope to identify primary and secondary languages.

2. **Framework detection**: read package manifests and config files to identify frameworks:
   - `package.json` → Node.js / React / Next.js / Express / etc.
   - `requirements.txt` / `pyproject.toml` / `Pipfile` → Python / Django / Flask / FastAPI / etc.
   - `go.mod` → Go / Gin / Echo / etc.
   - `Cargo.toml` → Rust / Actix / Axum / etc.
   - `pom.xml` / `build.gradle` → Java / Spring / etc.
   - `Gemfile` → Ruby / Rails / Sinatra / etc.
   - `composer.json` → PHP / Laravel / Symfony / etc.

3. **Entry point detection**: identify likely entry points based on framework conventions:
   - Web: route files, controller directories, API handler directories
   - CLI: main files, bin directories
   - Library: exported modules, public API surface

4. **Deployment model**: check for presence of `Dockerfile`, `docker-compose.yml`, `k8s/`, `.github/workflows/`, `serverless.yml`, `terraform/`, `Procfile`, etc.

5. **Scope exclusions**: identify directories to skip in L2/L3:
   - Test directories (`test/`, `tests/`, `__tests__/`, `spec/`, `*_test.go`)
   - Vendored/generated code (`vendor/`, `node_modules/`, `dist/`, `build/`, `generated/`)
   - Documentation (`docs/`, `*.md` outside root)
   - Static assets (`public/`, `static/`, `assets/` containing only images/fonts/CSS)

6. **Write recon block** to `vigolium-results/attack-surface/lite-recon.md`:
   ```markdown
   ## Lite Recon

   - **Languages**: <e.g. Python 3.11, TypeScript>
   - **Framework**: <e.g. FastAPI + React>
   - **Entry points**: <e.g. src/api/main.py, src/api/routes/>
   - **Auth**: <e.g. JWT (src/api/auth/), OAuth (src/api/oauth/)>
   - **Deployment**: <e.g. Docker (Dockerfile present), GitHub Actions>
   - **Excluded from scan**: <e.g. tests/, node_modules/, dist/, docs/>
   ```

Update `vigolium-results/audit-state.json`: set `L1` status to `complete` with timestamp.

### Phase L2 + L3 (parallel)

After L1 completes, run L2 and L3 **in parallel**. Both phases use `vigolium-results/attack-surface/lite-recon.md` to scope their work — skip directories listed in the recon exclusions.

### Phase L2: Secrets Scan

Scan the target scope (minus recon exclusions) for hardcoded secrets, credentials, and sensitive tokens.

1. Run secret detection tools available in the environment. Prefer tools in this order:
   - `trufflehog filesystem $TARGET --no-update --json` (if available)
   - `gitleaks detect --source $TARGET --no-git --report-format json` (if available)
   - Fall back to manual grep-based scanning if no tools are installed:
     ```bash
     # Scan for common secret patterns
     grep -rn --include='*.{js,ts,py,rb,go,java,rs,php,yml,yaml,json,toml,env,cfg,conf,ini,xml,sh}' \
       -E '(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20}|xox[bporsca]-[a-zA-Z0-9\-]+|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|password\s*[:=]\s*["\x27][^"\x27]{8,}|secret\s*[:=]\s*["\x27][^"\x27]{8,}|api[_-]?key\s*[:=]\s*["\x27][^"\x27]{8,}|token\s*[:=]\s*["\x27][^"\x27]{8,})' \
       ${TARGET:-.} 2>/dev/null || true
     ```

2. For each finding, write a minimal finding file to `vigolium-results/findings-draft/`:
   ```
   Filename: l2-NNN.md (NNN = 001, 002, ...)
   ```
   Each file:
   ```markdown
   ## L2-NNN: <Secret Type>

   - **Severity**: Critical | High | Medium
   - **File**: <path>
   - **Line**: <line number>
   - **Type**: <e.g. AWS Access Key, GitHub PAT, Private Key, Hardcoded Password>
   - **Verdict**: VALID

   ### Evidence
   <masked snippet — show enough context to locate but redact the actual secret value>
   ```

3. Severity assignment:
   - **Critical**: Private keys, cloud provider credentials (AWS, GCP, Azure), database connection strings with passwords
   - **High**: API keys, personal access tokens, OAuth secrets, JWT signing keys
   - **Medium**: Generic passwords, internal tokens, webhook secrets

Update `vigolium-results/audit-state.json`: set `L2` status to `complete` with timestamp.

### Phase L3: Fast Code Scan

Run a single pass of built-in static analysis security suites, scoped by L1 recon.

1. Read `vigolium-results/attack-surface/lite-recon.md` for languages, frameworks, and entry points. Use the detected languages to select the correct SAST rulesets. Use the excluded directories list to narrow scan scope.

2. Run Semgrep with built-in security rulesets (no custom rules):
   ```bash
   semgrep scan --config auto --severity ERROR --severity WARNING \
     --json --output vigolium-results/semgrep-res/lite-results.json \
     ${TARGET:-.} 2>/dev/null || true
   ```
   If Semgrep is not available, fall back to CodeQL built-in suites:
   ```bash
   # Create DB and run built-in security queries only
   codeql database create vigolium-results/codeql-artifacts/db --language=<lang> --overwrite 2>/dev/null
   codeql database analyze vigolium-results/codeql-artifacts/db --format=sarif-latest \
     --output=vigolium-results/codeql-artifacts/lite-results.sarif 2>/dev/null || true
   ```
   If neither tool is available, perform a manual pattern-based scan using `Grep` for common vulnerability patterns:
   - SQL injection: string concatenation in query strings
   - Command injection: unsanitized input in exec/system/spawn calls
   - Path traversal: user input in file path operations
   - XSS: unescaped user input in HTML output
   - Insecure deserialization: pickle.loads, yaml.load without SafeLoader, unserialize
   - Hardcoded crypto: weak algorithms (MD5, SHA1 for security), ECB mode

3. For each finding, write a minimal finding file to `vigolium-results/findings-draft/`:
   ```
   Filename: l3-NNN.md (NNN = 001, 002, ...)
   ```
   Each file:
   ```markdown
   ## L3-NNN: <Vulnerability Title>

   - **Severity**: Critical | High | Medium
   - **File**: <path>
   - **Line**: <line number>
   - **Rule**: <rule ID from tool, or manual pattern name>
   - **Category**: <e.g. SQL Injection, Command Injection, XSS, Path Traversal>
   - **Verdict**: VALID

   ### Evidence
   <code snippet showing the vulnerable pattern>

   ### One-Liner
   <single sentence explaining the risk>
   ```

4. Severity assignment — trust the tool's severity mapping. For manual scans:
   - **Critical**: SQL injection, command injection, SSRF, insecure deserialization with attacker input
   - **High**: XSS, path traversal, authentication bypass patterns, broken access control
   - **Medium**: Weak crypto, information disclosure, missing security headers

5. **Quick dedup and filter**:
   - If a L3 finding overlaps with a L2 finding (same file + line), keep the L2 finding and drop the L3 duplicate.
   - Using `vigolium-results/attack-surface/lite-recon.md` entry points and framework context, drop findings in files that are clearly not reachable from user input (e.g., build scripts, migration utilities, dev-only tooling). Mark dropped findings with `Verdict: FILTERED` rather than deleting them.

Update `vigolium-results/audit-state.json`: set `L3` status to `complete` with timestamp.

---

## Output

After all phases complete:

1. **Assign final IDs**: Collect all `vigolium-results/findings-draft/l2-*.md` and `vigolium-results/findings-draft/l3-*.md` with `Verdict: VALID`. Assign severity-prefixed IDs: `C1`, `C2`, ..., `H1`, `H2`, ..., `M1`, `M2`, ... Drop all Low severity findings.

2. **Finding consolidation**: For each confirmed finding with assigned ID:
   1. `mkdir -p vigolium-results/findings/<ID>-<slug>/evidence/`
   2. Copy the finding draft: `cp vigolium-results/findings-draft/<l2|l3>-<NNN>.md vigolium-results/findings/<ID>-<slug>/draft.md`

3. **PoC Building**: For each confirmed finding, spawn `vigolium-audit:poc-author` with `run_in_background: true`. Each receives: finding draft path, assigned ID, and `vigolium-results/attack-surface/lite-recon.md` path for project context. Wait for all PoC builders to complete.

4. **Post-audit cleanup**: Delete intermediate working artifacts:
   ```bash
   rm -rf vigolium-results/findings-draft/
   rm -rf vigolium-results/codeql-artifacts/
   rm -rf vigolium-results/semgrep-res/
   ```
   Retained: `vigolium-results/audit-state.json`, `vigolium-results/attack-surface/lite-recon.md`, `vigolium-results/findings/`.

5. **Print summary table** to the user:
   ```
   Lite Audit Complete — <N> findings

   | ID | Severity | Category | File:Line | One-Liner |
   |----|----------|----------|-----------|-----------|
   | C1 | Critical | AWS Key  | src/config.js:42 | Hardcoded AWS access key |
   | H1 | High     | SQLi     | api/users.py:87  | User input concatenated into SQL query |
   | ...| ...      | ...      | ...       | ... |

   Findings: vigolium-results/findings/
   For deeper analysis, run /vigolium-audit:balanced (6-phase) or /vigolium-audit:deep (full 11-phase).
   ```

6. Update `audits[-1].completed_at` and `audits[-1].status` to `complete`.

---

## Notes

- **No narrative report**: lite mode does not produce `vigolium-results/final-audit-report.md`. The findings + PoCs are the deliverable.
- **No knowledge base**: lite mode does not produce `vigolium-results/attack-surface/knowledge-base-report.md`.
- **Compatible output**: finding directories use the same `vigolium-results/findings/<ID>-<slug>/` structure as `/vigolium-audit:balanced` and `/vigolium-audit:deep` (with `draft.md`, `report.md`, `poc.*`, `evidence/`), so upgrading to a deeper audit preserves lite findings. The `/vigolium-audit:confirm` command works directly against lite output.
- **Minimal agent use**: lite mode runs the balanced pipeline phases inline — only `vigolium-audit:poc-author` agents are dispatched for PoC generation.
