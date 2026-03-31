# Audit Workflow Reference

Detailed per-phase instructions, resource management procedures, and architecture-aware attack pattern catalog for the audit skill.

## Table of Contents

1. [Setup](#setup)
2. [Phase 1: Intelligence Gathering](#phase-1-intelligence-gathering)
3. [Phase 2: Patch Bypass Analysis](#phase-2-patch-bypass-analysis)
4. [Phase 3: Knowledge Base](#phase-3-knowledge-base)
5. [Phase 4: Static Analysis — Resource Management](#phase-4-static-analysis--resource-management)
6. [Phase 5: Enrichment](#phase-5-enrichment)
7. [Phase 6: Spec Gap Analysis](#phase-6-spec-gap-analysis)
8. [Phase 7: Deep Bug Hunting](#phase-7-deep-bug-hunting)
9. [Phase 8: FP Elimination](#phase-8-fp-elimination)
9. [Phase 9: Variant Analysis](#phase-9-variant-analysis)
10. [Phase 10: Exploitation & Final Reporting](#phase-10-exploitation--final-reporting)
11. [Architecture and Project Attack Pattern Catalog](#architecture-and-project-attack-pattern-catalog)

---

## Setup

```bash
# Create the audit output directory and findings-draft staging area
mkdir -p archon/ archon/findings-draft/

# Initialize or append to audit-state.json (append-only history for this audit session)
AUDIT_ID=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
NEW_ENTRY="{\"audit_id\":\"$AUDIT_ID\",\"commit\":\"$COMMIT\",\"branch\":\"$BRANCH\",\"mode\":\"full\",\"model\":\"unknown\",\"agent_sdk\":\"unknown\",\"started_at\":\"$AUDIT_ID\",\"completed_at\":null,\"status\":\"in_progress\",\"phases\":{}}"

if [ -f archon/audit-state.json ]; then
  # Append new entry to existing audits array
  python3 -c "
import json, sys
data = json.load(open('archon/audit-state.json'))
data['audits'].append(json.loads(sys.argv[1]))
json.dump(data, open('archon/audit-state.json', 'w'), indent=2)
" "$NEW_ENTRY"
else
  # Create new file with first entry
  python3 -c "
import json, sys
json.dump({'audits': [json.loads(sys.argv[1])]}, open('archon/audit-state.json', 'w'), indent=2)
" "$NEW_ENTRY"
fi
```

---

## Phase 1: Intelligence Gathering

**Subagent**: `advisory-hunter`

**Goal**: Build a complete inventory of published security advisories, architecture context, and security-relevant dependency intelligence.

**Advisory source priority**:
1. Project-hosted advisory page (check README, SECURITY.md, or project website)
2. GitHub Security Advisories (`gh api graphql` or `gh api repos/{owner}/{repo}/security-advisories`)
3. NVD/CVE database (web search for `site:nvd.nist.gov <project-name>`)
4. OSV database (`https://osv.dev/list?q=<package-name>`)
5. Release notes / changelog (grep for `CVE`, `security`, `vulnerability`)

**Architecture inventory**:
- Identify components, processes, services, plugins, workers, control planes, and external dependencies.
- Identify transports and protocols: HTTP, gRPC, WebSocket, queues, files, CLI, IPC, schedulers, plugins, agent/tool invocation, and any custom RPC layer.
- Identify trust boundaries and execution environments: internet-facing, internal-only, desktop-local, CI/CD, control-plane vs data-plane, tenant vs admin.
- Record the handful of highest-risk flows that deserve Phase 3 DFD/CFD slices.

**Dependency intelligence**:
- Inspect manifests, lockfiles, build files, container files, and deployment config.
- Note outdated, unsupported, or historically bug-prone dependencies that influence parsing, auth, serialization, policy enforcement, code execution, or network handling.
- **Action**: Delegate to the `supply-chain-risk-auditor` skill to perform a comprehensive dependency analysis.
- Treat dependency findings as exploit hypotheses unless a reachable abuse path is established later in the audit.

**When only a patched version is known** (no direct commit reference):

```bash
# Find commits between vulnerable and patched tags
git log --oneline v<vulnerable>..v<patched>

# Narrow to security-relevant files
git log --oneline v<vulnerable>..v<patched> -- src/archon/ src/auth/ src/validation/

# Diff the full range
git diff v<vulnerable>..v<patched> -- <relevant-paths>
```

**Output**: `## Advisory Intelligence` section of `archon/knowledge-base-report.md`, populated with advisory inventory, architecture intelligence, vulnerability class patterns, and supply chain risk summary.

---

## Phase 2: Patch Bypass Analysis

**Subagent**: `patch-bypass-checker` (one instance per patch)

**Goal**: Determine whether each security patch is sound, bypassable, or relocated.

**Invocation**: spawn one `patch-bypass-checker` instance per patch commit. Each instance receives:
- The patch diff (`git show <commit>`)
- The advisory metadata (CVE/GHSA ID, severity, description)
- The repository path

**Parallelism**: multiple patch-bypass-checker instances can run in parallel since they are read-only.

**Output**: `## Bypass Analysis` section of `archon/knowledge-base-report.md`

---

## Phase 3: Knowledge Base

**Subagent**: `knowledge-base-builder`

**Goal**: Understand the system deeply enough to guide all subsequent phases.

**Key questions to answer**:
- What type of project is this? (See [Architecture and Project Attack Pattern Catalog](#architecture-and-project-attack-pattern-catalog))
- What are the major components and trust boundaries?
- How do data and control move between components?
- Where are the security-critical decisions made?
- Which paths cross trust boundaries, change execution context, or propagate identity?
- What does it protect? (Assets)
- Who can attack it? (Threat actors)
- Where does attacker input enter? (Attack surface)
- What specs/RFCs does it implement? (For Phase 6)

**Required outputs inside the existing reports**:
- A compact architecture inventory.
- DFD slices for only the highest-risk attacker-controlled flows.
- CFD slices for only the highest-risk authn/authz, policy, routing, orchestration, or privilege-transition paths.
- A list of components, wrappers, generated interfaces, and unusual trust boundaries that likely require custom Phase 4 modeling.
- **Action**: Invoke the `security-threat-model` skill to formally document and capture these elements.

**Domain Attack Research (Mode A/B/C)**:

After architecture mapping and spec identification, run domain attack research:

- **Mode A -- Library-as-target**: project type is `library`, `plugin`, or `protocol`. Delegate to
  `sharp-edges` (API footguns), `wooyun-legacy` (web-facing libraries only), and `last30days`
  (recent CVE discussions for the library by name).

- **Mode B -- Library-as-consumer**: security-sensitive dependencies identified in Phase 1 or
  Step 2. Delegate to `sharp-edges` (consumer usage), `insecure-defaults` (fail-open configs), and
  `last30days` (per dependency for recent misuse disclosures).

- **Mode C -- Domain-specific**: triggered when technology domains are detected (SAML, OAuth, JWT,
  HTTP, gRPC, GraphQL, WebSocket, XML/SOAP, TLS, DNS, SMTP, LDAP, SSH, serialization,
  compression, crypto). For each domain, run the research action sequence from
  `references/domain-attack-playbooks.md`: web search, `last30days`, `wooyun-legacy` (conditional),
  MCP tools (best-effort). Produce a domain attack taxonomy, custom SAST targets, and manual review
  checklist per domain.

All three modes are non-exclusive. Run Mode C alongside Mode A/B whenever domains are detected.
Write results to the `## Domain Attack Research` section of `archon/knowledge-base-report.md`.

**Output**: `archon/knowledge-base-report.md` with all Phase 3 sections populated (Project Classification, Architecture, Trust Boundaries, DFD/CFD Slices, Threat Model, Attack Surface, Domain Attack Research, Specs/RFCs, Dependencies, Phase 4 Modeling Targets)

---

## Phase 4: Static Analysis — Resource Management

**Subagent**: `static-analyzer`

**Execution order is mandatory**:
1. Run built-in CodeQL suites appropriate to the repo languages via the `codeql` skill.
2. Run built-in Semgrep baseline, language, and framework rulesets via the `semgrep` skill.
3. Check GitHub Actions workflows using the `agentic-actions-auditor` skill.
4. Add custom CodeQL and Semgrep coverage only where the Phase 3 DFD/CFD slices show blind spots, wrappers, or unusual trust boundaries.
5. If multiple SARIF outputs are produced, use `sarif-parsing` to deduplicate.

### Concurrency Management

CodeQL and Semgrep are resource-intensive. Check before spawning:

```bash
# Count running SAST processes
SAST_COUNT=$(ps aux | grep -E 'codeql|semgrep' | grep -v grep | wc -l)
echo "Running SAST processes: $SAST_COUNT"

# Only proceed if count < 2
if [ "$SAST_COUNT" -ge 2 ]; then
  echo "Too many SAST processes running. Wait before starting."
  exit 1
fi
```

### Disk Space Check

CodeQL databases can be large (1-10 GB for large repos). Check before building:

```bash
# Check available disk space
df -h .

# Estimate repo size
du -sh <target-repo>
```

As a rough guide: the CodeQL database is typically 2-5x the size of the source code.

### Language Detection

```bash
# Detect primary languages
find <target> -type f | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -20

# Or use github-linguist if available
github-linguist <target>
```

### Architecture-Specific Modeling Decision

Custom modeling is mandatory when one or more of these are true:
- security-critical data crosses multiple components or transports
- identity or policy decisions propagate across service boundaries
- the codebase relies on custom wrappers around frameworks, RPC, auth, parsing, storage, or execution
- generated interfaces, IDLs, schemas, plugins, or orchestration layers hide sources, summaries, or sinks from built-in tooling
- the highest-risk Phase 3 DFD/CFD slices do not map cleanly onto built-in sources, sinks, or enforcement checks

When custom modeling is required:
- store CodeQL artifacts under `archon/codeql-queries/`
- store Semgrep artifacts under `archon/semgrep-rules/`
- cite which DFD/CFD slices motivated each custom model or rule
- open the exact build references in [architecture-aware-sast.md](architecture-aware-sast.md) before writing custom queries or rules

See [architecture-aware-sast.md](architecture-aware-sast.md) for the modeling workflow.

### Semgrep Execution Policy

Semgrep Pro is mandatory when available, but do not run all Pro-heavy rulesets simultaneously on large repos.

Use this execution policy:
1. Run a whole-repo baseline pass for high-signal built-in rulesets.
2. Separate Pro-heavy taint passes from lightweight structural passes.
3. Batch Pro-heavy passes by high-risk subsystem or architecture slice from Phase 3.
4. Use file, path, and language scoping aggressively for targeted passes.
5. Record any batching, throttling, or narrowed scope in the `## Static Analysis Summary` section of
`archon/knowledge-base-report.md`.

The goal is bounded resource usage without losing baseline built-in coverage.

### Cleanup Commands

Run after the report is written:

```bash
# Remove CodeQL databases (can be very large)
rm -rf archon/codeql-db/ archon/codeql-db-*/

# Remove Semgrep cache
rm -rf ~/.semgrep/cache/

# Remove CodeQL package cache (optional — speeds up future runs if kept)
# rm -rf ~/.codeql/packages/

# Verify cleanup
du -sh archon/
```

### SARIF Merging

When multiple SARIF files exist (multi-language CodeQL + Semgrep), use the `sarif-parsing` skill to merge and deduplicate:

```bash
# Quick merge with jq
jq -s '{ version: "2.1.0", runs: [ .[].runs[] ] }' \
  archon/codeql-res/*.sarif \
  archon/semgrep-res/*.sarif \
  > archon/merged-results.sarif
```

**Output**: `## Static Analysis Summary` and `## GitHub Actions Audit` sections of
`archon/knowledge-base-report.md`. The Static Analysis Summary must record:
- built-in CodeQL suites and rulesets run
- built-in Semgrep rulesets run
- custom CodeQL artifacts run
- custom Semgrep artifacts run
- which DFD/CFD slices drove targeted custom analysis
- any batching, throttling, or coverage tradeoffs with justification

---

## Phase 5: Enrichment

**Goal**: Make the knowledge base and SAST findings more accurate by cross-referencing them.

### SAST → Threat Model Enrichment

After reading the `## Static Analysis Summary` section of `knowledge-base-report.md`, update the KB if SAST found:
- New entry points not identified in Phase 3
- New vulnerability classes relevant to the project type
- New high-risk functionality not in the attack surface
- New boundary crossings or decision points missing from the DFD/CFD slices

### Threat Model → SAST FP Filtering

Re-evaluate each SAST finding against the threat model:

| Project Type | Common FP Patterns |
|-------------|-------------------|
| CLI tool | Command execution with user-supplied args is often intentional |
| Library | Dangerous APIs are often intentional — the caller is responsible |
| Internal service | Network-only attacks may not apply if not internet-facing |
| Admin-only feature | Requires admin access — often out of scope for bug bounty |

Mark findings as FALSE POSITIVE or OUT OF SCOPE with explicit reasoning tied to the threat model.
Use the DFD/CFD slices to check whether the finding crosses a real trust boundary or reaches a security-critical decision point.

---

## Phase 6: Spec Gap Analysis

**Skill**: `spec-to-code-compliance`

**Goal**: Find implementation gaps between the project's spec/RFC implementations and the actual standards, focusing on gaps that are concretely exploitable.

### Pre-Work: Read Domain Attack Research

Before fetching any spec documents, read the `## Domain Attack Research` section of
`archon/knowledge-base-report.md`. Use the Mode C attack taxonomy and manual review checklist
as the primary list of patterns to test during spec gap analysis. This avoids re-researching
attacks that Phase 3 already catalogued and ensures spec gap analysis focuses on the highest-risk
protocol-specific patterns.

### Fetching Spec Documents

Use web search, fetch tools, or MCP to retrieve official spec documents:

```
# Examples of spec URLs to fetch
https://www.rfc-editor.org/rfc/rfc6749  # OAuth 2.0
https://www.rfc-editor.org/rfc/rfc7519  # JWT
https://www.rfc-editor.org/rfc/rfc9110  # HTTP Semantics
https://openid.net/specs/openid-connect-core-1_0.html
```

### High-Priority Gap Categories

Focus on these categories first — they have the highest historical yield:

1. **Authentication protocol gaps**: OAuth state/nonce, JWT algorithm confusion, SAML assertion validation
2. **Parsing discrepancies**: URL parsing, header parsing, multipart parsing (see deep-analysis.md §6)
3. **Canonicalization**: case normalization, Unicode normalization, path normalization
4. **Replay and freshness**: nonce validation, timestamp checking, token invalidation after use
5. **Downgrade attacks**: forced use of weaker algorithm or protocol version

### Exploitability Filter

Only include gaps where:
- An attacker can trigger the gap without requiring physical access or pre-existing full compromise
- The gap leads to a concrete security impact (auth bypass, data exfiltration, privilege escalation)
- The gap is not already mitigated by another control in the system

**Output**: `## Spec Gap Analysis` section of `archon/knowledge-base-report.md`. If no specs were identified in Phase 3, mark "None identified" and skip.

---

## Phase 7: Review Chamber Deep Bug Hunting

**Agents**: `chamber-synthesizer`, `attack-ideator`, `code-tracer`, `devils-advocate`, `variant-scout` (optional)

**Goal**: Find vulnerabilities through structured multi-agent debate. Four specialized roles
collaborate on each threat cluster to produce findings with higher creativity and lower
false-positive rates than a single auditor.

**Input**: `archon/knowledge-base-report.md` (all sections from phases 1-6),
`archon/codeql-artifacts/` (structural artifacts from Phase 4)

### Chamber Formation

1. Read `## High-Risk DFD Slices` and `## High-Risk CFD Slices` from the KB
2. Group slices by shared trust boundary or component affinity into threat clusters
3. Each cluster becomes one Review Chamber (typical: 3-8 chambers)
4. Priority order: authentication/authorization first, then data ingestion, then API surface
5. Create `archon/chamber-workspace/` and `archon/attack-pattern-registry.json`

### NNN Range Assignment

Assign non-overlapping finding ID ranges to prevent collisions across parallel chambers:
```
Chamber 1: p7-001 through p7-019
Chamber 2: p7-020 through p7-039
Chamber 3: p7-040 through p7-059
...
```

### Chamber Spawn (up to 3 concurrent)

For each chamber, create the workspace and spawn 4 agents:
```bash
mkdir -p archon/chamber-workspace/<chamber-id>/{evidence,variant-candidates}
```

- **Chamber Synthesizer**: orchestrates debate, issues verdicts, writes finding drafts
- **Attack Ideator**: generates 3-7 hypotheses using 8 creative attack modes
  (see `references/creative-attack-modes.md`)
- **Code Tracer**: traces each hypothesis through code using Method 2.6
  (see `references/deep-analysis.md`)
- **Devil's Advocate**: challenges every finding at 5 protection layers,
  checks 8 Claude-Specific FP patterns
- **Variant Scout** (optional, for 3+ DFD slices): monitors debate for confirmed patterns,
  searches for variants concurrently

### Debate Protocol

Each chamber proceeds through structured rounds via an append-only transcript at
`archon/chamber-workspace/<chamber-id>/debate.md`:

```
Round 1 (Ideation):   Ideator generates 3-7 hypotheses
Round 2 (Tracing):    Tracer traces each hypothesis through code
Round 3 (Challenge):  Advocate writes defense brief per hypothesis
Round 4 (Synthesis):  Synthesizer evaluates arguments, issues verdicts
Round 5-6 (Optional): Focused re-investigation (max 2 per hypothesis)
```

**Limits**: max 7 hypotheses per batch, max 3 rounds per hypothesis, max 3 concurrent chambers.

**Convergence criteria**:
- Tracer: UNREACHABLE + Advocate confirms → DROP
- Tracer: REACHABLE + Advocate cannot disprove (2 attempts) → VALID
- Tracer: REACHABLE + Advocate finds blocking protection → FALSE POSITIVE
- 3 rounds without resolution → Synthesizer judgment call
- Low severity → DROP immediately

See `references/chamber-protocol.md` for complete format and transcript template.

### Pre-Finding Quality Gate

Before the Synthesizer writes any draft, apply 5-point check:
1. Attacker control verified by Tracer (not just inferred)?
2. Framework protection searched by Advocate (all 5 layers)?
3. Trust boundary crossing confirmed (not same-origin)?
4. Exploitation requires normal attacker position (not admin)?
5. Vulnerable code ships to production (not test/example)?

### Cross-Chamber Intelligence

`archon/attack-pattern-registry.json` stores confirmed patterns with detection signatures
(CodeQL, grep, Semgrep). Other chambers read the registry before new ideation rounds.

### Specialized Delegations

Chambers may delegate to specialized skills for scope NOT covered by Phase 3 domain attack
research: `insecure-defaults`, `sharp-edges`, `wooyun-legacy`, `zeroize-audit`, `ffuf-web-fuzzing`.

See [Architecture and Project Attack Pattern Catalog](#architecture-and-project-attack-pattern-catalog) for specific attack patterns.

### Knowledge Base Feedback Loop

After all chambers close:
1. Collect all finding drafts and variant candidates
2. Append `## Phase 7 Addendum` to KB (newly discovered attack surfaces, revised trust
   boundaries, additional DFD/CFD paths). Forward-append only — preserve Phase 3 content.
3. Phase 9 must read the updated KB including the addendum.

**Output**: `archon/findings-draft/p7-<NNN>-<slug>.md` (Medium+ only),
`archon/chamber-workspace/<chamber-id>/debate.md` (audit artifacts),
`archon/attack-pattern-registry.json`,
`## Phase 7 Addendum` appended to KB

---

## Phase 8: P8-LITE FP Elimination

**Goal**: Eliminate false positives. Reduced from full adversarial review because the Devil's
Advocate already challenged every finding during the Phase 7 chamber debate.

### Stage 1: Analytical FP Check

**Skill**: `fp-check`

**Retain**: medium-to-critical findings exploitable in a bug bounty context.

**Exclude**:
- By-design behavior (document as such with reasoning)
- Informational findings (verbose errors, version disclosure without exploit chain)
- Defense-in-depth gaps with no direct exploit path
- Issues requiring full system compromise as a prerequisite
- Admin-only abuse (unless threat model explicitly includes admin-level attackers)

**Prioritize**: findings with `Pre-FP-Flag` annotations from the chamber debate.

**Incremental verdict persistence**: Write each verdict back into the corresponding
`archon/findings-draft/p7-*.md` file immediately. Add:

```
Verdict: VALID | FALSE POSITIVE | BY DESIGN | OUT OF SCOPE | DROP (low severity)
Rationale: <one-sentence explanation tied to the threat model>
```

Findings with `FALSE POSITIVE`, `BY DESIGN`, `OUT OF SCOPE`, or `DROP (low severity)` do not
proceed to Stage 2.

### Stage 2: Cold Verification (CRITICAL and HIGH only)

**Medium findings skip Stage 2** — already challenged by the Devil's Advocate during the
chamber debate. This reduces Phase 8 cost by ~60%.

**Applies to**: CRITICAL and HIGH findings with `Verdict: VALID` after Stage 1.

**Agent isolation**: Spawn a fresh agent per VALID CRITICAL/HIGH finding. The task description
contains only the finding draft file path. Do not include the debate transcript, Phase 7 reasoning,
or any other context. The fresh agent reads methodology from `references/adversarial-review.md`.

**Execution**: Cold verification reviews run in parallel across findings.

**Steps performed by each cold verifier** (detailed in `adversarial-review.md`):
1. Restate and decompose into testable sub-claims
2. Independent code path trace from entry point to sink
3. Attempt real-environment reproduction (follow `real-env-validation.md`)
4. Prosecution + defense briefs
5. Severity challenge (start at MEDIUM, require evidence to upgrade)
6. Verdict: CONFIRMED or DISPROVED

**Verdict integration**: Write results back into the finding draft:
```
Adversarial-Verdict: CONFIRMED | DISPROVED
Adversarial-Rationale: <one sentence citing the decisive evidence>
Severity-Final: <challenged severity>
PoC-Status: executed | theoretical | blocked
```
If `DISPROVED`, also update `Verdict:` to `FALSE POSITIVE (adversarial)`.

**Severity reconciliation**: lower severity always wins.

**Full review output**: `archon/adversarial-reviews/<slug>-review.md` using the template
from `report-templates.md`.

**Output**: updated `archon/findings-draft/` files (CRITICAL/HIGH with cold verification
verdicts), `archon/adversarial-reviews/<slug>-review.md` per CRITICAL/HIGH VALID finding

---

## Phase 9: Variant Analysis

**Skill**: `variant-analysis`

**Goal**: Find similar bugs to each confirmed finding elsewhere in the codebase.

**Primary input**: `archon/attack-pattern-registry.json` — the structured registry of confirmed
patterns from Phase 7 Review Chambers. Each pattern includes `detection_signature` fields with
ready-made CodeQL, grep, and Semgrep queries for automated variant hunting.

For each confirmed finding:
1. Read the matching pattern from `archon/attack-pattern-registry.json`
2. Run the pattern's `detection_signature` queries (CodeQL, grep, Semgrep) across the codebase
3. Check `untested_candidates` from the registry for specific locations to investigate
4. Read `archon/chamber-workspace/*/variant-candidates/` for pre-identified candidates from
   Variant Scouts
5. Use DFD/CFD slices — including `## Phase 7 Addendum` additions — to search for the same
   flow shape in sibling components, alternate transports, and adjacent enforcement paths

**Incremental variant persistence**: Write each confirmed variant immediately to
`archon/findings-draft/p9-<NNN>-<slug>.md` using the finding draft template. Update the
attack pattern registry with each confirmed variant.

**Output**: `archon/findings-draft/p9-<NNN>-<slug>.md` (one file per variant, Medium or higher only)

---

## Phase 10: Exploitation & Final Reporting

**Goal**: Prove the impact of confirmed vulnerabilities through realistic Proof-of-Concepts (PoCs) and generate a professional, executive-ready final report.

### Task A: Draft Promotion

Before generating individual reports, promote confirmed findings from the draft staging area:

1. List all files in `archon/findings-draft/` with `Verdict: VALID`.
2. Assign severity IDs (`C1`, `H1`, `M1`) in priority order across all confirmed Critical/High/Medium drafts. Discard any `F-NNN` or other sequential IDs used during Phase 7-9 drafting. Low severity findings are dropped entirely — no ID, no report, no summary table entry.
3. For each confirmed draft, create `archon/findings/<ID>-<slug>/` and copy the draft as the basis for the `vuln-report` output.
4. Leave non-VALID drafts in place for the audit record.

### Task B: Realistic PoCs

For each critical, high, and medium bug:
1.  **Environment Setup**: Identify the minimum setup required for a valid reproduction.
2.  **PoC Construction**: Use the shortest, most reliable path. Ensure the PoC is representative of a real-world attack (e.g., do not bypass a security boundary that would be present in production).
3.  **Refinement**: Minimize the PoC code. Style it as a clean, effective exploit script.

**Real-environment execution mandate for CRITICAL/HIGH findings**: For every CRITICAL or HIGH finding promoted to `archon/findings/`, PoC execution in a real environment is required before the final report is generated. Reuse the Stage 2 adversarial environment if it was successfully provisioned; otherwise provision a new environment following `real-env-validation.md`.

Capture evidence in `archon/findings/<ID>-<slug>/evidence/`:
```
archon/findings/<ID>-<slug>/evidence/
  setup.sh         # provisioning commands
  exploit.sh       # PoC exploit script
  exploit.log      # full output of PoC execution
  impact.log       # impact evidence
```

Annotate each CRITICAL/HIGH finding with:
```
PoC-Status: executed | theoretical | blocked
```

If execution is blocked, document the specific reason. Do not report a CRITICAL/HIGH finding without this annotation. A `PoC-Status: theoretical` finding must include a `PoC-Block-Reason:` line explaining why execution was not possible.

### Task C: Individual Vulnerability Reports

Invoke the `vuln-report` skill for each valid finding:
-   **ID Mapping**: Use severity prefixes `C1`, `H1`, `M1` (Critical/High/Medium). Do not invoke `vuln-report` for Low severity findings.
-   **Naming Convention**: Save each report to `archon/findings/<ID>-<slug>/report.md`.
-   **Structure**: Follow the required sections (Summary, Details, Root Cause, PoC, Impact) exactly as defined in `vuln-report/SKILL.md`.

### Task D: Consolidated Pentest-Style Report

This is the mandatory final step to synthesize the entire audit. Generate `archon/final-audit-report.md` using the template in `audit/references/report-templates.md`.

**Required Content**:
-   **Executive Summary**: High-level risk assessment for non-technical stakeholders.
-   **Methodology Summary**: Overview of Phases 1-9 to establish technical depth.
-   **Summary Table**: A prioritized list of all **VALID** findings with IDs and severity.
-   **Technical Detail Links**: Technical summaries for each valid finding, linking to the detailed `vuln-report` and PoC.
-   **Conclusion**: Final professional assessment of the project's security posture.

### Task E: Post-Audit Cleanup

After the consolidated report is written, delete all working artifacts. Only the knowledge base, final report, and individual findings are retained.

```bash
rm -rf archon/findings-draft/
rm -rf archon/adversarial-reviews/
rm -rf archon/real-env-evidence/
rm -rf archon/codeql-artifacts/
rm -rf archon/codeql-queries/
rm -rf archon/semgrep-rules/
rm -f archon/audit-state.json
rm -f archon/merged-results.sarif
rm -f archon/bounty-scope.md
```

Verify retained output:
```bash
ls archon/knowledge-base-report.md archon/final-audit-report.md archon/findings/
```

---

## Architecture and Project Attack Pattern Catalog

These are generic patterns that apply based on project type. For technology-domain-specific attack
patterns (SAML, OAuth, JWT, HTTP smuggling, gRPC, GraphQL, WebSocket, XML/SOAP, TLS, DNS, SMTP,
LDAP, SSH, serialization, compression, crypto), see `references/domain-attack-playbooks.md`.
Domain patterns from Phase 3 Mode C are always higher-priority targets than the generic patterns
below because they are tailored to the project's specific implementation.

### Cross-Cutting Architecture Patterns

Apply these regardless of product type:

| Pattern | Where to Look | Key Question |
|--------|--------------|--------------|
| Trust-boundary handoff | gateways, workers, handlers, adapters, clients | Does security context change or get widened when crossing the boundary? |
| Wrapper blindness | custom middleware, helper layers, generated SDKs | Do built-in SAST rules miss the real source, summary, or sink? |
| Control-plane vs data-plane confusion | admin APIs, job runners, orchestrators, schedulers | Can low-trust input trigger higher-privilege control actions? |
| Identity propagation drift | session, token, metadata, headers, claims | Is caller identity preserved, narrowed, and re-verified on each hop? |
| Async guarantee mismatch | queues, events, retries, delayed jobs | Does the consumer assume validation or auth happened earlier when it did not? |
| Schema or parser differential | serializers, IDLs, schemas, validators | Do two layers parse or normalize the same input differently? |

### Web Application

**Primary concerns**: SSRF, XSS, SQLi, auth bypass, IDOR, mass assignment

| Attack | Where to Look | Key Question |
|--------|--------------|--------------|
| SSRF | URL fetching, webhooks, import features, PDF generation | Can the server be made to fetch internal URLs? |
| Stored XSS | User-generated content, profile fields, comments | Is output HTML-encoded in all rendering contexts? |
| SQLi | Search, filter, sort parameters | Is user input concatenated into queries? |
| IDOR | Resource access by ID | Is ownership verified, not just existence? |
| Mass assignment | JSON/form body to model | Are protected fields excluded from bulk assignment? |
| Open redirect | `next`, `return_to`, `redirect` parameters | Is the destination validated against an allowlist? |
| CSRF | State-changing POST/PUT/DELETE | Is the CSRF token bound to the session? |
| Path traversal | File download, template rendering | Is the path normalized before the access check? |

### Library

**Primary concerns**: unsafe deserialization, injection via API misuse, prototype pollution, ReDoS

| Attack | Where to Look | Key Question |
|--------|--------------|--------------|
| Unsafe deserialization | `deserialize()`, `parse()`, `fromJSON()` | Are type constraints enforced? |
| Prototype pollution (JS) | Object merge, deep clone, `set()` with dot-path | Can `__proto__` be set via user input? |
| ReDoS | Regex patterns applied to user input | Does the pattern have catastrophic backtracking? |
| Path traversal via API | File path parameters | Is the path sanitized before use? |
| Command injection | Shell command construction from caller input | Is caller input shell-escaped? |

### CLI Tool

**Primary concerns**: argument injection, path traversal, symlink attacks, env var injection

| Attack | Where to Look | Key Question |
|--------|--------------|--------------|
| Argument injection | Values passed to `exec()`, `spawn()` | Are user-supplied values shell-escaped? |
| Path traversal | File arguments, config file paths | Are paths normalized and confined to expected dirs? |
| Symlink attack | Temp file creation, file operations | Does the tool follow symlinks it should not? |
| Env var injection | Reading sensitive config from environment | Can a lower-privileged process influence the env? |

### Plugin / Extension

**Primary concerns**: sandbox escape, privilege escalation, supply chain, cross-plugin leakage

| Attack | Where to Look | Key Question |
|--------|--------------|--------------|
| Sandbox escape | Host API access, native module loading | Can the plugin access APIs beyond its permissions? |
| Privilege escalation | Host operations triggered by plugin | Does the host re-verify permissions before acting? |
| Supply chain | Remote code fetching, auto-update | Is fetched code integrity-verified? |
| Cross-plugin leakage | Shared storage, event bus | Can one plugin read another's data? |

### Protocol Implementation

**Primary concerns**: spec non-compliance, token forgery, replay, downgrade

| Attack | Where to Look | Key Question |
|--------|--------------|--------------|
| Token forgery | Signature verification, algorithm selection | Is the algorithm verified before the signature? |
| Replay attack | Nonce/timestamp validation | Are nonces stored and checked for reuse? |
| Downgrade | Algorithm negotiation | Can the attacker force a weaker algorithm? |
| State machine bypass | Multi-step flows | Can steps be skipped or reordered? |

### Infrastructure / Agent

**Primary concerns**: SSRF, secret exfiltration, command injection, lateral movement

| Attack | Where to Look | Key Question |
|--------|--------------|--------------|
| SSRF | Job parameters, webhook URLs, artifact fetching | Can job input reach internal metadata endpoints? |
| Secret exfiltration | Log output, error messages, debug endpoints | Are secrets masked in all output paths? |
| Command injection | Job parameters passed to shell | Are parameters shell-escaped? |
| Lateral movement | Credentials scope, IAM roles | Are credentials scoped to minimum required permissions? |
