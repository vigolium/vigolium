# Review Chamber Protocol

Defines the debate format, agent interaction rules, round limits, and convergence criteria for the
Phase 7 Review Chamber multi-agent debate system.

## Overview

A Review Chamber is a 4-agent debate team that processes a threat scenario cluster (grouped
DFD/CFD slices sharing trust boundaries). Four roles — Attack Ideator, Code Tracer, Devil's
Advocate, and Chamber Synthesizer — operate through structured rounds of hypothesis generation,
evidence gathering, adversarial challenge, and verdict synthesis.

Findings emerge from structured argumentation, not solitary analysis. This eliminates the
confirmation bias inherent in a single agent both imagining and validating an attack.

## Chamber Formation

### Cluster Formation

After Phase 5 (enrichment) and Phase 6 (spec gap) complete, the orchestrator forms threat
clusters from the KB:

1. Read `## High-Risk DFD Slices` and `## High-Risk CFD Slices` from `archon/knowledge-base-report.md`
2. Group slices by shared trust boundary or component affinity (slices accessing the same data store,
   enforcement point, or transport layer belong together)
3. Each cluster becomes one chamber
4. Typical audit produces 3-8 chambers depending on architecture complexity
5. Priority ordering: clusters touching authentication/authorization first, then data ingestion,
   then external API surface, then internal components

### Chamber Directory Structure

```
archon/chamber-workspace/
  chamber-01-auth-flows/
    debate.md              # append-only debate transcript
    evidence/              # tracer evidence attachments (on-demand QL queries, screenshots)
    variant-candidates/    # scout-discovered variant candidates
  chamber-02-data-ingestion/
    debate.md
    evidence/
    variant-candidates/
```

### NNN Range Assignment

To prevent finding ID collisions across parallel chambers, the orchestrator assigns non-overlapping
ranges before spawning:

```
Chamber 1: p7-001 through p7-019
Chamber 2: p7-020 through p7-039
Chamber 3: p7-040 through p7-059
Chamber 4: p7-060 through p7-079
...
```

The Synthesizer receives its assigned range in the spawn prompt.

### Concurrency Limit

Up to 3 chambers run simultaneously. If more than 3 clusters exist, the orchestrator spawns the
first 3 in priority order, then spawns subsequent chambers as earlier ones complete.

## Agent Roles and Constraints

### Attack Ideator

- Generates attack hypotheses by cycling through 8 creative modes
  (see `creative-attack-modes.md`)
- Does NOT trace code paths, does NOT issue verdicts
- Reads: KB (threat model, domain attack research, attack surface), CodeQL structural analysis
  section, enrichment notes, spec gap analysis
- Writes: hypothesis batches to debate transcript
- Produces 3-7 numbered hypotheses (H-01 through H-07) per batch

### Code Tracer

- Takes each hypothesis and traces through actual code with evidence
- Uses Method 2.6 from `deep-analysis.md`: call-graph-slices.json, entry-points.json, sinks.json,
  flow-paths-all-severities.md, on-demand QL queries against live DB
- Does NOT generate hypotheses, does NOT issue final verdicts
- Reads: source code, CodeQL artifacts, KB structural analysis
- Writes: per-hypothesis evidence blocks to debate transcript
- Produces: reachability verdict (REACHABLE / UNREACHABLE / PARTIAL) with file:line chains

### Devil's Advocate

- Challenges EVERY finding the Tracer marks reachable
- Searches 5 protection layers: language, framework, middleware, application, documentation
- Must argue against even obvious vulnerabilities — inability to construct credible defense is
  itself strong evidence of a genuine vulnerability
- Does NOT generate hypotheses
- Reads: source code, framework documentation, project SECURITY.md, deployment configs
- Writes: defense briefs to debate transcript
- Must explicitly check all 8 Claude-Specific FP patterns from `triage-and-prereqs.md`

### Chamber Synthesizer

- Orchestrates the debate flow by writing phase markers to the transcript
- Reads all arguments from other roles and makes judgment calls
- Requests additional investigation rounds when evidence is insufficient
- Assigns calibrated severity per `triage-and-prereqs.md` Severity Calibration
- Only role that writes finding drafts to `archon/findings-draft/`
- Manages the attack pattern registry (append confirmed patterns)
- Does NOT generate hypotheses, does NOT trace code

## Debate Protocol

### Round Flow

```
Synthesizer writes "## Round 1 -- Ideation" marker to debate.md
  │
  ▼
Ideator reads marker, generates 3-7 hypotheses, appends to debate.md
  │
  ▼
Synthesizer writes "## Round 2 -- Tracing" marker
  │
  ▼
Tracer reads hypotheses, traces each through code, appends evidence to debate.md
  │
  ▼
Synthesizer writes "## Round 3 -- Challenge" marker
  │
  ▼
Devil's Advocate reads Tracer evidence, writes defense brief per hypothesis, appends to debate.md
  │
  ▼
Synthesizer writes "## Round 4 -- Synthesis" marker
  │
  ▼
Synthesizer reads all arguments, issues verdicts OR writes "INVESTIGATE:" directives
  │
  ▼
[Optional] Rounds 5-6: Focused re-investigation (max 2 additional rounds per hypothesis)
  │
  ▼
Synthesizer writes finding drafts for VALID findings, closes chamber
```

### Agent Communication

Within archon-audit-claude: agents communicate via the shared `debate.md` file AND `SendMessage`.
The Synthesizer uses `SendMessage` to notify each agent when its turn begins. Agents read
the transcript to understand prior arguments.

Within archon-audit-codex: agents poll `debate.md` for new sections (file-based coordination).

### Turn-Taking Rules

1. Only ONE agent writes to `debate.md` at a time (serialized by debate rounds)
2. Each agent appends to the end of the file — never edits prior sections
3. Each section is tagged with the role name: `### [IDEATOR]`, `### [TRACER]`, `### [ADVOCATE]`,
   `### [SYNTHESIZER]`
4. Timestamps are included for debugging and performance analysis

### Round Limits

- **Maximum 7 hypotheses per ideation batch**: if the Ideator generates more, the Synthesizer
  prioritizes by expected impact and defers the rest
- **Maximum 3 rounds per hypothesis**: 1 initial trace+challenge round + 2 follow-up rounds.
  If unresolved after 3 rounds, the Synthesizer issues a judgment call or marks INCONCLUSIVE
- **Maximum 6 total rounds per chamber** (1 ideation + 1 tracing + 1 challenge + 1 synthesis +
  2 follow-up). The Synthesizer may not request more than 2 follow-up rounds.

## Convergence Criteria

Debate ends for a hypothesis when any condition is met:

| Condition | Verdict | Action |
|-----------|---------|--------|
| Tracer: UNREACHABLE, Advocate confirms no alternate path | DROP | No draft written |
| Tracer: REACHABLE, Advocate cannot find blocking protection (2 attempts) | VALID | Write finding draft |
| Tracer: REACHABLE, Advocate finds blocking protection | FALSE POSITIVE | No draft written |
| 3 rounds without resolution | Synthesizer judgment | Verdict or INCONCLUSIVE |
| Duplicate of already-adjudicated finding | DUPLICATE | No draft written |
| Severity determined to be Low | DROP (low severity) | No draft written |

A chamber closes when all hypotheses have reached a terminal verdict.

## Pre-Finding Quality Gate

Before the Synthesizer writes any finding draft, apply this 5-point check:

1. **Attacker control verified?** Tracer confirmed input reaches the path (not inferred)?
2. **Framework protection checked?** Advocate searched all 5 layers?
3. **Same-origin confusion?** Is the attack cross-trust-boundary, not same-session?
4. **Config vs. vulnerability?** Exploitation requires only normal attacker position (not admin)?
5. **Test/example code?** Vulnerable code ships to production?

If any check fails, the finding is dropped. If ambiguous, the Synthesizer adds
`Pre-FP-Flag: check-N-ambiguous` to the finding draft for Phase 8 priority.

## Cross-Chamber Intelligence

### Attack Pattern Registry

File: `archon/attack-pattern-registry.json`

When the Synthesizer confirms a finding, it checks the registry:
- Pattern exists → append to `confirmed_instances`
- New pattern → create entry with `detection_signature` and `untested_candidates`

Other chambers read the registry before starting new ideation rounds. The Ideator
incorporates confirmed patterns to look for the same class of vulnerability in its cluster's scope.

Schema:

```json
{
  "patterns": [{
    "id": "AP-001",
    "title": "Unsafe ObjectInputStream deserialization",
    "bug_class": "deserialization",
    "root_cause": "ObjectInputStream.readObject() without ObjectInputFilter",
    "detection_signature": {
      "codeql": "<QL query fragment>",
      "grep": "<regex pattern>",
      "semgrep": "<semgrep pattern>"
    },
    "confirmed_instances": [
      {"finding_ref": "p7-003-admin-deser.md", "file": "src/admin/AdminService.java:142"}
    ],
    "untested_candidates": [
      {"file": "src/backup/BackupRestoreService.java:201", "reason": "Uses ObjectInputStream"}
    ],
    "severity": "CRITICAL"
  }]
}
```

### Variant Scout Integration

The Variant Scout (optional 5th agent) monitors the debate transcript for confirmed patterns
and immediately searches for structural variants in sibling components. Findings are written to
`archon/chamber-workspace/<chamber-id>/variant-candidates/` for the Synthesizer to decide
whether to open a new debate round or defer to Phase 9.

## Debate Transcript Format

File: `archon/chamber-workspace/<chamber-id>/debate.md`

```markdown
# Review Chamber: <chamber-id>

Cluster: <description of threat scenario cluster>
DFD Slices: <comma-separated slice identifiers from KB>
NNN Range: <assigned range, e.g., 001-019>
Started: <ISO timestamp>
Status: ACTIVE | CLOSED

---

## Round 1 -- Ideation

### [IDEATOR] Hypothesis Batch -- <ISO timestamp>

**H-01: <hypothesis title>**
- Attack class: <e.g., TOCTOU, second-order injection, trust boundary confusion>
- Chain: <multi-step chain description if applicable>
- Preconditions: <attacker starting position>
- Target asset: <what the attacker gains>
- Entry point: <suspected entry, may be approximate>
- Sink: <suspected sensitive operation>
- Creativity signal: <why a solo agent would miss this>

**H-02: <hypothesis title>**
...

---

## Round 2 -- Tracing

### [TRACER] Evidence for H-01 -- <ISO timestamp>

**Reachability: REACHABLE | UNREACHABLE | PARTIAL**

Code path:
1. `<file:line>` -- <description>
2. `<file:line>` -- <description>
3. `<file:line>` -- <description>

Sanitizers on path:
- `<file:line>` -- <description of control and bypassability>

CodeQL slice: call-graph-slices.json entry #<N>, reachable: <true|false>
On-demand query: <path to .ql file if run>

**Assessment**: <summary of reachability evidence>

---

## Round 3 -- Challenge

### [ADVOCATE] Defense Brief for H-01 -- <ISO timestamp>

**Protection search results:**

| Layer | Protection Found | Blocks Attack? |
|-------|-----------------|----------------|
| Language | <finding> | <Yes/No> |
| Framework | <finding> | <Yes/No> |
| Middleware | <finding> | <Yes/No> |
| Application | <finding> | <Yes/No> |
| Documentation | <finding> | <Yes/No> |

**Claude FP Pattern Check**: <which of the 8 patterns were checked, any matches>

**Defense argument**: <strongest case for false positive>

**Verdict recommendation**: Cannot disprove | Disproved by <layer> protection

---

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-01 -- <ISO timestamp>

**Prosecution summary**: <key evidence from Tracer>

**Defense summary**: <key argument from Advocate>

**Pre-FP Gate**: all checks passed | failed on check-<N>

**Verdict: VALID | FALSE POSITIVE | DROP | INCONCLUSIVE**
**Severity: MEDIUM | HIGH | CRITICAL**
**Rationale**: <one-sentence justification citing evidence from both sides>

**Finding draft written to**: archon/findings-draft/p7-<NNN>-<slug>.md
**Registry updated**: AP-<NNN> <title> (or "no new pattern")

---

## [Optional] Round 5 -- Focused Re-investigation

### [SYNTHESIZER] Investigation Request -- <ISO timestamp>

**Directed to**: TRACER | ADVOCATE
**Regarding**: H-<NN>
**Question**: <specific question>

### [TRACER|ADVOCATE] Response for H-<NN> -- <ISO timestamp>
...

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-01 | VALID | HIGH | p7-001-<slug>.md |
| H-02 | FALSE POSITIVE | -- | -- |
| H-03 | DROP (unreachable) | -- | -- |
| ... | | | |

Findings written: <count>
Patterns added to registry: <count>
Variant candidates: <count>

Chamber closed: <ISO timestamp>
```

## Relationship to Phase 8

The Devil's Advocate within the chamber subsumes most of Phase 8 Stage 2's adversarial function.
Phase 8 is reduced to **P8-LITE**:

- **Stage 1 (unchanged)**: apply `fp-check` skill to all VALID findings. Catches systematic
  FP patterns the Advocate might share with other chamber agents.
- **Stage 2 (CRITICAL/HIGH only)**: spawn one fresh cold-verification agent per CRITICAL/HIGH
  finding with ONLY the finding draft path (no debate transcript). Focus on real-environment
  reproduction per `real-env-validation.md`. Medium findings skip Stage 2 entirely — already
  challenged by the Devil's Advocate during debate.

## Error Recovery

- **Agent crashes mid-round**: Synthesizer detects via missing response. Notifies orchestrator.
  Orchestrator spawns replacement agent with the current debate transcript as context.
- **Chamber stalls**: if no new content appears in debate.md for an extended period, the
  orchestrator messages the Synthesizer to check status or force convergence.
- **Session recovery**: orchestrator reads `debate.md` Status field. ACTIVE chambers with
  incomplete rounds are resumed from the last completed round marker.
