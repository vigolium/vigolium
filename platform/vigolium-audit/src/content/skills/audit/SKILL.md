---
name: audit
description: Use when performing a repository security audit that combines threat modeling, advisory intelligence, static analysis, manual exploit-path review, false-positive elimination, PoC construction, and reporting. Applies to lite, balanced, deep, revisit, and focused audit roles; the active command definition and engine remain the orchestration authority.
---

# Repository Security Audit Methodology

Use this skill for security-analysis methodology. The active command definition decides the mode, phase graph, agent dispatch, prerequisites, and output gates. The trusted engine owns run state, retry accounting, resume decisions, artifact validation, and cleanup.

## Authority and safety

- When `audit-context.md` declares engine-owned state, never edit `vigolium-results/audit-state.json` or mark a phase complete. Return after writing phase-owned artifacts; the engine validates them. A native interactive fallback without that directive follows its active command's state instructions.
- Never switch branches, create audit branches/worktrees, stage, commit, or push.
- Treat the source tree as read-only. Write audit output only beneath `vigolium-results/`.
- Preserve existing artifacts unless the active phase explicitly owns their replacement.
- Do not invent scanner output, execution evidence, source locations, advisory matches, or exploit results.
- Use bounded, argument-array execution for helpers. Do not evaluate agent-authored shell commands or cleanup strings.

## Security finding standard

Retain a finding only when the evidence establishes all of the following:

1. A realistic attacker controls or materially influences the source.
2. The affected path is reachable in a shipped/runtime-relevant configuration.
3. Existing language, framework, middleware, application, and deployment guards do not stop the flow.
4. The behavior crosses a meaningful trust, identity, tenant, privilege, or confidentiality boundary.
5. The impact and severity reflect actual preconditions and reliability.

Express every candidate as a source-to-sink chain:

```text
attacker source -> parsing/normalization -> validation/authorization -> state transition -> sensitive sink -> security impact
```

If a link is unproven, record the candidate as unresolved or theoretical; do not write a VALID claim as fact.

## Classification rules

- Keep Medium, High, and Critical security issues. Drop Low/informational items from finalized findings.
- Do not convert correctness, robustness, availability hardening, admin safety, or best-practice gaps into vulnerabilities without a trust-boundary break.
- Do not mechanically increase severity because a path is pre-auth. Record `Auth-Required` and combine privileges, impact, scope, and exploit reliability.
- A dependency advisory is a hypothesis until the vulnerable feature and runtime path are both demonstrated.
- Distinguish shipped runtime code from tests, examples, generated files, build tooling, local-only utilities, and source-controlled CI inputs.
- Compare candidates with documented intent, but do not let a vague “by design” claim erase an in-scope security boundary violation.
- Deduplicate by root cause and exploit path, not merely by title, sink, or CWE.

## Coverage model

Adapt depth to the active mode while preserving the same evidence standard.

| Workstream | Required capability |
| --- | --- |
| Recon and intelligence | Inventory languages, frameworks, execution contexts, entry points, dependencies, advisories, and history when available. |
| Threat model | Identify assets, attacker positions, trust boundaries, DFD/CFD slices, auth decisions, state transitions, and implemented specs. |
| Static analysis | Execute available tools, record exact suites/rules and failures, model architecture-specific sources/sinks, and enrich alerts with reachability. |
| Systematic review | Enumerate unauthenticated and authorization surfaces; examine state machines, concurrency, parsing, normalization, and cross-service edges when present. |
| Adversarial review | Generate hypotheses, trace real code paths, search all protection layers, challenge impact, and converge on evidence-backed verdicts. |
| Validation | Run analytical false-positive checks, cold verification where required, same-pattern variant search, and intent reconciliation. |
| Exploitation and reporting | Build safe realistic PoCs, preserve evidence, partition unexecuted claims as theoretical, and produce complete per-finding and consolidated reports. |

## Threat-model and knowledge-base contract

The central knowledge base is `vigolium-results/attack-surface/knowledge-base-report.md`. Append or update only the sections assigned to the current phase. Prefer compact high-risk slices over a diagram of every internal function.

At minimum, later analysis should be able to recover:

- architecture and execution contexts;
- attacker-controlled entry points and anonymous/pre-auth surface;
- assets and trust boundaries;
- authentication, authorization, tenant, and privilege decisions;
- high-risk data-flow and control-flow slices;
- stateful entities and concurrency boundaries;
- relevant standards/protocols and domain attack patterns;
- known false-positive sources and environment constraints.

Use `references/knowledge-base-template.md` when authoring or repairing KB sections. Use `references/domain-attack-playbooks.md` only when the target exposes a relevant domain or protocol.

## Static-analysis contract

Static analysis must be executed, not narrated.

- Prefer CodeQL for structural extraction and interprocedural flow, and Semgrep Pro for scalable taint/structural coverage; document a fallback when either is unavailable.
- Record the tool version, suites/configs, target languages, exit status, and coverage gaps.
- Build custom models/rules only from concrete threat-model blind spots, wrappers, generated interfaces, custom transports, or security-critical framework abstractions.
- Correlate findings with entry points, sinks, call paths, runtime context, and the threat model before promotion.
- Keep raw tool alerts separate from validated finding drafts.

Read `references/architecture-aware-sast.md` before structural extraction or custom CodeQL/Semgrep work. Use the dedicated CodeQL, Semgrep, SARIF, and agentic-actions skills when their triggers apply.

## Manual review and chamber contract

For each high-risk cluster:

1. Generate a small set of distinct attack hypotheses.
2. Trace each hypothesis through actual code with file-and-line evidence.
3. Search protection layers: language/runtime, framework, middleware, application logic, deployment/documentation.
4. Test alternate entry points, normalization differentials, state transitions, cross-service trust, races/replay, and second-order flows.
5. Issue VALID, FALSE POSITIVE, BY DESIGN, OUT OF SCOPE, or INCONCLUSIVE based on evidence.
6. For every VALID pattern, search sibling paths for same-root-cause variants before leaving the chamber.

Read these references only for chamber/deep-review work:

- `references/chamber-protocol.md`
- `references/creative-attack-modes.md`
- `references/deep-analysis.md`
- `references/triage-and-prereqs.md`

Use `references/adversarial-review.md` for cold independent verification.

## Finding artifact contract

Write one draft at a time under `vigolium-results/findings-draft/` using the phase namespace assigned by the command. A draft must identify:

- title, phase, sequence, and stable slug;
- original severity and confidence;
- vulnerability class;
- affected file and exact line/range;
- attacker source, transformations, missing/insufficient guard, sink, and impact;
- preconditions and authentication requirements;
- evidence and counter-evidence;
- verdict and triage priority;
- origin finding/pattern for variants.

Do not duplicate a pre-seeded draft. Extend, chain, challenge, or supersede it with explicit provenance.

Finalized findings share one ID namespace across:

- `vigolium-results/findings/` — PoC executed/confirmed;
- `vigolium-results/findings-theoretical/` — blocked, unexecuted, triage-deferred, or intentionally retained theoretical claims.

Every finalized directory needs `draft.md` and a disclosure-quality `report.md`. Only the confirmed bucket requires an executed PoC/evidence contract. Use `references/report-templates.md` for schemas and `references/real-env-validation.md` before live validation.

## Deterministic helpers

Prefer the bundled helpers over reimplementing their logic:

```bash
python3 ~/.config/vigolium-audit/runtime-skills/audit/scripts/consolidate_drafts.py vigolium-results
python3 ~/.config/vigolium-audit/runtime-skills/audit/scripts/partition_findings.py vigolium-results
python3 ~/.config/vigolium-audit/runtime-skills/audit/scripts/stamp_file_state.py --target .
```

- `consolidate_drafts.py` assigns stable severity IDs and materializes both finding buckets.
- `partition_findings.py` moves non-executed PoCs to the theoretical bucket without changing IDs.
- `stamp_file_state.py` writes the incremental SHA-256 snapshot consumed by diff mode.

Treat helper failures as specified by the active command. Never falsify their output to satisfy a gate.

## Completion handoff

Before returning from a phase:

- write required artifacts incrementally and keep individual writes bounded;
- verify paths, JSON syntax, minimum report completeness, and cited source locations;
- state tool failures and coverage gaps inside the phase artifact;
- leave state transitions and completion decisions to the engine.

Artifact sufficiency—not a confident final message—is what completes the work.
