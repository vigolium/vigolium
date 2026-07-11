# Audit Workflow Compatibility Reference

This path is retained for compatibility with older prompts. It is not an orchestration contract.

The authoritative execution sources are:

1. `src/content/command-defs/<mode>.md` for the mode's phase graph and role dispatch;
2. command frontmatter `completion` blocks for deterministic artifact gates;
3. the trusted engine for state, resume, retries, budgets, cleanup, and completion;
4. `../SKILL.md` for shared security-analysis methodology.

Do not infer phase numbers from this reference. Lite, balanced, deep, revisit, confirmation, and specialized modes deliberately use different IDs.

## Stable workflow shape

The principal audit modes use the same capability ladder at different depth:

```text
recon/intelligence
  -> threat model and attack surface
  -> executable static/structural analysis
  -> systematic and hypothesis-driven review
  -> adversarial validation and intent reconciliation
  -> deterministic consolidation
  -> PoC/evidence and theoretical partition
  -> per-finding reports
  -> consolidated report
```

The active mode may omit, combine, parallelize, or revisit these capabilities. Follow its dependency graph exactly.

## Engine boundary

Agents must not:

- create, replace, or update `vigolium-results/audit-state.json`;
- claim a phase is complete;
- decide resume state from prose alone;
- evaluate cleanup commands written by another agent;
- delete durable artifacts;
- switch branches, create worktrees, or modify source files.

Agents write only phase-owned artifacts. The engine validates declared size, content, JSON, glob, and finding-report conditions, may request a bounded repair, and owns the final state transition.

## Role-to-reference routing

| Work | Read |
| --- | --- |
| Knowledge base structure | `knowledge-base-template.md` |
| Architecture-aware SAST/custom models | `architecture-aware-sast.md` |
| Protocol/domain research | `domain-attack-playbooks.md` |
| Deep code-path analysis | `deep-analysis.md` |
| Chamber debate | `chamber-protocol.md`, `creative-attack-modes.md` |
| Triage and severity | `triage-and-prereqs.md` |
| Cold verification | `adversarial-review.md` |
| Live validation | `real-env-validation.md` |
| Draft/state/report schemas | `report-templates.md` |

Read only the references needed by the current role.

## Durable output model

All artifacts live below `vigolium-results/`. Common durable outputs are:

- `attack-surface/knowledge-base-report.md`;
- `attack-surface/unauthenticated-surface.md`;
- `attack-surface/sbom.json`;
- `findings/<ID>-<slug>/` for executed/confirmed findings;
- `findings-theoretical/<ID>-<slug>/` for blocked or unexecuted findings;
- `final-audit-report.md` and mode-specific reports;
- `audit-state.json` and `file-state.json`, owned by the engine.

Working directories such as `findings-draft/`, `probe-workspace/`, `chamber-workspace/`, and scanner output remain available until the engine applies the active retention policy.

## Deterministic finalization

Use the bundled scripts when the command requests them:

```bash
python3 ~/.config/vigolium-audit/runtime-skills/audit/scripts/consolidate_drafts.py vigolium-results
python3 ~/.config/vigolium-audit/runtime-skills/audit/scripts/partition_findings.py vigolium-results
python3 ~/.config/vigolium-audit/runtime-skills/audit/scripts/stamp_file_state.py --target .
```

Do not reproduce their ID assignment, bucket routing, or file-state schema manually.

## No-history targets

Plain source folders remain auditable. When local Git history is unavailable, skip only history-dependent work and record the limitation in the phase artifact; continue source-snapshot recon, threat modeling, scanning, review, validation, and reporting.
