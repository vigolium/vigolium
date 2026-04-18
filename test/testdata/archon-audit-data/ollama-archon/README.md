# ollama/ollama Audit Bundle

This `archon/` directory is the normalized merged output of prior audit runs. The promoted findings under `archon/findings/` are the source of truth for IDs, severity, and per-finding reports.

## Snapshot
- Repository: `ollama/ollama`
- Merged at: `2026-04-17T15:52:40Z`
- Source runs: `/tmp/merge-ollama/ollama-archon`, `/tmp/merge-ollama/ollama-with-opus-4.7`
- Promoted findings: 45 (C:3, H:7, M:35)
- Quarantined findings: 21
- Semantic dedup merges: 2

## Primary Outputs
- `final-audit-report.md`: consolidated merged report for the retained findings.
- `findings/`: promoted findings with standardized `draft.md` and `report.md` files.
- `quarantine/`: findings that could not satisfy the merge contract, primarily due to missing evidence for promoted HIGH findings.
- `audit-state.json`: merge provenance plus the embedded rename map.
- `merge-report.md`: detailed normalization log for passes M1-M7.

## Variant Relationships
| Parent | Variants |
|--------|----------|
| C2 | M1 |
| H6 | C1 |

## Outstanding Review Items
- Promoted findings missing PoC scripts: 36
- Retained supporting artifacts left in place for provenance or references: adversarial-reviews/, bypass-analysis/, chamber-workspace/, codeql-artifacts/, codeql-queries/, findings-draft/, probe-workspace/, quarantine/, real-env-evidence/, semgrep-rules/, tmp/
- Top-level validation still depends on legacy audit artifacts outside merge mode; see `merge-report.md` for details.
