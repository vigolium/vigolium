# Stage 12 Variant Search Summary

Status: complete  
Surviving findings reviewed: `p10-001` through `p10-010`  
Variants retained (Medium+): 4

## Search Coverage

- Loaded the surviving P10 drafts and `piolium/attack-pattern-registry.json`.
- Reviewed Stage 03 knowledge base and P8 follow-up surfaces in `piolium/attack-surface/manual-attack-surface-inventory.md` and `piolium/attack-surface/deep-probe-summary.md` (the KB did not contain a literal `## Phase 8 Addendum` heading).
- Checked `piolium/chamber-workspace/*/variant-candidates/`; no candidate files were present.
- Reviewed `piolium/codeql-artifacts/entry-points.json`, `sinks.json`, flow summaries, and call-graph slices.
- Ran registry-driven grep, Semgrep, and a P12 structural CodeQL query:
  - `piolium/tmp/p12-registry-grep.txt`
  - `piolium/tmp/p12-semgrep-registry.json`
  - `piolium/codeql-queries/variant-p12-structures.ql`
  - `piolium/tmp/p12-codeql-variant-structures.json`
- Ran local proof snippets for retained runtime variants:
  - `piolium/tmp/p12-variant-proofs-output.txt`

## Confirmed Variants

| ID | Origin | Pattern | Severity | Summary |
|---|---|---|---|---|
| `p12-001-cleartext-http-git-sources` | `p10-003` | `AP-004` | MEDIUM | Custom GitLab/direct `.git` sources preserve `http://` and are cloned over cleartext, allowing MITM skill substitution. |
| `p12-002-unbounded-git-local-frontmatter-parse` | `p10-004` | `AP-005` | MEDIUM | Git/local/node_modules `SKILL.md` files reach the same unbounded YAML frontmatter parser used by well-known installs. |
| `p12-003-project-scope-remove-symlinked-agent-base-escape` | `p10-009` | `AP-003` | MEDIUM | Project-scoped remove follows symlinked agent bases and can delete skills outside the project. |
| `p12-004-node-modules-sync-duplicate-name-overwrite` | `p10-005` | `AP-006` | MEDIUM | `experimental_sync` accepts duplicate dependency-controlled skill names, then overwrites one install/lock entry by name. |

## Reviewed But Not Retained

- `AP-001` command boundary variants: `spawnSync()` update paths and `execSync('gh auth token')` were reviewed from P8 notes and sinks. They are command-adjacent, but their root causes differ from the confirmed simple-git URL/ref injection pattern and were not retained as structural variants in this pass.
- `AP-002` symlink-dereference copy variants: only one `cp(..., dereference: true)` sink exists. Additional symlinked discovery paths were reviewed but did not exceed the original copy/leak finding's scope.
- `AP-005` blob/search/telemetry fetches: matches exist, but most use fixed first-party services or have timeouts; without arbitrary attacker-controlled hosts comparable to well-known or git/package content, they were not retained as Medium+ variants.
- `AP-007`, `AP-008`, `AP-009`, and `AP-010`: registry/grep/CodeQL searches did not identify distinct new Medium+ instances beyond the surviving P10 drafts and the retained node_modules duplicate-name variant.

## Registry Updates

`piolium/attack-pattern-registry.json` was updated with the four new P12 drafts in the corresponding `confirmed_instances` arrays.
