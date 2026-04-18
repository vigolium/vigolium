# Merge Normalization Report

**Generated:** 2026-04-17T16:10:25Z
**Source dirs:**
- `/tmp/merge-ollama/ollama-archon`
- `/tmp/merge-ollama/ollama-with-opus-4.7`

## Validation (Pass M1)
- Findings inspected: 68
- Standard-conformant on entry: 0
- Issues detected (by code): `missing-frontmatter-field=57`, `missing-report-md=68`, `poc-malformed-json-trailer=9`, `severity-mismatch=11`, `severity-original-vs-final-divergent=11`, `missing-evidence-critical-high=21`

## Semantic Dedup (Pass M2)
| Canonical | Absorbed | Reason |
| --- | --- | --- |
| C3-agent-approval-shell-metachar-bypass | H22-yolo-mode-denylist-quoting-bypass | same root_cause x/agent/approval.go:94 command-injection |
| H21-agent-approval-command-substitution-path | M23-approval-cache-flag-blindness-sed-i | same root_cause x/agent/approval.go:215 command-injection |
- Re-slugged: none
- Skipped (no extractable root cause): M24-dns-rebinding-drive-by-identity-chain

## Auto-Fixes (Pass M3)
- Frontmatter patched: 63
- `report.md` synthesized from draft material: 66
- PoC JSON trailer helpers appended: 9
- Safe renames deferred to global renumbering: 43

## Quarantine (Pass M4)
| ID | Slug | Reason |
| --- | --- | --- |
| H12 | blank-mime-mtmd-null-deref | missing-evidence-critical-high |
| H13 | num-ctx-uncapped-runner-oom | missing-evidence-critical-high |
| H14 | quantize-unsafe-slice-elements-oob | missing-evidence-critical-high |
| H15 | gpu-backend-shape-overflow-disclosure | missing-evidence-critical-high |
| H24 | windows-backslash-digest-traversal | missing-evidence-critical-high |
| H25 | fsgguf-numvalues-int64-signed-overflow | missing-evidence-critical-high |
| H26 | ggml-backend-elements-loop-integer-wrap-dos | missing-evidence-critical-high |
| H27 | safetensors-extractor-headersize-oom | missing-evidence-critical-high |
| H28 | fsgguf-readstring-uint64-slice-panic | missing-evidence-critical-high |
| H29 | fsgguf-lazy-count-uncapped-iter | missing-evidence-critical-high |
| H3 | pushwithtransfer-traversal-read | missing-evidence-critical-high |
| H30 | fsgguf-readarraydata-uncapped-make | missing-evidence-critical-high |
| H31 | fsgguf-tensor-dims-uncapped-shape-alloc | missing-evidence-critical-high |
| H32 | extractor-openforextraction-uint64-oom | missing-evidence-critical-high |
| H33 | imagegen-safetensors-uint64-oom | missing-evidence-critical-high |
| H34 | xcreate-quantize-readheader-uint64-oom | missing-evidence-critical-high |
| H35 | audio-transcription-null-deref-mtmd | missing-evidence-critical-high |
| H36 | autoallow-single-word-cmd-subst | missing-evidence-critical-high |
| H37 | web-search-fetch-tool-session-cache-no-arg-discrimination | missing-evidence-critical-high |
| H6 | gguf-numtensor-uncapped | missing-evidence-critical-high |
| H7 | safetensors-header-int64-oom | missing-evidence-critical-high |
- Total quarantined: 21

## Renumber (Pass M5)
- Rename operations applied: 43
- The authoritative rename map is embedded under `audit-state.json -> merge_metadata.rename_map`.
- Reference rewrites touched: {'.md': 48, '.json': 2}

## Summary Regeneration (Pass M6)
- `final-audit-report.md`: regenerated from the normalized `archon/findings/` tree
- `README.md`: regenerated from the corrected metadata and post-cleanup tree
- `knowledge-base-report.md`: appended merge addendum plus placeholder consistency sections required by the merged bundle

## Validator Follow-up
- `python3 ~/.config/archon-audit/skills/audit/hooks/scripts/validate_phase_output.py all archon/` still fails after normalization. The remaining failures are dominated by intentionally retained `findings-draft/` VALID entries that were not promoted, plus legacy top-level provenance artifacts (`advisory-*`, `*_report.md`, `probe-workspace/`, `bypass-analysis/`, etc.). Merge mode normalized the promoted tree; it did not attempt to rewrite the full legacy phase-output inventory.

## Manual-Review Items
- Review the 21 quarantined high-severity findings if you want broader promotion despite missing evidence artifacts.
- The merged report assembler eventually completed, but the close-out used the merge-mode fallback to repair variant-origin references and rewrite README/KB notes from the corrected metadata.
- 36 promoted findings still have no PoC script on disk; that is a source-audit limitation, not a merge-mode fabrication.
- Legacy support artifacts remain under `archon/` because they are still useful provenance or are referenced by drafts/reports.

## Final Counts
- Findings (post-merge): CRITICAL=3, HIGH=7, MEDIUM=35, LOW=0
- Quarantined: 21
- Final promoted finding directories: 45
