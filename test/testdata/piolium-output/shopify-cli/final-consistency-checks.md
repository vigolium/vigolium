# Final Report Consistency Checks

- **PASS** — Finding report.md >500 bytes: 12 finding reports verified
- **PASS** — Finding ID cross-reference: 12 IDs cross-reference finding directories
- **PASS** — KB section completeness: 16 expected KB sections present and non-empty
- **PASS** — Finding completeness: 12 finding directories have draft/report/PoC
- **PASS** — No Low severity leakage: no L-prefixed or LOW findings in piolium/findings
- **PASS** — No stale separate reports: no top-level stale report-like markdown files detected
- **PASS** — CodeQL/SAST artifact completeness: 13 required CodeQL/SAST artifacts present
- **PASS** — Important artifact reference coverage: key audit artifact directories/files referenced by final report or KB
- **FAIL** — Archon validate_phase_output.py all: see piolium/final-validation.log (script reported failures)

Overall consistency: FAIL

## Failures
- Archon validate_phase_output.py all: see piolium/final-validation.log (script reported failures)
