## OpenCode-Family Override

For OpenCode-family platforms, this command runs with sequential orchestration semantics.
Use the shared deep-audit command below as the base workflow, but apply these override rules everywhere they conflict:

1. Execute phases strictly in dependency order.
   Use: `T1 -> T2 -> T3 -> T4 -> T5 -> T6 -> T8 -> T9 -> T10 -> T11`
   Do not start later phases early just because background execution is available.

2. Replace every instruction that says:
   - `run_in_background: true`
   - `in a single message`
   - `spawn both`
   - `spawn ALL`
   - `parallel`
   with:
   - spawn one agent at a time
   - wait for it to finish
   - validate its output
   - then continue

3. For fan-out work, run sequential loops:
   - Phase 2: one `patch-bypass-checker` per patch, sequentially
   - Phase 8 chambers: one chamber at a time; inside each chamber, one agent turn at a time
   - Phase 9 cold verification: one finding at a time
   - Phase 10 variant analysis: one finding at a time
   - Phase 11 PoC building: one finding at a time

4. Do not stop for intermediate progress summaries.
   After a phase is complete, immediately continue to the next eligible phase.
   Stop only for a real blocker: missing mandatory artifact, unrecoverable tool failure, or explicit user interruption.

5. Prefer artifact sufficiency over clean worker termination when resuming or deciding completion:
   - Phase 1 complete if `archon/knowledge-base-report.md` contains advisory intelligence sufficient for Phase 2.
   - Phase 2 complete if each intended patch produced bypass analysis output or an explicit "no bypass found" conclusion in the KB.
   - Phase 3 complete if the required KB sections for later phases exist.
   - Phase 4 complete if the required static-analysis artifacts exist and the KB contains `## Static Analysis Summary`, `## CodeQL Structural Analysis`, and `## SAST Enrichment` (enrichment runs inline inside Phase 4).
   - Phase 5 complete if probe workspace output exists and the deep-probe summary is usable by Phase 8.
   - Phase 6 complete if the KB contains `## Spec Gap Analysis` or an explicit "None identified" result.
   - Phase 8 complete if chamber workspace output exists and medium-or-higher validated findings were written, or the chamber closed with no valid findings.
   - Phase 9 complete if all current VALID drafts were processed by FP review and cold verification when required.
   - Phase 10 complete if each confirmed finding received variant output or an explicit "no variant found" result.
   - Phase 11 complete if final finding directories are assembled and `archon/final-audit-report.md` exists.

6. When a shared instruction describes grouped parallel phases, rewrite it as:
   - `T4 static analysis`
   - `T5 deep probe`
   - `T6 spec gap`
   in that order.

7. In Solo Mode, also stay sequential.
   Ignore any solo-mode instruction that reintroduces parallelism or background fan-out.
