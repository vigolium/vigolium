## OpenCode-Family Override

For OpenCode-family platforms, this command runs with sequential orchestration semantics.
Use the shared balanced-audit command below as the base workflow, but apply these override rules everywhere they conflict:

1. Execute phases strictly in dependency order.
   Use: `L1 -> L2 -> L3 -> L4 -> L5 -> L6`

2. Replace every instruction that says:
   - `run_in_background: true`
   - `in a single message`
   - `parallel`
   with:
   - spawn one agent at a time
   - wait for it to finish
   - validate its output
   - then continue

3. Run lite-probe and chamber steps sequentially:
   - L3 static analysis first
   - then L4 probe team agents one at a time
   - then L5 chamber agents one at a time
   - then L6 PoC builders one finding at a time

4. Do not stop for intermediate progress summaries.
   After a phase is complete, immediately continue to the next eligible phase.
   Stop only for a real blocker: missing mandatory artifact, unrecoverable tool failure, or explicit user interruption.

5. Prefer artifact sufficiency over clean worker termination when resuming or deciding completion:
   - L1 complete if the KB has the intelligence output needed by L2.
   - L2 complete if the KB sections needed by L3/L4 exist.
   - L3 complete if SAST artifacts exist and the KB has `## Static Analysis Summary`.
   - L4 complete if `archon/probe-workspace/lite-probe/probe-summary.md` exists or an explicit no-hypothesis result was written.
   - L5 complete if chamber output exists and VALID drafts were FP-checked or the chamber closed cleanly with none.
   - L6 complete if final finding directories are assembled and `archon/final-audit-report.md` exists.

6. When the shared command describes `L3 + L4` as parallel, rewrite it as:
   - `L3 static analysis`
   - `L4 lite probe`
   in that order.
