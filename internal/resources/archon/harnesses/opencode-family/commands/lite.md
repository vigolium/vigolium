## OpenCode-Family Override

For OpenCode-family platforms, this command runs with sequential orchestration semantics.
Use the shared lite-audit command below as the base workflow, but apply these override rules everywhere they conflict:

1. Execute phases strictly in dependency order.
   Use: `Q0 -> Q1 -> Q2 -> Output`

2. Replace every instruction that says:
   - `parallel`
   - `run_in_background: true`
   with:
   - run the current phase to completion
   - validate its output
   - then continue

3. Specifically for lite mode:
   - run Q0 first
   - run Q1 secrets scan next
   - run Q2 fast SAST after Q1
   - run PoC builders one finding at a time

4. Do not stop for intermediate progress summaries.
   After a phase is complete, immediately continue to the next eligible phase.
   Stop only for a real blocker: missing mandatory artifact, unrecoverable tool failure, or explicit user interruption.

5. Prefer artifact sufficiency over clean tool termination:
   - Q0 complete if `archon/lite-recon.md` exists and contains recon output.
   - Q1 complete if its findings were written or an explicit "no secrets found" result was recorded.
   - Q2 complete if its findings were written or an explicit "no security findings found" result was recorded.
   - Output complete if final finding directories are assembled.
