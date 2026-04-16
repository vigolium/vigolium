## OpenCode-Family Override

For OpenCode-family platforms, this command runs with sequential orchestration semantics.
Use the shared confirmation command below as the base workflow, but apply these override rules everywhere they conflict:

1. Execute phases strictly in dependency order.
   Use: `V1 -> V2 -> V3 -> V4 -> V5 -> V6`
   If `REMOTE_TARGET` is set, skip V2 and V3, then run `V1 -> V4 -> V6`.

2. Replace every instruction that says:
   - `TaskCreate`
   - `run_in_background: true`
   - parallel PoC execution
   with:
   - run the current phase to completion
   - spawn one agent at a time
   - wait for it to finish
   - validate output
   - then continue

3. For fan-out work, run sequential loops:
   - V4 PoC execution: one finding at a time
   - V5 test fallback: one finding at a time

4. Do not stop for intermediate progress summaries.
   After a phase is complete, immediately continue to the next eligible phase.
   Always run V6 and cleanup, even if earlier confirmation phases partially fail.

5. Prefer artifact sufficiency over clean worker termination:
   - V1 complete if `archon/confirm-workspace/findings-inventory.json` exists.
   - V2 complete if `archon/confirm-workspace/env-strategies.json` exists.
   - V3 complete if `archon/confirm-workspace/env-connection.json` exists, even when status is `failed`.
   - V4 complete if all findings with PoCs received a confirmation result or explicit execution error state.
   - V5 complete if all fallback candidates received a test result or explicit blocked/error state.
   - V6 complete if `archon/confirmation-report.md` exists.
