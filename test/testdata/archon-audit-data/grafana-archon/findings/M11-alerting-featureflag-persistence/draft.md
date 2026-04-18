Phase: 8
Sequence: 027
Slug: alerting-featureflag-persistence
Verdict: VALID
Rationale: Feature flag FlagSqlExpressions not re-checked during alerting evaluation; cached pipeline continues executing SQL expressions after flag is disabled; creates persistent DoS window combined with WITH RECURSIVE bypass.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-2/debate.md

## Summary

The alerting evaluator caches the expression pipeline at creation time via `BuildPipeline()`. The `FlagSqlExpressions` feature flag is checked during pipeline construction but is NOT re-checked on each evaluation cycle. If an administrator disables the feature flag after a user creates an alerting rule with SQL expressions, the existing evaluator continues executing the SQL expression on every evaluation schedule (minimum 10 seconds, default 1 minute) indefinitely.

Combined with the WITH RECURSIVE allowlist bypass (p8-025), this creates persistent scheduled DoS that continues after the admin disables the feature flag.

## Location

- **File**: `pkg/services/ngalert/eval/eval.go`
- **Line**: 876 (`BuildPipeline` called once at evaluator creation)
- **Line**: 80 (cached pipeline reused on every evaluation)

## Attacker Control

1. Attacker creates an alerting rule with SQL expression containing recursive CTE (while flag is enabled)
2. Admin disables the feature flag
3. Attacker's rule continues executing on every evaluation cycle

## Trust Boundary Crossed

Admin feature flag control -> persistent evaluation. The admin's action to disable the feature flag should stop SQL expression execution, but it does not affect already-built evaluators.

## Impact

- Persistent CPU/memory consumption on every alerting evaluation cycle
- Bounded per-evaluation by output cell limit (100k) and timeout (10s)
- Continues until: rule is deleted, alerting scheduler is restarted, or evaluator is garbage collected
- Admin's emergency disable of the feature flag is ineffective

## Evidence

1. `eval.go:876`: `BuildPipeline()` called once during evaluator creation
2. `eval.go:80`: `ExecutePipeline(pipeline)` reuses cached pipeline
3. Feature flag checked in `buildCMDNode()` during pipeline construction but not during evaluation
4. Deep Probe PH-R3-03 (sql-expression) validated with full trace

## Reproduction Steps

1. Enable `FlagSqlExpressions` feature flag
2. Create alerting rule with SQL expression: `WITH RECURSIVE counter(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM counter WHERE n < 100000) SELECT n FROM counter`
3. Set evaluation interval to 10 seconds
4. Verify the SQL expression executes on each evaluation
5. Disable `FlagSqlExpressions` feature flag
6. Verify the SQL expression CONTINUES executing (the evaluator does not re-check the flag)
7. Only deleting the rule or restarting the alerting scheduler stops execution
