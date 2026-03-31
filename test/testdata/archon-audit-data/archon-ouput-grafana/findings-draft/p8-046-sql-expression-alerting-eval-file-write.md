Phase: 10
Sequence: 046
Slug: sql-expression-alerting-eval-file-write
Verdict: VALID
Rationale: POST /api/v1/eval accepts SQL expressions with type:sql and requires only ActionAlertingRuleRead (Viewer role), routes through the same expr.Service.BuildPipeline -> DB.QueryFrames path as the confirmed p8-040 finding, enabling file write from the alerting evaluation endpoint.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-040-sql-expression-into-outfile-file-write.md
Origin-Pattern: AP-040

## Summary

The alerting rule evaluation endpoint `POST /api/v1/eval` accepts a full alert query payload including SQL expressions (type `sql` with `format: alerting`). The endpoint requires only `ActionAlertingRuleRead` permission, which is granted to Viewer role. When a SQL expression with `INTO OUTFILE` UNION syntax is submitted, it routes through the identical execution chain: `TestingApiSrv.RouteEvalQueries` -> `srv.evaluator.Create(eval.NewContext(...))` -> `getExprRequest` -> `expressionService.BuildPipeline` -> `SQLCommand.Execute` -> `DB.QueryFrames` -> go-mysql-server engine. The same 4-control failure from p8-040 applies, producing an arbitrary file write.

This endpoint is an independent attack surface from `POST /api/ds/query`. A Viewer-role user can exploit this endpoint to write files, with the attack surface being the alerting testing/preview API rather than the datasource query API.

## Location

- **Primary**: `pkg/services/ngalert/api/api_testing.go:166` -- `RouteEvalQueries` executes submitted queries via `evaluator.EvaluateRaw`
- **Route**: `POST /api/v1/eval` (under ngalert router, registered at `generated_base_api_testing.go:79`)
- **Authorization**: `authorization.go:94` -- `ac.EvalPermission(ac.ActionAlertingRuleRead)` (Viewer-level permission)
- **Execution chain**: `api_testing.go:190` -> `evaluator.Create` -> `eval.go:868` -> `getExprRequest` -> `expressionService.BuildPipeline` -> `sql_command.go:205` -> `sql/db.go:98` -> go-mysql-server engine
- **Same SQL engine context**: `pkg/expr/sql/db.go:71` -- identical context creation without `WithDisableFileWrites`
- **Feature gate**: `pkg/expr/nodes.go:128` -- `toggles.IsEnabledGlobally(FlagSqlExpressions)` applies to BuildPipeline

## Attacker Control

- **Input**: `EvalQueriesPayload.Data` array, each element an `AlertQuery` with `Model` containing `type: sql, expression: <sql>`
- **UNION bypass**: Same UNION syntax as p8-040 is required: `SELECT col FROM A UNION SELECT col FROM A INTO OUTFILE '/path'`
- **Minimum privilege**: Viewer role (`ActionAlertingRuleRead` -- granted to Viewer in `roles.go:41`)
- **Additional RBAC**: `api_testing.go:168` calls `srv.authz.AuthorizeDatasourceAccessForRule` -- this checks datasource query access, which Viewer has for any datasource they can query

## Trust Boundary Crossed

Viewer-role user alerting rule evaluation context -> OS filesystem write capability. The SQL expression evaluation runs in-process. A Viewer crosses from alerting rule read privilege to OS-level file write.

## Impact

Identical to p8-040: arbitrary file write as Grafana process user. Additional concern specific to this variant:
- **No datasource required**: `POST /api/v1/eval` can accept expression-only queries (SQL expression against empty frames), potentially requiring no datasource access at all if the UNION query self-supplies data via literal SELECTs
- **Simpler request format**: The eval endpoint accepts queries without requiring a real datasource UID for the data frame side -- an attacker can use `SELECT '1' FROM dual UNION SELECT '1' FROM dual INTO OUTFILE '/path'` with no table reference, making exploitation simpler

## Evidence

1. `authorization.go:94`: `case http.MethodPost + "/api/v1/eval": eval = ac.EvalPermission(ac.ActionAlertingRuleRead)` -- Viewer role has this permission
2. `roles.go:41`: `Grants: []string{string(org.RoleViewer)}` for `rulesReaderRole` which includes `ActionAlertingRuleRead`
3. `api_testing.go:190`: `srv.evaluator.Create(eval.NewContext(...), cond)` -- identical evaluator path
4. `eval.go:868`: `req, err := getExprRequest(ctx, condition, ...)` -> `expressionService.BuildPipeline`
5. `nodes.go:126-131`: `FlagSqlExpressions` check occurs in `BuildPipeline` -> `buildCMDNode` for TypeSQL
6. `sql_command.go:205`: `db.QueryFrames(ctx, tracer, gr.refID, gr.query, allFrames, ...)` -- same DB path
7. `sql/db.go:71`: `mysql.NewContext(ctx, mysql.WithSession(session))` -- missing `WithDisableFileWrites(true)`
8. go-mysql-server `rel.go:599-601`: file write proceeds when `DisableFileWrites()` is false

## Reproduction Steps

1. Enable `sqlExpressions` feature flag
2. As a Viewer-role user (with AlertingRuleRead permission), send:
   ```
   POST /api/v1/eval HTTP/1.1
   Content-Type: application/json

   {
     "data": [
       {
         "refId": "A",
         "datasourceUid": "__expr__",
         "model": {
           "type": "sql",
           "expression": "SELECT '1' FROM dual UNION SELECT '1' FROM dual INTO OUTFILE '/tmp/grafana-eval-poc.txt'",
           "datasource": {"uid": "__expr__", "type": "__expr__"}
         },
         "relativeTimeRange": {"from": 600, "to": 0}
       }
     ],
     "condition": "A"
   }
   ```
3. Verify file creation: `cat /tmp/grafana-eval-poc.txt` should contain `1`
