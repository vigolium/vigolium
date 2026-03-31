Phase: 10
Sequence: 049
Slug: sql-expression-alerting-persistent-rule-file-write
Verdict: VALID
Rationale: An Editor-role user can persist an alert rule containing a SQL expression with INTO OUTFILE UNION syntax; the Grafana alerting scheduler then evaluates the rule on every interval, causing repeated file writes from a server-side background process with no HTTP request context, creating a persistent foothold.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-040-sql-expression-into-outfile-file-write.md
Origin-Pattern: AP-040

## Summary

Unlike p8-040 (which requires an active HTTP request from a Viewer) and p8-046 (which uses the eval endpoint for one-shot execution), this variant leverages the alerting rule scheduler to create a **persistent, repeated** file write. An Editor-role user with `ActionAlertingRuleCreate` permission can create an alert rule whose query contains a SQL expression with the UNION-based INTO OUTFILE bypass. The Grafana alerting scheduler (`pkg/services/ngalert/schedule/`) evaluates all active alert rules at their configured interval (default: 1 minute) using an internal service user context, not the original HTTP request user. Each evaluation cycle triggers `DB.QueryFrames` with the malicious SQL, causing repeated file writes.

Key distinction from p8-040/p8-046: the attack persists after the initial HTTP request. The file write occurs **on every evaluation interval** from the scheduler's goroutine, and continues until the rule is manually deleted. The scheduler runs as the Grafana process (not as the original user), and there is no rate limiting on rule evaluation frequency.

Additionally, `POST /api/v1/rule/test/grafana` (which previews a rule before saving) also accepts SQL expressions and requires only `ActionAlertingRuleRead` (Viewer role) -- providing a Viewer-accessible test-preview path identical in execution to p8-046.

## Location

- **Primary attack surface**: `POST /api/ruler/grafana/api/v1/rules/:folderUID` -- alert rule creation (Editor role required, `ActionAlertingRuleCreate`)
- **Authorization**: `authorization.go:64-66` -- `ActionAlertingRuleCreate` (granted to Editor via `rulesWriterRole`)
- **Persistence**: Stored in Grafana database (`alert_rule` table), evaluated by scheduler at `pkg/services/ngalert/schedule/schedule.go`
- **Scheduler execution**: `schedule.go` -> `conditionEvaluator.Evaluate` -> `expressionService.ExecutePipeline` -> `SQLCommand.Execute` -> `DB.QueryFrames`
- **Secondary surface (Viewer-accessible)**: `POST /api/v1/rule/test/grafana` -- requires only `ActionAlertingRuleRead` (Viewer role), executes SQL expression immediately in preview mode
- **Same SQL engine**: `pkg/expr/sql/db.go:71` -- identical missing `WithDisableFileWrites(true)`

## Attacker Control

**Persistent route (Editor)**:
- **Input**: Alert rule `Data` array in POST /api/ruler/grafana/api/v1/rules/:folderUID body
- **Evaluation frequency**: Controlled by attacker via `interval` field in the rule group (minimum: 10 seconds by default)
- **Content**: Full control over file path and content via SQL expression
- **No request needed after creation**: Scheduler evaluates autonomously

**Preview route (Viewer)**:
- **Input**: `PostableExtendedRuleNodeExtended` body to POST /api/v1/rule/test/grafana
- **Requires**: `ActionAlertingRuleRead` (Viewer) + folder read access
- **Execution**: Immediate, single evaluation via `RouteTestGrafanaRuleConfig` -> `evaluator.Evaluate`
- **Authorization**: `authorization.go:81-84` -- only `ActionAlertingRuleRead` required

## Trust Boundary Crossed

**Editor route**: Editor creates and persists a malicious rule; the Grafana scheduler process executes the file write repeatedly as the service user -- an Editor-user-initiated background process escalates to repeated OS file system writes.

**Viewer route**: Viewer-role user triggers immediate SQL expression execution via alert rule preview endpoint, bypassing the `POST /api/ds/query` path entirely.

## Impact

- **Persistent RCE vector**: A file written on every evaluation interval (e.g., 10 seconds) can reliably establish a persistent backdoor even if the original file is deleted
- **Scheduler context**: The scheduler runs with the Grafana service account's full filesystem permissions; there is no HTTP session timeout or user logout that stops the writes
- **Overwrite scenario**: If the target path contains a periodically deleted/regenerated file (e.g., a config file that gets regenerated), the rule will reliably re-inject the malicious content
- **Low observable surface**: Rule evaluation errors are logged but not sent to users; the INTO OUTFILE may silently succeed or fail on each interval, making detection harder
- **Viewer preview path**: Viewer role can also trigger file writes via the preview endpoint (`/api/v1/rule/test/grafana`), reducing the required privilege level to match p8-046

## Evidence

1. `authorization.go:81-84`: `case http.MethodPost + "/api/v1/rule/test/grafana": eval = ac.EvalPermission(ac.ActionAlertingRuleRead)` -- Viewer role sufficient for preview execution
2. `roles.go:41`: `Grants: []string{string(org.RoleViewer)}` for `rulesReaderRole` (includes `ActionAlertingRuleRead`)
3. `roles.go:77`: `Grants: []string{string(org.RoleEditor)}` for `rulesWriterRole` (includes `ActionAlertingRuleCreate`) -- Editor can persist rules
4. `api_testing.go:88`: `srv.evaluator.Create(eval.NewContext(...), rule.GetEvalCondition().WithSource("preview"))` -- same evaluator as p8-046
5. `eval.go:868`: `getExprRequest(ctx, condition, ...)` -> `expressionService.BuildPipeline` -> identical SQL execution
6. `nodes.go:126-131`: `FlagSqlExpressions` check applies uniformly -- flag must be enabled
7. `sql/db.go:71`: Same `mysql.NewContext()` without `WithDisableFileWrites(true)`
8. Schedule evaluation in `pkg/services/ngalert/schedule/` calls `EvaluateRaw` on each tick for every active rule

## Reproduction Steps

**Viewer-accessible preview path:**
1. Enable `sqlExpressions` feature flag
2. As a Viewer-role user with folder read access, send:
   ```
   POST /api/v1/rule/test/grafana HTTP/1.1
   Content-Type: application/json

   {
     "namespaceUID": "<any-readable-folder-uid>",
     "ruleGroup": "test-group",
     "rule": {
       "title": "test",
       "condition": "B",
       "data": [
         {
           "refId": "A",
           "datasourceUid": "testdata-uid",
           "model": {"scenarioId": "csv_content", "csvContent": "col\n1"}
         },
         {
           "refId": "B",
           "datasourceUid": "__expr__",
           "model": {
             "type": "sql",
             "expression": "SELECT col FROM A UNION SELECT col FROM A INTO OUTFILE '/tmp/grafana-alert-preview.txt'",
             "format": "alerting"
           }
         }
       ],
       "intervalSeconds": 60,
       "noDataState": "NoData",
       "execErrState": "Alerting"
     }
   }
   ```
3. Verify: `cat /tmp/grafana-alert-preview.txt` contains `1`

**Persistent Editor path:**
1. As Editor, create alert rule via `POST /api/ruler/grafana/api/v1/rules/:folderUID` with same SQL expression in rule data
2. Rule persists and is evaluated on each scheduler interval, repeatedly writing the file
