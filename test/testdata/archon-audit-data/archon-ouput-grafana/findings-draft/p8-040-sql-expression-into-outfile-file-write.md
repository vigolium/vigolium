Phase: 8
Sequence: 040
Slug: sql-expression-into-outfile-file-write
Verdict: VALID
Rationale: Complete 4-control failure chain enabling arbitrary file write as Grafana process user when sqlExpressions flag is enabled; all 4 library-level controls (allowlist, IsReadOnly, DisableFileWrites, secure_file_priv) are bypassed or misconfigured; Viewer-role user achieves RCE with no additional controls once the feature flag is toggled.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-3/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: UNION syntax SELECT...UNION SELECT...INTO OUTFILE bypasses the SQL allowlist, and the go-mysql-server engine writes files despite IsReadOnly:true because Into.IsReadOnly() delegates to child SELECT; end-to-end file write confirmed through Grafana's QueryFrames with attacker-controlled content.
Severity-Final: HIGH
PoC-Status: executed

## Summary

The SQL Expression Engine in Grafana allows authenticated users to execute SQL queries against in-memory data frames via POST /api/ds/query when the `sqlExpressions` feature flag is enabled. The SQL allowlist at `parser_allow.go:113` permits `*sqlparser.Into` AST nodes unconditionally, which covers both `INTO OUTFILE` and `INTO DUMPFILE` variants. Combined with three additional control failures -- (1) `IsReadOnly:true` bypassed via `Into.IsReadOnly()` delegation to child SELECT, (2) `WithDisableFileWrites(true)` never called despite being designed for this use case, (3) `secure_file_priv` defaulting to empty string -- an authenticated Viewer-role user can write arbitrary content to any filesystem path writable by the Grafana process user. This enables RCE via cron job injection, SSH authorized_keys overwrite, or Grafana configuration modification.

**Adversarial Review Correction**: Direct `SELECT ... INTO OUTFILE` syntax is actually blocked by the allowlist because `sqlparser.Variables` (a child field of `*sqlparser.Into`) is not in the allowed list. However, UNION syntax (`SELECT ... FROM A UNION SELECT ... FROM A INTO OUTFILE '/path'`) bypasses this block, and the full exploitation chain was confirmed end-to-end through Grafana's `QueryFrames` method.

## Location

- **Primary**: `pkg/expr/sql/parser_allow.go:113` -- `case *sqlparser.Into: return` (allowlist bypass via UNION syntax)
- **Secondary**: `pkg/expr/sql/db.go:71` -- `mysql.NewContext()` missing `WithDisableFileWrites(true)`
- **Secondary**: `pkg/expr/sql/db.go:82-84` -- `IsReadOnly: true` ineffective (delegation bug in go-mysql-server)
- **Secondary**: `pkg/expr/sql/db.go:76-77` -- commented-out `secure_file_priv` (would set to "" anyway)
- **Entry point**: `pkg/api/api.go:521` -- `POST /api/ds/query` with `datasources:query` permission (Viewer role)
- **Feature gate**: `pkg/expr/nodes.go:128` -- `toggles.IsEnabledGlobally(FlagSqlExpressions)`

## Attacker Control

- **Input**: SQL expression string in POST /api/ds/query request body (field: `expression` within the query model)
- **Control scope**: Full control over both the file path (INTO OUTFILE '/path/to/file') and file content (SELECT result)
- **Content control**: Allowlist permits CONCAT, CHAR, FROM_BASE64 (parser_allow.go:228,244,248) -- attacker can construct arbitrary binary or text content
- **Minimum privilege**: Viewer role (has `datasources:query` permission by default)
- **Required syntax**: UNION-based query to bypass allowlist: `SELECT col FROM A UNION SELECT col FROM A INTO OUTFILE '/path'`

## Trust Boundary Crossed

User SQL expression execution context (in-memory data frame query) -> OS filesystem write capability. The go-mysql-server engine runs in-process sharing the Grafana OS process context and filesystem permissions. A Viewer-role user crosses from data query privilege to OS-level file write as the Grafana service user.

## Impact

- **Arbitrary file write**: Any path writable by the Grafana process user (new files only; cannot overwrite existing)
- **RCE via cron**: Write cron job file to `/etc/cron.d/` (if writable)
- **RCE via SSH**: Write to `.ssh/authorized_keys` (if Grafana has write access)
- **Auth disable**: Write new config file to config directory
- **Binary write**: `INTO DUMPFILE` writes raw binary data (e.g., shared libraries for LD_PRELOAD injection)
- **Scope**: Global when flag enabled -- single admin toggle exposes all Viewer+ users across all orgs

## Evidence

1. `parser_allow.go:113`: `case *sqlparser.Into: return` -- allows INTO node unconditionally
2. `db.go:71`: `mysql.NewContext(ctx, mysql.WithSession(session))` -- no `WithDisableFileWrites(true)`
3. `db.go:82-84`: `IsReadOnly: true` -- bypassed by `Into.IsReadOnly()` delegation to child SELECT
4. `db.go:76-77`: `//ctx.SetSessionVariable(ctx, "secure_file_priv", "")` -- commented out, default is "" anyway
5. go-mysql-server `rel.go:578`: `os.OpenFile` creates file at attacker-specified path
6. go-mysql-server `rel.go:599-601`: `ctx.DisableFileWrites()` returns false (never set to true)
7. go-mysql-server `rel.go:546-548`: `secureFileDir == ""` -> no path restriction
8. `api.go:521`: `authorize(ac.EvalPermission(datasources.ActionQuery))` -- Viewer has this permission
9. `nodes.go:128`: `toggles.IsEnabledGlobally(FlagSqlExpressions)` -- global boolean flag
10. **Adversarial test**: UNION syntax bypasses allowlist; file write confirmed through `QueryFrames`

## Reproduction Steps

1. Enable the `sqlExpressions` feature flag in grafana.ini: `[feature_toggles] enable = sqlExpressions`
2. Restart Grafana
3. Create or identify any datasource (even TestData)
4. As a Viewer-role user, send:
   ```
   POST /api/ds/query HTTP/1.1
   Content-Type: application/json
   Cookie: grafana_session=<viewer_session>

   {
     "queries": [
       {
         "refId": "A",
         "datasource": {"type": "testdata", "uid": "<uid>"},
         "scenarioId": "csv_content",
         "csvContent": "col\n1"
       },
       {
         "refId": "B",
         "datasource": {"type": "__expr__", "uid": "__expr__"},
         "type": "sql",
         "expression": "SELECT col FROM A UNION SELECT col FROM A INTO OUTFILE '/tmp/grafana-poc-outfile.txt'"
       }
     ],
     "from": "now-1h",
     "to": "now"
   }
   ```
5. Verify file creation: `cat /tmp/grafana-poc-outfile.txt` should contain "1"
6. For RCE escalation: replace path with `/etc/cron.d/backdoor` and adjust SELECT content

Note: The feature flag `sqlExpressions` is disabled by default. When enabled, no additional configuration is needed to exploit this vulnerability. Direct `SELECT ... INTO OUTFILE` syntax is blocked; the UNION syntax is required to bypass the allowlist.
