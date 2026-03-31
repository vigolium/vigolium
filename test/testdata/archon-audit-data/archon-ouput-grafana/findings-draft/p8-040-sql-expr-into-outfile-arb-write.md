---
id: p8-040
title: SQL Expression Engine SELECT INTO OUTFILE Enables Arbitrary File Write
severity: CRITICAL
status: VALID
verdict: VALID
cluster: Data Isolation & Rendering
---

Phase: 8
Sequence: 040
Slug: sql-expr-into-outfile-arb-write
Verdict: VALID
Rationale: When the sqlExpressions feature toggle is enabled, an Editor-role user can write arbitrary files to the server filesystem via SELECT INTO OUTFILE, bypassing all 4 layers of defense (parser allowlist includes INTO, Into.IsReadOnly() delegates to child, WithDisableFileWrites not called, secure_file_priv defaults to empty). No blocking protections were found by the Advocate after exhaustive 5-layer search.
Severity-Original: CRITICAL
PoC-Status: pending
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

The SQL Expression Engine (feature flag `sqlExpressions`, PublicPreview stage) allows authenticated users with Editor or Admin role to execute SQL queries against data source results. The engine uses an embedded go-mysql-server instance with an allowlist-based parser filter. However, 4 independent control failures create a complete attack chain that allows an attacker to write arbitrary files to the Grafana server's filesystem via `SELECT ... INTO OUTFILE '/path/to/file'`.

This is a variant of CVE-2024-9264 and represents a critical arbitrary file write vulnerability that can be chained into Remote Code Execution via cron jobs, SSH key injection, web shells, or overwriting Grafana configuration files.

## Affected Code

### Control Failure 1: Parser Allowlist Includes INTO
- **File**: `pkg/expr/sql/parser_allow.go:113-114`
- **Code**: `case *sqlparser.Into: return` -- the `*sqlparser.Into` AST node is explicitly on the allowlist, permitting `SELECT ... INTO OUTFILE` queries to pass parser validation.

### Control Failure 2: WithDisableFileWrites Not Called
- **File**: `pkg/expr/sql/db.go:67-84`
- **Code**: The SQL context is created via `mysql.NewContext(ctx, mysql.WithSession(session), mysql.WithTracer(tracer))` but `mysql.WithDisableFileWrites(true)` is NOT included as an option. The go-mysql-server library provides this option specifically to prevent file writes in embedded/sandboxed use cases.
- **Note**: A commented-out line at `db.go:76-77` (`//ctx.SetSessionVariable(ctx, "secure_file_priv", "")`) shows developer awareness of the risk but no fix was implemented.

### Control Failure 3: Into.IsReadOnly() Delegates to Child
- **File**: `go-mysql-server@v0.20.2-grafana/sql/plan/into.go:82-84`
- **Code**: `func (i *Into) IsReadOnly() bool { return i.Child.IsReadOnly() }` -- The `Into` plan node's `IsReadOnly()` delegates to its child node. Since the child is a SELECT (which is read-only), the engine's `readOnlyCheck` at `engine.go:787` passes, even though the `Into` node performs file I/O.

### Control Failure 4: secure_file_priv Defaults to Empty String
- **File**: `go-mysql-server@v0.20.2-grafana/sql/variables/system_variables.go:2227`
- **Code**: `Default: ""` -- The `secure_file_priv` system variable defaults to an empty string. In `sql/rowexec/rel.go:547`, empty string means no path restriction: `if secureFileDir == nil || secureFileDir == "" { return nil }`.

### Execution Sink
- **File**: `go-mysql-server@v0.20.2-grafana/sql/rowexec/rel.go:610-651`
- **Code**: `createIfNotExists(n.Outfile)` creates the file, then query results are written to it with no path validation.

## Attack Path

1. Attacker authenticates to Grafana with Editor role
2. Attacker creates or edits a dashboard panel using a SQL expression
3. Attacker crafts a SQL query: `SELECT 'malicious content' AS payload FROM datasource_result INTO OUTFILE '/var/spool/cron/crontabs/grafana'`
4. The query passes the parser allowlist (`*sqlparser.Into` is allowed)
5. The engine's `IsReadOnly` check passes (INTO delegates to child SELECT)
6. `DisableFileWrites()` returns false (never set)
7. `isUnderSecureFileDir` returns nil (empty default)
8. The file is created and written with the query results
9. Attacker achieves RCE via the written file (cron job, SSH key, etc.)

## Evidence

### Parser Allowlist (pkg/expr/sql/parser_allow.go:113)
```go
case *sqlparser.Into:
    return  // b is true (allowed)
```

### Engine Context Missing DisableFileWrites (pkg/expr/sql/db.go:67-84)
```go
mCtx := mysql.NewContext(ctx, mysql.WithSession(session), mysql.WithTracer(tracer))
// WithDisableFileWrites(true) is NOT passed
```

### Into.IsReadOnly Delegation (go-mysql-server sql/plan/into.go:82-84)
```go
func (i *Into) IsReadOnly() bool {
    return i.Child.IsReadOnly()  // SELECT is read-only -> returns true
}
```

### secure_file_priv Default (go-mysql-server sql/variables/system_variables.go:2227)
```go
Default: "",  // empty = no restriction
```

### File Write Execution (go-mysql-server sql/rowexec/rel.go:598-618)
```go
if ctx.DisableFileWrites() {  // false - never set
    return nil, sql.ErrFileWritesDisabled.New()
}
// ... proceeds to write
file, fileErr := createIfNotExists(n.Outfile)
```

## Reproduction Steps

1. Enable the `sqlExpressions` feature toggle in Grafana configuration
2. Log in as a user with Editor role
3. Create a new dashboard panel
4. Add a SQL expression that references a data source query result
5. Set the SQL expression to: `SELECT 'test' AS col FROM A INTO OUTFILE '/tmp/grafana-exploit-test'`
6. Execute the panel query (save and view the dashboard)
7. Verify that `/tmp/grafana-exploit-test` was created on the server with the query results

**Defense context from Advocate**: No blocking protections were found. The feature toggle is the sole gate, and it is commonly enabled in Grafana Cloud and self-hosted instances using preview features. The commented-out code at `db.go:76-77` confirms developer awareness of the risk.

## Severity Justification

- **CRITICAL** severity based on:
  - Remotely triggerable from any Editor-role user (standard authenticated position)
  - Arbitrary file write on the server filesystem
  - Direct path to RCE via cron/SSH/web shell
  - No significant preconditions beyond a commonly-enabled feature flag
  - 4 independent control failures, any ONE of which should have blocked the attack
  - Upgraded from HIGH to CRITICAL due to RCE potential and low preconditions
