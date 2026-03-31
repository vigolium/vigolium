# PATCH-T3-01: CVE-2024-9264 — SQL Expressions RCE Bypass Analysis

**Advisory:** CVE-2024-9264 (CRITICAL 9.4)
**Component:** `pkg/expr/` — SQL Expressions (originally duckdb-based)
**Patch PRs:** #94942 (main), #94955, #94959
**Cluster ID:** sql-expressions-rce

---

## Patch Summary

The original CVE-2024-9264 fix completely removed the duckdb dependency and disabled the SQL Expressions feature. The duckdb-based SQL Expressions allowed attackers with Viewer permissions or higher to execute arbitrary OS commands via the duckdb `read_csv_auto('/etc/passwd')` or `INSTALL httpfs; LOAD httpfs;` attack vectors.

The duckdb dependency has been fully removed from `go.mod`.

## Critical Finding: SQL Expressions Re-Introduced with New Engine

SQL Expressions has been **re-implemented** using `go-mysql-server` (dolthub GMS), an in-process pure-Go SQL engine, replacing the removed duckdb backend. The feature is present in `pkg/expr/sql/` with full implementation.

### Current Security Controls

1. **Feature flag gate** (`FlagSqlExpressions`): Set to `Expression: "false"` (disabled by default) at `FeatureStagePublicPreview`. Can be enabled by administrators via `custom.ini` or environment variables.

2. **AST allowlist** (`parser_allow.go`): A comprehensive allowlist of permitted SQL node types and functions. Blocks unknown functions like `load_file()`. The allowlist uses a deny-by-default approach at the AST node and function levels.

3. **Engine read-only mode**: `sqle.Config{IsReadOnly: true}` is set when creating the engine.

4. **Input/output cell limits and query timeouts**: Configurable resource limits.

### RCE Vector: Eliminated

The original RCE vector (duckdb shell-out and extension loading) is **fully eliminated**. The `go-mysql-server` engine is an in-process Go library with no OS command execution capability. There are no `exec.Command` or `os/exec` imports in `pkg/expr/`.

### Remaining Weakness: SELECT INTO OUTFILE / INTO DUMPFILE (Arbitrary File Write)

**Severity: Medium (requires feature flag enabled + authenticated user)**

The `*sqlparser.Into` AST node is on the allowlist (`parser_allow.go` line 113), and the vitess SQL parser fully supports `SELECT ... INTO OUTFILE '/path'` and `SELECT ... INTO DUMPFILE '/path'` syntax.

Defense layers that FAIL to block this:

- **AST allowlist**: `*sqlparser.Into` is explicitly allowed
- **Engine IsReadOnly**: `plan.Into.IsReadOnly()` delegates to `i.Child.IsReadOnly()`, and a SELECT child returns `true`, so the read-only check does NOT block this
- **DisableFileWrites**: Grafana does NOT call `mysql.WithDisableFileWrites(true)` when constructing the SQL context (see `pkg/expr/sql/db.go` line 71 -- only `mysql.WithSession` and `mysql.WithTracer` are passed)

Defense layers that partially mitigate:

- **Feature flag**: Disabled by default. Must be explicitly enabled by an admin.
- **secure_file_priv**: The go-mysql-server checks `secure_file_priv` system variable at execution time, but Grafana doesn't configure it (the commented-out code at `db.go:76-77` confirms awareness but no action).

If an admin enables `sqlExpressions`, an authenticated user (Viewer or higher) could potentially craft:
```sql
SELECT * FROM A INTO OUTFILE '/tmp/arbitrary_file.txt'
```

This would pass the allowlist, pass the read-only check, and attempt to write to the filesystem. The actual success depends on the GMS engine's default `secure_file_priv` value, but the code path is open.

### No expr-lang/expr Concerns

The `expr-lang/expr` library is NOT used in `pkg/expr/`. The math expression evaluator is a separate, purpose-built implementation without reflection-based command execution capabilities.

## Bypass Verdict: **sound** (for original RCE) / **relocated** (new file-write risk)

The original CVE-2024-9264 RCE via duckdb is fully patched -- duckdb is completely removed, and the new go-mysql-server engine cannot execute OS commands.

However, the re-introduction of SQL Expressions with `go-mysql-server` has created a new potential vulnerability:

| Finding | Risk | Status |
|---------|------|--------|
| Original duckdb RCE | Critical | **Fully patched** |
| `INTO OUTFILE` / `INTO DUMPFILE` file write | Medium | **Present but gated behind disabled feature flag** |
| `load_file()` file read | Low | **Blocked by function allowlist** |
| Feature flag bypass | Low | Feature flag is server-side, not bypassable by API callers |

### Recommendations

1. **Remove `*sqlparser.Into` from the allowlist** in `parser_allow.go`. There is no legitimate use case for `SELECT INTO OUTFILE` in the SQL Expressions context.
2. **Call `mysql.WithDisableFileWrites(true)`** when creating the GMS context in `db.go` as defense-in-depth.
3. **Set `secure_file_priv`** to an empty/restricted path as defense-in-depth.

## Evidence

- `pkg/expr/sql/parser_allow.go:113` — `*sqlparser.Into` on allowlist
- `pkg/expr/sql/db.go:71` — `mysql.NewContext()` does not include `WithDisableFileWrites`
- `pkg/expr/sql/db.go:76-77` — commented-out `secure_file_priv` configuration
- `go-mysql-server` `sql/plan/into.go:82-84` — `Into.IsReadOnly()` delegates to child
- `go-mysql-server` `sql/rowexec/rel.go:585-644` — `buildInto()` writes files when `Outfile`/`Dumpfile` set
- `go-mysql-server` `sql/rowexec/rel.go:600` — `DisableFileWrites()` check exists but Grafana never enables it
- `pkg/services/featuremgmt/registry.go:862` — `sqlExpressions` flag with `Expression: "false"`
- `pkg/expr/nodes.go:128` — Feature flag gate check before SQL command execution
