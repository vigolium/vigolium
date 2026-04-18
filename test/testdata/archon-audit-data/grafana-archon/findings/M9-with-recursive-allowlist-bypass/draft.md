Phase: 8
Sequence: 025
Slug: with-recursive-allowlist-bypass
Verdict: VALID
Rationale: SQL expression allowlist permits WITH RECURSIVE because *sqlparser.With is allowed unconditionally and the Recursive bool is invisible to the AST walker; enables sourceless DoS bounded by output/timeout limits.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-2/debate.md

## Summary

The SQL expression allowlist in `parser_allow.go` allows `*sqlparser.With` AST nodes unconditionally. The `Recursive` boolean field on the `With` struct is not an AST child node and is therefore invisible to the `sqlparser.Walk` visitor. This allows `WITH RECURSIVE` queries to pass the allowlist, enabling recursive CTE execution that generates arbitrary amounts of in-engine data without any datasource input, bounded only by the output cell limit (100k) and timeout (10s).

## Location

- **File**: `pkg/expr/sql/parser_allow.go`
- **Line**: 170-171
- **Code**:
```go
case *sqlparser.With:
    return
```
- **AST definition** (vitess fork): `type With struct { Ctes []*CommonTableExpr; Recursive bool }` -- `Recursive` is a plain bool, not an AST node

## Attacker Control

Authenticated user controls the SQL expression query string. Example payload:
```sql
WITH RECURSIVE counter(n) AS (
    SELECT 1 UNION ALL SELECT n+1 FROM counter WHERE n < 100000
) SELECT n, n*n, n*n*n FROM counter
```

## Trust Boundary Crossed

Authenticated user -> SQL expression allowlist (designed to prevent dangerous SQL constructs). The allowlist was explicitly introduced after CVE-2024-9264 and CVE-2026-28375 to prevent abuse of the SQL engine.

## Impact

- Bounded DoS: CPU/memory consumption up to 100k output cells or 10 seconds per query
- Input cell limit bypassed: recursive CTEs generate data in-engine with 0 input cells
- When used in alerting rules (see p8-027), impact is amplified to persistent scheduled DoS
- Third generation of SQL expression security issues (after CVE-2024-9264, CVE-2026-28375)

## Evidence

1. `parser_allow.go:170`: `*sqlparser.With` allowed unconditionally
2. vitess AST: `Recursive bool` is not an AST node, invisible to walker
3. `sql_command.go:193-199`: Input cell limit = 0 for recursive CTEs (no datasource input)
4. Deep Probe PH-11/PH-R3-01 (sql-expression) validated with full trace
5. Feature flag `FlagSqlExpressions` required (public preview)

## Reproduction Steps

1. Enable `FlagSqlExpressions` feature flag
2. Create a datasource query with SQL expression type
3. Use payload: `WITH RECURSIVE counter(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM counter WHERE n < 100000) SELECT n FROM counter`
4. Observe successful execution generating up to 100k rows
5. Monitor CPU/memory consumption during execution
6. Verify that `AllowQuery` does not block the recursive CTE
