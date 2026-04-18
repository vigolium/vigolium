Phase: 10
Sequence: 007
Slug: select-window-clause-not-walked
Verdict: VALID
Rationale: Select.walkSubtree does not traverse node.Window, so named WINDOW clause definitions (with PARTITION BY / ORDER BY expressions) are never presented to allowedNode and are invisible to AllowQuery.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-025-with-recursive-allowlist-bypass.md
Origin-Pattern: AP-025

## Summary

`parser_allow.go` allows `*sqlparser.Select` unconditionally. `Select.walkSubtree` traverses 10 fields but deliberately excludes `node.Window` (the named WINDOW clause). A SQL query can define named window specifications at the SELECT level using `SELECT ... WINDOW w AS (PARTITION BY ... ORDER BY ...)`. The `Window` field (`type Window []*WindowDef`) is never passed to `sqlparser.Walk`, and neither `Window` nor `*WindowDef` appears in the allowlist's `allowedNode` switch. This means any expression embedded in a named window definition's PARTITION BY or ORDER BY clause is invisible to `AllowQuery`. Additionally, the inline `OVER` handler (`*sqlparser.Over`) walks `PartitionBy`, `OrderBy`, and `Name` but NOT `Frame` -- however named window references via `OVER w` use `NameRef`, so the named window definition itself is never validated.

## Location

- **File**: `pkg/expr/sql/parser_allow.go`
- **Line**: 127 (Select allowed unconditionally)
```go
case *sqlparser.Select, sqlparser.SelectExprs, *sqlparser.ParenSelect:
    return
```
- **AST definition** (vitess fork):

`ast.go:673-690`: `Select.walkSubtree` -- `node.Window` is absent:
```go
func (node *Select) walkSubtree(visit Visit) error {
    if node == nil {
        return nil
    }
    return Walk(
        visit,
        node.With,
        node.Comments,
        node.SelectExprs,
        node.From,
        node.Where,
        node.GroupBy,
        node.Having,
        node.OrderBy,
        node.Limit,
        node.Into,
        // node.Window is NOT walked
        // node.Lock is NOT walked
        // node.QueryOpts is NOT walked
    )
}
```
`ast.go:7260-7287`: `Window.walkSubtree` does walk PartitionBy/OrderBy/Frame of WindowDef entries, but this is never called because `Select.walkSubtree` never calls `Walk(visit, node.Window)`.

## Attacker Control

Authenticated user controls the SQL expression query string. Example payload demonstrating expressions in named WINDOW that bypass allowlist:

```sql
SELECT val,
       ROW_NUMBER() OVER w AS rn
FROM tbl
WINDOW w AS (
    PARTITION BY (SELECT COUNT(*) FROM tbl CROSS JOIN tbl)
    ORDER BY val
)
```

The subquery `(SELECT COUNT(*) FROM tbl CROSS JOIN tbl)` inside the named WINDOW's `PARTITION BY` clause is parsed into `WindowDef.PartitionBy`. Since `Select.walkSubtree` never calls `Walk(visit, node.Window)`, this expression is never visited and `allowedNode` is never called for it. `AllowQuery` returns `true`.

## Trust Boundary Crossed

Authenticated user -> SQL expression allowlist -> go-mysql-server SQL engine. Named WINDOW clause expressions bypass the allowlist safety control.

## Impact

- Allowlist bypassed for expressions in named WINDOW PARTITION BY and ORDER BY clauses
- Attacker can embed resource-intensive expressions (e.g., Cartesian join subqueries) in PARTITION BY that generate large intermediate results invisible to the allowlist
- Severity is MEDIUM: `IsReadOnly: true` blocks writes; authenticated-only access; bounded by 10s timeout and 100k cell limit
- Similar scope to p8-025: this is a DoS vector, not data exfiltration, because named window expressions evaluate read-only data

## Evidence

1. `parser_allow.go:127`: `*sqlparser.Select` allowed unconditionally
2. `ast.go:673-690`: `Select.walkSubtree` does not include `node.Window` in the Walk call
3. `ast.go:7260-7287`: `Window.walkSubtree` and `WindowDef.walkSubtree` exist and would walk PartitionBy/OrderBy, but are never reachable from `AllowQuery` because `Select.walkSubtree` does not walk `node.Window`
4. `parser_allow.go` (entire file): Neither `sqlparser.Window` nor `*sqlparser.WindowDef` appear as cases in `allowedNode` -- if the walker did reach them, they would be rejected by the `default: return false` case
5. `ast.go:654-671`: `Select.Format` confirms `node.Window` is rendered: `buf.Myprintf("...%v...", ... node.Window ...)`, proving the field is active and populated by the parser

## Reproduction Steps

1. Enable `FlagSqlExpressions` feature flag
2. Execute via the SQL expression API:
   ```sql
   SELECT val, ROW_NUMBER() OVER w AS rn
   FROM A
   WINDOW w AS (PARTITION BY val ORDER BY val)
   ```
3. Verify that `AllowQuery` returns `(true, nil)` -- the WINDOW clause is not walked
4. Test with a more complex expression in PARTITION BY to confirm allowlist bypass:
   ```sql
   SELECT val, ROW_NUMBER() OVER w AS rn
   FROM A
   WINDOW w AS (PARTITION BY (SELECT 1 FROM A CROSS JOIN A CROSS JOIN A) ORDER BY val)
   ```
5. Confirm `AllowQuery` returns `(true, nil)` even with the Cartesian-join subquery inside the WINDOW definition
