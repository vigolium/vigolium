Phase: 10
Sequence: 005
Slug: setop-with-recursive-walker-skip
Verdict: VALID
Rationale: SetOp.walkSubtree does not traverse node.With, so a WITH RECURSIVE attached to a UNION/INTERSECT/EXCEPT statement is never visited by the allowlist walker and the With node is never checked at all.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-025-with-recursive-allowlist-bypass.md
Origin-Pattern: AP-025

## Summary

`parser_allow.go` handles `*sqlparser.SetOp` (UNION/INTERSECT/EXCEPT) by checking only that `v.GetInto() == nil`. However, a `WITH RECURSIVE` CTE can be attached to the top-level statement when that statement is a `SetOp`, stored in `SetOp.With`. `SetOp.walkSubtree` only walks `Left` and `Right` child statements -- it does NOT walk `node.With`. This means the `*sqlparser.With` node (and its `Recursive bool`) is never even visited by `sqlparser.Walk`, so `allowedNode` is never called for it. The original p8-025 finding addresses `With.Recursive` being an invisible scalar on `Select.With`; this variant shows that for SetOp queries the `With` node itself is completely absent from the walk traversal.

## Location

- **File**: `pkg/expr/sql/parser_allow.go`
- **Lines**: 130-133 (SetOp allowedNode case)
- **Code**:
```go
case *sqlparser.SetOp:
    // SetOp.walkSubtree() does not traverse Into, so reject explicitly.
    return v.GetInto() == nil
```
- **AST definition** (vitess fork): `SetOp.walkSubtree` walks only `Left` and `Right`, not `With`, `Limit`, `Lock`, or `OrderBy`
- **Vitess file**: `go/vt/sqlparser/ast.go:890-898`
```go
func (node *SetOp) walkSubtree(visit Visit) error {
    if node == nil {
        return nil
    }
    return Walk(
        visit,
        node.Left,
        node.Right,
    )
}
```
- **Grammar** (`sql.y:796-803`): `WITH with_clause select_or_set_op` calls `selectStatement.SetWith(with)`, which for a SetOp calls `SetOp.SetWith`, storing the With in `SetOp.With`.

## Attacker Control

Authenticated user controls the SQL expression query string. Example payload:

```sql
WITH RECURSIVE counter(n) AS (
    SELECT 1
    UNION ALL
    SELECT n+1 FROM counter WHERE n < 100000
) SELECT n FROM counter UNION ALL SELECT n FROM counter
```

In the grammar, `WITH RECURSIVE ... SELECT ... UNION ALL SELECT ...` parses with the `With` attached to the outer `SetOp` node. Since `SetOp.walkSubtree` never walks `node.With`, the `*sqlparser.With{Recursive: true}` node is never presented to `allowedNode`. The SetOp case only checks `GetInto() == nil`, which is satisfied, so `AllowQuery` returns `true`.

## Trust Boundary Crossed

Authenticated user -> SQL expression allowlist (designed to prevent dangerous SQL constructs). The allowlist was introduced to prevent abuse of the SQL engine after CVE-2024-9264 and CVE-2026-28375.

## Impact

- Same bounded DoS as p8-025: CPU/memory consumption, up to 100k output cells or 10s per query
- The bypass path is structurally distinct from p8-025: the `With` node is entirely absent from the walk, meaning even a future fix to check `With.Recursive` in `allowedNode` would not cover this case unless `SetOp.walkSubtree` is also patched to walk `node.With`
- When combined with alerting rules (as in p8-027), amplifies to persistent scheduled DoS

## Evidence

1. `parser_allow.go:130-133`: SetOp case only checks `GetInto() == nil`
2. `ast.go:890-898`: `SetOp.walkSubtree` walks only `Left`, `Right` -- `node.With` is not included
3. `ast.go:841-843`: `SetOp.SetWith(w *With)` stores the With in `node.With`
4. `sql.y:796-803`: Grammar rule `WITH with_clause select_or_set_op` calls `selectStatement.SetWith(with)`; if `select_or_set_op` is a UNION, the result is a SetOp, so SetOp.With is populated
5. `sql.y:806-812`: `RECURSIVE cte_list` sets `Recursive: true` on the With struct

## Reproduction Steps

1. Enable `FlagSqlExpressions` feature flag
2. Create a SQL expression with:
   ```sql
   WITH RECURSIVE counter(n) AS (
       SELECT 1 UNION ALL SELECT n+1 FROM counter WHERE n < 100000
   ) SELECT * FROM counter UNION ALL SELECT 0
   ```
3. Call `AllowQuery("A", query)` -- observe it returns `(true, nil)`
4. The `SetOp.With.Recursive` field is never checked because `SetOp.walkSubtree` never walks `node.With`
5. The recursive CTE executes and generates up to 100k rows
