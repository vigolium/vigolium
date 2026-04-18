Phase: 10
Sequence: 006
Slug: jsontable-colopts-expr-bypass
Verdict: VALID
Rationale: JSONTableColDef.walkSubtree does not walk col.Opts (JSONTableColOpts), and JSONTableColOpts.walkSubtree calls Walk with no arguments, making ValOnEmpty and ValOnError expressions completely invisible to the allowlist walker.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-025-with-recursive-allowlist-bypass.md
Origin-Pattern: AP-025

## Summary

`parser_allow.go` allows `*sqlparser.JSONTableColDef` unconditionally. However, `JSONTableColDef.walkSubtree` only walks `col.Name` and `col.Type` -- it does NOT walk `col.Opts` (of type `JSONTableColOpts`). `JSONTableColOpts` itself has a `walkSubtree` that calls `Walk(visit)` with zero arguments, so even if `col.Opts` were walked, the `ValOnEmpty Expr` and `ValOnError Expr` fields within `col.Opts` would never be visited. An attacker can place arbitrary SQL expressions -- including expressions that call blocked functions or generate large intermediate results -- in the `DEFAULT <expr> ON EMPTY` and `DEFAULT <expr> ON ERROR` clauses of a `JSON_TABLE` column definition, and those expressions will never be checked by `AllowQuery`.

## Location

- **File**: `pkg/expr/sql/parser_allow.go`
- **Line**: 124 (JSONTableColDef allowed unconditionally)
```go
case *sqlparser.JSONTableExpr, *sqlparser.JSONTableSpec, *sqlparser.JSONTableColDef:
    return
```
- **AST definition** (vitess fork):

`ast.go:3478-3487`:
```go
func (col *JSONTableColDef) walkSubtree(visit Visit) error {
    if col == nil {
        return nil
    }
    return Walk(
        visit,
        col.Name,
        col.Type,
    )
}
```
`ast.go:3516-3518`:
```go
func (opt JSONTableColOpts) walkSubtree(visit Visit) error {
    return Walk(visit)  // zero arguments: ValOnEmpty and ValOnError never walked
}
```
`ast.go:3489-3496`:
```go
type JSONTableColOpts struct {
    ValOnEmpty   Expr   // never walked
    ValOnError   Expr   // never walked
    Path         string
    ErrorOnEmpty bool
    ErrorOnError bool
    Exists       bool
}
```

## Attacker Control

Authenticated user controls the SQL expression query string. Example payload:

```sql
SELECT jt.val FROM tbl, JSON_TABLE(
    tbl.data,
    '$[*]' COLUMNS(
        val INT PATH '$.v'
            DEFAULT (SELECT COUNT(*) FROM tbl CROSS JOIN tbl CROSS JOIN tbl) ON EMPTY
            DEFAULT (SELECT COUNT(*) FROM tbl CROSS JOIN tbl CROSS JOIN tbl) ON ERROR
    )
) AS jt
```

The expressions in `DEFAULT ... ON EMPTY` and `DEFAULT ... ON ERROR` are parsed into `JSONTableColOpts.ValOnEmpty` and `JSONTableColOpts.ValOnError`. These are `Expr` AST nodes, but neither `JSONTableColDef.walkSubtree` nor `JSONTableColOpts.walkSubtree` presents them to the visitor. `AllowQuery` returns `true`.

## Trust Boundary Crossed

Authenticated user -> SQL expression allowlist -> go-mysql-server SQL engine. The allowlist is the primary security control for the SQL expression engine. Expressions that bypass it are evaluated by the engine without any sandboxing at the expression level.

## Impact

- Allowlist bypassed: any expression, including ones calling blocked functions, can be hidden in JSON_TABLE ON EMPTY/ON ERROR clauses
- In practice go-mysql-server's `IsReadOnly: true` config blocks DML, but arbitrary read-side expressions can still cause bounded resource exhaustion (Cartesian join amplification referenced in probe chain PH-09 -> PH-R3-02)
- If future go-mysql-server versions add dangerous functions in the expression evaluation path (consistent with the recurring vulnerability history in this component), the bypass surface already exists
- Severity stays MEDIUM rather than HIGH because: (1) IsReadOnly blocks file writes, (2) no unauthenticated access path

## Evidence

1. `parser_allow.go:124`: `*sqlparser.JSONTableColDef` allowed unconditionally without restriction
2. `ast.go:3478-3487`: `JSONTableColDef.walkSubtree` walks only `col.Name` and `col.Type`, not `col.Opts`
3. `ast.go:3516-3518`: `JSONTableColOpts.walkSubtree` calls `Walk(visit)` with no arguments
4. `ast.go:3489-3496`: `JSONTableColOpts` contains `ValOnEmpty Expr` and `ValOnError Expr` -- attacker-controlled expression AST nodes that are never checked
5. Probe workspace note: "PH-09 (JSON_TABLE input bypass) → PH-R3-02 (amplified data generation) → cartesian explosion" confirms the JSON_TABLE attack surface was identified in deep probing

## Reproduction Steps

1. Enable `FlagSqlExpressions` feature flag
2. Create a SQL expression table source `tbl` with JSON data
3. Execute query:
   ```sql
   SELECT jt.val FROM tbl, JSON_TABLE(
       tbl.data, '$[*]'
       COLUMNS(val INT PATH '$.v'
           DEFAULT (SELECT 1+1+1+1+1) ON EMPTY)
   ) AS jt
   ```
4. Verify that `AllowQuery` returns `(true, nil)` -- the DEFAULT ON EMPTY expression is not visited
5. Confirm that expressions blocked by the allowlist (e.g., a hypothetical `SLEEP(5)` or deep recursive subquery) in ON EMPTY/ON ERROR positions also pass `AllowQuery` without error
