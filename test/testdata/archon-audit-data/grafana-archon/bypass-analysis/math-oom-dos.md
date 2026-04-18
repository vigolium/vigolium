# Bypass Analysis: Math Expression OOM DoS (Cartesian Explosion)

**Commit:** 7d62590d00088e691d8b5a8ba9f613cf285da736
**Component:** pkg/expr/mathexp/ (Expression engine math operations)
**Tag:** [undisclosed]
**Cluster ID:** expr-oom-dos

## Patch Summary

The patch adds a pre-execution memory estimate for math expression binary operations
(e.g., `$A + $B`). When two result sets with incompatible label sets are combined, the
`union()` function produces a cartesian product of all value pairs. Before this fix, there
was no limit on this expansion, allowing OOM kills.

The fix works as follows:

1. A new `MathExpressionMemoryLimit` config option (default: 1 GiB) is read from
   `[expressions] math_expression_memory_limit` in `conf/defaults.ini`.
2. `estimateBinaryMemory()` replays the exact label-matching logic from `union()` to
   count the number of output pairs and estimate per-pair allocation cost.
3. `checkBinaryMemoryLimit()` is called in `walkBinary()` before `union()` runs. If the
   estimate exceeds the limit, an error is returned.
4. The limit is passed from `setting.Cfg` through `MathCommand` to `State.MemoryLimit`
   via a functional option `WithMemoryLimit`.

## Bypass Verdict: **bypassable** (partial — two vectors identified)

## Evidence

### Vector 1: Config-gated check — limit can be set to 0

The limit is configurable and `0` explicitly disables it:

```
// conf/defaults.ini
math_expression_memory_limit = 1073741824
```

```go
// pkg/expr/mathexp/exp.go:501
if e.MemoryLimit > 0 {
```

Setting `math_expression_memory_limit = 0` in `custom.ini` or via environment variable
override (`GF_EXPRESSIONS_MATH_EXPRESSION_MEMORY_LIMIT=0`) fully disables the protection.
This is a documented escape hatch, not a bug per se, but operators who set it to 0 to
"fix" expression errors will silently re-enable the vulnerability.

**Severity:** Low — requires admin configuration change. However, this is a common
anti-pattern when users encounter the new error messages.

### Vector 2: Pipeline-level chaining bypasses per-operation limits

The memory limit applies **per individual binary operation within a single math
expression**. The expression engine supports chaining multiple `MathCommand` nodes in a
pipeline (e.g., expression B = `$A + $A`, expression C = `$B + $B`, expression D =
`$C + $C`, etc.).

Each MathCommand node independently evaluates `walkBinary` with the memory limit. However,
consider this scenario:

- Query A returns 1000 series with empty labels (`data.Labels{}`)
- Expression B = `$A + $A` — this produces 1,000,000 union pairs

The limit catches this single operation correctly. But the pipeline allows a different
amplification pattern:

- Expression B = `$A + 1` (produces 1000 series, passes limit trivially)
- Expression C = `$B + $B` (1000 x 1000 with empty labels = 1M pairs)

This is still caught because the binary operation `$B + $B` is evaluated within one
`walkBinary` call.

**However**, the estimate uses `max(aLen, bLen)` for output datapoint count, which is an
**upper bound** (the actual output uses timestamp intersection via `biSeriesSeries`). If
an attacker crafts series with fully overlapping timestamps, the actual memory usage equals
the estimate. If timestamps partially overlap, the estimate is conservative (over-estimates).
This means the limit is safe but may reject valid expressions. This is not a bypass but a
usability concern that may lead operators to raise or disable the limit.

### Vector 3 (Not bypassed): Sibling expression types

- **ReduceCommand**: Iterates input values 1:1, reducing each Series to a Number. No
  amplification possible. Not vulnerable.
- **ResampleCommand**: Has its own `MaxNewSeriesLength` cap (1,000,000 datapoints per
  series). No cartesian product. Not vulnerable.
- **Classic Conditions**: Iterates input values linearly, reducing each to a boolean
  outcome. No union/cross-product. Not vulnerable.
- **SQL Expressions**: Has separate `SQLExpressionCellLimit`, `SQLExpressionOutputCellLimit`,
  and `SQLExpressionTimeout` protections. Not vulnerable to this specific pattern.
- **ThresholdCommand**: 1:1 mapping over input values. Not vulnerable.
- **HysteresisCommand**: Wraps threshold evaluation. Not vulnerable.
- **Built-in math functions** (`abs`, `log`, `round`, etc.): All are 1:1 per-value
  transforms via `perFloat()`. No amplification.

### Vector 4 (Not bypassed): Nested binary operations within a single expression

An expression like `$A + $B + $C` parses to nested `BinaryNode`s: `($A + $B) + $C`.
Each `walkBinary` call independently checks the memory limit. If `$A + $B` produces
a large intermediate result, the subsequent `(result) + $C` operation is also checked.
This is correctly handled.

### Vector 5 (Not bypassed): Estimate-vs-union logic consistency

The `estimateBinaryMemory()` function carefully mirrors the `union()` function's label
matching logic, including:
- Empty labels matching everything (cartesian case)
- Subset/superset label containment
- Same-length-different-keys rejection
- Single-value fallback when no unions match
- NoData early return

No divergence was found between the estimate and the actual union logic.

## Residual Risk

1. The 1 GiB default limit is still substantial. An attacker who can create alerting rules
   or dashboard expressions can force the server to attempt up to 1 GiB of allocation per
   binary operation. Multiple concurrent requests could still exhaust memory.

2. There is no limit on the **number of binary operations** within a single math expression.
   An expression like `$A + $A + $A + $A + ...` creates a chain of binary operations, each
   allowed up to 1 GiB. However, since the intermediate results do not amplify (union with
   matching labels produces 1:1 output), this is only a concern if intermediate results
   have incompatible labels.

3. There is no pipeline-level aggregate memory limit across all expression nodes in a
   single evaluation. Each MathCommand gets its own 1 GiB budget.

## Recommendations

1. Consider adding a pipeline-level memory budget that is shared across all expression
   nodes, not just per-binary-operation.
2. Consider logging/alerting when expressions approach the limit (e.g., >50% of limit)
   to help operators identify problematic expressions before they hit the wall.
3. Document that setting the limit to 0 re-enables the OOM vulnerability.
