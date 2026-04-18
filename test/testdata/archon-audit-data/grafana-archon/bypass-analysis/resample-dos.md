# Bypass Analysis: CVE-2026-27879 / CVE-2026-27880 -- Resample DoS & Testdata Data Point Limit

**Cluster ID**: resample-testdata-dos
**Commit**: 0e5d9e01ef31f072fd41626cd744699374e70127

---

## Patch Summary

### CVE-2026-27879 -- Resample Math Expression (pkg/expr/mathexp/resample.go)

The `Series.Resample()` function computes `newSeriesLength = (to - from) / interval`. Previously, there was no upper bound on this value, allowing an attacker to craft a query with a tiny interval (e.g., 1 microsecond) and a large time range (e.g., 11 seconds) to request millions of data points, causing memory exhaustion.

**Fix**: Added `MaxNewSeriesLength = 1,000,000` constant. If `newSeriesLength` exceeds this, the function returns `ErrNewSeriesLengthTooLong`.

### CVE-2026-27880 -- Testdata Datasource (pkg/tsdb/grafana-testdata-datasource/)

Several testdata scenarios used client-controlled `MaxDataPoints` or `Lines` values without upper bounds, enabling resource exhaustion.

**Fix**: Applied caps across multiple scenarios:
- `randomWalkTable`: `maxDataPoints` capped at 10,000
- `handleLogsScenario`: `lines` capped at 10,000
- `sims/engine.go`: `maxPoints` capped at 10,000
- `usa_stats.go`: total data points capped at `maxUSAResults = 10,000` distributed across states x fields

---

## Bypass Verdict: **sound** (with caveats)

The patches address the identified attack vectors correctly. However, there are residual amplification risks worth noting.

---

## Detailed Analysis

### Vector: Per-series vs. aggregate limit in Resample

**Finding**: The `MaxNewSeriesLength` cap of 1,000,000 is applied **per individual series** within `Series.Resample()`. The caller in `ResampleCommand.Execute()` (pkg/expr/commands.go:303-327) iterates over all series in the input variable:

```go
for _, val := range vars[gr.VarToResample].Values {
    // Each series individually calls v.Resample() with the 1M cap
    num, err := v.Resample(gr.refID, gr.Window, ...)
    newRes.Values = append(newRes.Values, num)
}
```

If a datasource query returns N series (e.g., a high-cardinality Prometheus query), each series can be resampled to up to 1,000,001 data points. For N=100 series, that is 100 million float64 values (~800 MB). This is a theoretical amplification concern but is mitigated by:
1. The upstream datasource itself typically limits series count.
2. The Math expression engine has a separate `MemoryLimit` guard for binary operations.
3. There is no evidence of a direct aggregate limit on Resample output across all series.

**Risk**: Low-Medium. An attacker with access to a high-cardinality datasource could potentially trigger significant memory allocation, but practical exploitation requires both a permissive datasource and a crafted Resample expression.

### Vector: Zero or negative interval

**Finding**: If `interval.Nanoseconds()` returns 0 (e.g., from parsing "0s"), the float64 division produces `+Inf`, and Go's `int(+Inf)` yields a large negative number on most platforms. This would be caught by the existing `newSeriesLength <= 0` check on line 39. **Not bypassable.**

### Vector: Integer overflow in newSeriesLength calculation

**Finding**: The calculation uses `float64` arithmetic, which avoids integer overflow. The result is converted to `int` after division. For extremely large time ranges with nanosecond intervals, `float64` precision loss could theoretically produce inaccurate values, but the 1M cap prevents any dangerous allocation regardless. **Not bypassable.**

### Vector: Testdata scenario coverage gaps

**Finding**: All loop-based testdata scenarios were reviewed:
- `randomWalkTable` (line 957): capped at 10,000 -- **patched**
- `handleLogsScenario` (line 638): capped at 10,000 -- **patched**
- `sims/engine.go` (line 155): capped at 10,000 -- **patched**
- `usa_stats.go` (line 71): capped at 10,000 total -- **patched**
- `predictableSeries` (line 1068): already hardcoded to 10,000 -- **pre-existing cap**
- Other scenarios at lines 612, 882, 1149: already had hardcoded caps (10, 10000, 100) -- **pre-existing caps**

No uncapped testdata loops remain. **Not bypassable.**

### Vector: Backtesting Resample caller

**Finding**: `pkg/services/ngalert/backtesting/eval_data.go` calls `s.Resample()` with user-controlled `from`, `to`, and `interval`. The new `MaxNewSeriesLength` cap applies here as well. Additionally, the backtesting API is gated behind `featuremgmt.FlagAlertingBacktesting` feature flag. **Covered by the patch.**

### Vector: Config-gated or default-state gaps

**Finding**: The `MaxNewSeriesLength` constant is hardcoded to 1,000,000 and is not configurable. There is no way to disable the check. **Not bypassable.**

### Vector: Sibling expression nodes (Reduce, Math, Threshold)

**Finding**:
- `ReduceCommand`: Collapses a series to a single Number -- no amplification risk.
- `MathCommand`: Has its own `MemoryLimit` guard for binary operation output size.
- `ThresholdCommand`: Operates on existing values without amplification.
- No sibling expression nodes lack resource limits. **Not bypassable.**

---

## Residual Risk Summary

| Vector | Status | Risk |
|--------|--------|------|
| Per-series 1M cap (aggregate amplification) | Partial mitigation | Low-Medium |
| Zero interval | Handled by <= 0 check | None |
| Integer overflow | Float64 arithmetic prevents | None |
| Testdata uncapped loops | All capped | None |
| Backtesting caller | Covered + feature-flagged | None |
| Config bypass | Hardcoded constant | None |
| Sibling expression nodes | Independently guarded | None |

The primary residual concern is the per-series (not aggregate) nature of the 1M cap in Resample. In an environment with high-cardinality datasources, an attacker could potentially force allocation of N x 1M points by crafting a query that feeds many series into a Resample node. However, practical exploitation is limited by upstream datasource constraints and requires authenticated access.
