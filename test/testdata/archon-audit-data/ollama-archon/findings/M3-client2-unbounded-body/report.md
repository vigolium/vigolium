## Summary

When `OLLAMA_EXPERIMENT=client2` is set, `server/internal/registry/server.go:264` dispatches `/api/pull` before the gin middleware chain runs. `handlePull` decodes the JSON body with `decodeUserJSON[*params](r.Body)` which wraps `json.NewDecoder(r.Body).Decode(...)` without any `http.MaxBytesReader` wrapper or `Content-Length` pre-check. A multi-GB JSON body (or a never-ending stream of whitespace followed by a single JSON token) is consumed in its entirety.

## Details

When `OLLAMA_EXPERIMENT=client2` is set, `server/internal/registry/server.go:264` dispatches `/api/pull` before the gin middleware chain runs. `handlePull` decodes the JSON body with `decodeUserJSON[*params](r.Body)` which wraps `json.NewDecoder(r.Body).Decode(...)` without any `http.MaxBytesReader` wrapper or `Content-Length` pre-check. A multi-GB JSON body (or a never-ending stream of whitespace followed by a single JSON token) is consumed in its entirety.

### Location

- `server/internal/registry/server.go:264` — `decodeUserJSON[*params](r.Body)` (per Group A probe — cluster also contains the `handlePull` dispatcher)

### Attacker Control

Network client of `/api/pull` (default loopback-only, but `OLLAMA_HOST=0.0.0.0` in containers exposes it more widely). No authentication required by default.

### Trust Boundary Crossed

Network request body → process memory.

### Evidence

Deferred to Deep Probe PH-A-11 round-1-evidence.md (Group A). Key lines from probe:

```go
// server/internal/registry/server.go:264
if err := decodeUserJSON[*params](r.Body); err != nil {
    ...
}
```

`decodeUserJSON` uses `json.NewDecoder(r.Body).Decode(...)` — streams but does not cap total bytes. Gin's `MaxBytesReader` wrapping is applied in the default HTTP chain but bypassed by the client2 path.

## Root Cause

Validated rationale: OLLAMA_EXPERIMENT=client2 routes /api/pull through registry.Local.serveHTTP → handlePull → decodeUserJSON without gin's BodyLimit middleware; Advocate confirmed MaxBytesReader is absent.

Primary cited code reference: `server/internal/registry/server.go:264`.

Merge extraction sink line: - `server/internal/registry/server.go:264` — `decodeUserJSON[*params](r.Body)` (per Group A probe — cluster also contains the `handlePull` dispatcher)

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Set `OLLAMA_EXPERIMENT=client2`.
2. Launch ollama.
3. `curl -X POST -H 'Content-Type: application/json' --data-binary @10GB.json http://127.0.0.1:11434/api/pull`.
4. Observe RSS growth and eventual OOM.

Debate context: Advocate concurred gate is config-gated but the sink is unambiguously absent of limits. Fix: wrap `r.Body = http.MaxBytesReader(w, r.Body, N)` at the handler entry.

## Impact

- Memory-exhaustion DoS on each `/api/pull`; cheap to execute.
- Gated behind `OLLAMA_EXPERIMENT=client2` environment variable — NOT default. Severity calibrated MEDIUM because the experiment flag is opt-in; any production operator who enables `client2` should be aware.

_Synthesized during merge normalization from `archon/findings/M3-client2-unbounded-body/draft.md`._
