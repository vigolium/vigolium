Phase: 8
Sequence: 042
Slug: num-ctx-uncapped-runner-oom
Verdict: VALID
Rationale: Tracer confirmed `options.num_ctx` is passed through to `NewInputCache` / `reserveWorstCaseGraph` without an upper clamp; when the loaded GGUF lacks a `context_length` KV the `trainCtx > 0` guard is skipped, and a user-supplied `num_ctx=2^29` allocates ~4GB in the runner subprocess (or wraps int32 negative for larger values) — `defer recover()` in `allocModel` catches only `ml.ErrNoMem`, not `runtime.makeslice` panics, so the runner subprocess crashes and all concurrent sessions are dropped.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-03/debate.md

## Summary

`/api/generate` accepts `options.num_ctx` verbatim. `llm/server.go:167-170` clamps `num_ctx` against `f.KV().ContextLength()` ONLY if `trainCtx > 0`. Many GGUFs ship without an explicit `context_length` metadata key (old quantizations, converted LoRA-only models, or attacker-crafted files) in which case the clamp is skipped and `opts.NumCtx` flows unmodified into `KvSize = opts.NumCtx * numParallel`. Downstream, `runner/ollamarunner/runner.go:1223` builds an InputCache that triggers `reserveWorstCaseGraph` which performs `make([]*input.Input, numCtx)` — for `num_ctx = 2^29` this allocates ~4 GB; for `num_ctx = 2^30+` and `numParallel >= 2`, the `int32(KvSize)` cast wraps negative and either errors out or — in the borderline window — produces a giant allocation that OOM-panics the runner. The runner's `defer recover()` catches only `ml.ErrNoMem`, so the Go runtime panic propagates up and kills the subprocess.

## Location

- `server/routes.go:127-141` -- `opts.FromMap` copies `num_ctx` without any upper bound
- `llm/server.go:167-170` -- clamp against `trainCtx` gated by `trainCtx > 0`; bypassed when GGUF lacks `context_length` KV
- `llm/server.go:175` -- `KvSize: opts.NumCtx * numParallel` without overflow check
- `runner/ollamarunner/runner.go:1079` -- `make([]*input.Input, numCtx)` (CodeQL flags `go/uncontrolled-allocation-size` here)
- `runner/ollamarunner/runner.go:1223` -- `NewInputCache(model, kvCacheType, int32(KvSize), ...)` — int32 cast risk
- `runner/ollamarunner/cache.go:37-38` -- negative-int32 guard; does NOT catch in-range `num_ctx=2^29`

## Attacker Control

Unauthenticated `POST /api/generate` with:
```json
{"model":"<any-loaded-model>","prompt":".","options":{"num_ctx":536870912,"num_batch":536870912}}
```

Also reachable via `/api/chat`, `/api/embed`, and `/v1/chat/completions` (all propagate `options`).

## Trust Boundary Crossed

Unauthenticated HTTP request -> runner subprocess OOM/panic -> scheduler-wide inference outage for that model.

## Impact

Runner subprocess OOM crash. All concurrent inference requests on the affected model fail. Scheduler respawns the runner, but cold-start is expensive (model reload from disk). A single request of ~200 bytes triggers the crash. Repeated request every few seconds holds the model unavailable. Cross-user impact: all users of that model share the outage. On memory-constrained hosts (containers with 4-8GB) even smaller `num_ctx` values (2^28) can trigger OOM.

## Evidence

Tracer verification (Round 2, 2026-04-17T07:26:00Z):

```
llm/server.go:167-175
    trainCtx = f.KV().ContextLength()   // uint64; 0 if missing
    if trainCtx > 0 && opts.NumCtx > int(trainCtx) * numParallel {
        opts.NumCtx = int(trainCtx) * numParallel     // guard bypassed when trainCtx=0
    }
    ...
    KvSize: opts.NumCtx * numParallel,

runner/ollamarunner/runner.go:1079 (CodeQL: go/uncontrolled-allocation-size)
    inputs := make([]*input.Input, numCtx)

runner/ollamarunner/cache.go:37-38
    if numCtx <= 0 || int(numCtx) < batchSize { return ...error }
    // 2^29 passes; batch=2^29 passes; allocation ~4GB succeeds then write-phase OOMs

allocModel:
    defer func() { if err := recover(); err != nil { if errors.Is(err, ml.ErrNoMem) { ... } else { panic(err) } } }()
    // re-panics runtime.makeslice failures
```

CodeQL slice: `flow-paths-all-severities.md` `go/uncontrolled-allocation-size` at `runner/ollamarunner/runner.go:1079` — confirmed.

Advocate did not file a defense brief on H-NEW-48 in Round 1 (it was novel to Ideator Round 2). Tracer's Round 2 extended evidence is the authoritative record.

## Reproduction Steps

1. Start Ollama. Load any model that either lacks `llama.context_length` KV, or set `num_ctx` to a value smaller than the model's trained context so both legit and malicious paths are observable.
2. `curl -X POST http://127.0.0.1:11434/api/generate -d '{"model":"<model>","prompt":".","options":{"num_ctx":536870912,"num_batch":536870912}}'`
3. Observe runner subprocess crash + scheduler reload.
4. Fix direction: (a) add absolute cap `const MaxNumCtx = 1 << 20` enforced at `opts.FromMap` validation; (b) change the `trainCtx > 0` gate to always clamp against `max(trainCtx, MaxNumCtx)`; (c) widen `allocModel`'s recover to catch all panics and convert to HTTP 400.

Pattern: AP-043 `uncapped-config-from-request-into-runner-allocation`.
