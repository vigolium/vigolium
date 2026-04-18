Phase: 8
Sequence: 011
Slug: graphsize-nil-type-assertion
Verdict: VALID
Rationale: fs/ggml/ggml.go:607 performs an unchecked type assertion on f.KV()["tokenizer.ggml.tokens"] without nil or ok-check; a GGUF missing that key or where the value is not a *array[string] panics the caller. Recovery middleware catches the HTTP path but background scheduler goroutines are unprotected.
Severity-Original: MEDIUM
Severity-Final: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-02/debate.md

## Summary

`fs/ggml/ggml.go:607` reads vocab size as `uint64(f.KV()["tokenizer.ggml.tokens"].(*array[string]).size)`. The map read returns `nil` if the key is absent, or a differently-typed value if the GGUF declares `tokenizer.ggml.tokens` as (for example) a scalar uint64 rather than an array of strings. In either case the type assertion panics with "interface conversion: interface is nil, not *array[string]" or "interface is uint64, not *array[string]".

## Location

`fs/ggml/ggml.go:607` in `GraphSize`.

## Attacker Control

Any GGUF reaching `GraphSize`. Reached from the VRAM scheduler during model-load and layer estimation.

## Trust Boundary Crossed

Network API (pull/create) -> process panic.

## Impact

- HTTP path: gin.Recovery catches -> per-request 500 DoS. Every `/api/chat` that needs VRAM estimation on the poisoned model fails.
- Background goroutine path: `server/sched.go` calls `GraphSize` during scheduling; panics there are NOT wrapped in gin.Recovery and exit the goroutine. Depending on scheduler error handling, this can lock up model scheduling for the entire process.

## Evidence

```
// fs/ggml/ggml.go:599-607
func (f GGML) GraphSize(context, batch uint64, numParallel int, ...) (...) {
    context *= uint64(numParallel)
    ...
    vocab := uint64(f.KV()["tokenizer.ggml.tokens"].(*array[string]).size)
```

Tracer verification (Round 2): no nil-check or comma-ok idiom.

Advocate (Round 3): "Real-world GGUFs always include tokenizer.ggml.tokens" -- true for benign models but trivially controllable by the attacker. Recovery covers HTTP path only; scheduler goroutine path is unprotected.

## Reproduction Steps

1. Craft a GGUF that omits `tokenizer.ggml.tokens` KV entirely.
2. `POST /api/pull` of that model.
3. `POST /api/chat` to the model -> 500 (HTTP path) or scheduler lockup (if VRAM estimation is called from the scheduler).

Fix direction:
```
val, ok := f.KV()["tokenizer.ggml.tokens"].(*array[string])
if !ok || val == nil {
    return ..., fmt.Errorf("model missing tokenizer.ggml.tokens")
}
vocab := uint64(val.size)
```
