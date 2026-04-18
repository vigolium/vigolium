Phase: 8
Sequence: 022
Slug: gguf-array-length-truncation
Verdict: VALID
Rationale: readGGUFArray reads an attacker uint64 as the array length, then casts to int. On 64-bit the cast wraps large values to negative; newArray's gate compares against maxSize and lets negative values through, reaching make([]T, negative) which panics with "makeslice: len out of range".
Severity-Original: MEDIUM
PoC-Status: executed
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-02/debate.md

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Unit-level PoC reproduces the exact "makeslice: len out of range" panic in fs/ggml.Decode with a 33-byte crafted GGUF; no length validation exists between the attacker-controlled uint64 and make([]T, int(n)), and while gin.Recovery caps HTTP-path impact to per-request 500, the runner-subprocess callers (ml/backend/ggml/ggml.go:130) have no such protection.
Severity-Final: MEDIUM
PoC-Status: executed

## Summary

`fs/ggml/gguf.go:424-437` reads the array length `n` as uint64, then calls `newArray[T](int(n), llm.maxArraySize)`. On 64-bit platforms, `int(n)` for `n >= 2^63` wraps to a negative int. `newArray` at `fs/ggml/gguf.go:416-422` gates allocation on `size <= maxSize` which is trivially true for any negative size, so `make([]T, size)` is invoked with a negative length and panics.

## Location

- `fs/ggml/gguf.go:430-437` -- `n, _ := readGGUF[uint64]; ...; newArray[T](int(n), llm.maxArraySize)`
- `fs/ggml/gguf.go:416-422` -- newArray gate lets negative size through

## Attacker Control

Any GGUF blob reaching `Decode`. Reached from `/api/create`, `/api/pull`, `/api/show` (via lazy parser).

## Trust Boundary Crossed

Network API -> process panic.

## Impact

Recoverable panic (gin.Recovery catches `runtime: makeslice: len out of range` as a standard runtime.Error). Effect is DoS-per-request returning 500. Severity is MEDIUM rather than HIGH because Recovery middleware catches the panic when reached through HTTP handlers; the vulnerability is still real when reached from background scheduler goroutines or non-gin code paths (model-load from `ml/backend/ggml`).

## Evidence

```
// fs/ggml/gguf.go:424-437
func readGGUFArray(llm *gguf, r io.Reader) (any, error) {
    t, err := readGGUF[uint32](llm, r)
    ...
    n, err := readGGUF[uint64](llm, r)
    ...
    switch t {
    case ggufTypeUint8:
        a := newArray[uint8](int(n), llm.maxArraySize)    // int(n) wraps
        ...
```

```
// fs/ggml/gguf.go:416-422
func newArray[T any](size, maxSize int) *array[T] {
    a := array[T]{size: size}
    if maxSize < 0 || size <= maxSize {   // negative size passes
        a.values = make([]T, size)        // panics
    }
    return &a
}
```

Advocate (Round 3): `runtime.makeslice` on negative length IS a recoverable Go runtime.Error, so gin.Recovery catches it. Severity downgraded from HIGH to MEDIUM as a result.

Cold-verification PoC (Darwin arm64, unit test against fs/ggml):
```
=== RUN   TestGGUFLengthTruncationPanic
bits = 64
GOARCH = arm64
PANIC RECOVERED: runtime error: makeslice: len out of range
--- PASS
```
Evidence file: `archon/real-env-evidence/gguf-array-length-truncation/poc_output.txt`

## Reproduction Steps

1. Craft a GGUF KV value of type `ggufTypeArray`, subtype `ggufTypeUint8`, length field = 0xFFFFFFFFFFFFFFFF.
2. `POST /api/create` referencing that blob.
3. Observe: server returns 500, process survives via gin.Recovery.
4. For a non-HTTP entry: use `ollama run <model>` against the crafted blob to see if model-load path (outside gin scope) exits the process.

Fix direction: check `if n > uint64(math.MaxInt32) { return error }` before truncation; also fix `newArray` to reject negative sizes explicitly.
