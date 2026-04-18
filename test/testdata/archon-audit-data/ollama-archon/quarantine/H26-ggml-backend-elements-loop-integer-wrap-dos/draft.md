Phase: 10
Sequence: 020
Slug: ggml-backend-elements-loop-integer-wrap-dos
Verdict: VALID
Rationale: ml/backend/ggml/ggml.go iterates for e < t.Elements() on the _exps.bias BF16 branch and computes bts[:min(len(bts), int(t.Elements()-e)*2)]; when t.Elements() is an AP-020-overflowed huge value the arithmetic wraps to 0 and the loop becomes infinite, hanging the inference backend goroutine permanently.
Severity-Original: HIGH
Severity-Final: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-020-gguf-shape-uint64-overflow-oob.md
Origin-Pattern: AP-020

## Summary

`ml/backend/ggml/ggml.go:573-593` contains a streaming BF16-to-F32 conversion
loop for tensors whose name ends in `_exps.bias` and whose `Kind == 30`
(BF16).  The loop bound is `t.Elements()`, which is computed without overflow
checks (see AP-020, `fs/ggml/ggml.go:505`).

When an attacker delivers a GGUF with a BF16 `_exps.bias` tensor whose Shape
overflows `Elements()` to a huge value (e.g.
`Shape=[0x4000000000000001,1]` → `Elements()=0x4000000000000001`), the loop
variable `e` can never reach `t.Elements()` within any reasonable time, and
each iteration evaluates:

```go
bts[:min(len(bts), int(t.Elements()-e)*2)]
```

where `int(t.Elements()-e)` wraps negative (because the difference is a large
uint64 that exceeds `math.MaxInt64`).  Specifically:

- When `e = 0`: `t.Elements()-e = 0x4000000000000001` → `int(...)` = `-9223372036854775807` → `*2` = `2`. Reads 2 bytes. Fine.
- When `e = 1`: `t.Elements()-e = 0x4000000000000000` → `int(...)` = `-9223372036854775808` → `*2` overflows to `0`. Reads 0 bytes. `n = 0`, `e` does not advance.
- All subsequent iterations: perpetual 0-byte reads. **Infinite loop.**

The SectionReader `sr` is created with size `int64(t.Size())` = 4 (wrapped
small value), so the file backing is only 4 bytes, but the loop logic hangs
before exhausting it.

The goroutine is a member of an `errgroup.Group` limited by `GOMAXPROCS`.
Because it never returns, it occupies one of the goroutine slots permanently,
eventually starving all tensor-load goroutines and hanging model load.

## Location

- `ml/backend/ggml/ggml.go:526` — SectionReader created with wrapped-small `int64(t.Size())`
- `ml/backend/ggml/ggml.go:573` — loop bound `for e < t.Elements()` (huge)
- `ml/backend/ggml/ggml.go:578` — `int(t.Elements()-e)*2` wraps to 0 on second iteration

## Attacker Control

Same delivery path as AP-020: the crafted GGUF reaches the blob store via
`POST /api/create` (Modelfile FROM), `POST /api/pull`, or
`POST /api/blobs/:digest`.  The BF16 `_exps.bias` tensor name check
(`strings.HasSuffix(t.Name, "_exps.bias") && t.Kind == 30`) is met by naming
the single crafted tensor `blk.0.ffn_gate_exps.bias` (a common MoE tensor
name used by DeepSeek-style architectures already present in the codebase).

## Trust Boundary Crossed

Network API → inference backend goroutine pool; a single crafted model upload
permanently hangs a GOMAXPROCS worker, starving subsequent model loads across
all users of the shared server process.

## Impact

- **Denial of service (permanent goroutine hang)**: the errgroup worker
  occupies a GOMAXPROCS slot forever; subsequent `POST /api/generate` or
  `/api/chat` for any model that shares the same runner process hang until the
  Ollama server is restarted.
- **Cross-tenant**: on shared deployments, one attacker model hangs the server
  for all users.

## Evidence

```go
// ml/backend/ggml/ggml.go:526
sr := io.NewSectionReader(file,
    int64(b.meta.Tensors().Offset+t.Offset),
    int64(t.Size()))   // <-- t.Size() wraps to 4 via AP-020

// ml/backend/ggml/ggml.go:567-593
} else if strings.HasSuffix(t.Name, "_exps.bias") && t.Kind == 30 && tts[0]._type == 0 {
    bts := make([]byte, 128*format.KibiByte)
    var e uint64
    for e < t.Elements() {                  // <-- t.Elements() == 0x4000000000000001
        n, err := io.ReadFull(sr,
            bts[:min(len(bts),
                int(t.Elements()-e)*2)])    // <-- wraps to 0 on iteration 2
        // n == 0, e never advances -> infinite loop
        e += uint64(n / 2)
    }
}
```

Walkthrough with `Shape=[0x4000000000000001, 1]`, Kind=BF16, Name="blk.0.ffn_gate_exps.bias":
- `Elements()` = `0x4000000000000001` (no overflow check)
- `Size()` = `0x4000000000000001 * 2 / 1` = wraps to 2 (uint64 overflow)
- Iteration 0: diff=`0x4000000000000001`, `int(diff)=-9223372036854775807`, `*2=2`, reads 2 bytes, e→1
- Iteration 1: diff=`0x4000000000000000`, `int(diff)=-9223372036854775808`, `*2=0`, reads 0 bytes, e→1
- All further iterations: 0-byte reads, e stuck at 1, goroutine hangs

## Reproduction Steps

1. Craft a GGUF with one BF16 tensor named `blk.0.ffn_gate_exps.bias`,
   `Shape=[0x4000000000000001, 1]`, with 2 bytes of tensor payload.
2. Upload via `POST /api/create` with `FROM /path/to/crafted.gguf`.
3. Issue `POST /api/chat` or `/api/generate` to trigger model load.
4. Observe: the server hangs on model load; no response is ever returned;
   server logs show no error; restarting is the only recovery.

Fix: add overflow-checked `Elements()` computation (math/bits.Mul64) so that
an overflowed `Elements()` returns an error before entering the streaming loop;
add `if n == 0 { break }` guard in the streaming loop to detect stall.
