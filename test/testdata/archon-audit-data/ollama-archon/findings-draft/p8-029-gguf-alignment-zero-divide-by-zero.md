Phase: 8
Sequence: 029
Slug: gguf-alignment-zero-divide-by-zero
Verdict: VALID
Rationale: ggufPadding(offset, align) computes (align - offset%align) % align with no validation that align != 0; kv.Uint("general.alignment", 32) returns 0 when the attacker sets the key to 0 (default fires only on missing key); reached from Decode during any parse, and from fixBlobs during GC so a poisoned blob survives delete attempts.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-02/debate.md

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: 57-byte crafted GGUF reproduces "runtime error: integer divide by zero" at fs/ggml/gguf.go:688 via Decode (stack trace captured); fs/gguf already uses cmp.Or so the oversight is confirmed. Severity reduced to MEDIUM: gin.Recovery converts HTTP-path panic to 500, and the draft's fixBlobs chain claim is factually incorrect (fixBlobs only renames ":" to "-", it does not call Decode).
Severity-Final: MEDIUM
PoC-Status: executed

## Summary

`fs/ggml/gguf.go:687-689` implements `ggufPadding(offset, align int64) int64 { return (align - offset%align) % align }` with no guard against `align == 0`. `fs/ggml/gguf.go:238` reads alignment as `llm.kv.Uint("general.alignment", 32)` -- the default 32 only applies when the key is ABSENT; if the attacker declares `general.alignment = 0`, `Uint` returns 0 and the subsequent `ggufPadding(offset, int64(alignment))` at line 245, 573, and 580 panics with "integer divide by zero".

Note: the parallel implementation in `fs/gguf` uses `cmp.Or(attribute_value, 32)` which DOES rescue the zero case. `fs/ggml` and `fs/gguf` are inconsistently hardened.

## Location

- `fs/ggml/gguf.go:687-689` -- `ggufPadding` without zero-check
- `fs/ggml/gguf.go:238` -- `alignment := llm.kv.Uint("general.alignment", 32)`
- `fs/ggml/gguf.go:245, 573, 580` -- three call sites reachable under normal Decode

## Attacker Control

Any GGUF blob. Reached from `/api/create`, `/api/pull`, `/api/show`, and from `fixBlobs` during blob-store GC.

## Trust Boundary Crossed

Network API -> process panic. Chained with `ollama rm`/`fixBlobs`, panic during cleanup leaves the poisoned blob on disk indefinitely.

## Impact

- HTTP path: gin.Recovery catches -> 500 per request. `/api/show` on the poisoned blob always fails.
- Model-load path (`ml/backend/ggml`): panics here exit the goroutine; scheduler behavior uncertain.
- `fixBlobs` GC path: panic during blob scan leaves the blob orphaned but on-disk. Attacker's poisoned content is now uncollectable.
- Chain with PH-A-02 (Chamber-01): size-only cache-hit substitution places the poisoned blob; every subsequent `/api/show` panics and the server is in a persistent 500 loop for any query touching that model.

## Evidence

```
// fs/ggml/gguf.go:687-689
func ggufPadding(offset, align int64) int64 {
    return (align - offset%align) % align    // offset%0 panics
}

// fs/ggml/gguf.go:238, 245
alignment := llm.kv.Uint("general.alignment", 32)
...
padding := ggufPadding(offset, int64(alignment))
```

Contrast with `fs/gguf/gguf.go` which uses `cmp.Or(alignment, 32)` -- inconsistent hardening.

## Reproduction Steps

1. Craft a GGUF declaring `general.alignment = uint32(0)` KV value (ggufTypeUint32).
2. `POST /api/create` referencing the blob.
3. Observe 500 response; attempt `ollama rm` and `fixBlobs` -- blob remains on disk.

Fix direction:
- Replace `llm.kv.Uint("general.alignment", 32)` with the `cmp.Or` variant used in `fs/gguf`.
- Add explicit guard at `ggufPadding` entry: `if align <= 0 { return 0 }` or return an error.
- Unify alignment parsing across `fs/ggml` and `fs/gguf`.
