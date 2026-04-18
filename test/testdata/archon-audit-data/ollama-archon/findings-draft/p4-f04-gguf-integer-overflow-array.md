# p4-f04: GGUF Parser — Integer Overflow in readGGUFArray (uint64 -> int cast)

**Severity**: HIGH
**CWE**: CWE-190 (Integer Overflow), CWE-125 (Out-of-Bounds Read)
**DFD Slice**: DFD-4 (HTTP body -> blob write -> GGUF parse)
**CVE Pattern**: Matches CVE-2025-1975, CVE-2024-39720

## Location

- `fs/ggml/gguf.go:430-437`: `readGGUFArray()`

## Description

```go
// fs/ggml/gguf.go:430-437
n, err := readGGUF[uint64](llm, r)  // array count from untrusted GGUF
...
case ggufTypeUint8:
    a := newArray[uint8](int(n), llm.maxArraySize)  // uint64 -> int TRUNCATION
```

`int(n)` on a 64-bit system: if `n > math.MaxInt` (e.g., `n = 0x8000000000000001`), the cast wraps to a negative value. `newArray` then checks `size <= maxSize`:

```go
func newArray[T any](size, maxSize int) *array[T] {
    a := array[T]{size: size}
    if maxSize < 0 || size <= maxSize {
        a.values = make([]T, size)  // make([]T, negative_int) → panic
    }
    return &a
}
```

When `maxSize < 0` (callers using `-1`), `make([]T, size)` with a negative `size` panics. When `maxSize >= 0`, the comparison `size <= maxSize` with a negative `size` is true (negative < positive), causing the same panic-inducing `make`.

This is a panic/crash (DoS) on any GGUF with a crafted array count field.

## Evidence

- `fs/ggml/gguf.go:437` — `int(n)` cast without overflow check
- `fs/ggml/gguf.go:418-420` — `make([]T, size)` called when `maxSize < 0 || size <= maxSize`
- `server/create.go:468,684`, `server/model.go:65` — callers use `maxArraySize = -1`

---

## Phase 7 Enrichment Verdict

**Classification**: SECURITY — likely security (DoS against server process)

**Attacker Control**: Same attack surface as p4-f03. The array count is an attacker-controlled 64-bit field in the GGUF binary. Any unauthenticated client with blob upload capability can trigger this.

**Runtime**: `ollama serve` HTTP server process. The panic is an unrecovered Go runtime panic, crashing the server goroutine (and potentially the entire process depending on panic recovery placement).

**Trust Boundary Crossed**: Network-to-server. Unauthenticated remote attacker crashes server.

**Effect**: Denial of service. Same cross-user impact as p4-f03.

**CodeQL Reachability**: No pre-computed slice. Manual trace identical to p4-f03 up to `readGGUFArray()`. The `int(n)` cast at line 437 is on the hot path for any GGUF with array-type KV entries (which is nearly all GGUF files). Confirmed reachable.

**KB Cross-Reference**: CVE-2025-1975 (OOB array index from spoofed manifest) and CVE-2024-39720 (OOB read from 4-byte malformed GGUF) match this pattern. Both are rated HIGH (CVSS 7.5). The KB identifies the GGUF parser as the highest-heat component with 9 advisories.

**Exploit Prerequisites**: Same as p4-f03 — network access, no auth required.

**Verdict**: KEEP — HIGH security finding. Can be consolidated with p4-f03 and p4-f05 as a GGUF parser bounds-checking cluster for Phase 8. Each has a distinct code location and distinct CWE. Fix: validate `n` against `math.MaxInt` before cast; reject GGUF files with array counts exceeding a reasonable maximum.
