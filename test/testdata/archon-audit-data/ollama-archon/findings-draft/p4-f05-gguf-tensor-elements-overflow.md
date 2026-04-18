# p4-f05: GGUF Parser — Tensor.Elements() Multiplication Overflow

**Severity**: HIGH
**CWE**: CWE-190 (Integer Overflow)
**DFD Slice**: DFD-4 (HTTP body -> blob write -> GGUF parse)
**CVE Pattern**: Related to CVE-2024-8063, CVE-2025-0317

## Location

- `fs/ggml/ggml.go:505-511`: `Tensor.Elements()`
- `fs/ggml/ggml.go:513-515`: `Tensor.Size()`

## Description

```go
func (t Tensor) Elements() uint64 {
    var count uint64 = 1
    for _, n := range t.Shape {
        count *= n  // no overflow check
    }
    return count
}

func (t Tensor) Size() uint64 {
    return t.Elements() * t.typeSize() / t.blockSize()
}
```

`t.Shape` values are read directly from the GGUF file as `uint64`. A crafted tensor with `Shape = [2^32, 2^32]` causes `Elements()` to return 0 (overflow wraps to 0). Then `Size() = 0 * typeSize / blockSize = 0`.

Later validation in `gguf.Decode`:
```go
tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()
if tensorEnd > uint64(fileSize) { return error }
```
With `Size() = 0`, validation passes even for an out-of-bounds tensor. When the tensor data is subsequently read (in `llm/server.go` or the C++ runner), an out-of-bounds read occurs.

Additionally, `Tensor.Size()` divides by `blockSize()`, which always returns >= 1, so no div-by-zero here. However `typeSize()` returns 0 for unknown tensor kinds (`default:` case returns 0), causing `Size() = 0` and bypassing the bounds check.

## Evidence

- `fs/ggml/ggml.go:508` — `count *= n` without overflow check
- `fs/ggml/ggml.go:513-515` — `Size()` uses overflowed Elements()
- `fs/ggml/gguf.go:259-262` — bounds check uses the potentially-zero Size()

---

## Phase 7 Enrichment Verdict

**Classification**: SECURITY — likely security (bounds-check bypass enabling out-of-bounds read in C++ runner)

**Attacker Control**: Tensor shape dimensions are attacker-controlled fields in the GGUF binary. Any unauthenticated client can upload a crafted GGUF to `/api/blobs/:digest` and trigger this via `/api/create` or model load.

**Runtime**: The overflow occurs in the Go GGUF parser, but the resulting security impact occurs in the C++ llama.cpp runner (`llm/server.go` launches the C++ subprocess). The Go bounds check at `gguf.go:259` is the only guard before tensor data is handed to the C++ runner. An overflow causing `Size() = 0` bypasses this guard.

**Trust Boundary Crossed**: Network-to-server (Go parser) AND Go-to-C++ boundary (the unsafe tensor data crosses into C++ without bounds validation). The C++ runner is a memory-unsafe context — an OOB read there can be exploited for information disclosure or (with careful crafting) more serious memory corruption.

**Effect**: Potential information disclosure or memory corruption in C++ runner. At minimum, process crash (DoS). At maximum, depending on C++ runtime memory layout, arbitrary read or control flow influence.

**CodeQL Reachability**: No pre-computed slice. Manual trace: blob upload -> model load -> `gguf.Decode()` -> `tensor.Size()` uses overflowed `Elements()` -> bounds check at line 259 passes with `Size()=0` -> tensor offset/data passed to C++ runner. The C++ runner reads tensor data at the stored offset + claimed size; with size=0, it reads 0 bytes but the offset may be crafted to point outside the file mapping. Confirmed reachable.

**Exploit Prerequisites**: Same as p4-f03/f04 — network access to blob upload + model create/load endpoints.

**Verdict**: KEEP — HIGH security finding. The overflow-to-bounds-bypass is a more severe variant than pure DoS because it enables a garbage `Size()` value to reach C++ memory-unsafe code. Fix: use `math/bits.Mul64` to detect overflow in `Elements()`; validate `typeSize() > 0` before using the result in `Size()`.
