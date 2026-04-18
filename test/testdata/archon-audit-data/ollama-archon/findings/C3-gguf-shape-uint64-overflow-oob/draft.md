Phase: 8
Sequence: 003
Slug: gguf-shape-uint64-overflow-oob
Verdict: VALID
Rationale: Attacker-controlled Shape[] produces uint64 overflow in Tensor.Elements()/Size() which wraps Size() to a small value, defeating the tensorEnd > fileSize guard while leaving Elements() at its huge pre-wrap value; downstream unsafe.Slice(ptr, Elements()) + cgo ggml_fp16_to_fp32_row reads past the mmapped tensor region into adjacent memory.
Severity-Original: CRITICAL
Severity-Final: CRITICAL
PoC-Status: executed
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-02/debate.md

## Summary

`fs/ggml/ggml.go:505-514` computes `Tensor.Elements()` and `Tensor.Size()` using unchecked uint64 multiplication over the attacker-supplied `Shape []uint64`. A crafted `Shape = [0x4000000000000001, 1]` with `Kind = F32` causes `Elements() = 0x4000000000000001` and `Size() = (Elements * 4) mod 2^64 = 4` -- the bounds check at `fs/ggml/gguf.go:260` (`tensorEnd > uint64(fileSize)`) is satisfied by the wrapped `Size()`. Downstream call sites (`server/quantization.go:43`, `ml/backend/ggml/quantization.go:24`) still use the un-wrapped `Elements()` value to size `unsafe.Slice(ptr, Elements())`, producing a slice header declaring ~4.6 billion float32 entries backed by only 4 bytes of mapped storage. The slice is then passed to `C.ggml_fp16_to_fp32_row` which performs an OOB read, corrupting or disclosing adjacent process memory.

## Location

- `fs/ggml/ggml.go:505-514` -- `Tensor.Elements()` and `Tensor.Size()` (no overflow check)
- `fs/ggml/gguf.go:258-277` -- `Decode` bounds guard using the wrapped Size
- `server/quantization.go:43` -- `unsafe.Slice(ptr, Elements())` downstream
- `ml/backend/ggml/quantization.go:24` -- same primitive in ggml backend

## Attacker Control

Any caller who can push a GGUF into the blob store: `POST /api/create` with a Modelfile `FROM <path>` pointing at an attacker crafted file, `POST /api/pull` of a crafted registry model, or direct blob-upload via `POST /api/blobs/:digest`. All three are reachable from the unauthenticated loopback default.

## Trust Boundary Crossed

Network API (pull/create/blobs) -> process virtual memory, including cgo-owned pages.

## Impact

OOB read via `unsafe.Slice` fed to cgo. Depending on heap layout, consequences include:
- Information disclosure of adjacent mmapped tensors from OTHER models in the blob store (cross-tenant weight theft on shared hosts).
- Process crash via SIGSEGV when the read crosses a mapped-page boundary.
- Chain with PH-A-02 (size-only cache-hit from Chamber-01): a substituted blob turns every subsequent `/api/show`, `/api/tags`, or server restart into a persistent crash loop because `server/images.go:89` eagerly opens every blob for capability enumeration before any hash re-verification can fire.
- gin.Recovery middleware CANNOT mitigate: the OOB occurs inside cgo code without returning to Go's defer/recover machinery.

## Evidence

Tracer verification (Round 2):

```
// fs/ggml/ggml.go:505-514
func (t Tensor) Elements() uint64 {
    var count uint64 = 1
    for _, n := range t.Shape {
        count *= n      // <-- unchecked uint64 multiply
    }
    return count
}

func (t Tensor) Size() uint64 {
    return t.Elements() * t.typeSize() / t.blockSize()  // <-- wraps
}

// fs/ggml/gguf.go:258-262 -- bounds guard uses wrapped value
for _, tensor := range llm.tensors {
    tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()
    if tensorEnd > uint64(fileSize) {
        return fmt.Errorf(...)   // <-- bypassed when Size() wraps small
    }
```

Advocate 5-layer defense search (Round 3) found NO blocking protection:
- Language: Go has no unsigned multiply overflow check.
- Framework: gin.Recovery catches Go-side panics, but the OOB is cgo-side.
- Middleware: no request-body shape validation.
- Application: the bounds guard uses the wrapped Size, not the un-wrapped Elements.
- Runtime: `unsafe.Slice` does no length check; `C.ggml_fp16_to_fp32_row` has no length param.

## Reproduction Steps

1. Craft a GGUF with a single F32 tensor whose `Shape = [0x4000000000000001, 1]`, pad the tensor payload to 4 bytes.
2. `POST /api/create` with a Modelfile `FROM /path/to/crafted.gguf`.
3. Trigger quantize or inference: `POST /api/chat` targeting the created model.
4. Observe process behavior: either SIGSEGV (server exits), heap corruption detectable via subsequent request failures, or silent data corruption in another user's model weights.

Fix direction: replace `count *= n` with `math/bits.Mul64` overflow-detected multiply; replace the `tensorEnd > fileSize` guard with a check that derives `tensorEnd` from an overflow-safe Size computation; add defense-in-depth length check at every `unsafe.Slice(ptr, n)` call site to ensure `n * sizeof(elem) <= mapped_region`.
