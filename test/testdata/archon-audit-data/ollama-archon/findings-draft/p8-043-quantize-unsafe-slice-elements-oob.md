Phase: 8
Sequence: 043
Slug: quantize-unsafe-slice-elements-oob
Verdict: VALID
Rationale: Tracer confirmed the F32 path of `server/quantization.go:43` constructs `unsafe.Slice(ptr, q.from.Elements())` where `Elements()` is the un-wrapped attacker-supplied shape product; the subsequent `ggml.Quantize(newType, f32s, q.from.Shape)` iterates the over-length slice past `data`'s backing array, producing an OOB read of Go heap memory — distinct from the mmap-backed OOB in chamber-02 p8-020 because the source buffer is a bounded `io.ReadAll` of the (wrap-sized) `Size()` and the over-read enters Go-managed heap adjacent to it.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-03/debate.md

## Summary

Chamber-02 p8-020 already documents the `fs/ggml/ggml.go:505-514` uint64 overflow in `Elements()` / `Size()`. This chamber-03 finding documents a distinct sink reached by the same primitive: the quantize path at `server/quantization.go:26-47`. The `io.NewSectionReader` reads `Size()` bytes (wrapped small) into `data`. Then:

- For the F32 type branch at line 43: `f32s = unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())` creates a Go slice whose length is the un-wrapped `Elements()` (e.g., `2^62`) but whose backing array is only `len(data)` = wrap-sized bytes.
- For non-F32: `ml/backend/ggml/quantization.go:20` calls `make([]float32, nelements)` which OOM-panics immediately (DoS) rather than reading past the buffer.

Downstream `ggml.Quantize(newType, f32s, q.from.Shape)` iterates `f32s` for up to `shape[0] * shape[1] * ...` = `2^62` float32 values. The read proceeds past `data`'s backing store into adjacent Go heap — which on a busy daemon contains other active HTTP request bodies, auth tokens, and the in-memory copy of `~/.ollama/id_ed25519`. Unlike chamber-02 p8-020 (OOB into mmap'd tensors of other models on disk), this OOB lands in live Go heap.

## Location

- `server/quantization.go:26` -- `sr := io.NewSectionReader(q, int64(q.offset), int64(q.from.Size()))` — reads wrap-sized small buffer
- `server/quantization.go:37-38` -- `if uint64(len(data)) < q.from.Size()` — bypassed when wrapped `Size()` equals actual bytes read
- `server/quantization.go:43` -- `f32s = unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())` — SLICE HEADER LIES about length
- `server/quantization.go:47` -- `data = ggml.Quantize(newType, f32s, q.from.Shape)` — iteration reads OOB
- `fs/ggml/ggml.go:505-514` -- `Elements()` / `Size()` overflow root (cross-ref p8-020)

## Attacker Control

Same as p8-020: any caller who can push a GGUF into the blob store — `POST /api/blobs/:digest` + `POST /api/create` with `r.Quantize="q4_0"` (or any non-F16/F32 target that triggers the F32-intermediate branch) and a tensor `Shape = [0x4000000000000001, 1]` with `Kind = F32` padded to small bytes.

## Trust Boundary Crossed

Unauthenticated HTTP upload -> Go heap of the parent `ollama serve` process (distinct from p8-020's mmap'd tensor heap).

## Impact

OOB read of Go heap via the slice-header lie. The quantization function encodes each over-read float32 into the output blob, so the leaked heap contents are preserved (scrambled by the quantization format) in the tensor file attacker receives. Chain with p8-020: chamber-02's finding leaks mmap'd tensor data; this one leaks Go-managed heap — bearer tokens, mTLS material, other tenants' prompt bodies. Both should be fixed by the same root-cause fix in `fs/ggml/ggml.go` (`math/bits.Mul64` overflow-detected multiply in `Elements()` and `Size()`), but the quantize sink may also need a belt-and-suspenders check `if q.from.Elements() > uint64(len(data) / 4) { return error }` at line 42.

## Evidence

Tracer verification (Round 2, H-00.01 and H-CHAIN-A.1, 2026-04-17T07:01-07:15):

```
server/quantization.go:26-47
    sr := io.NewSectionReader(q, int64(q.offset), int64(q.from.Size()))
    data, _ := io.ReadAll(sr)
    if uint64(len(data)) < q.from.Size() { return 0, fmt.Errorf(...) }
    ...
    case fsggml.TensorTypeF32:
        f32s = unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())  // OOB view
    default:
        f32s = ggml.ConvertToF32(data, q.from.Kind, q.from.Elements())  // make() OOMs first
    ...
    data = ggml.Quantize(newType, f32s, q.from.Shape)
```

Advocate Round 1 H-00.01 brief acknowledged: "`make([]float32, nelements)` allocation with `nelements = shape-product` will typically hit Go's allocator ceiling... converting the intended memory-disclosure primitive into a DoS." Synth disposition: this is true for the non-F32 branch (p8-020 also notes it). The F32 branch at line 43 uses `unsafe.Slice`, NOT `make` — no allocation occurs and no ceiling applies. Advocate did not address the F32 branch separately.

Tracer chain trace (H-CHAIN-A.1, 2026-04-17T07:15): step 1 OOB-read is REACHABLE; step 2 (exfil through `/api/embed`) is complicated by quantization encoding acting as a scrambler, but the first step by itself is a confirmed OOB read primitive.

## Reproduction Steps

1. Craft a GGUF with one tensor: `Shape = [0x4000000000000001, 1]`, `Kind = F32`, padded to 4 bytes on disk (to satisfy `tensorEnd > fileSize` through wrap).
2. `POST /api/blobs/sha256:<digest>` uploading the crafted GGUF.
3. `POST /api/create` with `{"model":"evil","from":"sha256:<digest>","quantize":"q4_0"}` to trigger the quantize + F32-intermediate branch.
4. Observe Go heap OOB read; the resulting q4_0 tensor file encodes adjacent-heap bytes.
5. Fix direction: fix `Elements()` with overflow-detected multiply (p8-020), AND add a pre-unsafe.Slice invariant check at `server/quantization.go:42` asserting `Elements() * 4 <= uint64(len(data))`.

Pattern: reuse AP-020 (chamber-02) + register sub-pattern AP-044 for "unsafe.Slice over attacker-derived Elements() count at quantize sink".
