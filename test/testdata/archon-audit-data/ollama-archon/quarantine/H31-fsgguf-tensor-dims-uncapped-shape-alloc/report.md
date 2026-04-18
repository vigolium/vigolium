## Summary

`fs/gguf/gguf.go:99-110` (`readTensor`) reads a `uint32 dims` from the file and immediately allocates `shape := make([]uint64, dims)` with no cap. Inside the lazy tensor-count loop (p10-023-a), each iteration calls `readTensor`, so a GGUF that declares `numTensor = N` and sets `dims = 0xFFFFFFFF` in the first tensor record causes a single `make([]uint64, 4294967295)` = **32 GB allocation** before any other tensor is read.

This is the inner allocation that the confirmed AP-023 loop produces. The outer loop (p10-023-a) would keep trying to allocate 32 GB on each successive tensor until the process is killed. Even a single tensor with this `dims` value triggers an OOM in `gguf.Open`, which is called from `server/images.go:89` during every `/api/show` request.

The equivalent code in `fs/ggml/gguf.go:206` does the same (`shape := make([]uint64, dims)`) and is also uncapped, but `fs/ggml/` is partially gated by `maxArraySize` for KV arrays. Neither parser caps `dims` for shape allocation.

## Details

`fs/gguf/gguf.go:99-110` (`readTensor`) reads a `uint32 dims` from the file and immediately allocates `shape := make([]uint64, dims)` with no cap. Inside the lazy tensor-count loop (p10-023-a), each iteration calls `readTensor`, so a GGUF that declares `numTensor = N` and sets `dims = 0xFFFFFFFF` in the first tensor record causes a single `make([]uint64, 4294967295)` = **32 GB allocation** before any other tensor is read.

This is the inner allocation that the confirmed AP-023 loop produces. The outer loop (p10-023-a) would keep trying to allocate 32 GB on each successive tensor until the process is killed. Even a single tensor with this `dims` value triggers an OOM in `gguf.Open`, which is called from `server/images.go:89` during every `/api/show` request.

The equivalent code in `fs/ggml/gguf.go:206` does the same (`shape := make([]uint64, dims)`) and is also uncapped, but `fs/ggml/` is partially gated by `maxArraySize` for KV arrays. Neither parser caps `dims` for shape allocation.

### Location

`fs/gguf/gguf.go:99-110` — `(*File).readTensor`

```go
func (f *File) readTensor() (TensorInfo, error) {
    name, err := readString(f)
    ...
    dims, err := read[uint32](f)    // dims is raw uint32 from wire — uncapped
    ...
    shape := make([]uint64, dims)   // allocates 8*dims bytes — up to 32 GB
    for i := range dims {
        shape[i], err = read[uint64](f)
        ...
    }
    ...
}
```

Also present in `fs/ggml/gguf.go:201-212`:

```go
dims, err := readGGUF[uint32](llm, rs)
...
shape := make([]uint64, dims)       // same uncapped pattern in the older parser
for i := 0; uint32(i) < dims; i++ {
    shape[i], err = readGGUF[uint64](llm, rs)
    ...
}
```

### Attacker Control

The call chain is identical to p10-023-a:

1. Attacker pulls or creates a model referencing a crafted GGUF blob.
2. `server/images.go:89` calls `gguf.Open(m.ModelPath)`.
3. `gguf.Open` calls `newLazy(f, f.readTensor)` which starts the lazy tensor iterator.
4. The first call to `readTensor` reads `dims = 0xFFFFFFFF` and calls `make([]uint64, 4294967295)`.
5. Go runtime attempts a 32 GB allocation.

Alternatively, the same `dims` field in `fs/ggml/gguf.go:206` is triggered via `ggml.Decode(blob, -1)` called from `server/create.go:687` during GGUF model upload/creation.

### Trust Boundary Crossed

Network API (unauthenticated by default) / model blob -> process heap -> kernel OOM-killer.

### Evidence

```go
// fs/gguf/gguf.go:99-110
dims, err := read[uint32](f)       // raw uint32 from file: 0..4294967295
...
shape := make([]uint64, dims)      // 8 * 4294967295 = 34359738360 bytes ≈ 32 GB
for i := range dims {
    shape[i], err = read[uint64](f)
    ...
}

// fs/ggml/gguf.go:201-212 (same uncapped pattern in the older parser)
dims, err := readGGUF[uint32](llm, rs)
...
shape := make([]uint64, dims)
for i := 0; uint32(i) < dims; i++ {
    shape[i], err = readGGUF[uint64](llm, rs)
```

No cap exists in either parser for `dims`. The confirmed AP-023 finding mentions `shape := make([]uint64, dims)` at line 206 of `fs/ggml/gguf.go` but treats it as secondary. This finding elevates it as a primary attack vector in both parsers.

## Root Cause

Validated rationale: fs/gguf/gguf.go readTensor reads dims as uint32 from wire and calls make([]uint64, dims) with no cap; a single crafted tensor record with dims=0xFFFFFFFF triggers a 32 GB allocation inside the lazy tensor-count loop, compounding the AP-023 heap-exhaustion effect.

Primary cited code reference: `fs/gguf/gguf.go:99`.

Merge extraction sink line: `fs/gguf/gguf.go:99-110` — `(*File).readTensor`

This finding was retained as a variant during merge normalization. Origin finding: `H6`. Origin pattern: `AP-023`.

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Craft a GGUF v3: magic=`GGUF`, version=3, numTensor=1, numKV=0.
   Tensor record: name-length=5, name="evil\x00", dims=0xFFFFFFFF (uint32 max),
   then immediately EOF (no shape elements needed — the crash occurs at `make`).
   Total file size: ~25 bytes.
2. Upload blob via `POST /api/blobs/sha256:<digest>`, reference in `POST /api/create` or `POST /api/pull`.
3. Issue `GET /api/show?name=<model>` or any API call that triggers `Capabilities()`.
4. `gguf.Open` → `newLazy` → `readTensor` → `make([]uint64, 4294967295)` → OOM / panic.

Fix direction: cap `dims` before `make`:
```go
const maxTensorDims = 8
dims, err := read[uint32](f)
if dims > maxTensorDims {
    return TensorInfo{}, fmt.Errorf("tensor dims %d exceeds limit %d", dims, maxTensorDims)
}
shape := make([]uint64, dims)
```
Apply the same cap in `fs/ggml/gguf.go:201`.

## Impact

A single GGUF tensor record with `dims=0xFFFFFFFF` causes an immediate 32 GB allocation attempt in `readTensor`. The Go runtime calls `runtime.mallocgc` which either:
- Succeeds but immediately starves all other heap users (on servers with very large swap),
- Or triggers the kernel OOM-killer before the allocation completes.

Unlike p10-023-a (gradual per-tensor growth) and p10-023-b (single-KV-array large alloc), this variant combines both: the outer tensor-count loop drives the inner shape allocation. A GGUF with `numTensor=5` and `dims=0xFFFFFFFF` in each tensor would attempt 5 × 32 GB = 160 GB before file-EOF stops the loop.

The GGUF need only be a few hundred bytes (magic + header + numTensor + numKV + first tensor partial record) — the process crashes before finishing the first read.

_Synthesized during merge normalization from `archon/findings/H31-fsgguf-tensor-dims-uncapped-shape-alloc/draft.md`._
