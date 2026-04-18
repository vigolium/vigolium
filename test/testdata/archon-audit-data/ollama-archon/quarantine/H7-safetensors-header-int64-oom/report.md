## Summary

`convert/reader_safetensors.go:34-41` reads an int64 header length `n` from the safetensors file and immediately invokes `bytes.NewBuffer(make([]byte, 0, n))`. Go's `make([]byte, 0, n)` with huge n calls `runtime.mallocgc` -> `mheap.alloc` -> `mmap`, which on most hosts fails via `runtime: out of memory` -- unrecoverable. In addition the length field is signed (int64) whereas the safetensors specification declares it as uint64, so any value >= 2^63 on the wire is read as a negative int64.

## Details

`convert/reader_safetensors.go:34-41` reads an int64 header length `n` from the safetensors file and immediately invokes `bytes.NewBuffer(make([]byte, 0, n))`. Go's `make([]byte, 0, n)` with huge n calls `runtime.mallocgc` -> `mheap.alloc` -> `mmap`, which on most hosts fails via `runtime: out of memory` -- unrecoverable. In addition the length field is signed (int64) whereas the safetensors specification declares it as uint64, so any value >= 2^63 on the wire is read as a negative int64.

### Location

`convert/reader_safetensors.go:34-41`

### Attacker Control

Any safetensors file reaching `parseSafetensors`. Reached from both:
- `POST /api/create` with a Modelfile whose FROM references a directory containing `.safetensors` (invokes `convert.Convert` -> `parseTensors` -> `parseSafetensors`).
- `x/create/client.CreateSafetensorsModel` under the `--experimental` CLI gate (localhost-only).

### Trust Boundary Crossed

Network API / local filesystem -> process heap -> kernel OOM-killer.

### Evidence

```
// convert/reader_safetensors.go:34-41
var n int64
if err := binary.Read(f, binary.LittleEndian, &n); err != nil {
    return nil, err
}

b := bytes.NewBuffer(make([]byte, 0, n))   // allocates n bytes of cap
if _, err = io.CopyN(b, f, n); err != nil {
    return nil, err
}
```

Advocate (Round 3): `--experimental` + `isLocalhost` gate covers the `x/create` path but the non-experimental `convert.Convert` path via `POST /api/create` remains reachable without the flag.

## Root Cause

Validated rationale: parseSafetensors reads an int64 header length n from the attacker file and calls make([]byte, 0, n) with no cap; for n near MaxInt64 this triggers an unrecoverable OOM condition before io.CopyN could error out.

Primary cited code reference: `convert/reader_safetensors.go:34`.

Merge extraction sink line: `convert/reader_safetensors.go:34-41`

An adversarial review was preserved alongside the draft and should be consulted for counter-arguments and any severity challenge.

## Proof of Concept

Merge-normalized status: `executed`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Craft a safetensors file whose first 8 bytes are `\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F` (MaxInt64).
2. Place it in a directory along with a minimal `config.json`.
3. `POST /api/create` with a Modelfile that imports that directory.
4. Observe process OOM-kill.

Fix direction: change `n int64` to `n uint64` per spec; cap against file size (`n <= fileStat.Size() - 8`); explicit reject of `n <= 0`.

## Impact

Instant process kill on any host without multi-EB of virtual address space. gin.Recovery does NOT prevent kernel OOM-kill.

_Synthesized during merge normalization from `archon/findings/H7-safetensors-header-int64-oom/draft.md`._
