# Patch 9d902d63 — `ggml: ensure tensor size is valid`

- **Type**: undisclosed-fix (silent security fix)
- **Cluster ID**: gguf-parser-recurrence (siblings: CVE-2024-39720, CVE-2024-12055, CVE-2025-0315)
- **Files**: `fs/ggml/gguf.go`, `server/quantization.go`
- **Tag**: `[undisclosed]`

## Patch Summary

Two related additions:

1. `fs/ggml/gguf.go` `(*gguf).Decode`: after parsing tensor metadata, the parser now seeks to end-of-file, captures `fileSize`, seeks back, and for each tensor computes
   `tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()` and rejects when `tensorEnd > uint64(fileSize)`.
2. `server/quantization.go` `(quantizer).WriteTo`: after `io.ReadAll(sr)`, rejects when `uint64(len(data)) < q.from.Size()`.

The motivation is to refuse GGUF files whose tensor info table claims tensor data extending past the on-disk byte range. Pre-patch, `Decode` would happily accept such metadata; downstream consumers (`ml/backend/ggml/ggml.go` weight loader, `server/quantization.go` quantizer, `model/model.go` model loader) all derive their read positions from `Tensors().Offset + tensor.Offset` and a length of `tensor.Size()`. With a crafted GGUF, those `io.NewSectionReader` calls would either silently truncate, produce uninitialized buffers, or — combined with the quantizer's `unsafe.Slice` over `q.from.Elements()` — produce out-of-bounds reads via cgo dequantize routines.

## Bypass Hypotheses Tested

### 1. Integer overflow in `tensor.Size()` / `tensor.Elements()` (CRITICAL — likely bypassable)

`fs/ggml/ggml.go:505-515`:
```go
func (t Tensor) Elements() uint64 {
    var count uint64 = 1
    for _, n := range t.Shape {
        count *= n     // unchecked uint64 wrap
    }
    return count
}

func (t Tensor) Size() uint64 {
    return t.Elements() * t.typeSize() / t.blockSize()   // multiply also wraps
}
```

The shape entries are fully attacker-controlled `uint64` values from the GGUF tensor info section (`fs/ggml/gguf.go:206-212`). Crafting `Shape = [1<<62 + 1, 1]` with `Kind = TensorTypeF32` (typeSize 4, blockSize 1) gives `Elements()` = `2^62 + 1`, `Size()` = `(2^62 + 1) * 4` = `2^64 + 4` which wraps to `4`.

Consequences:

- The new bounds check `tensorOffset + tensor.Offset + Size()` evaluates against the wrapped `Size()=4`, so `tensorEnd` is small and the check trivially passes regardless of declared shape.
- In `server/quantization.go:24-43`, `sr := io.NewSectionReader(q, ..., int64(q.from.Size()))` reads only 4 bytes; the new short-data guard `uint64(len(data)) < q.from.Size()` also uses the wrapped Size, so 4 bytes satisfies it. Then:
  ```go
  f32s = unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())
  ```
  uses raw `Elements()` = `2^62 + 1` — a slice header with a hugely-larger-than-backing length, immediately enabling OOB memory disclosure when `f32s` is iterated or passed to cgo.
- The non-F32 branch is worse: `ConvertToF32(data, q.from.Kind, q.from.Elements())` (`ml/backend/ggml/quantization.go:19-21`) does `make([]float32, nelements)` with `nelements = 2^62+1`. If allocation succeeds (or the value wraps further inside `make`), it then calls `C.ggml_fp16_to_fp32_row(... &data[0], &f32s[0], int64(nelements))` which dereferences `data[0]` and reads `nelements` source elements — wild OOB read into adjacent process memory, exploitable through quantize endpoint.
- Same overflow primitive also applies to the upstream `tensorOffset + tensor.Offset` summation. An attacker can pick `tensor.Offset` so the full sum wraps to a small positive value, passing the bounds check while the loader (`ml/backend/ggml/ggml.go:526`) reads from a confused absolute file offset.

The patch is therefore **bypassable** for the same vulnerability class it claims to fix, via the unguarded multiplication in `Elements()` / `Size()`.

### 2. Negative `fileSize` cast

`rs.Seek(0, io.SeekEnd)` returns int64. The patch does `uint64(fileSize)`. A custom `io.ReadSeeker` that returns a negative offset (not possible with `*os.File`, but production code wraps `rs` with `bufioutil.NewBufferedSeeker` and downstream tests pass arbitrary seekers) would wrap to a huge `uint64`, allowing tensorEnd to "fit". For the on-disk path this is not exploitable today.

### 3. Parallel parser at `fs/gguf` lacks the bounds check (sound for now)

`fs/gguf/gguf.go` is a separate, lazy GGUF parser used by `server/images.go:89` for capability detection (`gguf.Open` then `KeyValue` lookups). `fs/gguf/gguf.go:338-347` `TensorReader` returns `io.NewSectionReader(f.file, f.offset+int64(t.Offset), t.NumBytes())` with NO bounds check at all. `t.NumBytes()` is a float64 cast (`fs/gguf/tensor.go:28-30`) and `NumValues()` is signed int64 multiplication of arbitrary `Shape` values — also overflowable.

Production callers of `TensorReader` in this repo are test-only today (`fs/gguf/gguf_test.go`, `model/models/gemma4/tokenizer_reference_test.go`), so this is **latent**, not an active bypass. But the patch did not unify the two parsers, leaving an unguarded sibling that future code may pick up.

### 4. v1 / v2 / v3 differential

All three GGUF versions share the same `(*gguf).Decode`; the patch is applied uniformly. Note that `Decode` reads tensor `offset` and each `shape[i]` as `uint64` even for v1 files (where the spec uses uint32). This pre-existing parser confusion does not bypass the new bounds check but does mean v1 files with junk high bits land into the same overflow gadget described in #1.

### 5. KV / metadata side channel

The bounds check only covers tensor data. KV strings (`readGGUFString`) and arrays (`readGGUFArray`) bypass it entirely. They are unbounded by `maxArraySize`/string-length validation against file size: a crafted nested array element count of `2^63` will cause `make([]T, n)` to OOM or panic, and `readGGUFString` does `make([]byte, length)` with length read directly from the file. Class-equivalent to CVE-2025-66959 territory but **out of scope** for this patch — confirms the patch is narrow and this remains a recurrence target.

### 6. Compatibility / alternate entry points

- `ml/backend/ggml/ggml.go` weight loader: routes through `fsggml.Decode` → covered by patch.
- `model/model.go:150` `fsggml.Decode(r, -1)` → covered.
- `server/create.go:471, 653, 687` and `server/model.go:66` quantize/import paths → covered.
- `llama/llama.go:308` `C.llama_model_load_from_file` shim — bypasses Go-side validation entirely, relies on upstream llama.cpp bounds checks. Not an Ollama-side bypass but worth flagging.

### 7. mmap vs read differential

The Ollama Go side does not mmap the GGUF directly; ggml.cpp may, behind the cgo `New` call. The Go-side bounds check is moot for that path — but again, that's outside the patch's intended scope.

### 8. Double-counted padding

`Decode` adds per-tensor `padding` between tensor data, but the bounds check uses `tensorOffset + tensor.Offset + Size()` without including inter-tensor padding for the *last* tensor. If a writer pads after the last tensor (`WriteGGUF` uses `s += ggufPadding(...)` after each tensor info, including the trailing one — `fs/ggml/gguf.go:572-574`), an attacker's last tensor that exactly equals `fileSize - tensorOffset - lastOffset` passes the check, but the seek-loop in `Decode` (`gguf.go:269-275`) also seeks an additional padding past the last tensor, which can land at or past EOF without erroring on the buffered seeker. Minor; not a meaningful bypass on its own.

## Conclusion

**Verdict**: `bypassable`.

The added `tensorEnd > fileSize` check is necessary but not sufficient because it is computed from `tensor.Size()`, which is an unchecked product of attacker-controlled `Shape[]` and `typeSize()` values. A crafted shape that wraps the `uint64` multiplication in `Tensor.Elements()` produces a tiny `Size()` that satisfies the new guard while `Elements()` continues to return the un-wrapped, enormous value used directly by `unsafe.Slice` in `server/quantization.go:43` and by `ConvertToF32` in `ml/backend/ggml/quantization.go:19-21`. The result is an exploitable OOB read / cgo memory corruption primitive reachable through any code path that ingests an attacker-supplied GGUF (model creation, model import, quantization).

The patch is best characterized as **relocated**: the seek-past-EOF crash is fixed, but the same root cause (unvalidated tensor metadata) is still reachable through the `Elements()` / `Size()` arithmetic and through the still-unbounded sibling parser at `fs/gguf/gguf.go`.

## Notes for Phase 5/8

- **Primary follow-up**: `Tensor.Elements()` and `Tensor.Size()` need overflow-checked arithmetic (e.g., `math/bits.Mul64`, or sequential `bits.Mul64`-with-carry over `Shape`). Both call sites — the new bounds check in `gguf.go:259` AND the `unsafe.Slice` / `make([]float32, nelements)` in `quantization.go` — must agree on a sentinel error rather than silently wrapping.
- **Recommend additional guard**: cap `len(Shape) * each dim` against fileSize before the bounds check, e.g. reject when `Elements() == 0` for non-empty `Shape` (overflow indicator), or compute `Size()` with explicit overflow detection and return error from `Decode`.
- **Sibling parser**: `fs/gguf/gguf.go:338` `TensorReader` and `fs/gguf/tensor.go:28` `NumBytes` lack any bounds check. Any future production caller will inherit the original CVE pattern.
- **KV-side recurrence target**: `readGGUFString` (`gguf.go:348`) and `readGGUFArray` (`gguf.go:424`) trust file-supplied lengths for `make`, sibling to CVE-2025-66959-class issues. Patch does not address these.
- **Pair with `expert_used_count` / KV trust**: many quantization decisions key off `kv.Uint("expert_count", 0)` etc.; out-of-range values may interact with the overflow primitive to make exploitation easier.
- **Confidence**: high. Bypass is mechanical from reading the diff plus `ggml.go` Size/Elements implementation; a one-page Go fuzz target over `Decode` + `quantize` should reproduce the crash.
