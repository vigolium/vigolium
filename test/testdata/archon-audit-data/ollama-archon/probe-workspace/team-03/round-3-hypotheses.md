# Round 3 Hypotheses: Causal-Verifier-03

## Reasoning Approach
Counterfactual intervention tests: for each cross-model seed and surviving NEEDS-DEEPER item, identify the minimal change that would prevent the vulnerability and verify whether that change is present in the code. If absent, the vulnerability is confirmed causal.

---

## PH-R3-01: CONFIRMED — Unbounded Allocation via Array Count (CROSS-01 causal trace)

**Counterfactual**: IF `newArray` had a check `if size > someMaximum { return error }`, the allocation would be prevented.
**Current code** (`gguf.go:416-421`):
```go
func newArray[T any](size, maxSize int) *array[T] {
    a := array[T]{size: size}
    if maxSize < 0 || size <= maxSize {
        a.values = make([]T, size)
    }
    return &a
}
```
No maximum exists for size itself. When maxSize=-1, `make([]T, size)` is called for ALL values of size.

**Intervention test**: Set maxArraySize=0 (not -1) in `ggufLayers`. With maxArraySize=0: `0 < 0` is false, `size <= 0` is only true for size=0. So ANY non-empty array would NOT be allocated — array values would be nil. This would prevent the OOM but ALSO break all functionality that reads array KV values. CONFIRMS: there is no safe default. The parameter was designed for performance control, not security hardening.

**Causal mechanism confirmed**: The allocation path `make([]T, int(n))` is called unconditionally when maxArraySize=-1. The `int(n)` cast from uint64 can produce values up to MaxInt64 (about 9.2×10^18 bytes), which will cause OOM before the runtime can panic. Values near MaxInt64 will cause the runtime to panic with "makeslice: len out of range" if they exceed the platform's addressable memory.

**Target**: `fs/ggml/gguf.go:416-421` — `newArray` + `fs/ggml/gguf.go:437` — called from `readGGUFArray`
**Attack input**: GGUF with KV entry type=ggufTypeArray, element_type=ggufTypeUint8, n=0x40000000 (1 billion elements = 1GB)
**Minimum viable exploit**: 4+4+8 + 4+8 bytes header + KV type/count bytes = ~34 bytes of GGUF metadata. File must also contain 1GB of uint8 data for the array (since `readGGUFArrayData` reads actual bytes via `binary.Read`). Alternatively: use a sparse file or exploit that `io.ReadFull` returns EOF midway — but this causes an error return, not OOM.
**Revised assessment**: The OOM requires the attacker to ALSO provide the actual array data bytes. So a 1GB array requires a 1GB file upload. This is rate-limited by upload bandwidth and server storage quotas. HOWEVER: there is no upload size limit in `CreateBlobHandler` — the server reads the entire request body.
**Security consequence**: DoS via 1GB upload causing 1GB memory allocation. More efficiently: multiple concurrent requests with 100MB uploads each, each triggering 100MB allocations.
**Severity estimate**: HIGH
**Validation status**: VALIDATED (causal; bypassing requires adding a max allocation check)

---

## PH-R3-02: CONFIRMED — Panic via Negative int in readGGUFString (PH-02 causal trace)

**Counterfactual**: IF `readGGUFString` checked `if length < 0 || length > maxStringSize { return "", fmt.Errorf(...) }`, the panic would be prevented.
**Current code** (`gguf.go:359-364`):
```go
length := int(llm.ByteOrder.Uint64(buf))
if length > len(llm.scratch) {
    buf = make([]byte, length)
} else {
    buf = llm.scratch[:length]
}
```
For uint64 value `0x8000000000000000`: `int(0x8000000000000000)` on 64-bit = `-9223372036854775808` (MinInt64).
- `MinInt64 > 16384` → false → `buf = llm.scratch[:MinInt64]` → **panic: runtime error: slice bounds out of range**

For uint64 value `0x7FFFFFFFFFFFFFFF`: `int(0x7FFFFFFFFFFFFFFF)` = `9223372036854775807` (MaxInt64).
- `MaxInt64 > 16384` → true → `buf = make([]byte, 9223372036854775807)` → **OOM / panic: makeslice: len out of range**

**Intervention test**: Add check `if length < 0 || length > 1<<20 { return "", fmt.Errorf("string too long") }` — would prevent both cases. No such check exists.

**Causal mechanism confirmed**: The uint64→int cast is unchecked. For string lengths ≥ 2^63, the slice indexing panics.

**Attack input**: GGUF file where first KV key length field is set to 0x8000000000000000. Since the key length is the very first data read after the header, this is an 8-byte string length field.
**Minimum viable exploit file size**: 4 (magic) + 4 (version) + 8 (numTensor) + 8 (numKV=1) + 8 (key_length = 0x8000000000000000) = 32 bytes total
**Security consequence**: Server panic (crash) — 32-byte file sent via POST /api/blobs/:digest + POST /api/create → immediate process crash
**Severity estimate**: HIGH (DoS; 32-byte file causes immediate panic)
**Validation status**: VALIDATED (strongest finding — minimal file, immediate impact)

---

## PH-R3-03: CONFIRMED — Unknown Tensor Kind Bypasses Bounds Check via TypeSize()=0 (new finding)

**Discovery source**: Direct code inspection during causal analysis of PH-09/PH-16 (CROSS-02)
**Target**: `fs/ggml/ggml.go:513-515` — `Tensor.Size()` + `fs/ggml/gguf.go:258-262` — bounds check

**Causal chain**:
1. `Tensor.Kind` is read directly from file as uint32 (gguf.go:214)
2. `TypeSize()` at ggml.go:436 uses a switch with `default: return 0`
3. For any unknown/undocumented Kind value (e.g., 9999): `typeSize() = 0`
4. `BlockSize()` default returns 256
5. `Size() = Elements() * 0 / 256 = 0`
6. Bounds check: `tensorEnd = tensorOffset + offset + 0 = tensorOffset + offset`
7. If `offset < fileSize - tensorOffset`, the bounds check PASSES
8. Tensor with Kind=9999 (unknown), arbitrary shape, and zero computed size is stored in `llm.tensors`
9. Downstream llama.cpp backend processes this tensor — behavior undefined

**Counterfactual**: IF the bounds check used the tensor's DECLARED size from the manifest OR rejected unknown Kind values, this would be prevented. Neither check exists.

**Secondary effect — divide by zero**: For `typeSize()=0` and `blockSize()=256`, `Size() = Elements() * 0 / 256`. There is NO divide-by-zero here since `typeSize() = 0` is the numerator, not divisor. The result is just 0. The original CVE-2025-0317 (divide-by-zero in ggufPadding) is a different function. However, in `WriteGGUF` (gguf.go:573), `ggufPadding(int64(s), int64(alignment))` where alignment comes from `kv.Uint("general.alignment", 32)`. If a crafted GGUF sets `general.alignment = 0`, then `ggufPadding(offset, 0)` computes `(0 - offset%0) % 0` → **divide by zero**. This is CVE-2025-0317's class.

**Bounds check bypass confirmed**: An attacker sets tensor Kind to any value not in the TensorType enum (e.g., uint32(0xFFFFFFFF)). TypeSize returns 0. Size()=0. Bounds check passes trivially. Tensor is accepted with its declared shape. When llama.cpp loads this model, it will attempt to use the Kind value to determine the actual tensor type — behavior implementation-defined/undefined.

**Attack input**: GGUF with one tensor, Kind=0xFFFFFFFF, Shape=[1024, 1024], Offset=0, plus 4 bytes of tensor data
**Security consequence**: GGUF parser accepts tensor with unknown type. C++ backend behavior undefined — potential crash or exploit depending on how unknown kinds are handled in llama.cpp.
**Severity estimate**: MEDIUM-HIGH (requires downstream C++ analysis to confirm exploitability)
**Validation status**: VALIDATED (bounds check bypass confirmed; downstream impact NEEDS-DEEPER)

---

## PH-R3-04: CONFIRMED — general.alignment=0 Causes Divide-By-Zero in ggufPadding

**Counterfactual**: IF `alignment` were validated to be non-zero before calling `ggufPadding`, the divide-by-zero would be prevented.
**Current code** (`gguf.go:238`):
```go
alignment := llm.kv.Uint("general.alignment", 32)
```
And `gguf.go:245`:
```go
padding := ggufPadding(offset, int64(alignment))
```
And `gguf.go:687`:
```go
func ggufPadding(offset, align int64) int64 {
    return (align - offset%align) % align
}
```
If `align = 0`: `offset % 0` → **panic: integer divide by zero**

**Causal mechanism**: The default is 32, but if `general.alignment = 0` is explicitly set in the GGUF KV section, `kv.Uint` returns 0, and `ggufPadding(offset, 0)` panics.

**KV lookup path**: `kv.Uint("general.alignment", 32)` — if the key exists with value 0, returns 0. The default of 32 is only used when the key is absent.

**CVE lineage**: This is the same class as CVE-2025-0317 (divide-by-zero in ggufPadding via block_count=0). That CVE was for `ggufPadding` being called with block_count. The same function is vulnerable here through `general.alignment`.

**Counterfactual**: `alignment := max(llm.kv.Uint("general.alignment", 32), 1)` would fix this.

**Attack input**: GGUF file with KV entry `general.alignment = 0` (type uint32, value 0). File is valid up to that point.
**Minimum viable exploit**: Header + one KV entry (string "general.alignment" + uint32 type + uint32 value 0) + numTensor=0 + parsing reaches line 238-245 → panic.
**Security consequence**: Server crash via panic — remote DoS
**Severity estimate**: HIGH
**Validation status**: VALIDATED (direct code path; same class as a known CVE)

---

## PH-R3-05: CONFIRMED — No Upload Size Limit in CreateBlobHandler (Amplifier)

**Target**: `server/routes.go:1538` — `manifest.NewLayer(c.Request.Body, "")`
**Counterfactual**: IF `http.MaxBytesReader` were used, large uploads would be rejected before writing to disk.
**Current code**: `manifest.NewLayer(c.Request.Body, "")` reads `io.Copy(io.MultiWriter(temp, sha256sum), r)` with no size limit.

**Impact**: Without an upload size limit:
1. Attacker can upload terabyte-sized blobs, exhausting disk space
2. The blob file is written to disk BEFORE the digest comparison — so an attacker who uploads 100GB with a mismatched digest wastes 100GB of disk I/O before getting a 400 error
3. This amplifies the effectiveness of PH-01 (attacker needs to upload actual array data) — the disk-fill attack may be feasible before the OOM attack

**Note**: Go's default `http.Server` has a 10MB ReadHeaderTimeout but no body size limit. Gin does not add a body size limit by default.

**Security consequence**: Disk exhaustion via unlimited blob uploads — DoS
**Severity estimate**: MEDIUM-HIGH (amplifier; disk exhaustion)
**Validation status**: VALIDATED

---

## PH-R3-06: NEEDS-DEEPER — llama.cpp Tensor Metadata Trust (downstream of PH-R3-03/CROSS-02)

**Question**: Does the llama.cpp C++ backend independently validate tensor shapes and kinds from the GGUF file, or does it trust the Go-parsed metadata?

**Relevant code**: When ollama loads a model, it passes tensor metadata to llama.cpp (or its replacement). If llama.cpp re-reads the GGUF file itself, the Go parser's acceptance/rejection of tensors may not matter — llama.cpp applies its own validation. If llama.cpp trusts Go-parsed shapes, an overflow-accepted tensor (PH-09/PH-16) or unknown-Kind tensor (PH-R3-03) would be passed through.

**Why unresolved**: The bridge between Go tensor parsing and the C++ backend is in runner code not included in the source files reviewed. The actual tensor data loading is outside the Go GGUF parser scope.

**Suggested follow-up**: Review `runner/` or `llm/` packages for how parsed tensor shapes are handed to the C++ side. Specifically look for whether the `Shape []uint64` from Go's `Tensor` struct is marshaled to llama.cpp's tensor API directly.
