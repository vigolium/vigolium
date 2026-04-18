# Evidence File — Group B (All Rounds)

## Evidence for PH-01/PH-12/PH-C01 (CRITICAL): uint64 Shape Overflow → OOB cgo primitive

**File/Line**: `fs/ggml/ggml.go:505-514`
```go
func (t Tensor) Elements() uint64 {
    var count uint64 = 1
    for _, n := range t.Shape {
        count *= n   // NO overflow check
    }
    return count
}
func (t Tensor) Size() uint64 {
    return t.Elements() * t.typeSize() / t.blockSize()  // NO overflow check
}
```

**File/Line**: `fs/ggml/gguf.go:258-260`
```go
for _, tensor := range llm.tensors {
    tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()
    if tensorEnd > uint64(fileSize) {  // uses WRAPPED Size()
```

**File/Line**: `server/quantization.go:26,37,43`
```go
sr := io.NewSectionReader(q, int64(q.offset), int64(q.from.Size()))  // reads wrapped-size bytes
// ...
if uint64(len(data)) < q.from.Size() {  // guard uses SAME wrapped Size() — always passes
// ...
f32s = unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())  // uses PRE-WRAP Elements()
```

**Fragility**: NONE — this is a direct arithmetic property, not an invariant. The guard and the slice use mathematically different values from the same tensor.

**Confidence**: CONFIRMED. The overflow chain is mechanically verifiable: for `Shape=[1<<62+1, 1]`, `Kind=TensorTypeF32`:
- `Elements() = 1<<62+1` (no overflow yet — fits in uint64)
- `Size() = (1<<62+1) * 4` = `0x10000000000000004` → wraps to `4`
- Bounds check passes (tensorOffset + offset + 4 <= fileSize)
- `io.NewSectionReader` reads 4 bytes
- `uint64(4) < 4` → false → guard passes
- `unsafe.Slice(ptr, 1<<62+1)` → OOB slice header over 4-byte backing

---

## Evidence for PH-03/PH-10/PH-C02 (HIGH): readGGUFString/readString Unbounded Allocation

**File/Line**: `fs/ggml/gguf.go:353-371` — `readGGUFString`
```go
length := int(llm.ByteOrder.Uint64(buf))
if length > len(llm.scratch) {      // 16KB scratch
    buf = make([]byte, length)       // DIRECT ALLOC of attacker-controlled size
} else {
    buf = llm.scratch[:length]
}
```

**File/Line**: `fs/gguf/gguf.go:188-205` — `readString`  
```go
n, err := read[uint64](f)
// ...
if int(n) > len(f.bts) {            // int(n) conversion — negative for n >= 2^63
    f.bts = make([]byte, n)          // DIRECT ALLOC of attacker-controlled size
}
bts := f.bts[:n]                     // PANIC if n > 2^63 (int overflow -> negative, slice OOB)
```

**Call path to lazy parser**: `server/images.go:89` → `gguf.Open(m.ModelPath)` → key-value parsing → `readString` 
```go
if m.ModelPath != "" {
    f, err := gguf.Open(m.ModelPath)  // line 89
```

**Trigger route**: `/api/show` → `GetModel` → `m.Capabilities()` → `gguf.Open`

**Fragility**: SOLID — this code path is called on every `/api/show` and every model first-access. No probabilistic or timing dependency.

**Confidence**: CONFIRMED.

---

## Evidence for PH-04/PH-14/PH-C03 (HIGH): readGGUFArray uint64→int Truncation → Negative make

**File/Line**: `fs/ggml/gguf.go:431-437`
```go
n, err := readGGUF[uint64](llm, r)
// ...
switch t {
case ggufTypeUint8:
    a := newArray[uint8](int(n), llm.maxArraySize)  // int(n): wraps for n > 2^63
```

**File/Line**: `fs/ggml/gguf.go:416-422` — `newArray`
```go
func newArray[T any](size, maxSize int) *array[T] {
    a := array[T]{size: size}
    if maxSize < 0 || size <= maxSize {
        a.values = make([]T, size)   // PANIC for size < 0: runtime.throw
    }
    return &a
}
```

**Trigger**: `Decode(rs, -1)` at `model/model.go:150` passes `maxArraySize=-1` → `maxSize < 0` always true → `make([]T, negative)` → `runtime.throw` (not recoverable by `recover()`).

**Confidence**: CONFIRMED.

---

## Evidence for PH-18/PH-C03 (HIGH): numTensor Not Capped → Tensor Slice OOM

**File/Line**: `fs/ggml/gguf.go:194-232`
```go
for range llm.numTensor() {   // iterates up to 2^64 times
    // ...
    llm.tensors = append(llm.tensors, &tensor)
    llm.parameters += tensor.Elements()   // unchecked uint64 accumulation
}
```

**numTensor max**: `numTensor()` returns `llm.V3.NumTensor` which is a raw uint64 from the file — no cap.

For `numTensor = 1000000` with minimal 1-dim tensors (each needing ~33 bytes to parse), the tensor slice grows to 1M entries × sizeof(*Tensor) ≈ 70 bytes each ≈ 70 MB. For 10M entries: 700 MB. No bounds checking until AFTER the full loop completes.

**Confidence**: CONFIRMED.

---

## Evidence for PH-05/PH-C04 (HIGH): Safetensors Header OOM

**File/Line**: `convert/reader_safetensors.go:34-41`
```go
var n int64
if err := binary.Read(f, binary.LittleEndian, &n); err != nil {
    return nil, err
}

b := bytes.NewBuffer(make([]byte, 0, n))   // n is raw int64 from file; no cap
if _, err = io.CopyN(b, f, n); err != nil {
    return nil, err
}
```

No file-size validation, no maximum-header-size constant.

**Call path**: `convert.Convert` → `parseTensors` → `parseSafetensors`. This is called from `server/create.go` when processing a `POST /api/create` with safetensors model files.

**Confidence**: CONFIRMED.

---

## Evidence for PH-06/PH-C07 (MEDIUM-HIGH): Template Size DoS + Per-Request Vars() Walk

**File/Line**: `server/images.go:351-361` — no size limit before template parse
```go
bts, err := os.ReadFile(layer.BlobPath)   // reads entire template blob; no io.LimitReader
// ...
m.Template, err = template.Parse(string(bts))
```

**File/Line**: `template/template.go:257-259` — `Vars()` called per-request
```go
func (t *Template) Execute(w io.Writer, v Values) error {
    system, messages := collate(v.Messages)
    vars, err := t.Vars()   // O(N) AST walk on every Execute call
```

**File/Line**: `template/template.go:327` — `Root.Copy()` per-request
```go
nodes := deleteNode(t.Template.Root.Copy(), func(n parse.Node) bool {
```
`Root.Copy()` deep-copies the entire AST. For N=100k nodes: 100k allocations per request.

**Confidence**: CONFIRMED.

---

## Evidence for PH-16/CROSS-03 (MEDIUM): Capabilities() Proceeds on Vars() Error → Capability Spoofing

**File/Line**: `server/images.go:131-137`
```go
v, err := m.Template.Vars()
if err != nil {
    slog.Warn("model template contains errors", "error", err)  // LOGS but does NOT return
}
if slices.Contains(v, "tools") || (builtinParser != nil && builtinParser.HasToolSupport()) {
    capabilities = append(capabilities, model.CapabilityTools)
}
```

A template `{{.Tools}}{{template "x"}}` would:
1. Return `(["tools"], error)` from `Vars()` — "tools" collected before the nil-pipe error
2. `Capabilities()` logs the error and continues
3. `slices.Contains(v, "tools")` returns true (after lower-casing: "tools" in ["tools"])
4. `CapabilityTools` is set despite the template being malformed

**Confidence**: CONFIRMED — the code is directly visible. The Vars() error is non-fatal to Capabilities().

---

## Evidence for PH-C05/PH-21 (MEDIUM): GraphSize nil Type Assertion

**File/Line**: `fs/ggml/ggml.go:607`
```go
vocab := uint64(f.KV()["tokenizer.ggml.tokens"].(*array[string]).size)
```

- `f.KV()["tokenizer.ggml.tokens"]` returns `nil` interface if key absent
- Type assertion on nil interface panics
- Call chain: `llm/server.go:536` → `s.ggml.GraphSize(...)` → panic recovered by gin → HTTP 500

For a crafted GGUF with `tokenizer.ggml.tokens` stored as `uint64(0)` instead of `*array[string]`, the type assertion also panics: "interface conversion: interface is uint64, not *array[string]".

**Confidence**: CONFIRMED.

---

## Evidence for PH-08 (HIGH): x/create Missing EvalSymlinks

**File/Line**: `x/create/create.go:695-711` — `CreateSafetensorsModel`
```go
entries, err := os.ReadDir(modelDir)
// ...
for _, entry := range entries {
    if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".safetensors") {
        continue
    }
    stPath := filepath.Join(modelDir, entry.Name())   // NO EvalSymlinks
    extractor, err := safetensors.OpenForExtraction(stPath)   // opens symlinked file
```

No `filepath.EvalSymlinks`, no `filepath.IsLocal` check. A symlink `model.safetensors -> /etc/shadow` would be opened by `safetensors.OpenForExtraction`.

**Confidence**: CONFIRMED — grep for EvalSymlinks in x/create returned no matches.

---

## Evidence for PH-20/CROSS-03 (MEDIUM): findToolCallNode Skips TemplateNode

**File/Line**: `tools/template.go:50-103` — `findToolCallNode` (confirmed from KB bypass analysis B4)

The function only recurses into `IfNode`, `ListNode`, `RangeNode`, `WithNode`. A `{{template "tools" .}}` invocation produces a `TemplateNode` which is silently skipped. Tool detection falls back to the `"{"` heuristic.

**Confidence**: CONFIRMED per KB bypass analysis.

---

## Summary Table

| PH-ID | Finding | Evidence Source | Fragility | Confidence |
|-------|---------|-----------------|-----------|------------|
| PH-01/PH-12/PH-C01 | uint64 shape overflow → OOB unsafe.Slice | Direct code reading ggml.go:505-514, quantization.go:43 | NONE | CONFIRMED |
| PH-02/PH-C01 | F16/quantized path: make([]float32, huge) → panic/corruption | Direct code reading quantization.go:44-45 | LOW | CONFIRMED |
| PH-03/PH-10/PH-C02 | readGGUFString/readString unbounded alloc → OOM | Direct code gguf.go:348-371, gguf.go:194-205 | NONE | CONFIRMED |
| PH-04/PH-14 | readGGUFArray int(n) negative make → runtime.throw | Direct code gguf.go:431-437, newArray | NONE | CONFIRMED |
| PH-05/PH-C04 | parseSafetensors make([]byte,0,n) OOM | Direct code reader_safetensors.go:34-41 | NONE | CONFIRMED |
| PH-06/PH-C07 | Template size DoS + per-request Vars() CPU amplification | Direct code template.go:257-259, images.go:351 | LOW | CONFIRMED |
| PH-07 | TOCTOU EvalSymlinks race in fileDigestMap | Code reading parser.go:173-228 | MEDIUM (timing) | NEEDS-DEEPER |
| PH-08 | x/create missing EvalSymlinks symlink escape | grep x/create returns no EvalSymlinks | NONE | CONFIRMED |
| PH-09 | tools/template.go nil-Pipe deref via Subtree | Code reading, KB B3 | MEDIUM (requires specific template) | NEEDS-DEEPER |
| PH-16 | Capabilities() proceeds on Vars() error → cap spoofing | Direct code images.go:131-137 | NONE | CONFIRMED |
| PH-18/PH-C03 | numTensor not capped → tensor slice OOM | Direct code gguf.go:194, numTensor() | NONE | CONFIRMED |
| PH-20 | findToolCallNode skips TemplateNode → heuristic fallback | KB bypass analysis B4 | NONE | CONFIRMED |
| PH-21/PH-C05 | GraphSize nil type assertion on missing tokenizer.ggml.tokens | Direct code ggml.go:607 | NONE | CONFIRMED |
| PH-C06 | deleteNode nil type assertion (PH-19) | Code analysis shows fn doesn't match BranchNode | FRAGILE | DOWNGRADED |
