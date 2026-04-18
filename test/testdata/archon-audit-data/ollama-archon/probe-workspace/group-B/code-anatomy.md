# Code Anatomy: Group B — Parser / Convert / GGUF / Template

## File Inventory

| File | LOC | Role |
|------|-----|------|
| `fs/ggml/gguf.go` | 689 | Primary GGUF parser (used for model loading, quantization) |
| `fs/ggml/ggml.go` | 921 | GGML types, Tensor struct, `Decode` entry point, `GraphSize` |
| `fs/gguf/gguf.go` | 348 | Lazy GGUF parser (capability detection) |
| `fs/gguf/tensor.go` | 289 | TensorInfo, TensorType, NumBytes, NumValues |
| `fs/gguf/keyvalue.go` | 91 | KeyValue wrapper, reflection-based getters |
| `fs/gguf/reader.go` | 24 | bufferedReader wrapper |
| `fs/gguf/lazy.go` | (iterator machinery) | Lazy value iterator |
| `server/quantization.go` | 321 | Quantizer: reads GGUF tensor via unsafe.Slice, calls cgo |
| `ml/backend/ggml/quantization.go` | 86 | cgo bridge: `ConvertToF32`, `Quantize` |
| `convert/convert.go` | (main convert dispatch) | Orchestrates convert pipeline |
| `convert/reader.go` | 99 | Tensor interface, `parseTensors` dispatch |
| `convert/reader_safetensors.go` | ~200 | Safetensors header reader; dangerous `make([]byte, n)` |
| `convert/reader_torch.go` | ~150 | PyTorch pickle reader |
| `convert/tokenizer.go` | ~200 | Tokenizer JSON parse |
| `convert/tokenizer_spm.go` | ~100 | SentencePiece tokenizer |
| `convert/tensor.go` | ~150 | Tensor type normalization |
| `template/template.go` | 647 | Template parse, execute, Vars/Identifiers walk |
| `parser/parser.go` | 672 | Modelfile rune-by-rune parser, filesForModel, fileDigestMap |
| `tokenizer/tokenizer.go` | ~100 | Tokenizer interface |
| `tokenizer/bytepairencoding.go` | ~200 | BPE implementation |
| `tokenizer/sentencepiece.go` | ~200 | SPM implementation |
| `tokenizer/vocabulary.go` | ~100 | Vocabulary loading |
| `tokenizer/wordpiece.go` | ~100 | WordPiece implementation |

---

## Critical Data Flows

### Flow 1: GGUF Model Load (Primary Attack Path)

```
POST /api/blobs/sha256-<digest>
  → server/routes.go:CreateBlobHandler
  → manifest.BlobsPath (digest regex only)
  → os.Create + stream body to disk
  → [later] server/images.go:GetModel
  → fs/ggml/ggml.go:Decode(rs, maxArraySize)
  → fs/gguf/gguf.go:Open (lazy parser, for capability detection)
     OR
  → fs/ggml/gguf.go:containerGGUF.Decode → (*gguf).Decode(rs)
        reads: numTensor (uint64), numKV (uint64)
        KV loop: readGGUFString (uint64 length → make([]byte, length))
                 readGGUFArray (uint64 n → int(n) → newArray[T](size))
        Tensor loop: Shape[] ([]uint64, dims entries)
                     Kind (uint32), Offset (uint64)
        Bounds check: tensor.Size() vs fileSize
            BUT tensor.Size() = Elements() * typeSize() / blockSize()
            AND Elements() = product of Shape[] — UNCHECKED uint64 multiply
  → [if quantize] server/quantization.go:quantizer.WriteTo
        unsafe.Slice(ptr, q.from.Elements())  ← OOB if Elements() wrapped
        OR ggml.ConvertToF32(data, kind, Elements())  ← cgo OOB read
  → [model load] C.llama_model_load_from_file (bypasses Go-side checks)
```

### Flow 2: Safetensors Conversion (DFD-10, DFD-15)

```
ollama create --experimental /path/to/model-dir
  → cmd/cmd.go:CreateHandler
  → x/create.CreateSafetensorsModel
  → directory walk (NO EvalSymlinks, NO root confinement)
  → convert/reader_safetensors.go:parseSafetensors
        binary.Read(f, LittleEndian, &n)   ← int64 from file
        make([]byte, 0, n)                  ← no cap: OOM if n=0x7FFF...
        io.CopyN(buf, f, n)
        json.Decode → header map
```

### Flow 3: Template Parse/Execute (DFD-4)

```
POST /api/create {template: "..."}  OR  pulled model with template blob
  → parser/parser.go:ParseFile → Command{Name:"template", Args:templateString}
  → server/create.go:setTemplate → template.Parse(templateString)
       text/template.New("").Parse(s)  ← no size limit
       t.Vars() → Identifiers walk (recursive, no depth limit)
       ↳ nil-Pipe check for TemplateNode/ActionNode/BranchNode (post 1ed2881e)
       ↳ NO check for deeply-nested if/range/with DoS
  → [chat/generate] template.Execute(w, values)
       t.Vars() called AGAIN per request
       deleteNode + template.Must(...).Execute  ← recursive walk
  → [tool call path] tools/template.go:findToolCallNode
       n.Pipe.Cmds dereference WITHOUT nil check (depends on stdlib invariant)
       findTextNode — same pattern
```

### Flow 4: Modelfile `FROM` → filesForModel → symlink race

```
POST /api/create {files: {"sha256-xxx": "/path/to/model/dir"}}
  → server/create.go:CreateHandler
  → parser/parser.go:fileDigestMap(path)
  → filepath.Stat → filesForModel(path)  ← glob patterns, no TOCTOU protection
  → for each file f:
        filepath.EvalSymlinks(f)  ← line 173 — resolves symlink AT THIS MOMENT
        filepath.IsLocal(rel)     ← line 183 — validates result
  → files = append(files, f)    ← stores ORIGINAL PATH f, not resolved path
  → digestForFile(f):
        filepath.EvalSymlinks(filename)  ← line 221 — second resolve, TOCTOU window
        os.Open(filepath)
```

---

## Key Function Signatures

### `fs/ggml/ggml.go`

```go
func (t Tensor) Elements() uint64 {
    var count uint64 = 1
    for _, n := range t.Shape {
        count *= n   // UNCHECKED uint64 overflow
    }
    return count
}

func (t Tensor) Size() uint64 {
    return t.Elements() * t.typeSize() / t.blockSize()  // UNCHECKED overflow chain
}
```

### `fs/gguf/tensor.go`

```go
func (ti TensorInfo) NumValues() int64 {
    var numItems int64 = 1
    for _, dim := range ti.Shape {
        numItems *= int64(dim)   // signed int64 overflow; can go negative
    }
    return numItems
}

func (ti TensorInfo) NumBytes() int64 {
    return int64(float64(ti.NumValues()) * ti.Type.NumBytes())  // float64 precision loss above 2^53
}
```

### `fs/gguf/gguf.go`

```go
func readString(f *File) (string, error) {
    n, err := read[uint64](f)
    // ...
    if int(n) > len(f.bts) {
        f.bts = make([]byte, n)  // n is attacker-controlled uint64; no cap against file size
    }
    bts := f.bts[:n]             // if n overflows int, this panics
    // ...
}
```

### `fs/ggml/gguf.go`

```go
func readGGUFArray(llm *gguf, r io.Reader) (any, error) {
    // ...
    n, err := readGGUF[uint64](llm, r)
    // ...
    a := newArray[uint8](int(n), llm.maxArraySize)  // int(n) wraps if n > math.MaxInt64
    // newArray: if size <= maxSize → make([]T, size) with NEGATIVE size → panic
```

### `server/quantization.go`

```go
func (q quantizer) WriteTo(w io.Writer) (int64, error) {
    sr := io.NewSectionReader(q, int64(q.offset), int64(q.from.Size()))  // Size() may be wrapped-small
    // ...
    if uint64(len(data)) < q.from.Size() {  // guard uses same wrapped Size() — always passes
        return 0, ...
    }
    f32s = unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())
    // Elements() returns the REAL (un-wrapped) large value: OOB slice header
```

---

## Structural Observations

### 1. Two Separate GGUF Parsers with Different Safety Levels

- `fs/ggml/gguf.go` (primary): Received the `9d902d63` patch adding `tensorEnd > fileSize`. But `Elements()` / `Size()` overflow bypass still present.
- `fs/gguf/gguf.go` (lazy): No bounds check at all. `readString` allocates `make([]byte, n)` without cap. Currently test-only for `TensorReader` but `Open` + `KeyValue` is called from `server/images.go:89` for capability detection on every `/api/show` request.

### 2. Invariant Coupling in Template Walking

- `template/template.go:Identifiers` has nil-Pipe guards for `TemplateNode/ActionNode/BranchNode`
- `tools/template.go:findToolCallNode` (line 52) directly accesses `n.Pipe.Cmds` without nil check
- The safety relies on `text/template` stdlib always producing non-nil List for `if/range/with` bodies
- `template.Subtree` builds raw `parse.Tree` nodes bypassing all validation

### 3. `readGGUFString` Allocation Without File-Size Cap

Both GGUF parsers allocate string buffers directly from the uint64 length field. In `fs/gguf/gguf.go:readString` (line 194-195):
```go
if int(n) > len(f.bts) {
    f.bts = make([]byte, n)  // reuses buffer; single alloc of up to 2^64 bytes
}
bts := f.bts[:n]            // if n > math.MaxInt on 32-bit: panic at slice operation
```
On 64-bit platform: `make([]byte, n)` where `n=0x7FFFFFFFFFFFFFFF` will trigger OOM.

### 4. Safetensors Header: No File-Size Guard

`convert/reader_safetensors.go` reads int64 `n` then:
```go
buf := bytes.NewBuffer(make([]byte, 0, n))
io.CopyN(buf, f, n)
```
`make([]byte, 0, n)` with `n=math.MaxInt64` will OOM before `io.CopyN` reads anything.

### 5. PyTorch Pickle — Classically Unsafe Deserialization

`convert/reader_torch.go` parses `.pth`/`.bin` files using pickle deserialization. No class allowlist is enforced in the Go implementation; attacker-controlled class names in pickle opcodes can trigger arbitrary code in some configurations.

### 6. Template Execution Budget

`template.Execute` calls `t.Vars()` (an O(nodes) AST walk) on every invocation. A model with a 100k-node template causes O(n) work on every chat/generate request, compounding server load.

---

## Call Graph for Top Sinks

| Sink | Reached from | Trust boundary crossed |
|------|-------------|----------------------|
| `unsafe.Slice(ptr, Elements())` | `quantizer.WriteTo` ← `quantize()` ← `server/create.go:687` | disk file → Go → cgo |
| `C.ggml_fp16_to_fp32_row(..., nelements)` | `ConvertToF32` ← `quantizer.WriteTo` | disk file → cgo |
| `C.llama_model_load_from_file` | `llama/llama.go:308` ← `llm.New()` ← model load | disk file → cgo |
| `make([]byte, n)` in `readString` | GGUF parser | network/disk → Go heap |
| `make([]byte, 0, n)` in `parseSafetensors` | `x/create` path | local FS → Go heap |
| `text/template.Execute` | `template.Execute` ← chat handler | network → Go template engine |
| `os.Open(filepath)` in `digestForFile` | `fileDigestMap` ← `CreateRequest` | Modelfile → FS |
