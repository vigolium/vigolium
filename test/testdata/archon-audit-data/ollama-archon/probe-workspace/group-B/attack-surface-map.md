# Attack Surface Map: Group B — Parser / Convert / GGUF / Template

## Entry Points

- `fs/ggml/gguf.go:47` — `(*containerGGUF).Decode` — accepts raw `io.ReadSeeker` from any caller; reads attacker-controlled uint64 version, uint64 numKV, uint64 numTensor, all tensor shape[]uint64 and offset uint64 fields
- `fs/ggml/gguf.go:141` — `(*gguf).Decode` — inner decode loop; reads attacker-controlled KV keys (string with uint64 length), KV values (typed unions), tensor info (name, dims, shape[], kind, offset)
- `fs/ggml/gguf.go:348` — `readGGUFString` — reads uint64 length then `make([]byte, length)` with no upper bound check against file size
- `fs/ggml/gguf.go:424` — `readGGUFArray` — reads uint64 element count N, then `newArray[T](int(n), maxArraySize)` — cast from uint64 to int with no overflow check; if N > 2^63, `int(n)` goes negative or wraps
- `fs/gguf/gguf.go` — `Open` / `TensorReader` — parallel lazy parser for capability detection; `TensorReader` returns `io.NewSectionReader(f.file, f.offset+int64(t.Offset), t.NumBytes())` with no bounds check; `NumBytes()` = signed int64 product of Shape dims
- `fs/gguf/tensor.go:19` — `TensorInfo.NumValues` — signed int64 multiplication of attacker-controlled uint64 Shape dims (cast to int64 first); can produce negative or wrapped result
- `fs/gguf/tensor.go:28` — `TensorInfo.NumBytes` — `int64(float64(NumValues()) * Type.NumBytes())` — double float64 cast loses integer precision above 2^53
- `fs/ggml/ggml.go:505` — `Tensor.Elements` — unchecked uint64 product of all Shape[] dims; wraps on overflow
- `fs/ggml/ggml.go:513` — `Tensor.Size` — `Elements() * typeSize() / blockSize()`; all operands are attacker-controlled; result wraps
- `server/quantization.go:26` — `quantizer.WriteTo` — `io.NewSectionReader(q, int64(q.offset), int64(q.from.Size()))` with size from wrapped `Size()`; then `unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())` uses raw unvalidated `Elements()` for slice length
- `ml/backend/ggml/quantization.go:19` — `ConvertToF32` — `make([]float32, nelements)` with nelements = attacker-controlled `q.from.Elements()`; then `C.ggml_fp16_to_fp32_row(... elems)` cgo call with nelements as the element count
- `convert/reader_safetensors.go` — `parseSafetensors` — `binary.Read(f, LittleEndian, &n)` reads int64 header length; `make([]byte, 0, n)` followed by `io.CopyN(buf, f, n)` — n is fully attacker-controlled with no file-size guard
- `convert/reader_torch.go` — `parseTorch` — PyTorch pickle deserialization (classically unsafe; no class allowlist)
- `convert/tokenizer.go` — `parseTokenizer` — `json.NewDecoder(f).Decode(&tt)` on attacker-supplied `tokenizer.json`; no size limit on the file open
- `template/template.go:145` — `Parse` — accepts attacker-controlled template string; calls `text/template.Parse` with no size/depth limit, then `t.Vars()` which recursively walks the AST
- `template/template.go:171` — `Vars` — recursive `Identifiers` walk of all template trees; no depth cap; stack overflow reachable with deeply-nested `{{if}}` at ~50k depth
- `template/template.go:257` — `Execute` — calls `t.Vars()` again on every execution (per-request cost); calls `deleteNode` which uses `walk` (mutual recursion)
- `parser/parser.go:380` — `ParseFile` — rune-by-rune state machine over Modelfile; input from `io.Reader`; no overall size limit
- `parser/parser.go:239` — `filesForModel` — `filepath.Glob` over attacker-controlled directory; no TOCTOU protection between glob and digest
- `parser/parser.go:157` — `fileDigestMap` — `filepath.EvalSymlinks` called on glob results then `filepath.IsLocal` check; race window between EvalSymlinks return and actual file open in `digestForFile`
- `parser/parser.go:632` — `expandPathImpl` — handles `~username/` paths via `user.Lookup(parts[0])` — arbitrary username lookup from Modelfile `FROM` value

## Trust Boundary Crossings

- **Remote registry → local GGUF file → Go GGUF parser → cgo**: A pulled or uploaded GGUF file crosses from untrusted network into privileged Go parsing code and then into cgo/C GGUF decoder (llama.cpp via `C.llama_model_load_from_file`). The boundary guard is only the `tensorEnd > fileSize` bounds check, which is bypassable via `uint64` overflow in `Elements()`.
- **Unauthenticated HTTP blob upload (`POST /api/blobs/:digest`) → GGUF parse**: `CreateBlobHandler` accepts any body stream to disk without authentication on many configurations, then later parsing trusts the stored file.
- **CLI `FROM /path/to/dir` → `filesForModel` → symlink traversal**: The Modelfile `FROM` argument is user-controlled; symlink validation uses `EvalSymlinks + IsLocal` but has a TOCTOU race between stat and open.
- **CLI `ollama create --experimental` → `x/create.CreateSafetensorsModel` → no EvalSymlinks**: The x/create path does not call `EvalSymlinks`, allowing symlink escape to read files outside the specified directory.
- **Modelfile TEMPLATE string → `text/template` parse+execute**: A malicious model's template blob is parsed and executed for every chat/generate request with no size limit, no recursion depth limit, and executed via `text/template` (not `html/template`) — no HTML escaping.
- **Safetensors directory → `parseSafetensors` header read**: The int64 header length field is attacker-controlled and directly fed into `make([]byte, 0, n)` with no file-size validation, allowing OOM via crafted header.
- **`tokenizer.json` → `json.Decode`**: No file size limit before decoding; deeply nested JSON can cause stack overflow or OOM in the JSON decoder.
- **`text/template` → `tools/template.go` AST walkers**: `findToolCallNode` / `findTextNode` in tools/template.go walk template ASTs without the nil-Pipe / nil-List guards added by commit `1ed2881e`, coupling safety to an undocumented stdlib invariant.

## Auth / AuthZ Decision Points

- `server/routes.go:1508` — `CreateBlobHandler` — checks only that digest matches `^sha256[:-][0-9a-fA-F]{64}$` regex; no authentication on the endpoint itself when server is not in a restricted mode
- `server/routes.go:46` — `CreateHandler` — validates file paths from `req.Files` map via `fs.ValidPath`; no authentication check for the create operation against local model directories
- `parser/parser.go:183` — `fileDigestMap` — `filepath.IsLocal(rel)` is the sole authority for path escape prevention after `EvalSymlinks`; no owner/ACL check

## Validation / Sanitization Functions

- `fs/ggml/gguf.go:258-276` — bounds check `tensorEnd > fileSize` — validates tensor offset+size fits within file; **bypassable** via uint64 overflow in `Size()` / `Elements()`
- `server/quantization.go:37` — `uint64(len(data)) < q.from.Size()` — short-data guard; **bypassable** same overflow as above
- `parser/parser.go:173,183` — `filepath.EvalSymlinks + filepath.IsLocal` — symlink escape prevention; **has TOCTOU race window** between EvalSymlinks call (line 173) and subsequent `os.Open` in `digestForFile` (line 223)
- `template/template.go:155-157` — `t.Vars()` in `Parse` — validates nil-Pipe nodes (post `1ed2881e`); does NOT cap template size, recursion depth, or execution time
- `parser/parser.go:418,623` — `isValidCommand` / `unquote` — syntactic validation of Modelfile command names and quoted strings; no semantic validation of template content
- `convert/reader_safetensors.go` — no validation of header length `n` against file size before `make([]byte, 0, n)`

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| Network (HTTP request body) | Disk blob (OLLAMA_MODELS/blobs/) | Digest regex validates path; content untrusted | YES (CreateBlobHandler uses regex) | `pullWithTransfer` in DFD-1 skips `manifest.BlobsPath` for tensor layers |
| Disk blob | Go GGUF parser (`fs/ggml/gguf.go::Decode`) | File is a valid GGUF; tensor metadata is self-consistent | NO — attacker controls all uint64 fields | - |
| Go GGUF parser (`Decode`) | Bounds check (`tensorEnd > fileSize`) | `tensor.Size()` accurately reflects actual data size | NO — `Elements()` and `Size()` use unchecked uint64 multiply; wraps to small value | - |
| Bounds check | cgo quantizer (`unsafe.Slice` / `ConvertToF32`) | Slice length from `Elements()` matches actual backing data | NO — `Elements()` returns pre-wrap large value; `Size()` returns post-wrap small value; 4-byte read satisfies bounds, but `unsafe.Slice(len=2^62)` is OOB | - |
| Modelfile `FROM` path | `filesForModel` symlink check | `EvalSymlinks` resolves all symlinks before `IsLocal` check | NO (TOCTOU) | `x/create` path does NOT call `EvalSymlinks` at all |
| `filesForModel` / glob result | `digestForFile` open | Path from `EvalSymlinks` is still the same file | NO — TOCTOU race between `EvalSymlinks` at line 173 and `os.Open` at line 228 | - |
| Modelfile `TEMPLATE` string | `template.Parse` | Template is well-formed, bounded size | NO — no size/depth limit; nil-Pipe nodes now handled but deeply-nested DoS is not | Direct `text/template.New("").Parse()` in tools/thinking (bypasses ollama wrapper) |
| `template.Parse` (validated) | `tools/template.go` AST walkers | Returned template tree has nil-safe Pipes / Lists | FRAGILE — relies on undocumented stdlib invariant that `if/range/with` always has non-nil List; `Subtree` + hand-built trees may violate this | `template.Subtree` and `thinking.InferTags` construct sub-trees without re-validating |
| Safetensors file on disk | `parseSafetensors` header decoder | Header length `n` fits in available memory | NO — `n` is int64 from file; no cap before `make([]byte, 0, n)` | - |
| `fs/gguf` lazy parser | `TensorReader` | Tensor offset+NumBytes() fits within file | NO — `NumBytes()` uses float64 cast losing precision; no bounds check in this parser | Only `fs/ggml` parser was patched by `9d902d63` |

## Trust Chain Gaps (rows where "Alternate Paths" column is NOT empty)

1. **GGUF tensor uint64 overflow (CRITICAL)**: `Elements()` and `Size()` do unchecked uint64 multiplication over attacker-controlled `Shape[]` dims. The `tensorEnd > fileSize` bounds check passes because `Size()` wraps to a small value. Downstream `unsafe.Slice(ptr, Elements())` uses the un-wrapped large value, producing an OOB memory read/write primitive reachable through any GGUF ingestion path (blob upload → generate, quantize, model create).

2. **`pullWithTransfer` skips `manifest.BlobsPath` digest validation (CRITICAL)**: When any layer has mediaType `application/vnd.ollama.image.tensor`, the entire manifest is pulled via `pullWithTransfer`, which uses `transfer.digestToPath` with no regex validation. A malicious registry can inject path-traversal digests like `sha256:../../../etc/cron.d/evil`.

3. **Sibling `fs/gguf` parser has no bounds check (HIGH)**: `fs/gguf/gguf.go::TensorReader` and `fs/gguf/tensor.go::NumBytes` have no equivalent of the patch from `9d902d63`. `NumBytes()` is a float64 product, losing precision above 2^53 elements. Any future production caller inherits the original CVE pattern. Currently test-only but capabilities-detection code could evolve to call `TensorReader`.

4. **Safetensors header OOM (HIGH)**: `parseSafetensors` reads int64 `n` from file and calls `make([]byte, 0, n)` with no file-size guard. An attacker-controlled `.safetensors` with `n=0x7FFFFFFFFFFFFFFF` causes OOM or panic before `io.CopyN` returns an error. Path is `x/create --experimental` (DFD-10, DFD-15).

5. **Template size/depth DoS (MEDIUM-HIGH)**: No size cap on `application/vnd.ollama.image.template` blob; `text/template.Parse` and `Identifiers` recurse without depth limit. A crafted multi-MB template causes OOM. Reachable from `/api/show`, `/api/chat`, `/api/generate` when model has oversized template blob.

6. **`tools/template.go` walkers lack nil-Pipe guards (MEDIUM)**: `findToolCallNode` and `findTextNode` dereference `n.Pipe.Cmds` (line 52) and recurse without nil-checking `.List`. Safety depends on undocumented stdlib invariant that `if/range/with` always produces a non-nil ListNode. `Subtree` can construct trees that violate this.

7. **TOCTOU between `EvalSymlinks` and `os.Open` in `fileDigestMap` (MEDIUM)**: Line 173 calls `EvalSymlinks(f)` and line 183 checks `IsLocal(rel)`. Line 223 in `digestForFile` opens the *original* path `f` (not the resolved path), re-calling `EvalSymlinks` — but the time between the two calls is a race window. On fast storage a concurrent `rename` or symlink replace can win.

8. **`x/create` path missing `EvalSymlinks` (HIGH)**: `x/create/create.go` and `x/create/imagegen.go` enumerate files from a directory without calling `EvalSymlinks`, allowing a directory containing symlinks to escape the model directory boundary into arbitrary filesystem reads.

9. **`readGGUFString` allocates unbounded heap (HIGH)**: `readGGUFString` (gguf.go:348) does `make([]byte, length)` where `length` is a uint64 directly from the file, only bounded by `llm.scratch` capacity for small strings. A KV key or string value with `length=0x7FFFFFFF_FFFFFFFF` will trigger OOM before any IO error.

10. **`readGGUFArray` uint64→int truncation (HIGH)**: `readGGUFArray` (gguf.go:424) casts array element count `n` (uint64) to `int` and passes to `newArray[T](int(n), maxArraySize)`. On a 64-bit platform with `n > math.MaxInt64` this produces a negative `size` field; `make([]T, size)` panics with "negative make argument".
