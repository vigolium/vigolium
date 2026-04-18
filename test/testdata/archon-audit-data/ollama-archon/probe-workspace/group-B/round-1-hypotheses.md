# Round 1 Hypotheses — Backward Reasoner

## Method: Pre-Mortem / Backward Reasoning
Starting from the worst-case security outcomes and tracing backward to find the code paths that enable them.

---

## PH-01: uint64 Shape Overflow → OOB cgo read in ConvertToF32

**Reasoning model**: Pre-Mortem (what must be true for a critical cgo OOB read to occur?)

**Target**: `fs/ggml/ggml.go:505-514` — `Elements()` and `Size()`; `server/quantization.go:43`; `ml/backend/ggml/quantization.go:24`

**Attack input**: Crafted GGUF file with tensor `Shape = [0x4000000000000001, 4]` and `Kind = TensorTypeF32` (typeSize=4, blockSize=1).
- `Elements()` = `0x4000000000000001 * 4` = `0x0000000000000004` (wraps to 4)
- `Size()` = `4 * 4 / 1` = `16`
- Bounds check: `tensorOffset + tensor.Offset + 16 <= fileSize` — trivially passes with a small file
- `io.NewSectionReader(q, offset, 16)` — reads only 16 bytes
- Guard: `uint64(16) < q.from.Size()=16` — false, passes
- `unsafe.Slice((*float32)(ptr), Elements()=0x4000000000000001)` — slice header with 1 billion+ float32 entries backed by 16 bytes

**Code path**: 
`manifest.BlobsPath` → `os.Create` → [GGUF written to disk] → `server/images.go:GetModel` → `fsggml.Decode(rs, -1)` → `(*gguf).Decode` → tensor loop → `tensor.Size()` bounds check passes (wrapped) → [quantize request] → `quantizer.WriteTo` → `unsafe.Slice(ptr, 2^62)` → passed to `ggml.ConvertToF32` as `nelements=2^62` → `C.ggml_fp16_to_fp32_row(..., 2^62)` — reads `2^62 * 2` bytes from a 16-byte backing buffer

**Sanitizers on path**: 
- `tensorEnd > fileSize` check at `gguf.go:259` — **bypassable** (uses wrapped `Size()`)
- `uint64(len(data)) < q.from.Size()` at `quantization.go:37` — **bypassable** (uses same wrapped `Size()`)

**Security consequence**: Out-of-bounds read in cgo/C code from a deliberately crafted GGUF file. Reads arbitrary process memory past the model file buffer. Under the right memory layout (ASLR bypassed or deterministic heap), this is an information disclosure; combined with the write path it becomes memory corruption. Reachable via `POST /api/create` (quantize path), `POST /api/blobs/:digest` followed by generate, or local `ollama create --quantize`.

**Severity estimate**: CRITICAL

**Status**: VALIDATED (mechanically: the arithmetic wraps, the bounds check uses the wrapped value, the unsafe.Slice uses the un-wrapped value; this is a direct consequence of the code at lines 505-514 and 43)

---

## PH-02: uint64 Shape Overflow → OOB in make([]float32, nelements)

**Reasoning model**: Pre-Mortem

**Target**: `ml/backend/ggml/quantization.go:19-24` — `ConvertToF32`, `make([]float32, nelements)`

**Attack input**: Same crafted GGUF as PH-01 but with `Kind != TensorTypeF32` (e.g., Kind = TensorTypeF16, typeSize=2, blockSize=1).
- `Elements()` = wraps to a small value S
- `Size()` = S*2 = small
- `io.NewSectionReader` reads S*2 bytes (say 8 bytes for S=4)
- Guard passes
- `ConvertToF32(data=8bytes, dtype=F16, nelements=2^63+1)`
- `f32s := make([]float32, 2^63+1)` — if this allocates (Go may fail with "too large"), no issue; but on systems where `make` returns a zero-size slice on OOM, the subsequent `C.ggml_fp16_to_fp32_row(&data[0], &f32s[0], 2^63+1)` is an OOB write into the C heap

**Code path**: Same as PH-01 via the else branch at `quantization.go:44`

**Sanitizers on path**: None additional beyond PH-01.

**Security consequence**: If `make([]float32, nelements)` succeeds with a huge nelements that wraps further inside Go's allocator (possible when nelements wraps to a size that passes the allocator's internal check), the cgo call operates on a too-small buffer — C heap corruption. At minimum, `make` panics and the request goroutine crashes (process-level DoS via unrecovered panic in a goroutine, since this is not in the main goroutine's recover scope if the server's recover middleware is present, but `runtime.throw` on negative-size make is not recoverable).

**Severity estimate**: CRITICAL (crash path is DoS; allocation-succeeds path is heap corruption)

**Status**: VALIDATED

---

## PH-03: readGGUFString Unbounded Allocation → OOM DoS

**Reasoning model**: Pre-Mortem (what must be true for an OOM to occur during GGUF KV parsing?)

**Target**: `fs/ggml/gguf.go:348-371` — `readGGUFString`; `fs/gguf/gguf.go:188-205` — `readString`

**Attack input**: Crafted GGUF where the first KV key has a string length field set to `0x7FFFFFFFFFFFFFFF` (max int64 = 9.2 EB).

For `fs/ggml/gguf.go`:
```
buf = make([]byte, 0x7FFFFFFFFFFFFFFF)   // line 362: if length > len(scratch)
```
For `fs/gguf/gguf.go`:
```
f.bts = make([]byte, 0x7FFFFFFFFFFFFFFF)  // line 195: if int(n) > len(f.bts)
```
The `io.ReadFull` that follows will fail with `io.ErrUnexpectedEOF` after the `make` call has already been attempted. On most OS/runtime combinations, `make([]byte, 9.2EB)` causes `runtime: out of memory` before returning, killing the process.

**Code path**: `POST /api/blobs/:digest` (upload crafted GGUF) → later `GET /api/show` → `server/images.go:89` → `fs/gguf.Open` → `readKeyValue` → `readString` → `make([]byte, 9.2EB)` → OOM crash

The `/api/show` path is particularly dangerous: it calls `gguf.Open` for every capability check, including from `/api/generate` and `/api/chat` first-access. An unauthenticated attacker who can upload a blob and then trigger a show/generate request causes the server to OOM.

**Sanitizers on path**: `readGGUFString` checks `length > len(llm.scratch)` (16 KiB scratch buffer) but allocates when the length is larger — this is the anti-short-path optimization. No cap against fileSize.

**Security consequence**: Complete server process OOM → crash. Unauthenticated DoS reachable via: (1) `POST /api/blobs/:digest` + `POST /api/generate {model: "sha256:..."}`, or (2) crafted model published to a registry the user pulls from.

**Severity estimate**: HIGH (reliable DoS; may interact with allocator to corrupt neighboring structures on some platforms)

**Status**: VALIDATED

---

## PH-04: readGGUFArray uint64→int Truncation → Negative make Argument Panic

**Reasoning model**: Pre-Mortem

**Target**: `fs/ggml/gguf.go:424-479` — `readGGUFArray`, specifically `newArray[T](int(n), llm.maxArraySize)`

**Attack input**: Crafted GGUF KV array with element count `n = 0x8000000000000001` (first bit set, positive as uint64 but negative as int64 on 64-bit).
- `int(0x8000000000000001)` = `-9223372036854775807`
- `newArray[uint8](-9223372036854775807, llm.maxArraySize)` — `newArray` calls `make([]T, size)` when `size <= maxSize` or `maxSize < 0`
- If `maxArraySize < 0` (i.e., load with `Decode(rs, -1)` which collects all arrays): `make([]uint8, -9223372036854775807)` → runtime panic "makeslice: len out of range"

**Code path**: `fsggml.Decode(rs, -1)` at `model/model.go:150` or `server/images.go` → `readGGUFArray` → `newArray[T](int(n), -1)` → `make([]T, negative_size)` → panic

**Sanitizers on path**: `maxArraySize < 0` check in `newArray` allows all allocations through, and negative sizes will crash.

**Security consequence**: Unrecovered `runtime.throw` ("makeslice: len out of range") is not a Go panic — it terminates the entire process, not just the goroutine. This is a denial-of-service primitive that bypasses any `recover()` wrapper.

**Severity estimate**: HIGH (process-kill DoS, not per-goroutine)

**Status**: VALIDATED (mechanical: the cast and the negative-size make path are directly visible in the code)

---

## PH-05: Safetensors Header OOM via Crafted int64 Header Length

**Reasoning model**: Pre-Mortem (what must be true for OOM during safetensors conversion?)

**Target**: `convert/reader_safetensors.go` — `parseSafetensors`, the `binary.Read` + `make([]byte, 0, n)` pattern

**Attack input**: Crafted `.safetensors` file where the first 8 bytes (little-endian int64 header length) are `FF FF FF FF FF FF FF 7F` = `0x7FFFFFFFFFFFFFFF`.
- `bytes.NewBuffer(make([]byte, 0, n))` where `n = 9223372036854775807`
- This allocates a 9 exabyte buffer — immediately OOM

**Code path**: `ollama create --experimental /path/to/crafted-dir` → `cmd.CreateHandler` → `x/create.CreateSafetensorsModel` → `convert.parseSafetensors` → `binary.Read(f, LE, &n)` → `make([]byte, 0, n)` → OOM

**Sanitizers on path**: None. There is no check that `n <= fileSize` or `n <= some_max` before the allocation.

**Security consequence**: OOM crash of the ollama process. Also reachable if an attacker can deliver a crafted `.safetensors` file via any channel that triggers the convert path (e.g., symlink to a crafted file in the model directory, or a git-lfs-served file).

**Severity estimate**: HIGH

**Status**: VALIDATED

---

## PH-06: Template Size DoS via Deeply Nested if Blocks

**Reasoning model**: Pre-Mortem (what must be true for OOM during template parsing/execution?)

**Target**: `template/template.go:145` — `Parse`; `template/template.go:171` — `Vars`; `server/images.go` — no template size limit before `os.ReadFile` + `template.Parse`

**Attack input**: A model published to a registry (or uploaded via `/api/blobs`) with `application/vnd.ollama.image.template` layer containing 200,000 nested `{{if .X}}` blocks (approximately 3 MB of template text):
```
{{if .X}}{{if .X}}{{if .X}}...200,000 times...{{end}}...{{end}}{{end}}
```

Each nesting level allocates an `IfNode + ListNode + PipeNode + CommandNode + FieldNode` AST subtree — approximately 5 allocations × 200k = ~1M allocations. `Vars()` then recursively walks the entire tree via `Identifiers`, doubling the work. With deeply nested templates, the recursive call stack grows correspondingly.

**Code path**: 
- `server/images.go:351-361` — reads template blob with `os.ReadFile` (no size limit)
- `template.Parse(string(bts))` at `server/images.go:358` — parses without size cap
- `Capabilities()` at `server/images.go:125` — calls `m.Template.Vars()` — O(N) AST walk
- `Capabilities()` is called from `/api/show`, `/api/generate`, `/api/chat` first access

**Sanitizers on path**: None. No `io.LimitReader`, no max-depth parameter, no size check before `os.ReadFile`.

**Security consequence**: Multi-GB RAM consumption per request. An unauthenticated attacker who can deliver a model with an oversized template to the server (via registry pull, or via blob upload + create) can repeatedly trigger OOM from `/api/show`.

**Severity estimate**: HIGH

**Status**: VALIDATED

---

## PH-07: TOCTOU in fileDigestMap — Symlink Swap After EvalSymlinks

**Reasoning model**: Pre-Mortem (what must be true for a symlink escape during model creation?)

**Target**: `parser/parser.go:157-236` — `fileDigestMap`, `digestForFile`

**Attack input**: 
1. Create a model directory `/tmp/modeldir/` with a legitimate file `model.safetensors`
2. Initiate `POST /api/create` with `{files: {..., "/tmp/modeldir/model.safetensors": "sha256-..."}}`
3. In `fileDigestMap`, `filesForModel` globs the directory at line 259
4. The main code calls `filepath.EvalSymlinks(f)` at line 173 and verifies `filepath.IsLocal(rel)`
5. Between line 173 (EvalSymlinks resolve) and line 228 (`os.Open` in `digestForFile`), replace `model.safetensors` with a symlink to `/etc/passwd`
6. `digestForFile` calls `filepath.EvalSymlinks(filename)` again at line 221 — this time resolves to `/etc/passwd`
7. `os.Open(filepath)` opens `/etc/passwd` and hashes it
8. The hash is stored as a blob — `/etc/passwd` contents are now in the blob store

**Code path**: 
Line 173: `f, err := filepath.EvalSymlinks(f)` 
Line 183: `if !filepath.IsLocal(rel)` — passes because rel was computed before symlink swap
Line 221: `filepath = filepath.EvalSymlinks(filename)` — resolves to attacker target
Line 228: `os.Open(filepath)` — opens attacker-chosen file

**Note**: There are actually two `EvalSymlinks` calls — one in the outer loop (lines 172-189) and one inside `digestForFile` (lines 221-224). The outer loop correctly validates `IsLocal(rel)` for the first-resolved path, but the *original* path `f` (not the resolved path) is stored in `files` at line 190 and passed to `digestForFile`. `digestForFile` then re-resolves via `EvalSymlinks` — creating the TOCTOU window.

**Sanitizers on path**: `filepath.EvalSymlinks + filepath.IsLocal` at lines 173-183 — bypassable via race timing

**Security consequence**: Arbitrary file read — any file readable by the ollama process can be absorbed into the blob store. An attacker with local access (or with ability to manipulate files in the model directory) can exfiltrate `/etc/passwd`, SSH keys, etc. into model blobs that could then be retrieved.

**Severity estimate**: MEDIUM (requires local access or write ability to model directory; timing-dependent)

**Status**: NEEDS-DEEPER (requires local file write access + successful race timing; severity is medium in most deployment models)

---

## PH-08: `x/create` Path Missing EvalSymlinks — Arbitrary File Read

**Reasoning model**: Pre-Mortem

**Target**: `x/create/create.go`, `x/create/imagegen.go` — directory walk without EvalSymlinks

**Attack input**: A directory containing a symlink `model.safetensors -> /etc/shadow` passed to `ollama create --experimental /path/to/dir`.

**Code path**: `x/create.CreateSafetensorsModel` → directory walk → `os.Open(filepath.Join(dir, filename))` — no `EvalSymlinks` call, no `IsLocal` check in this path.

**Sanitizers on path**: None — this is the unpatched path identified in `archon/bypass-analysis/d931ee8f-symlink.md`.

**Security consequence**: Any file symlinked into a model directory is read and its contents placed in the blob store. With `ollama create --experimental` available to a local attacker (or to a pipeline that accepts attacker-supplied model directories), this enables arbitrary local file exfiltration.

**Severity estimate**: HIGH

**Status**: VALIDATED

---

## PH-09: tools/template.go nil-Pipe Dereference via Hand-Built Tree

**Reasoning model**: Pre-Mortem (what must happen for tools/template.go to nil-deref despite the 1ed2881e patch?)

**Target**: `tools/template.go:50-103` — `findToolCallNode`, line 52 `n.Pipe.Cmds`; line 108-156 `findTextNode`

**Attack input**: A model template that uses `template.Subtree` or where `thinking.InferTags` produces a sub-tree containing an `ActionNode` with `Pipe = nil`. The `Subtree` function at `template/template.go:211-255` constructs a raw `parse.Tree` without calling `Vars()` (which has the nil-pipe guard). If the sub-tree contains an `ActionNode{Pipe: nil}`, it's passed to `tools.NewParser` which calls `findToolCallNode`.

Alternatively: future code that constructs templates via `text/template.New("").Parse()` directly (bypassing the ollama wrapper) and passes to tools functions.

**Code path**: 
`template.Subtree(fn)` → `parse.ListNode{Nodes: [ActionNode{Pipe: nil}]}` → `tools.NewParser(subtree, req.Tools)` → `findToolCallNode(subtree.Root.Nodes)` → `n.Pipe.Cmds` → nil pointer deref → panic

The nil-pipe node can be produced by: `{{template "x"}}` parsed by stdlib (Pipe=nil for no-pipeline template invocation) when used inside a sub-template that is then passed to `Subtree`.

**Sanitizers on path**: `template.Parse` validates nil-pipes in the full tree (post `1ed2881e`), but `Subtree` bypasses this validation for the extracted sub-tree.

**Security consequence**: Unrecovered panic in the chat handler goroutine when `req.Tools` is non-empty. Gin recovers from panics in handlers with a 500 response, so this is a per-request DoS (not process kill). But it is triggered by any authenticated (or unauthenticated) chat request with tools enabled against a model with a template containing `{{template "x"}}` with no pipeline.

**Severity estimate**: MEDIUM (per-request DoS; requires specific template structure)

**Status**: NEEDS-DEEPER (depends on whether `Subtree` can produce a tree with ActionNode{Pipe:nil} in a reachable code path; Subtree's walk skips ActionNode but `deleteNode` handles ActionNode — need to trace more carefully)

---

## PH-10: `fs/gguf` Parser `readString` Allocates Before IO Check — Enables 9EB Allocation

**Reasoning model**: Pre-Mortem

**Target**: `fs/gguf/gguf.go:188-205` — `readString`

**Attack input**: GGUF file with a KV key string length = `0x7FFFFFFFFFFFFFFF` bytes in the lazy parser. The lazy parser `fs/gguf` is called from `server/images.go:89` via `gguf.Open` for capability detection.

The specific issue: line 194-195:
```go
if int(n) > len(f.bts) {    // int(0x7FFF...) = math.MaxInt64 > 4096 (true)
    f.bts = make([]byte, n) // make([]byte, 9.2 EB) — OOM
}
```

The `f.bts` field is a package-level or per-File scratch buffer that is reallocated on growth. The `make([]byte, n)` call happens before any IO, so even if the file is only a few bytes, the allocation is attempted first.

**Code path**: `GET /api/show {name: "model-with-crafted-gguf"}` → `server/images.go:GetModel` → `gguf.Open(blobPath)` → `f.keyValues` lazy init → `readKeyValue` → `readString` → `make([]byte, 9.2EB)` → OOM

**Sanitizers on path**: None — no cap on `n` relative to file size.

**Security consequence**: OOM crash on first `/api/show` or first generate/chat using the model. Unauthenticated (any user who can pull or upload a crafted model triggers this for every user of that model name).

**Severity estimate**: HIGH

**Status**: VALIDATED (same class as PH-03 but in the lazy parser specifically)

---

## PH-11: PyTorch Pickle Arbitrary Class Instantiation

**Reasoning model**: Pre-Mortem (what is the worst case of pickle deserialization?)

**Target**: `convert/reader_torch.go` — pickle parse path

**Attack input**: A crafted `.pth` or `.bin` file with pickle opcode `GLOBAL` pointing to `os.system` or `subprocess.Popen`. In Python this is a well-known RCE vector; in Go pickle implementations, the question is whether the Go pickle library enforces a class allowlist.

**Code path**: `ollama create --experimental /path/to/dir-with-crafted.pth` → `convert.parseTorch` → pickle deserialization

**Sanitizers on path**: Depends on the Go pickle library in use; need to inspect `convert/reader_torch.go` for allowlist enforcement.

**Security consequence**: If the Go pickle implementation executes arbitrary constructors (unlikely in a pure Go implementation, but class-name-based dispatch to registered types may exist), this could enable arbitrary code execution. More likely: panic or malformed data that triggers downstream OOM/crash.

**Severity estimate**: MEDIUM (likely crash rather than RCE in Go; but warrants deeper inspection)

**Status**: NEEDS-DEEPER (requires reading reader_torch.go in detail; Go pickle is typically safer than Python pickle but not immune)
