# Cross-Model Seeds: Group B

## CROSS-01: Size()/Elements() Split — Unified OOB Primitive

Source-A: PH-01 (backward-reasoner) — `Elements()` and `Size()` unchecked uint64 overflow, bounds check uses wrapped `Size()`, `unsafe.Slice` uses un-wrapped `Elements()`
Source-B: PH-12 (contradiction-reasoner) — Same contradiction analyzed from the invariant angle: guard uses `Size()` (wrapped), slice uses `Elements()` (un-wrapped), these are intentionally different functions but share broken arithmetic

Connection: Both findings identify the identical code paths at `fs/ggml/ggml.go:505-514` and `server/quantization.go:26-43`. PH-01 identifies the specific exploit shape (`Shape = [1<<62+1, 1]`). PH-12 analyzes why the existing guard is structurally insufficient. Together they confirm a CRITICAL double-path OOB: the guard path uses one value (small, wrapped) and the slice path uses another (large, un-wrapped). The findings complement each other: PH-01 gives the concrete exploit shape, PH-12 explains why any shape-based overflow will evade the guard.

Combined hypothesis: For any `Shape[]` array whose `Elements() * typeSize()` overflows uint64, the `tensorEnd` bounds check passes (because it uses the wrapped `Size()`), the data guard passes (same), but `unsafe.Slice` and `ConvertToF32` operate with the un-wrapped `Elements()` value, creating an OOB read/write of C heap memory reachable from any GGUF ingestion endpoint.

Test direction for causal-verifier: Construct a minimal GGUF in memory with `Shape=[1<<62+1, 1]`, `Kind=TensorTypeF32`, `Offset=0`, and a 4-byte tensor data section equal in size to `Size()=4`. Verify that (a) `Decode` accepts it without error, (b) `tensor.Elements()=1<<62+1`, (c) `tensor.Size()=4`, (d) the resulting `unsafe.Slice` slice header has length `1<<62+1` with backing of 4 bytes. This can be done with a pure Go unit test without triggering cgo.

---

## CROSS-02: Two-Parser Asymmetry Creates Dual Attack Paths for Same Bug

Source-A: PH-03 (backward-reasoner) — `readGGUFString` in `fs/ggml/gguf.go` makes unbounded allocation
Source-B: PH-17 (contradiction-reasoner) — `readString` in `fs/gguf/gguf.go` (lazy parser) is a separate, unpatched code path for the same vulnerability; this parser is called from `/api/show`

Connection: Both findings target string-length OOM in GGUF parsers. PH-03 focuses on the primary parser (triggered by quantize/load). PH-17 focuses on the lazy parser (triggered by show/capabilities). The lazy parser path (PH-17) has a LOWER barrier to trigger — it only requires a `/api/show` call, which is typically unauthenticated and called automatically by clients. The combined attack surface is: a single crafted GGUF uploaded to the blob store can kill the server via EITHER the `/api/show` route (lazy parser) OR the `/api/generate` route (primary parser), covering all possible server access patterns.

Combined hypothesis: A crafted GGUF with a KV string length field set to `0x7FFFFFFFFFFFFFFF` kills the ollama server process via OOM in EITHER `fs/gguf/readString` (reachable from `/api/show`) or `fs/ggml/readGGUFString` (reachable from model load). The `/api/show` path is preferable for an attacker because it's simpler to trigger (GET-like semantics) and does not require a model to be in a running state.

Test direction for causal-verifier: Confirm that `gguf.Open` is called during `/api/show` handling (trace `server/images.go:GetModel` → `gguf.Open`). Then construct a minimal GGUF where the first KV entry has a key with length field = `0x100000` (1 MB) — small enough to allocate but verifiable — to confirm the allocation happens before any IO read. Then test with `0x7FFFFFFFFFFFFFFF` to confirm OOM.

---

## CROSS-03: Template Partial-Vars + Tool-Walker Skip = Two-Stage Capability Spoofing

Source-A: PH-09 (backward-reasoner) — `tools/template.go` walkers lack nil-Pipe guard; safety relies on undocumented stdlib invariant about `TemplateNode`
Source-B: PH-16 (contradiction-reasoner) — `Vars()` returns partial result on error; `Capabilities()` proceeds on error and uses partial list (B5 bypass scenario); PH-20 (game-theory) — `findToolCallNode` skips `TemplateNode` nodes so tool detection falls to heuristic

Connection: PH-09 and PH-20 share the same trust boundary: `tools/template.go` AST walker invoked with the result of `template.Subtree` or the main template parsed by stdlib. PH-16 shares the `Vars()` / `Capabilities()` trust chain. A single model template can exploit all three: (1) use `{{.Tools}}` before a nil-pipe `{{template "x"}}` to force partial-`Vars()` to return `["tools"]` and trick `Capabilities()` into setting `CapabilityTools=true`; (2) hide tool-call emission inside `{{template "tools" .}}` which `findToolCallNode` skips; (3) if `Subtree` later processes the template, the `TemplateNode{Pipe: nil}` reaches `findToolCallNode` and causes nil-Pipe deref.

Combined hypothesis: A single crafted template: `{{.Tools}}{{template "tools" .}}{{template "x"}}` (where template "x" is defined with a nil-pipe invocation somewhere in the chain) achieves: (a) `Capabilities()` marks model as tool-capable due to partial `Vars()`, (b) actual tool-call detection uses heuristic `"{"` fallback because `findToolCallNode` skips the `{{template "tools"}}` node, (c) if `Subtree` is called, nil-deref in `findToolCallNode` when it encounters the nil-pipe template node.

Test direction for causal-verifier: Parse the template `{{.Tools}}{{template "x"}}` through `template.Parse`; verify that `Capabilities()` returns `CapabilityTools=true` despite the template being malformed (the error from `Vars()` is logged but not propagated). Then pass the parsed template to `tools.NewParser` with a non-empty tools list and verify behavior. Separately: use `template.Subtree` to extract a subtree containing an `ActionNode{Pipe:nil}` (by constructing via `template.New("").Parse("{{template \"x\"}}")`) and pass to `findToolCallNode`; verify nil deref.

---

## CROSS-04: Inflated numTensor + Per-Tensor Elements() = Compounded Memory Exhaustion

Source-A: PH-18 (contradiction-reasoner) — large `numTensor` in GGUF header causes unbounded tensor slice growth before any bounds check
Source-B: PH-01 (backward-reasoner) — `Elements()` accumulates into `llm.parameters += tensor.Elements()` at `gguf.go:232` with no overflow check

Connection: PH-18 identifies that `numTensor` is not capped — the decoder creates one `*Tensor` per tensor declared. PH-01 identifies that `llm.parameters += tensor.Elements()` accumulates un-overflow-checked values. With `numTensor = 1000` and each tensor having `Elements() = 1<<60`, `llm.parameters` accumulates to `1000 * 1<<60` which overflows uint64 many times. The result is `general.parameter_count` set to a wildly incorrect value used by `GGML.GraphSize` for VRAM estimation. Combined with PH-21 (missing nil-check on `tokenizer.ggml.tokens`), an attacker can force `GraphSize` to report false VRAM requirements, causing the server to over-allocate GPU layers.

Combined hypothesis: A GGUF file with inflated `numTensor` and overflowed `Elements()` per tensor causes: (a) high memory allocation for the tensor slice, (b) `general.parameter_count` to overflow to a small/incorrect value, (c) `GraphSize` computations to return incorrect VRAM estimates, (d) the model to be loaded with wrong GPU layer allocation — potentially causing OOM in the C/cgo layer during actual inference.

Test direction for causal-verifier: Construct a GGUF with `numTensor=10000` and each tensor having `Shape=[1<<60]`. Verify that `llm.parameters` overflows to a small value at parse time. Check what `GraphSize` reports for such a model. Determine if the wrong VRAM estimate causes the model to load with wrong `numGPULayers`.

---

## CROSS-05: Safetensors OOM + No Root Confinement = Local Privilege Escalation Primitive

Source-A: PH-05 (backward-reasoner) — `parseSafetensors` `make([]byte, 0, n)` with no cap; n from file header
Source-B: PH-08 (backward-reasoner) — `x/create` path missing `EvalSymlinks` allows arbitrary file read via symlink

Connection: Both PH-05 and PH-08 affect the same `x/create.CreateSafetensorsModel` code path (DFD-15). PH-08 allows an attacker to make the converter read an arbitrary file as a `.safetensors` by symlinking it. If the attacker creates a symlink from `model.safetensors -> /dev/urandom` or a crafted file with a specific 8-byte header, PH-05 is triggered via the symlinked file. Alternatively: symlink `model.safetensors -> /proc/self/mem` to attempt to OOM via the safetensors parser on an accessible but unbounded read source.

Combined hypothesis: A directory containing `model.safetensors -> /path/to/crafted-header-file` (first 8 bytes = `FF FF FF FF FF FF FF 7F`) triggers OOM via the safetensors parser when the converter walks the directory without checking symlinks. This combines a read-any-file primitive (no EvalSymlinks) with an OOM primitive (no header size cap) into a local DoS/exploitation path.

Test direction for causal-verifier: Verify that `x/create.CreateSafetensorsModel` opens files without calling `filepath.EvalSymlinks` (confirm the absence by grepping the x/create directory). Then confirm that `parseSafetensors` calls `make([]byte, 0, n)` with the raw header int64 before checking file size. Confirm the two vulnerabilities are in the same code path.
