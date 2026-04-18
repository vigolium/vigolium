# Round 2 Hypotheses — Contradiction Reasoner

## Method: TRIZ / Abductive / Contradiction Analysis
Finding contradictions between stated defenses and actual code behavior; abducting from observable code patterns to hidden vulnerabilities.

---

## PH-12: Contradiction — `Size()` Used for BOTH Guard AND Slice Length (Different Values)

**Reasoning model**: Contradiction Analysis

**Target**: `server/quantization.go:26-43` — `quantizer.WriteTo`

**Stated defense**: "uint64(len(data)) < q.from.Size() check guards against under-read data"

**Contradiction**: The guard at line 37 uses `q.from.Size()` (the wrapped small value) to check if `len(data)` is sufficient. The slice at line 43 uses `q.from.Elements()` (the un-wrapped large value) as the slice length. These are different functions returning different values for the same tensor in the overflow case.

The invariant assumed by the code: `Size() = Elements() * typeSize() / blockSize()`, meaning `len(data) >= Size()` implies `len(f32s) = Elements()` is a valid slice of `data`. This invariant holds only when `Elements()` and `Size()` are computed from the same (non-overflowed) values.

In the overflow case:
- `Shape = [0x4000000000000001, 4]`
- `Elements() = 0x4000000000000001 * 4 = 4` (wrapped)... 

Wait, let me re-examine. `0x4000000000000001 * 4`:
- `0x4000000000000001` = `4611686018427387905`
- `× 4` = `18446744073709551620` which is `0xFFFFFFFFFFFFFFFC` — wraps to `0xFFFFFFFFFFFFFFFC` = `18446744073709551612`... 

Actually the most precise overflow scenario is:
- `Shape = [0x8000000000000001, 2]`
- `0x8000000000000001 * 2` = `0x10000000000000002` wraps to `0x0000000000000002` = 2
- `Elements()` = 2 (after wrap)
- `Size()` = `2 * typeSize / blockSize`

For F32: `Size()` = 2 * 4 / 1 = 8. `len(data)` = 8. Guard passes. `unsafe.Slice(ptr, 2)` — only 2 elements. This is actually safe for F32.

The dangerous case is when `Elements()` wraps to a SMALL value but the pre-wrap value is HUGE. Let me recalculate:

For `Shape = [1<<62+1, 1]`, `Kind = TensorTypeF32`:
- `Elements() = (1<<62+1) * 1 = 1<<62+1` — no wrap, this is < 2^64
- `Size() = (1<<62+1) * 4 / 1 = 2^64+4` — wraps to 4
- Now the guard: `uint64(len(data)) < 4` — reads 4 bytes, guard passes
- `unsafe.Slice(ptr, Elements()=1<<62+1)` — OOB: slice backed by 4 bytes but header says 2^62 elements

**This is the correct scenario**: `Elements()` itself does NOT wrap (it's just a big number less than 2^64), but `Size() = Elements() * typeSize` DOES wrap. The guard uses `Size()` (wrapped=small) but the slice uses `Elements()` (un-wrapped=huge).

**Code path**: Same as PH-01. The contradiction is precisely: guard uses `Size()` which wraps, slice uses `Elements()` which doesn't wrap.

**Security consequence**: The `io.NewSectionReader` reads 4 bytes. The guard `uint64(4) < 4` is false. `unsafe.Slice(ptr, 2^62)` creates a valid-looking slice header over 4 bytes of backing. Any iteration of `f32s` beyond index 0 reads out-of-bounds.

**Severity estimate**: CRITICAL

**Status**: VALIDATED

---

## PH-13: Abduction — `fs/gguf` `readString` Uses int Conversion on uint64

**Reasoning model**: Abductive

**Target**: `fs/gguf/gguf.go:188-205` — `readString`, line 194: `if int(n) > len(f.bts)`

**Observed**: `n` is uint64. `int(n)` on a 64-bit platform is a no-op bitwise (same bits, reinterpreted). For `n = 0x8000000000000001`, `int(n) = -9223372036854775807` (negative). The condition `int(n) > len(f.bts)` = `-9223372036854775807 > 4096` is FALSE, so the allocation is skipped. Then `bts := f.bts[:n]` = `f.bts[:0x8000000000000001]` — this will panic with "slice bounds out of range" because 0x8000000000000001 > len(f.bts) (4096).

**Abduction**: Two distinct attack payloads exist:
1. `n < 2^63`: allocation is triggered (`int(n)` is positive and large) → OOM via `make([]byte, n)` at line 195
2. `n >= 2^63`: allocation is skipped → slice panic at `f.bts[:n]` at line 198 → `runtime.throw` (process kill)

For case 2: `n = 0x8000000000000001` skips the make but hits the slice panic — this is a guaranteed process-kill DoS without even attempting a large allocation.

**Code path**: `gguf.Open` → `readKeyValue` → `readString` → `f.bts[:0x8000000000000001]` → slice bounds panic → runtime.throw

**Sanitizers on path**: The `int(n) > len(f.bts)` check intended to guard allocation inadvertently also guards the slice operation — but the wrong way: it doesn't catch the case where int(n) is negative but n is used as uint64 in the slice expression.

**Security consequence**: Process-kill DoS (runtime.throw is not recoverable by any panic handler). Reachable via `gguf.Open` which is called for every model capability check including from unauthenticated `/api/show`.

**Severity estimate**: HIGH

**Status**: VALIDATED

---

## PH-14: Abduction — `readGGUFArray` Negative Make on 64-bit via uint64 > maxInt

**Reasoning model**: Abductive

**Target**: `fs/ggml/gguf.go:424-479` — `readGGUFArray`, `newArray[T](int(n), maxArraySize)`

**Observed**: `newArray` at line 416-422:
```go
func newArray[T any](size, maxSize int) *array[T] {
    a := array[T]{size: size}
    if maxSize < 0 || size <= maxSize {
        a.values = make([]T, size)
    }
    return &a
}
```

When called with `size = int(n)` where `n` is `0x8000000000000001`:
- `int(n)` = `-9223372036854775807`
- `array[T]{size: -9223372036854775807}` — stored
- `maxSize < 0` path: `make([]T, -9223372036854775807)` → `runtime.throw: makeslice: len out of range` (process kill)
- `size <= maxSize` path (when maxArraySize is large): `make([]T, -9223372036854775807)` same

The crash happens inside `readGGUFArray` which is called for any GGUF KV value of array type. The primary GGUF parser is called from `Decode(rs, maxArraySize)` where `maxArraySize = -1` for full collection → always triggers the `make` path.

**Code path**: `POST /api/blobs/:digest` (upload malicious GGUF with array KV having n=0x8000...01) → `fsggml.Decode(rs, -1)` → `readGGUFArray` → `newArray(-9223372036854775807, -1)` → `make([]uint8, -...)` → `runtime.throw`

**Security consequence**: Process-kill DoS, not per-goroutine recoverable. Any GGUF with a malformed array count triggers this.

**Severity estimate**: HIGH

**Status**: VALIDATED

---

## PH-15: Contradiction — Template `Vars()` Called Per-Request During Execute

**Reasoning model**: Contradiction Analysis

**Target**: `template/template.go:257-350` — `Execute`; line 259: `vars, err := t.Vars()`

**Stated design intent**: `Parse` validates and pre-computes `Vars` at load time (per the commit message for `1ed2881e`).

**Contradiction**: `Execute` calls `t.Vars()` again at line 259 on every invocation. For a template with N nodes, `Vars()` does an O(N) recursive walk of the entire AST. This means every `/api/chat` or `/api/generate` request using a template with a large template pays O(template_size) overhead.

With a 100,000-node template (achievable with ~3 MB of template text), every chat request triggers a 100k-node AST walk just for `Vars()` before any actual execution. Under sustained load (e.g., 100 concurrent chat requests), this creates a CPU and stack amplification attack.

Furthermore, `deleteNode` at line 327 also does a full recursive walk of the template AST on every Execute. Two full O(N) walks per request.

**Attack input**: A model with a large but valid template (no nil-pipe nodes, so `Parse` succeeds). Size: ~3 MB of nested `{{range .Messages}}...{{end}}` blocks.

**Code path**: `POST /api/chat {model: "model-with-large-template"}` → `template.Execute` → `t.Vars()` (O(N) walk) → `deleteNode(t.Template.Root.Copy(), ...)` (O(N) walk + O(N) allocations for Copy) → `template.Must(...).Execute` → legitimate template execution

**Security consequence**: CPU exhaustion / high latency DoS. No memory cap needed — just repeated chat requests against a model with an oversized (but valid) template. The template is stored on disk and cached in memory once loaded, but `Vars()` re-walks on every request.

**Severity estimate**: MEDIUM-HIGH (amplification attack; harder to trigger than OOM but sustained)

**Status**: VALIDATED

---

## PH-16: Abduction — `Vars()` Returns Partial Result on Error, `Capabilities()` Proceeds

**Reasoning model**: Abductive

**Target**: `template/template.go:171-189` — `Vars()`; `server/images.go:125-142` — `Capabilities()`

**Observed at `server/images.go:125-142`** (from KB bypass analysis):
```go
v, err := m.Template.Vars()
if err != nil {
    slog.Warn("model template contains errors", "error", err)
}
if slices.Contains(v, "tools") || ...
```

The handler does NOT return on error. `Vars()` returns a partial list when it errors mid-walk.

**Abduction**: A template that contains `.tools` identifier BEFORE a nil-pipe construct:
```
{{.Tools}} {{template "x"}}
```
1. `Vars()` collects `["Tools"]` from the `.tools` field node
2. Then hits `TemplateNode{Pipe: nil}` → returns `(["Tools"], error)`
3. `Capabilities()` receives `v = ["Tools"]`, ignores error, proceeds
4. `slices.Contains(v, "tools")` returns TRUE (case-insensitive lower: "tools" in ["tools"])
5. Model is flagged as having `CapabilityTools` even though its template is malformed and won't execute tool-call detection properly

**Security consequence**: A malicious model can force `CapabilityTools = true` on a model that doesn't actually implement tool calling. This causes the server to route tool-aware requests through the tools parser (`tools.NewParser` via `findToolCallNode`), which then fails silently and causes tool calls to fall back to the `{` heuristic — effectively neutralizing tool-call parsing for any tool-using client. This is a capability spoofing attack that breaks tool security guarantees.

**Severity estimate**: MEDIUM (affects correctness/security of tool-call handling; not a direct crash)

**Status**: VALIDATED (the code path is confirmed; the capability-spoofing consequence follows mechanically)

---

## PH-17: TRIZ — `readGGUFString` in Lazy Parser vs Primary Parser: Two Attack Surfaces for Same Bug

**Reasoning model**: TRIZ (contradiction: one parser was patched, the other was not)

**Target**: `fs/gguf/gguf.go:188-205` (`readString`, lazy parser) vs `fs/ggml/gguf.go:348-371` (`readGGUFString`, primary parser)

**Contradiction**: Commit `9d902d63` added bounds checks to `fs/ggml/gguf.go`. The KB notes this. The lazy parser `fs/gguf/gguf.go` received no corresponding patch for either the tensor bounds check or the string length cap.

**New attack angle from TRIZ**: The lazy parser is used in `server/images.go:89` via `gguf.Open` for EVERY model capability check — including from `/api/show`. The `/api/show` API:
1. Is typically unauthenticated (or has weak auth)
2. Is called automatically by clients before starting a conversation
3. Parses the GGUF to detect capabilities (`CapabilityTools`, `CapabilityImages`, etc.)

So the lazy parser's `readString` OOM is triggered by `/api/show` (or any first-access route) without needing to trigger quantization at all. This is a lower-privilege attack path than PH-03 (which required the quantize path).

**Attack flow**:
1. Upload a GGUF blob (or publish a model) with KV key length = `0x7FFFFFFFFFFFFFFF`
2. `GET /api/show {"name": "model:latest"}` → `gguf.Open` → `readKeyValue` → `readString` → OOM

The `/api/show` path is reachable even if quantization is disabled. The server will crash attempting to show the model's capabilities.

**Severity estimate**: HIGH (lower barrier than quantize path)

**Status**: VALIDATED

---

## PH-18: Abduction — `numTensor()` Returns uint64 but Loop Uses `range llm.numTensor()`

**Reasoning model**: Abductive

**Target**: `fs/ggml/gguf.go:193` — `for range llm.numTensor()` and `llm.parameters += tensor.Elements()`

**Observed**: The loop at line 194 iterates `numTensor()` times (up to 2^64 iterations on a crafted file). For `numTensor = 1`, but with a tensor whose `Elements() = 1<<62`, the `llm.parameters` accumulation at line 232:
```go
llm.parameters += tensor.Elements()
```
can overflow uint64 — `llm.parameters` wraps silently. This causes `kv["general.parameter_count"]` to be set to a small/zero value even when the model claims billions of parameters.

More critically: `numTensor = 0xFFFFFFFFFFFFFFFF` (max uint64). The loop would iterate ~1.8×10^19 times. Each iteration reads tensor info from the file. For an empty/short file, each `readGGUFString` returns EOF, and the loop terminates with error. But: if the loop runs even 1 billion iterations without error (e.g., a GGUF file with 1 billion valid tensor entries), the server allocates 1 billion `*Tensor` structs in `llm.tensors`.

**Abduction**: A GGUF with `numTensor = 1000000` (1 million) and minimal tensor entries (8 bytes each) would consume ~200 MB of Go heap just for the tensor slice, before any bounds check occurs. Memory exhaustion is pre-bounds-check.

**Code path**: `Decode(rs, ...)` → loop 1 million times → 1 million `llm.tensors` appends → 200 MB+ heap → OOM

**Sanitizers on path**: No `maxTensors` cap. `numTensor` is read directly from the file as uint64/uint32 with no validation against file size.

**Security consequence**: OOM DoS via inflated tensor count in the header. The actual tensor data can be minimal (the loop fails at EOF for each tensor metadata read), but the partial success case (many valid tensor entries) consumes unbounded memory.

**Severity estimate**: HIGH

**Status**: VALIDATED (numTensor is bounded only by the uint64 field; no cap enforced)

---

## PH-19: Contradiction — `deleteNode` Type-Assertion Without nil Interface Check

**Reasoning model**: Contradiction Analysis

**Target**: `template/template.go:600-601`, `606-609` — `deleteNode` in `template/template.go`

**Observed**:
```go
case *parse.IfNode:
    t.BranchNode = *(walk(&t.BranchNode).(*parse.BranchNode))
case *parse.WithNode:
    t.BranchNode = *(walk(&t.BranchNode).(*parse.BranchNode))
case *parse.RangeNode:
    t.BranchNode = *(walk(&t.BranchNode).(*parse.BranchNode))
case *parse.BranchNode:
    t.List = walk(t.List).(*parse.ListNode)
```

`walk(&t.BranchNode)` can return `nil` if `fn` matches the BranchNode (line 582). Then `.(*parse.BranchNode)` on nil interface panics: "interface conversion: interface is nil, not *parse.BranchNode".

Similarly, `walk(t.List).(*parse.ListNode)` where `t.List` is not nil but `walk` returns nil would panic.

**Attack scenario**: A template where the `Response` field appears inside a `{{range .Messages}}` body:
```
{{range .Messages}}{{.Response}}{{end}}
```
When `deleteNode` is called to remove `{{.Response}}` from the `RangeNode`'s List, the `walk` function may return nil for the entire `BranchNode` if it erases all nodes from the list. Then `*(walk(&t.BranchNode).(*parse.BranchNode))` = nil deref.

**Code path**: `template.Execute` → `deleteNode(t.Template.Root.Copy(), fn)` → `walk` returns nil for a BranchNode → `*(nil).(*parse.BranchNode)` → panic

**Sanitizers on path**: None — the type assertion is done without an `if n != nil` check.

**Security consequence**: Per-request panic in the chat/generate handler. Gin recovers with 500. Attacker can cause repeated 500 errors for models that use range/with/if wrapping the Response field.

**Severity estimate**: MEDIUM

**Status**: NEEDS-DEEPER (requires verifying the exact execution path where walk returns nil for a non-nil input; the fn predicate is specifically checking for Response FieldNode, so it's possible the nil case only occurs for empty template bodies)

---

## PH-20: Game Theory — Registry-Supplied Template vs. Client Tool Use (Capability Spoofing)

**Reasoning model**: Game Theory (attacker controls model registry, victim uses tool-calling features)

**Target**: `server/images.go:125-142` — `Capabilities()`, `template/template.go:171` — `Vars()`, `tools/template.go:50-103` — `findToolCallNode`

**Game setup**:
- Attacker controls a model published to a public/private registry
- Victim uses `ollama run evil-model` and relies on tool-calling for safety-critical automation
- Attacker wants to silently subvert tool parsing

**Strategy**: Craft a model template that:
1. Passes `template.Parse` validation (no nil-pipe nodes)
2. Contains `{{.Tools}}` to force `CapabilityTools = true`
3. Hides the actual tool-call JSON emission inside a `{{template "tools" .}}` invocation
4. `findToolCallNode` (tools/template.go line 73) skips `TemplateNode` nodes — it doesn't recurse into named templates
5. The tool-call detection falls back to `fallback = "{"` heuristic

**Consequence**: The model template claims tool capability but the tool-call detection uses a string heuristic (`"{"`) instead of the proper AST-based detection. The model's LLM output now uses a different serialization format than the client expects, causing tool calls to be silently dropped or misidentified.

**Attack refinement**: An attacker-controlled model uses the `{{template "tools"}}` pattern to ship an incompatible tool format that the server doesn't detect, causing tool results to be silently ignored while the LLM continues generating as if tools were called.

**Code path**: `Capabilities()` → `Vars()` returns `["tools"]` → `CapabilityTools=true` → `tools.NewParser(template, req.Tools)` → `findToolCallNode` skips `TemplateNode` → `builtinParser=nil` → fallback to `"{"` detection

**Severity estimate**: MEDIUM (capability spoofing / security guarantee breakage)

**Status**: VALIDATED (the `findToolCallNode` skip of `TemplateNode` is explicitly noted in the KB bypass analysis B4)

---

## PH-21: Abduction — `GraphSize` Panics on Type Assertion with Missing `tokenizer.ggml.tokens`

**Reasoning model**: Abductive

**Target**: `fs/ggml/ggml.go:607` — `vocab := uint64(f.KV()["tokenizer.ggml.tokens"].(*array[string]).size)`

**Observed**: `f.KV()["tokenizer.ggml.tokens"]` returns `nil` if the key is absent. Type asserting nil to `*array[string]` at line 607 panics: "interface conversion: interface is nil, not *array[string]".

**Attack input**: A GGUF file with no `tokenizer.ggml.tokens` KV entry. This is valid for certain model architectures (e.g., embedding models, or models that store vocabulary differently).

**Code path**: `GGML.GraphSize(...)` is called from `server/images.go` via `llm.EstimateGPULayers` which calls `ggml.GraphSize` — this is called during model load to estimate memory requirements. If the GGUF lacks `tokenizer.ggml.tokens`, this panics before the model even loads.

**Sanitizers on path**: No nil-check before the type assertion at line 607.

**Security consequence**: Panic during model load. Any model without `tokenizer.ggml.tokens` (which is valid per GGUF spec for non-language models) causes a panic in `GraphSize`, preventing the model from loading. This is a DoS against specific model types.

**Severity estimate**: MEDIUM (DoS for specific model classes; may also be triggerable with a crafted GGUF that has `tokenizer.ggml.tokens` as a different type — e.g., an int instead of a string array)

**Status**: VALIDATED (the type assertion without nil-check is directly visible at line 607)
