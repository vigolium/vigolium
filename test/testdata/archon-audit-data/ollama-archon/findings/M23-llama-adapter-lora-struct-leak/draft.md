Phase: 8
Sequence: 023
Slug: llama-adapter-lora-struct-leak
Verdict: VALID
Rationale: Tracer confirmed that although `llama/llama.go:346` correctly frees the `cLoraPath` CString via defer, there is NO corresponding free for the `llama_adapter_lora` C struct returned by `C.llama_adapter_lora_init` — each `ApplyLoraFromFile` leaks one adapter struct; with no cap on `len(req.LoraPath)`, a crafted manifest with many adapter layers amplifies the leak; the leak is bounded per subprocess lifetime but represents a confirmed C-heap growth primitive.
Severity-Original: MEDIUM
Severity-Final: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-03/debate.md

## Summary

`llama/llama.go:344-356` (`ApplyLoraFromFile`) calls `C.llama_adapter_lora_init(m.c, cLoraPath)` to allocate a `llama_adapter_lora` struct on the C heap, then calls `C.llama_set_adapter_lora(lc.c, loraAdapter, scale)` to register it with the context. There is NO matching `C.llama_adapter_lora_free(loraAdapter)` — neither deferred nor tracked — so each call permanently leaks the adapter struct.

`runner/llamarunner/runner.go:852-856` iterates `req.LoraPath` and calls `ApplyLoraFromFile` for each entry. `req.LoraPath` is built by the parent daemon from `manifest.AdapterPaths` (`server/images.go:334-348`) — an attacker who can publish a manifest with many adapter layers amplifies the leak linearly.

Since the runner enforces single-load (`runner/llamarunner/runner.go:884-887`), the leak is bounded per subprocess. Across the lifetime of one runner, the total leak is `sum(sizeof(llama_adapter_lora))` across all adapters — typically small. The finding is MEDIUM because:
- The leak is real and unambiguous (no defer, no explicit free).
- The pattern is asymmetric to the adjacent `cLoraPath` free (line 346 correctly defers), suggesting a review-miss rather than intentional.
- Combined with p8-048 supply-chain vector, it enables an amplification DoS if `MaxRunners` is raised or subprocess recycling is introduced.

## Location

- `llama/llama.go:348-355` -- `loraAdapter := C.llama_adapter_lora_init(m.c, cLoraPath)`; `C.llama_set_adapter_lora(lc.c, loraAdapter, scale)`; **no `defer C.llama_adapter_lora_free(loraAdapter)`**
- `runner/llamarunner/runner.go:852-856` -- unbounded loop over `req.LoraPath`
- `server/images.go:334-348` -- parent builds `AdapterPaths` from manifest layers

## Attacker Control

Supply-chain: the attacker publishes a manifest with many (`ADAPTER` entries) adapter layers. Victim pulls the model; at load-time the runner processes each adapter, leaking one struct per entry.

Alternate: `POST /api/create` with a Modelfile containing many `ADAPTER` lines; same amplification.

## Trust Boundary Crossed

Manifest/supply-chain -> runner subprocess C heap.

## Impact

- Per subprocess: leak grows linearly with adapter count. `llama_adapter_lora` struct is non-trivial (contains vectors of tensor pointers, names, etc.) — typically on the order of kilobytes per adapter.
- Crafted manifest with 10,000 adapter entries: MB-scale leak per subprocess.
- Bounded by subprocess lifetime; reclaimed on unload. Not a process-lifetime DoS today.

Severity MEDIUM because the bounding argument is fragile: if a future change (a) increases subprocess lifetime beyond single load, (b) supports dynamic adapter swap without subprocess restart, or (c) reuses the runner across multiple model loads, the leak compounds into a reliable DoS.

## Evidence

Tracer verification (Round 3, H-NEW-45, 2026-04-17T10:23:00Z):

```
llama/llama.go:344-356
    func (m *Model) ApplyLoraFromFile(lc *Context, loraPath string, scale float32, threads int) error {
        cLoraPath := C.CString(loraPath)
        defer C.free(unsafe.Pointer(cLoraPath))    // CString correctly freed

        loraAdapter := C.llama_adapter_lora_init(m.c, cLoraPath)
        if loraAdapter == nil { return ... }
        // MISSING: defer C.llama_adapter_lora_free(loraAdapter)

        err := C.llama_set_adapter_lora(lc.c, loraAdapter, scale)
        ...
        return nil
    }
```

Tracer finding: "What DOES accumulate: `C.llama_adapter_lora_init` allocates a `llama_adapter_lora` struct on the C heap. `llama_set_adapter_lora` registers it with the context. The adapter is NOT freed after `ApplyLoraFromFile` returns (no `defer C.llama_adapter_lora_free`). So each call to `ApplyLoraFromFile` leaks a `llama_adapter_lora` struct."

Ideator's original claim (H-NEW-45) incorrectly attributed the leak to `C.CString`; tracer corrected: "The CString leak claimed in H-NEW-45 is INCORRECT (CString is freed via defer). However, there IS a real leak of the `llama_adapter_lora` C struct per `ApplyLoraFromFile` call."

## Reproduction Steps

1. Prepare multiple valid (small, no-op) LoRA adapter GGUFs.
2. Build a Modelfile listing many `ADAPTER` entries pointing to the blobs.
3. `POST /api/create`; observe runner subprocess RSS growth correlated with adapter count.
4. Fix direction: (a) change `llama_set_adapter_lora` registration to transfer ownership (upstream change); OR (b) add `defer C.llama_adapter_lora_free(loraAdapter)` paired with a context-lifetime tracking list that frees on context teardown; (c) cap `len(req.LoraPath)` at a reasonable value (e.g., 16) in the runner or parent.

Pattern: register AP-051 `cgo-returned-handle-no-free-pair` — a cgo init function returns a handle that must be freed, but the Go wrapper omits the pair free. Detection signature:

```
grep: "C\\.[a-z_]+_init\\(" with nearby absence of "C\\.[a-z_]+_free\\("
```
