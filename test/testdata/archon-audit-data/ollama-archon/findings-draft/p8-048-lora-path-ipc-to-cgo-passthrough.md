Phase: 8
Sequence: 048
Slug: lora-path-ipc-to-cgo-passthrough
Verdict: VALID
Rationale: Tracer confirmed `runner/llamarunner/runner.go:852-856` iterates `req.LoraPath` and calls `llama/llama.go:348` → `C.llama_adapter_lora_init(path)` on every element; path is parent-daemon-controlled (blobs dir) so attacker control requires supply-chain (malicious registry) or IPC impersonation (p8-chain-B unreachable in practice); cgo parse of arbitrary GGUF-shaped file is the attack surface — finding is MEDIUM because the LoRA GGUF parser is a distinct attack surface from the main model parser.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-4-partial (requires attacker-planted LoRA blob; no direct HTTP-to-arbitrary-path pivot)
Debate: archon/chamber-workspace/chamber-03/debate.md

## Summary

The llamarunner subprocess applies LoRA adapters by iterating `req.LoraPath` (from the IPC `/load` request) and calling `C.llama_adapter_lora_init(m.c, cLoraPath)` for each entry. Each path flows unchanged to llama.cpp's adapter loader, which calls `gguf_init_from_file(path_lora)` and performs the full GGUF parse on the pointed-to file. 

The path values are constructed by the parent daemon from manifest blob digests (`server/images.go:334-348`), so they are not directly attacker-controlled HTTP strings. Attacker control requires one of:

1. **Supply-chain**: an attacker publishes a model to a registry the victim pulls from; the model's manifest references a malicious LoRA adapter blob. Victim's `/api/pull` fetches the blob into the blobs dir; subsequent inference loads it. This is realistic.
2. **Malicious `/api/create`**: a local attacker `POST /api/create` with a Modelfile referencing attacker-crafted adapter blobs.
3. **IPC impersonation** (p8-chain-B): unreachable in practice per tracer Round 3.

The cgo parser surface at `llama_adapter_lora_init` is separate from the main model GGUF parser and receives less fuzzing. Any parser bug there is reachable through an attacker-planted LoRA blob.

## Location

- `runner/llamarunner/runner.go:852-856` -- loop over `lpath`; calls `ApplyLoraFromFile`
- `llama/llama.go:344-356` -- `ApplyLoraFromFile` → `C.llama_adapter_lora_init(m.c, cLoraPath)`
- `llama.cpp/src/llama-adapter.cpp:417-430` -- adapter init performs `gguf_init_from_file` on the path
- `server/images.go:334-348` -- parent builds `LoraPath` from manifest adapter layers

## Attacker Control

Supply-chain (pull-a-model): the attacker publishes a manifest that declares one or more adapter layers. When victim `POST /api/pull`s the model, the adapter blobs are placed in the blobs dir with their declared digests. At inference, `LoraPath` is populated from these blobs. The LoRA GGUF parser is fed the attacker-crafted bytes.

Local: `POST /api/create` with a Modelfile that references adapter digests controlled by the attacker. Unauthenticated on the default loopback bind.

## Trust Boundary Crossed

Registry/manifest supply chain -> runner subprocess cgo parser.

## Impact

Any parser bug in `gguf_init_from_file` or `llama_adapter_lora_init` is reachable. Known classes include:
- Integer overflow in GGUF shape/offset fields (p8-020, p8-043) — same primitives apply to the adapter parser.
- Null-deref on malformed header (similar to p8-040's pattern).
- Out-of-bounds read from tensor data sized against attacker dims.

The immediate consequence is DoS (parser crash → runner SIGSEGV → scheduler respawn). Severity escalates if any adapter-parser bug permits memory corruption beyond crash.

Additionally: there is no cap on `len(req.LoraPath)` in the runner (see p8-051 for the related leak). An attacker-supplied manifest with many adapter entries amplifies any per-adapter bug.

## Evidence

Tracer verification (Round 3, H-00.06, 2026-04-17T10:07:00Z):

```
runner/llamarunner/runner.go:852-856
    for _, path := range lpath {
        s.model.ApplyLoraFromFile(s.lc, path, 1.0, threads)
    }

llama/llama.go:344-356
    cLoraPath := C.CString(loraPath)
    defer C.free(unsafe.Pointer(cLoraPath))
    loraAdapter := C.llama_adapter_lora_init(m.c, cLoraPath)
    if loraAdapter == nil { return fmt.Errorf("cannot init adapter %s", loraPath) }
    C.llama_set_adapter_lora(lc.c, loraAdapter, scale)
```

Tracer Round 3: "The `C.llama_adapter_lora_init` function at `llama.cpp/src/llama-adapter.cpp:417-430` calls `gguf_init_from_file(path_lora)` → full GGUF parsing on the provided file... Standalone exploitation requires IPC impersonation (H-00.12). For a supply-chain attacker who registered a malicious LoRA GGUF, this is the REACHABLE path into `llama_adapter_lora_init` cgo parsing — which may have its own vulnerabilities."

Advocate Round 1 H-00.06: "runner's `/load` endpoint binds to `127.0.0.1`... same-host attackers who can bind a loopback port are by definition running as the same Unix user..." Accepted for direct IPC but does not neutralize supply-chain.

## Reproduction Steps

1. Prepare a malicious GGUF-formatted "LoRA" file exercising any known GGUF parser bug (e.g., shape overflow per p8-020).
2. Compute its sha256 digest; upload as a blob via `POST /api/blobs/:digest`.
3. Create a Modelfile that includes `ADAPTER sha256:<digest>` (or equivalent manifest construction).
4. `POST /api/create`. At load-time, the LoRA parser is fed the malicious bytes.
5. Observe runner crash or whatever primitive the adapter parser bug yields.
6. Fix direction: (a) apply p8-020's `math/bits.Mul64` fix to the adapter parser's shape handling; (b) enforce a cap on `len(req.LoraPath)` (see p8-051); (c) add a structural integrity check (magic bytes + minimum fields) before handing bytes to cgo; (d) fuzz `llama_adapter_lora_init` with OSS-Fuzz.

Pattern: register AP-048 `adapter-parser-attack-surface-via-manifest` — supply-chain-delivered bytes reaching a distinct cgo parser not covered by main-model parser hardening.
