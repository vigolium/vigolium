## Summary

`fs/ggml/gguf.go:194` runs `for range llm.numTensor()` with `numTensor` read directly from the attacker-supplied header. Each iteration allocates a `Tensor` struct plus a shape slice and appends the pointer to `llm.tensors`. There is no cap on numTensor and no check against `fileSize / minTensorInfoSize` before the loop starts. The only bound is that each iteration consumes ~33 bytes from the input stream, so a 1GB input can declare ~30M tensors, producing ~2GB of Tensor metadata allocation -- well above what a typical server can tolerate for a single unauthenticated request.

## Details

`fs/ggml/gguf.go:194` runs `for range llm.numTensor()` with `numTensor` read directly from the attacker-supplied header. Each iteration allocates a `Tensor` struct plus a shape slice and appends the pointer to `llm.tensors`. There is no cap on numTensor and no check against `fileSize / minTensorInfoSize` before the loop starts. The only bound is that each iteration consumes ~33 bytes from the input stream, so a 1GB input can declare ~30M tensors, producing ~2GB of Tensor metadata allocation -- well above what a typical server can tolerate for a single unauthenticated request.

### Location

`fs/ggml/gguf.go:194-233` -- tensor-info loop in `Decode`.

### Attacker Control

Any GGUF blob. Reached from `/api/create`, `/api/pull`, `/api/show`.

### Trust Boundary Crossed

Network API -> process heap exhaustion.

### Evidence

```
// fs/ggml/gguf.go:194-233
for range llm.numTensor() {
    name, err := readGGUFString(llm, rs)
    ...
    shape := make([]uint64, dims)
    ...
    tensor := Tensor{Name: name, Kind: kind, Offset: offset, Shape: shape[:]}
    llm.tensors = append(llm.tensors, &tensor)
    llm.parameters += tensor.Elements()   // also overflows (see p8-020)
}

// bounds check runs AFTER the full loop completes
for _, tensor := range llm.tensors {
    tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()
    if tensorEnd > uint64(fileSize) { ... }
}
```

Advocate (Round 3): structural bound of `numTensor * 33 bytes <= fileSize` reduces but does not eliminate the attack; 500MB upload produces ~300MB-1GB of metadata allocations. Cannot fully disprove.

## Root Cause

Validated rationale: The tensor-metadata loop at fs/ggml/gguf.go:194 iterates numTensor times with no cap and appends ~70-byte Tensor records to llm.tensors before any file-size bounds check runs; a GGUF declaring numTensor = 100M causes ~7GB of pre-bounds-check allocation.

Primary cited code reference: `fs/ggml/gguf.go:194`.

Merge extraction sink line: `fs/ggml/gguf.go:194-233` -- tensor-info loop in `Decode`.

An adversarial review was preserved alongside the draft and should be consulted for counter-arguments and any severity challenge.

## Proof of Concept

Merge-normalized status: `executed`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Craft a GGUF header with `NumTensor = 0xFFFFFF`, tensor-info body filled with minimal-size tensor records (short name, 1 dim, shape=1).
2. `POST /api/create` referencing the blob.
3. Observe RSS growth before any response arrives.

Fix direction: `if numTensor > (fileSize - headerSize) / minTensorInfoSize { return error }` before the loop; define a safe hard cap (e.g., 1M tensors).

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Reproduced 1.5 GB peak heap for a 228 MB crafted GGUF at commit 57653b8e; file-size bound check at gguf.go:258 runs after the full tensor loop so per-record allocations proceed unchecked.
Severity-Final: HIGH
PoC-Status: executed

## Impact

Memory exhaustion DoS bounded by file-size but not by any RAM cap. On a server with 16GB RAM, a 500MB malicious upload produces ~15M tensor records = ~1GB of metadata, driving the host into swap. Sustained at low RPS produces effective permanent DoS.

_Synthesized during merge normalization from `archon/findings/H6-gguf-numtensor-uncapped/draft.md`._
