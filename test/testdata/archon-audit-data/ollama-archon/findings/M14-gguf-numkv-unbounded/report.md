## Summary

`fs/ggml/gguf.go:143` runs `for i := 0; uint64(i) < llm.numKV(); i++` with no cap. Each iteration reads a KV key (via `readGGUFString`, p8-021 applies) and a typed value, then stores the pair in `llm.kv map[string]any`. For a 1GB input with minimum-size KV entries (~14 bytes each), numKV can reach ~7×10^7 entries, each requiring a map allocation plus the key string's heap footprint.

## Details

`fs/ggml/gguf.go:143` runs `for i := 0; uint64(i) < llm.numKV(); i++` with no cap. Each iteration reads a KV key (via `readGGUFString`, p8-021 applies) and a typed value, then stores the pair in `llm.kv map[string]any`. For a 1GB input with minimum-size KV entries (~14 bytes each), numKV can reach ~7×10^7 entries, each requiring a map allocation plus the key string's heap footprint.

### Location

`fs/ggml/gguf.go:141-191`

### Attacker Control

Any GGUF blob.

### Trust Boundary Crossed

Network API -> process heap.

### Evidence

```
// fs/ggml/gguf.go:141-191
for i := 0; uint64(i) < llm.numKV(); i++ {
    k, err := readGGUFString(llm, rs)
    ...
    llm.kv[k] = v
}
```

## Root Cause

Validated rationale: The KV header loop at fs/ggml/gguf.go:143 iterates numKV times with no cap; each iteration allocates a map entry and triggers readGGUFString's unbounded alloc (see p8-021); combined with numTensor loop, these form an uncapped-loop cluster that consumes memory proportional to attacker declarations until file EOF or OOM.

Primary cited code reference: `fs/ggml/gguf.go:141`.

Merge extraction sink line: `fs/ggml/gguf.go:141-191`

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Craft a GGUF header declaring `numKV = 0x1000000` with body filled with minimal-size KV entries.
2. `POST /api/create` -> observe RSS growth.

Fix direction: hard cap `numKV <= 100000` or `numKV * minEntrySize <= fileSize`; mirror fix with p8-023 (numTensor).

## Impact

CPU + memory DoS, structurally bounded by file-size. Combined with p8-021 (unbounded string alloc per iteration) the memory growth per byte of input is high. Same class as p8-023 (numTensor uncapped loop).

_Synthesized during merge normalization from `archon/findings/M14-gguf-numkv-unbounded/draft.md`._
