## Summary

The Ollama Go loader treats `tokenizer.ggml.tokens` (an array of strings) as the authoritative source of vocabulary size at `fs/ggml/ggml.go:607`. cgo-side llama.cpp uses a separate `n_vocab` value derived from the model architecture. There is NO cross-check in the Go model-load path that validates `len(tokenizer.ggml.tokens) == n_vocab` or constrains the Go-side tokenizer to emit only IDs in `[0, n_vocab)`.

An attacker publishing a poisoned model with `len(tokens) > n_vocab` (e.g., tokens array of 50000, n_vocab declared as 32000) can cause the Go BPE/WordPiece tokenizer to emit IDs in the range `[n_vocab, len(tokens))` when processing crafted prompts. Those IDs flow to the cgo embedding lookup, which performs OOB read into memory adjacent to the declared `n_vocab × embedding_dim` table.

## Details

The Ollama Go loader treats `tokenizer.ggml.tokens` (an array of strings) as the authoritative source of vocabulary size at `fs/ggml/ggml.go:607`. cgo-side llama.cpp uses a separate `n_vocab` value derived from the model architecture. There is NO cross-check in the Go model-load path that validates `len(tokenizer.ggml.tokens) == n_vocab` or constrains the Go-side tokenizer to emit only IDs in `[0, n_vocab)`.

An attacker publishing a poisoned model with `len(tokens) > n_vocab` (e.g., tokens array of 50000, n_vocab declared as 32000) can cause the Go BPE/WordPiece tokenizer to emit IDs in the range `[n_vocab, len(tokens))` when processing crafted prompts. Those IDs flow to the cgo embedding lookup, which performs OOB read into memory adjacent to the declared `n_vocab × embedding_dim` table.

### Location

- `fs/ggml/ggml.go:607` -- vocab = len of tokens array
- `model/process_text.go` and `runner/llamarunner/runner.go` -- ID shipping to cgo without bounds check

### Attacker Control

Model publisher (supply-chain) OR any caller who can push a GGUF via `/api/pull`/`/api/create`.

### Trust Boundary Crossed

Model-file trust -> cgo embedding memory.

### Evidence

Round 2 trace: `fs/ggml/ggml.go:607` reads `vocab := uint64(f.KV()["tokenizer.ggml.tokens"].(*array[string]).size)`. No comparison is performed anywhere in fs/ggml/ or model/ against `llm.kv["n_vocab"]` or architecture-derived vocab size. The Go tokenizer (`model/process_text.go`) emits IDs based on its learned BPE merges / WordPiece vocab, bounded only by the loaded tokens array, not by `n_vocab`.

## Root Cause

Validated rationale: The Go loader derives vocab size from len(tokenizer.ggml.tokens) in fs/ggml/ggml.go:607 but does not cross-check it against the model's declared n_vocab; cgo embedding matmul sizes its embedding table from n_vocab. When the two disagree, token IDs produced by the Go tokenizer can exceed the cgo embedding table bounds.

Primary cited code reference: `fs/ggml/ggml.go:607`.

Merge extraction sink line: - `fs/ggml/ggml.go:607` -- vocab = len of tokens array

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Craft a GGUF with `tokenizer.ggml.tokens` = array of 50000 strings and model arch declaring `n_vocab = 32000`.
2. `POST /api/pull` of the model.
3. `POST /api/chat` with a prompt designed to produce tokens in the [32000, 50000) range (e.g., rare unicode sequences the attacker-trained BPE encodes to high-indexed tokens).
4. Observe: either cgo-side SIGSEGV (if OOB crosses mapped-page boundary) or subtle output-token anomalies (if OOB reads into adjacent tensor weights).

Fix direction: at model-load time, require `len(tokenizer.ggml.tokens) == n_vocab`; reject models where the two disagree.

## Impact

Potential OOB read in cgo embedding lookup, memory-disclosure oracle for adjacent mmapped weights. Cgo-side exploitation is speculative without llama.cpp source review; this finding captures the Go-side defect (missing invariant check) rather than the cgo-side consequence.

_Synthesized during merge normalization from `archon/findings/M16-tokenizer-vocab-size-mismatch/draft.md`._
