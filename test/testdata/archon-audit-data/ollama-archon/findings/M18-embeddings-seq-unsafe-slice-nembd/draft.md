Phase: 8
Sequence: 018
Slug: embeddings-seq-unsafe-slice-nembd
Verdict: VALID
Rationale: Tracer confirmed `llama/llama.go:217-218` uses `make([]float32, c.Model().NEmbd())` + `unsafe.Slice(..., NEmbd())` where `NEmbd()` flows from the model's GGUF `llama.embedding_length` KV with no upstream bound; a crafted model with `embedding_length = 2^31-1` triggers an 8 GB allocation in the runner subprocess on `/api/embed` calls — not direct memory disclosure (advocate's C-and-Go-share-n_embd argument is valid for the read range) but a reliable unauthenticated DoS, and the dual-read at lines 217-218 creates a small TOCTOU window worth hardening.
Severity-Original: MEDIUM
Severity-Final: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-2-partial (advocate Round 1 showed the C side allocates with matching n_embd so the unsafe.Slice stays in-bounds; the residual concern is the `make` allocation DoS + TOCTOU between lines 217/218)
Debate: archon/chamber-workspace/chamber-03/debate.md

## Summary

`llama/llama.go:211-243` (`GetEmbeddingsSeq`, `GetEmbeddingsIth`, `GetLogitsIth`) construct per-request result buffers sized by `c.Model().NEmbd()`, which returns `C.llama_model_n_embd(m.c)` — derived from the GGUF `llama.embedding_length` metadata. No upstream validation bounds this value. For a crafted model with `embedding_length = 2^31-1`:

- `make([]float32, NEmbd())` allocates ~8 GB in the runner subprocess (OOM on most hosts).
- If the make succeeds (high-memory host), `unsafe.Slice((*float32)(e), NEmbd())` creates a slice that reads from the C-allocated embedding buffer. Per advocate Round 1: the C side allocated its buffer using the same `n_embd` at context creation, so the slice stays within the C allocation. This is defensible.
- Residual concern: `NEmbd()` is called TWICE at lines 217 and 218. If a concurrent model reload (unlikely but not prevented) changes `n_embd` between the two reads, the slice could exceed the C allocation.

The advocate's disclosure-primitive disproof is credible. The remaining finding is the DoS: unauthenticated `/api/embed` on a model with crafted `embedding_length` → runner OOM → session outage.

## Location

- `llama/llama.go:217-218` -- `embeddings := make([]float32, c.Model().NEmbd())` then `copy(embeddings, unsafe.Slice(..., c.Model().NEmbd()))` — dual NEmbd() read
- `llama/llama.go:228, 241` -- same pattern in `GetEmbeddingsIth` and `GetLogitsIth`
- `fs/ggml/ggml.go` -- `llama.embedding_length` KV read without bound

## Attacker Control

Unauthenticated `POST /api/embed` (or `/api/generate` for logits) with `"model":"crafted"` where the model has a maliciously large `embedding_length` KV. Preconditions same as p8-020/p8-042: attacker can push a GGUF via `/api/blobs/:digest` + `/api/create`.

## Trust Boundary Crossed

Unauthenticated HTTP -> runner subprocess OOM/crash.

## Impact

Runner OOM on unauthenticated `/api/embed`. Scheduler-wide impact: all active sessions on the model drop. The DoS persists as long as the crafted model is the `/api/embed` target. The parent daemon continues running; only the runner crashes.

The advocate's counter-argument (C and Go share `n_embd` source, so the `unsafe.Slice` stays in-bounds) is accepted — this finding does NOT claim an OOB-read primitive. The VALID severity rests on (a) the DoS and (b) the hardening value of bounding `NEmbd()` at model-load time.

## Evidence

Tracer verification (Round 2, H-00.07, 2026-04-17T07:06:00Z):

```
llama/llama.go:211-219
    e := unsafe.Pointer(C.llama_get_embeddings_seq(c.c, C.int(seqId)))
    if e == nil { return nil }
    embeddings := make([]float32, c.Model().NEmbd())       // 1st NEmbd() call
    copy(embeddings, unsafe.Slice((*float32)(e), c.Model().NEmbd()))  // 2nd NEmbd() call
```

Advocate Round 1 defense brief for H-00.07:
> "The strongest defense: `C.llama_get_embeddings_seq` returns a pointer that lives in the C-allocated context buffer whose size is determined by the same n_embd value at model-load time... the `unsafe.Slice(..., NEmbd())` Go view covers exactly the buffer the C side allocated; it is NOT reading past the C allocation."

Tracer Round 2 accepted this for the read-range argument but flagged the DoS path as REACHABLE: a crafted `embedding_length` of 2^31-1 causes `make([]float32, 2^31-1)` = 8 GB allocation → OOM on the runner subprocess.

Synth disposition: severity MEDIUM — the disclosure claim is disproved, but the DoS is real and unauthenticated. Consolidation of the dual NEmbd() read into a local variable is a correctness improvement regardless of exploit severity.

## Reproduction Steps

1. Craft a GGUF with `general.architecture = "llama"` and `llama.embedding_length = 2147483646` (near-max int32). Other KVs minimal.
2. `POST /api/blobs/:digest` upload; `POST /api/create` to register.
3. `POST /api/embed` with the crafted model name. Watch runner OOM in logs.
4. Fix direction: (a) validate `n_embd` at model load — reject `n_embd > 1 << 16` (32K-dim embedding is already larger than any known model); (b) cache `NEmbd()` into a local to eliminate TOCTOU at `llama/llama.go:217-218, 228, 241`; (c) in the `make`, use `cap = nembd` and check against a hard ceiling before allocating.

Pattern: register AP-046 `cgo-model-metadata-unbounded-alloc` — attacker-controlled model metadata used as an allocation size with no upper bound.
