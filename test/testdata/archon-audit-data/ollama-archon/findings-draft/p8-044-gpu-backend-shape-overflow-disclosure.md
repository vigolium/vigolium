Phase: 8
Sequence: 044
Slug: gpu-backend-shape-overflow-disclosure
Verdict: VALID
Rationale: Tracer confirmed the shape-overflow primitive from p8-020 is reachable at the ggml CUDA/Metal backend via `ml/backend/ggml/ggml.go:526` with no Go/cgo-level sanitizer preventing a wrapped-small `Size()` from being fed to `cudaMalloc` while the kernel launch uses the un-wrapped dims — uninitialized-page disclosure is then GPU-driver-specific (historically CUDA does not zero device pages on `cudaMalloc`), so the finding is VALID at HIGH for shared-GPU deployments while downgraded to MEDIUM for single-tenant hosts.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: check-2-ambiguous (GPU driver behavior not verified at code level; partly empirical)
Debate: archon/chamber-workspace/chamber-03/debate.md

## Summary

A crafted GGUF with `Shape = [2^31-1, 2]` (each dim individually within int32) has `Elements() = 2^32-2` but — depending on `typeSize/blockSize` — can produce a small `Size()` value that passes the `tensorEnd > fileSize` bounds check. When the GPU backend tensor-upload path at `ml/backend/ggml/ggml.go:526` reads `int64(t.Size())` bytes, `cudaMalloc` is called with a small allocation size, while the kernel launch parameters derived from `t.Shape` assume the full `2^32-2` element count. Kernel reads/writes over the declared dims reach device memory outside the allocation, which on NVIDIA/AMD drivers is typically uninitialized recycled memory from prior process or tenant allocations.

This is the GPU-side sibling of chamber-02 p8-020 / chamber-03 p8-043. The Go + cgo layer cannot sanitize this; the kernel dispatch takes the un-wrapped dims as truth. The severity is hardware- and deployment-dependent: on shared-GPU cloud (Kubernetes GPU nodes, Colab-style multi-tenant, GPU virtualization) this discloses other tenants' activations/weights/keys; on single-tenant dedicated GPU hosts (typical Ollama desktop usage), the disclosure is self-to-self within the same process.

## Location

- `fs/ggml/ggml.go:505-514` -- shape-overflow root (p8-020)
- `fs/ggml/gguf.go:258-262` -- bounds check bypassed by wrap
- `ml/backend/ggml/ggml.go:526` -- `sr := io.NewSectionReader(file, int64(tensorOffset + t.Offset), int64(t.Size()))` — wrap-sized byte count sent to GPU upload
- `ml/backend/ggml/ggml.go:497-544` -- tensor-upload dispatch to GPU backend
- Vendored ggml CUDA/Metal kernel launch code: kernel dispatch uses `t.Shape[]` directly, not `t.Size()`

## Attacker Control

Unauthenticated `POST /api/create` with crafted GGUF (same primitive as p8-020/p8-043). The attack is only meaningful when:

1. GPU backend is enabled (default when CUDA/Metal/Vulkan driver is detected)
2. Shared-GPU deployment with other tenants on the same device

Entry points are identical to p8-020: `POST /api/blobs/:digest` + `POST /api/create`.

## Trust Boundary Crossed

Unauthenticated HTTP -> Go/cgo -> CUDA/Metal driver -> GPU device memory (cross-tenant, cross-VM on shared-GPU virtualization).

## Impact

Cross-tenant GPU memory disclosure on shared-GPU hosts: other ML jobs' weights, activations, prompts, and any data the GPU driver has allowed to persist across allocations. The disclosed bytes are returned to the attacker through the legitimate embedding-retrieval path (`GetEmbeddingsSeq` -> HTTP JSON response) — the GPU OOB read produces tensor values that `cudaMemcpy` copies back to host, which then flow through the standard inference response.

On single-tenant hosts: self-process GPU-memory disclosure (uninitialized pages from this process's own prior allocations). Severity MEDIUM; may leak earlier-request activations but not cross-user.

## Evidence

Tracer verification (Round 3, H-CHAIN-E.1, 2026-04-17T10:15:00Z):

```
fs/ggml/gguf.go:258-262 — bypassed by typeSize/blockSize wrap
ml/backend/ggml/ggml.go:526
    sr := io.NewSectionReader(file, int64(b.meta.Tensors().Offset+t.Offset), int64(t.Size()))
    // t.Size() wrapped small; SectionReader reads a handful of bytes
ml/backend/ggml/ggml.go:497-544
    // tensor-upload path dispatches to CUDA/Metal via cgo; kernel launch uses t.Shape
    // (not t.Size()) — over-read occurs on GPU device memory
```

Tracer note: "CUDA runtime: `cudaMalloc(0)` behavior is driver-specific; NOT a code-level sanitizer." The GPU driver assumption (non-zeroed recycled pages) is well-documented for NVIDIA; Metal's behavior is also historically non-zeroing for performance.

CodeQL: DFD-6 `reachable: false` (CUDA backend not modeled by Go extractor).

Advocate did not file a defense brief on H-CHAIN-E.1 in Round 1 (it was novel to Ideator). Synth disposition: the Go/cgo layer has no mitigation; the risk is real on shared-GPU deployments.

## Reproduction Steps

1. Configure Ollama with CUDA backend; run on a host where recent memory pressure has exercised the GPU heap (e.g., prior inference on a large model).
2. Craft GGUF per p8-043 reproduction steps.
3. `POST /api/create` + `POST /api/embed` with the crafted model.
4. Compare returned embedding bytes to expected model output; bytes deviating from initial-weight values indicate OOB read from prior GPU allocations.
5. Fix direction: (a) in `ml/backend/ggml/ggml.go:526`, add assert `t.Size() == shape-product * elementSize / blockSize` (overflow-checked) before sending to GPU; (b) in the GPU backend glue, reject tensors where `t.Shape` product does not match `t.Size()` per the type's byte width; (c) upstream fix per p8-020 root-cause (overflow-detected multiply in `Elements()`).

Pattern: register AP-045 `gpu-backend-shape-size-decoupled` — same root cause as AP-020 but different sink class (GPU vs CPU OOB).
