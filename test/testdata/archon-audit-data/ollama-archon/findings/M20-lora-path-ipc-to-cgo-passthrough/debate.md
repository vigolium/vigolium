# Review Chamber: chamber-03

Cluster: Runner / cgo / Native Boundary — DFD-6 (cgo calls into llama.cpp / ggml), DFD-8 (runner IPC subprocess), DFD-11 (audio / multimodal), DFD-14 (cgo length / size arguments)
DFD Slices: DFD-6, DFD-8, DFD-11, DFD-14
NNN Range: 040-059
Started: 2026-04-17T03:10:00Z
Closed: 2026-04-17T15:58:00Z
Status: CLOSED

Findings: 14 (p8-040 through p8-053). HIGH: 5. MEDIUM: 9. Cross-chamber duplicate: chamber-02 p8-020 for H-00.01 root cause.

Ideator: ideator-03
Tracer: tracer-03
Advocate: advocate-03

---

## Pre-Seeded Hypotheses (from Deep Probe — Group D + SAST + Spec Gap)

These hypotheses are already validated or have strong signal from the Deep Probe phase. The Ideator MUST incorporate them as H-00.* entries and build chain/variant hypotheses on top. The Tracer MUST verify and extend the existing evidence rather than re-tracing from scratch.

| Pre-Seed ID | Source | Severity | One-liner |
|-------------|--------|----------|-----------|
| H-00.01 | PH-D-01 | CRITICAL | GGUF shape overflow → `ConvertToF32` OOB read via `C.ggml_fp16_to_fp32_row` at `ml/backend/ggml/quantization.go:19-24`. Attacker-controlled GGUF tensor dims overflow C-level size computation → arbitrary memory disclosure class. |
| H-00.02 | PH-D-02 | MEDIUM | `C.CString(modelPath)` permanent C heap leak at `llama/llama.go:308` — no `defer C.free`. Load/unload loop exhausts C heap; useful as a chain primitive to stress the allocator for UAF shaping. |
| H-00.03 | PH-D-03 | HIGH | `NewGrammar` vocabIds/vocabValues length mismatch → OOB read in `add_token_pieces` C code at `llama/llama.go:724-735`. Fragile: current callers are safe but contract violation is one refactor away from exploit. |
| H-00.04 | PH-D-06 | MED-HIGH | `ollamarunner` multimodal lacks zero-length image guard at `ollamarunner/runner.go:274`. `EncodeMultimodal([]byte{})` may deref nil inside vision encoder cgo. |
| H-00.05 | PH-D-07 | HIGH | `mlxrunner.resolveManifestPath` no `filepath.IsLocal`. Component-level gap; upstream protects via `isValidPart` but defense-in-depth fragile. Traversal to read arbitrary manifests from mlxrunner. |
| H-00.06 | PH-D-08 | MED-HIGH | Runner subprocess trusts `LoraPath` from IPC at `runner/llamarunner/runner.go:852` → `C.llama_adapter_lora_init` on arbitrary path. Local attacker (or IPC-impersonator) can load arbitrary file as LoRA adapter → cgo parse attack surface. |
| H-00.07 | PH-D-10 | HIGH | `GetEmbeddingsSeq`/`GetLogitsIth` `unsafe.Slice` on C-returned size at `llama/llama.go:211-243`. Crafted model sets `NEmbd()` huge → Go slice over C heap → disclosure via API response. |
| H-00.08 | PH-D-05 (NEEDS-DEEPER) | HIGH | `MultimodalTokenize` no upper bound at `llama/llama.go:566`: `C.size_t(len(data))` passes 2GB image straight into mtmd cgo → potential integer overflow in vendored mtmd (CVE-2025-15514 class). |
| H-00.09 | PH-D-04 (NEEDS-DEEPER) | MEDIUM | `ggml.go` int64 overflow in `io.NewSectionReader` offset computed from sum of `uint64` tensor offsets; may wrap to negative offset → read from beginning of file or panic. |
| H-00.10 | SAST-UAF-01 | HIGH | `ggml-alloc.c:894` use-after-free — `galloc->leaf_allocs` freed then accessed in `ggml_gallocr_alloc_graph`. Triggered by normal inference on any graph that re-runs allocation. Potential RCE via freelist shaping. |
| H-00.11 | Spec Gap 11 | HIGH | Blank MIME `data:;base64,` bypass reaches mtmd cgo with arbitrary binary payload — MIME validation gates image-vs-audio dispatch but empty mediatype treated as default. |
| H-00.12 | PH-D-08-deeper | MEDIUM | Runner IPC port TOCTOU — ephemeral port selection race; another local process can bind the chosen port before the runner claims it → IPC impersonation. |

Chain seeds (for Ideator to expand into H-CHAIN-* hypotheses):

- **CHAIN-A (memory-exfil loop)**: H-00.01 (GGUF shape overflow OOB read into F32 buffer) + H-00.07 (unsafe.Slice over C-returned size) → crafted model causes `ConvertToF32` to read past allocation, and then `GetEmbeddingsSeq` returns a Go slice over that over-read buffer in the HTTP response. Full memory-leak primitive delivered to unauthenticated `/api/embed` caller.
- **CHAIN-B (IPC pivot)**: H-00.12 (port TOCTOU) + H-00.06 (LoRA path trust) → attacker binds the ephemeral port first, proxies IPC, and injects `LoraPath` pointing at attacker-controlled file. Runner `C.llama_adapter_lora_init` parses adversarial LoRA → cgo parse bugs reachable without needing registry.
- **CHAIN-C (blank-MIME → UAF)**: H-00.11 (blank-MIME default-dispatch) + H-00.10 (ggml-alloc UAF) → attacker feeds crafted "image" that reaches ggml allocation graph in a way that double-registers a leaf → freelist control → RCE.
- **CHAIN-D (subprocess flag injection)**: explore whether `--model <path>` passed to llamarunner subprocess is shell-quoted and whether any caller interpolates user input; if a traversal or `--lora` flag can be smuggled via `modelPath`, single `/api/generate` becomes arbitrary cgo parse on arbitrary file.
- **CHAIN-E (GPU memory disclosure)**: CUDA/Metal backend allocations in ggml may expose uninitialized device memory if tensor dims overflow int32 in one dimension but pass the per-dim check. Chain H-00.01 + GPU backend = cross-VM memory disclosure on shared GPU hosts.
- **CHAIN-F (C.CString leak + UAF shaping)**: H-00.02 (permanent CString leak) as a primitive to stress the C heap and create predictable allocator state for exploiting H-00.10 (UAF) — heap spray via model-reload DoS into UAF trigger window.

Attack classes NOT yet explored (Ideator must generate H-NEW-* entries):

- **Tokenizer C boundary**: `llama_tokenize` with adversarial UTF-8 / surrogate-pair sequences; byte-vs-rune size mismatches between Go `len()` and C `size_t` expectations.
- **Audio pipeline length**: DFD-11 audio decode path — sample count overflow, float32 PCM bounds; does `whisper`-style mel computation have unchecked dims?
- **Sampler state carryover**: sampler chain re-use across requests without reset → previous request's logit bias influences next request (information leak across users).
- **KV cache reuse across sessions**: shared `llama_context` KV cache — one user's prompt tokens reachable in another user's continuation when session IDs collide.
- **Embedding model vs chat model confusion**: load a chat model where an embedding model is expected; `GetEmbeddings` returns logits → information disclosure.
- **Subprocess exit-code handling**: runner crash mid-generation — partial response sent, status 200, error buried; silent correctness failure.
- **cgo callback reentrancy**: any C callback that calls back into Go (e.g., log, progress) under a Go lock → deadlock or goroutine explosion.
- **GGUF metadata string overflow**: `kv.String` fields copied into Go via `C.GoStringN(ptr, n)` where `n` is attacker-controlled uint64; cast to int panics or wraps.
- **Integer type confusion at cgo boundary**: Go `int` is 64-bit on amd64/arm64 but some llama.cpp APIs take `int` (C int = 32-bit). Negative-wrap on cast.
- **`--verbose` / `--log-file` flag injection**: runner accepts log file path from parent; if parent is driven by any user-controlled request path, arbitrary file write.
- **Context length > model max**: does runner validate `n_ctx` request against model's trained ctx? Oversize allocation DoS.
- **Lora stacking**: can a request specify multiple LoRAs to force repeated `llama_adapter_lora_init` → OOM or path traversal amplification?

---

## Round 1 -- Ideation

**Directed to**: @ideator-03 (Ideator for Chamber 03)
**Scope**: Runner / cgo / Native Boundary (DFD-6, DFD-8, DFD-11, DFD-14)
**Instructions**:

1. Pre-seeded H-00.01 through H-00.12 are already validated/strong-signal. DO NOT re-generate them. Build chain/variant hypotheses on top.
2. Expand chain seeds CHAIN-A through CHAIN-F above into concrete H-CHAIN-* hypotheses with clear input → sink → consequence statements.
3. Generate H-NEW-* hypotheses covering the "Attack classes NOT yet explored" list — prioritize: tokenizer C boundary, audio pipeline length, integer-type-confusion at cgo, KV cache reuse, subprocess flag injection.
4. Hard cap: at most 7 novel hypotheses per batch (chains + new combined). Prioritize by blast radius (CRITICAL/HIGH first). Defer MEDIUM-only ideas.
5. For each H-NN, write:
   - Title (one line)
   - Attacker control vector (what input they send and via which endpoint)
   - Target sink (file:line)
   - Security consequence (memory disclosure / RCE / DoS / auth bypass)
   - Severity estimate
6. Write output to this debate.md under a `### [IDEATOR] H-NN ...` heading per hypothesis.

_Pending ideator-03 response._

## Round 2 -- Tracing

**Directed to**: @tracer-03
**Instructions**:

1. For pre-seeded H-00.* hypotheses: verify the evidence citations are still accurate at current HEAD (commits post probe may have moved lines). If evidence moved, update file:line and re-confirm reachability. For H-00.01, H-00.07, H-00.08, H-00.10 — expand the trace with full call chain from HTTP handler → cgo sink.
2. For H-CHAIN-* and H-NEW-*: perform a fresh trace. Classify each as REACHABLE / PARTIAL / UNREACHABLE with:
   - Entry point (HTTP handler, IPC message type, CLI flag)
   - Call graph (function → function → sink)
   - Attacker-controlled data type at each hop
   - Sanitizers or checks on the path (name + file:line if present; "none" if absent)
3. Write output under `### [TRACER] H-NN ...` headings.

_Pending round 1 completion._

## Round 3 -- Challenge

**Directed to**: @advocate-03
**Instructions**:

1. For every REACHABLE or PARTIAL hypothesis from Tracer, search all 5 protection layers:
   - Input validation (middleware, struct tags, parsers)
   - Framework protections (gin middleware, net/http hardening, Go runtime checks)
   - Crypto/auth gates (TLS, signature verification, token validation)
   - Defense-in-depth (second-layer checks, assertions, debug mode gates)
   - Deployment constraints (is the vulnerable code compiled in default build? behind feature flag? admin-only endpoint?)
2. Produce a Defense Brief per hypothesis: either "no blocking protection found after exhaustive search" OR "blocked by <specific check> at <file:line>; check is <complete/partial> and <correctly/incorrectly> configured".
3. For H-00.10 (ggml-alloc UAF): evaluate whether it is reachable under default inference workloads or requires specific graph-rebuild timing; check upstream llama.cpp issue tracker references.
4. Write under `### [ADVOCATE] H-NN ...` headings.

_Pending round 2 completion._

## Round 4 -- Synthesis

**Synthesizer (this agent)** issues verdicts after reading all prior rounds. Verdicts written as `### [SYNTHESIZER] Verdict for H-NN ...` with verdict, severity, rationale, and finding draft path (if VALID).

_Pending rounds 1-3 completion._

---

## Ideator-03 Batch 1 — Chain Expansions on Pre-Seeded Hypotheses

**H-CHAIN-A.1: Amplified memory-exfil loop via quantize endpoint + embeddings response**
- Attack class: Mode 1 (Vulnerability Chaining)
- Cross-modes: Mode 4 (Second-Order) + Mode 8 (Supply Chain — vendored ggml)
- Chain: multi-step
  1. Attacker uploads crafted GGUF via `POST /api/create` with `Shape=[1<<62+1, 1]` and `Kind=F32` (H-00.01 primitive).
  2. `ml/backend/ggml/quantization.go:19-24` `ConvertToF32` computes `make([]float32, 2^62+1)`; if Go allocator returns a smaller-than-requested slice (wraparound or partial fulfillment), `C.ggml_fp16_to_fp32_row` OOB-reads into adjacent process memory (Go heap, contains other users' request bodies, keypair bytes, mTLS material).
  3. OOB bytes land in the F32 target buffer, which becomes the embedding tensor for THIS model when loaded.
  4. Attacker calls `POST /api/embed` with `"model":"crafted"`. `GetEmbeddingsSeq` (H-00.07) returns `unsafe.Slice` over C heap at `NEmbd`-huge size — delivers the stolen bytes as a JSON float32 array in the HTTP response.
- Preconditions: unauthenticated HTTP access to Ollama (default localhost:11434; remote if `OLLAMA_HOST=0.0.0.0`); ability to create/import one model (`/api/create` is unauthenticated).
- Target asset: Go-process memory contents — other concurrent HTTP bodies, `~/.ollama/id_ed25519` loaded in memory, cloud-proxy bearer tokens, in-flight prompts from other tenants.
- Entry point: `POST /api/create` (model upload) + `POST /api/embed` (exfil channel).
- Sink: `ConvertToF32` → `C.ggml_fp16_to_fp32_row` + `GetEmbeddingsSeq` → JSON response.
- Creativity signal: A solo agent sees H-00.01 as a local crash and H-00.07 as a theoretical disclosure; the novelty is recognising the F32 overflow BUFFER itself becomes the embedding tensor that the JSON API faithfully serializes — a two-bug handoff that turns a read primitive into a fully-automated exfil oracle where the attacker never needs to run arbitrary code. SAST cannot model the model-format-to-API-shape transformation.

**H-CHAIN-B.1: Port TOCTOU → IPC impersonation → flag injection → arbitrary file read via `--lora`**
- Attack class: Mode 3 (Race / TOCTOU)
- Cross-modes: Mode 5 (Trust Boundary) + Mode 7 (State Machine)
- Chain: multi-step
  1. Parent `server/` reserves ephemeral port P via `net.Listen("tcp", ":0")`, closes listener, and passes P on argv to child runner (H-00.12 TOCTOU window). Between close and child's re-bind, local attacker `bind(P)`.
  2. Attacker's fake runner speaks the parent's JSON-over-HTTP protocol; parent treats attacker's `/health` OK as "runner ready".
  3. First `POST /api/generate` is proxied to the attacker, who extracts the internal shared-secret/session-id that parent uses for subsequent calls.
  4. Alternatively (Mode 5): attacker's process legitimately spawns the SAME runner binary but with additional `--lora /etc/shadow` or `--log-file ~/.ssh/authorized_keys` flags (H-00.06); parent has no way to validate the child's exact argv.
- Preconditions: local unprivileged user on the same host (the threat model already admits local-low as a realistic actor per Phase 2). No shell access needed on the server account.
- Target asset: cross-UID privilege escalation — runner process typically runs as ollama system user; attacker reads `/etc/shadow` via LoRA parse path or writes to `.ssh/authorized_keys` via `--log-file` flag.
- Entry point: Local process binding ephemeral port before runner.
- Sink: `runner/llamarunner/runner.go:852` `C.llama_adapter_lora_init(path)` OR runner log-file open.
- Creativity signal: Combines three boundary assumptions — parent trusts "port-is-mine" after listener close, parent trusts child argv identity, and cgo trusts path validity — into a single local-to-local-root chain. Each individual flaw is dismissible; the combination is a clean privesc.

**H-CHAIN-C.1: Blank-MIME bypass → audio branch → mtmd audio-pipeline UAF in ggml-alloc**
- Attack class: Mode 6 (Parser Differential)
- Cross-modes: Mode 1 (Chaining) + Mode 4 (Second-Order)
- Chain: multi-step
  1. Attacker sends `POST /api/chat` with `"images":["data:;base64,<blob>"]` (Spec Gap 11 / H-00.11). Blank MIME causes the dispatcher to fall through to default (image) path; but by appending a known audio-magic header (RIFF/WAVE) inside the blob, the vendored mtmd library's content-sniffing branch jumps to audio-mel compute.
  2. Mel-compute path allocates a graph via ggml that re-uses `galloc->leaf_allocs` from an earlier prompt's image graph (different tensor layout).
  3. Re-entry into `ggml_gallocr_alloc_graph` triggers SAST-UAF-01 (H-00.10): freed-then-accessed leaf_allocs.
  4. Because blob is attacker-sized, freelist shaping is precise; UAF write through stale pointer yields controlled-write primitive.
- Preconditions: unauthenticated HTTP; a multimodal model loaded (gemma-3, llava, qwen-vl are default-recommended).
- Target asset: RCE in runner process (often ollama system user on Linux packaged install → full host compromise since runner has fd to all on-disk models + `~/.ollama/id_ed25519`).
- Entry point: `POST /api/chat` with crafted `data:;base64,` image.
- Sink: `mtmd_*` audio-mel → `ggml_gallocr_alloc_graph` freelist.
- Creativity signal: Cross-mode combination (Mode 6 parser differential routes user-controlled bytes into a DIFFERENT code path than validation assumed, feeding Mode 1's memory-safety bug). A solo agent scanning for UAF never reaches the audio branch; a solo agent scanning for MIME bypass never reaches the UAF. Only the chain is exploitable.

**H-CHAIN-D.1: `modelPath` → flag smuggling through unquoted argv propagation**
- Attack class: Mode 5 (Trust Boundary)
- Cross-modes: Mode 2 (Business Logic) + Mode 6 (Parser Differential)
- Chain: multi-step (single-request)
  1. Attacker creates a model whose on-disk blob path is symlinked/crafted such that the Ollama-computed absolute path contains a `--lora` or `--verbose-prompt` substring, or better: the MANIFEST `model` field references a name that embeds `--flag`-like bytes the parent interpolates unquoted into `exec.Command(runnerBin, "--model", derivedPath, ...)`.
  2. If `derivedPath` starts with `-` (e.g., `--lora=/etc/passwd`) Go's `exec.Cmd` passes it as a separate argv element; the runner's flag-parser accepts it as a flag rather than a positional.
  3. Runner happily loads `/etc/passwd` as a LoRA adapter → cgo parse → either crash (DoS) or information disclosure via error-message reflection.
- Preconditions: attacker can publish a model to a registry the victim pulls from, OR attacker can `POST /api/create` with a crafted Modelfile.
- Target asset: Arbitrary-file-as-LoRA parse (expands H-00.06 to an unauthenticated HTTP-reachable trigger rather than needing local IPC impersonation).
- Entry point: `POST /api/create` with Modelfile whose `FROM` derives a path with leading `-`.
- Sink: `exec.Cmd.Args` → runner flag parser → `C.llama_adapter_lora_init`.
- Creativity signal: Exploits the Go-specific quirk that `exec.Cmd` is NOT `execvp`-shell-quoted and positional-vs-flag disambiguation is pushed to the child's flag library. A single Modelfile becomes a universal flag-smuggling primitive. SAST will see `exec.Command` with constant-appearing argv and flag it as safe.

**H-CHAIN-E.1: GPU backend uninitialized-memory disclosure via shape-per-dim underflow**
- Attack class: Mode 8 (Supply Chain — CUDA/Metal/Vulkan backend in vendored ggml)
- Cross-modes: Mode 1 (Chaining) + Mode 4 (Second-Order)
- Chain: multi-step
  1. Attacker crafts GGUF with `Shape=[2^31-1, 2]` (each dim passes int32 check) but product overflows: `2^31 * 2 = 2^32` wraps to 0 on int32 multiply in vendored CUDA kernel dispatch.
  2. CUDA backend `ggml_cuda_alloc_tensor` issues `cudaMalloc(0)` (or a small allocation) but kernels launched with declared tensor dims read/write as-if-large.
  3. GPU driver returns recycled device memory containing other process/VM tenant data (NVIDIA drivers historically do NOT zero device-allocation pages; shared-GPU cloud or multi-tenant ML hosts are vulnerable).
  4. Embedding/logit retrieval path (H-00.07 `GetEmbeddingsSeq`) copies GPU→host and emits the stale device memory in the JSON response.
- Preconditions: shared-GPU host (cloud ML, Kubernetes GPU-node, Colab-style); Ollama configured with CUDA/Metal backend.
- Target asset: Cross-tenant GPU memory disclosure — other ML jobs' weights, activations, prompts.
- Entry point: `POST /api/create` + `POST /api/embed`.
- Sink: GPU backend `cudaMalloc` + post-compute `cudaMemcpy` to host → JSON response.
- Creativity signal: Hypothesis spans three trust boundaries (Go → cgo → CUDA driver → GPU hardware) and requires understanding that cudaMalloc does NOT zero pages by default — a well-known but under-weaponized fact. A Go-only scanner never reaches this; a ggml auditor never considers JSON-API exposure.

---

## Ideator-03 Batch 2 — H-NEW-* Attack Classes (unexplored)

**H-NEW-40: Sampler-state carryover across tenants → logit-bias information leak**
- Attack class: Mode 7 (State Machine)
- Cross-modes: Mode 4 (Second-Order)
- Chain: multi-step across two distinct requests
  1. Attacker A calls `POST /api/generate` with `"options":{"logit_bias":{...},"repeat_penalty":1.3,"mirostat":2}` — sampler chain is allocated via cgo (`C.llama_sampler_chain_init`) and may be cached per-model rather than per-request for latency.
  2. Victim B calls `POST /api/generate` (or `/v1/chat/completions`) with no `logit_bias`. If runner does NOT reset the sampler chain between requests, A's logit_bias perturbs B's token distribution.
  3. A repeats calls and observes token probabilities via `logprobs` in the OpenAI-compat response to learn *which* tokens B's sampler still perturbs → infers A's bias still applied → next request can probe B's prompt content by setting boolean bias combinations and watching if B's output is pinned.
- Preconditions: multi-tenant Ollama instance (internal API gateway, shared developer server). Same underlying model used by both callers.
- Target asset: cross-tenant prompt/response inference (side-channel information disclosure).
- Entry point: `/api/generate` `options.logit_bias` + `/v1/chat/completions` `logprobs`.
- Sink: `C.llama_sampler_chain_init` per-model singleton.
- Creativity signal: Pure state-machine/lifecycle attack — no memory bug, no parser bug. Only detectable by modelling the sampler's temporal state across requests. Every solo SAST tool treats `/api/generate` as stateless.

**H-NEW-41: KV-cache reuse across sessions via shared `llama_context` prompt-prefix leak**
- Attack class: Mode 4 (Second-Order)
- Cross-modes: Mode 7 (State Machine) + Mode 2 (Business Logic)
- Chain: multi-step
  1. `ollamarunner` reuses one `llama_context` across HTTP requests (for speed: prompt-prefix caching). KV cache is indexed by session ID or by `context[]` token sequence.
  2. Victim B sends an "ephemeral" chat with sensitive system prompt → cache populated. B's session closes.
  3. Attacker A sends `"context":[... prefix tokens stolen via timing oracle ...]` in `/api/generate`. If runner's cache-lookup matches A's prefix to B's stale entry (e.g., hash collision, or prefix-match-by-length rather than exact content), A continues B's conversation as if it were their own.
  4. More subtly: token-probability analysis on A's output distinguishes "cached" vs "recomputed" prefixes, leaking which token sequences B used.
- Preconditions: multi-tenant instance with prompt caching enabled (default in modern runners).
- Target asset: other tenants' system prompts, API keys embedded in prompts, past user messages.
- Entry point: `POST /api/generate` with crafted `context` array.
- Sink: `C.llama_decode` with shared `llama_context`.
- Creativity signal: Exploits a performance optimization (KV cache) as an information side-channel. Not a code bug per-se — a design gap. SAST tools will never flag cache reuse as vulnerable.

**H-NEW-42: Embedding-model vs chat-model confusion via `/api/embed`**
- Attack class: Mode 2 (Business Logic)
- Cross-modes: Mode 5 (Trust Boundary)
- Chain: single-step
  1. Attacker calls `POST /api/embed` with `"model":"llama3"` (a chat model, not an embedding model).
  2. If the runner does not check `model.HasEmbeddingHead()`, `GetEmbeddingsSeq` returns the raw final-layer hidden state — which for a chat model is effectively a logit projection over the full vocabulary.
  3. The returned float32 array (H-00.07 sink) encodes the model's top-token predictions for the input prompt — i.e., the attacker can recover the next-token distribution for ANY prompt even when `/api/generate` is rate-limited, when streaming is disabled, or when output-filtering middleware strips sensitive tokens. The embedding JSON bypasses all text-content filters.
- Preconditions: unauthenticated `/api/embed`.
- Target asset: raw model-output distribution — bypass of any content moderation on `/api/generate`.
- Entry point: `/api/embed`.
- Sink: `GetEmbeddingsSeq` returning hidden-state for a non-embedding model.
- Creativity signal: It's a *semantic* vulnerability — the API contract says "embedding" but the underlying cgo happily returns whatever `NEmbd`-sized vector the model exposes. A content-filter bypass that looks like normal usage. Only an adversarial mindset considers "what if the two endpoints are aliases for the same C call?".

**H-NEW-43: cgo callback reentrancy deadlock via llama.cpp log callback**
- Attack class: Mode 3 (Race / TOCTOU)
- Cross-modes: Mode 8 (Supply Chain)
- Chain: single-step (DoS)
  1. `llama.cpp` invokes `ggml_log_callback` from within `llama_decode` while holding its internal mutex.
  2. The Go-side callback (registered via `C.llama_log_set`) is `export`ed and may acquire a Go mutex (e.g., `slog` handler or a progress mutex in runner).
  3. If the same mutex is held by a concurrent HTTP handler that is waiting on `C.llama_decode` (via cgo call that holds llama.cpp mutex internally), circular wait → permanent deadlock; all subsequent `/api/generate` requests block forever.
  4. Attacker triggers via pathological prompt that forces many log lines (low-level tensor debug on tokenizer error) while concurrently issuing many legitimate requests — deterministic DoS.
- Preconditions: any valid model; two concurrent HTTP requests.
- Target asset: process-level DoS (server unresponsive until restart).
- Entry point: `/api/generate` with malformed prompt that triggers internal warning path.
- Sink: Go-C-Go reentrancy across mutex boundaries.
- Creativity signal: Requires understanding cgo's lack of deadlock detection AND the Go runtime's P-stealing behavior when a goroutine is blocked in C — a very specific, under-audited intersection.

**H-NEW-44: GGUF metadata `kv.String` uint64 → int cast overflow → panic OR truncation**
- Attack class: Mode 6 (Parser Differential)
- Cross-modes: Mode 1 (Chaining)
- Chain: single-step
  1. GGUF KV section allows `uint64` length for string values (per spec). Go reads `length uint64` then `C.GoStringN(ptr, C.int(length))`. If `length > MaxInt32`, Go's `C.int` cast wraps to negative → `GoStringN` either panics (defensive implementation) or reads a huge span (naive implementation).
  2. If the KV value is `general.architecture` or `tokenizer.ggml.tokens`, downstream consumers (template engine, tokenizer init) receive corrupt/truncated strings → second-order: template parsing of attacker-controlled oversized string may chain into template-CVE-2025-... family.
- Preconditions: attacker uploads or references crafted GGUF.
- Target asset: DoS OR chained template-injection via oversized metadata string.
- Entry point: `/api/create` or pull of malicious registry model.
- Sink: `C.GoStringN(ptr, C.int(uint64_value))` at GGUF metadata parse.
- Creativity signal: Integer-type-confusion at the cgo boundary is a KNOWN class but almost never audited for non-numeric metadata strings. Chains naturally into Chamber 01's template gaps.

**H-NEW-45: LoRA-stacking amplification → C heap exhaustion + path-traversal amplifier**
- Attack class: Mode 2 (Business Logic)
- Cross-modes: Mode 8 (Supply Chain)
- Chain: single-step amplification
  1. `/api/generate` request schema accepts a `LoraPath` (or `adapters` array in newer versions). Runner iterates and calls `C.llama_adapter_lora_init` for each.
  2. No cap on adapter count → attacker sends 10,000 adapter paths in one JSON body.
  3. Each `lora_init` `C.CString`s the path without `defer C.free` (H-00.02 class leak) → permanent C heap growth; 10k × avg path-len = MB leak per request; 100 requests OOMs a 2GB container.
  4. Additionally, each path goes through `C.llama_adapter_lora_init` which does its own file-read — stressing the filesystem + allowing race-window timing oracles for path-traversal detection.
- Preconditions: unauthenticated HTTP; `/api/generate`.
- Target asset: process-level OOM DoS; amplifier for H-00.02 leak primitive; path-oracle for adjacent traversal bugs.
- Entry point: `/api/generate` with large `adapters`/`LoraPath` array.
- Sink: `C.llama_adapter_lora_init` loop.
- Creativity signal: A legitimate feature (LoRA stacking) combined with a minor memory leak (H-00.02) becomes a reliable DoS. Each piece is dismissed individually; together they're exploitable.

**H-NEW-46: Audio-pipeline float32 sample-count overflow in mel-spectrogram compute**
- Attack class: Mode 1 (Chaining)
- Cross-modes: Mode 8 (Supply Chain — vendored mtmd)
- Chain: single-step
  1. `/v1/audio/transcriptions` accepts multipart audio upload. Runner decodes to float32 PCM at 16kHz.
  2. `sample_count = int(file_size / 4)`. For a 2GB upload, `sample_count = 536M`. Mel-compute FFT window-shift loop multiplies `sample_count * n_mels = 536M * 80 = 42.8B` which overflows int32 → negative index → buffer.
  3. Unlike H-00.08 which targets mtmd image path, the audio path in mtmd is younger and less fuzzed (vendored whisper.cpp-style code).
- Preconditions: unauthenticated HTTP with audio-capable multimodal model loaded (Qwen-Audio, Whisper-integration).
- Target asset: OOB read/write in runner process; potential RCE in audio-mel vendored C.
- Entry point: `POST /v1/audio/transcriptions`.
- Sink: mtmd audio mel-compute.
- Creativity signal: DFD-11 is explicitly listed in the chamber but the audio sample-count overflow is architecture-distinct from the image path. Extends H-00.08 to a sibling entrypoint that may share a fix-or-miss.

**H-NEW-47: Tokenizer C-boundary surrogate-pair len/size mismatch**
- Attack class: Mode 6 (Parser Differential)
- Cross-modes: Mode 4 (Second-Order)
- Chain: multi-step
  1. Go `len(s)` counts BYTES; C `llama_tokenize(..., text, C.int(len(s)), ...)` also wants bytes — so far consistent.
  2. BUT: some llama.cpp forks that Ollama vendors interpret the `int` as code-point count under UTF-8 normalization mode. A Go prompt with 100 bytes of unpaired surrogates (lone high-surrogate `\xED\xA0\x80`) normalizes to different byte/codepoint counts.
  3. If C code writes normalized output back into a buffer sized by Go's `len(s)`, an expanding normalization (e.g., NFC that lengthens) overflows the output buffer.
  4. Chains with tokenizer `out_tokens` buffer: Go-side allocates `n_tokens_max = len(s) + 1` but C returns `n_tokens > n_tokens_max` if normalization expands.
- Preconditions: unauthenticated `/api/generate` prompt with crafted Unicode.
- Target asset: tokenizer-output buffer overflow in runner.
- Entry point: `/api/generate` `prompt` field.
- Sink: `C.llama_tokenize` output buffer.
- Creativity signal: Go-vs-C Unicode-counting mismatch is an under-explored cgo pattern. Requires knowing that vendored llama.cpp varies in Unicode handling across commits — which a solo code-tracer only exploring the current HEAD misses.

**H-NEW-48: `n_ctx` oversize allocation → KV cache DoS + correlated with memory-exfil**
- Attack class: Mode 2 (Business Logic)
- Cross-modes: Mode 1 (Chaining)
- Chain: multi-step
  1. `/api/generate` request accepts `options.num_ctx`. Runner passes through to `llama_new_context_with_model(n_ctx=req_value)` without clamping to `model.n_ctx_train`.
  2. Attacker requests `num_ctx = 1 << 30` → KV cache = `n_ctx * n_layer * 2 * d_head * bytes_per_elt` = tens of GB. `malloc` succeeds on overcommit Linux, returns lazy page → when runner writes, OOM-kills the whole process.
  3. Additionally, if KV-cache bytes are uninitialized, chained with H-00.07 embedding-exfil: a crafted prompt that doesn't touch most of KV-cache leaves post-init stale memory in slots that the embedding-final-layer then mixes.
- Preconditions: unauthenticated `/api/generate`.
- Target asset: process DoS; correlated memory disclosure.
- Entry point: `/api/generate` `options.num_ctx`.
- Sink: `C.llama_new_context_with_model`.
- Creativity signal: `num_ctx` is a legitimate tuning knob — the creativity is recognising that the validation gap (no max-clamp) chains with BOTH a DoS and H-00.07 disclosure, giving attacker choice of impact.

**H-NEW-49: Subprocess-crash-mid-stream → correctness failure with 200 OK (observability blindness)**
- Attack class: Mode 7 (State Machine)
- Cross-modes: Mode 2 (Business Logic)
- Chain: multi-step
  1. Runner subprocess crashes (e.g., via H-00.01 or H-00.10) mid-response while parent has already flushed `HTTP/1.1 200 OK` + streaming chunks.
  2. Parent detects child-EOF, but HTTP response header is already committed; parent closes the body with `{"done":true,"done_reason":"stop"}` rather than `"error"` because JSON-over-SSE chunks don't carry trailer metadata.
  3. Downstream automation (agentic pipelines) treats truncated-partial-response as authoritative complete response. Attacker uses crash-inducing prompts to force desired truncation points, manipulating agent decisions.
- Preconditions: attacker can supply prompts to an agent that calls Ollama; crash primitive (H-00.01, H-00.10, or any panic).
- Target asset: agentic-decision manipulation via truncated-as-complete responses.
- Entry point: `/api/chat` or `/api/generate` streaming.
- Sink: SSE `done_reason` semantic.
- Creativity signal: A correctness failure that looks like a reliability bug but is exploitable as a prompt-injection amplifier in agent frameworks. Invisible to any tool that only checks status codes.


---

## Round 1 — Advocate Defense Briefs (advocate-03)

Advocate note: chamber-03 debate file was opened with only pre-seeded hypotheses (H-00.01 .. H-00.12). Ideator-03 and Tracer-03 have not yet appended their H-NEW / H-CHAIN / tracer-evidence rounds at the time of this writing. Per the engagement rules I still owe a defense brief for every seeded hypothesis — the pre-seeds are carried forward as validated or strong-signal findings, so I treat them as REACHABLE/PARTIAL until demonstrated otherwise. I will append further briefs in a later round once ideator-03/tracer-03 publish H-NEW-* / H-CHAIN-* entries.

### [ADVOCATE] Defense Brief for H-00.01 -- 2026-04-17T14:52:00Z

Hypothesis: GGUF shape overflow -> `ConvertToF32` OOB read via `C.ggml_fp16_to_fp32_row` at `ml/backend/ggml/quantization.go:19-24`. Attacker-controlled GGUF tensor dims overflow C-level size computation -> arbitrary memory disclosure.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `make([]float32, nelements)` will panic if nelements exceeds available memory — does NOT prevent precision loss in `uint64 -> C.int64_t` cast | No | `ml/backend/ggml/quantization.go:20` — `make([]float32, nelements)` with attacker uint64 |
| Framework | GGUF reader at `fs/ggml/gguf.go:205-212` reads tensor dims as raw uint64; `Elements()` does unchecked uint64 multiplication (`fs/ggml/ggml.go:505-511`) | No | Shape dims never bounded; product wraps silently |
| Framework | File-size bound check at `fs/ggml/gguf.go:258-262` (`tensorEnd := tensorOffset + tensor.Offset + tensor.Size(); if tensorEnd > fileSize`) bounds the on-disk bytes; but `Elements()` (dims product) is NOT bounded by this — a tensor can advertise 2^62 elements in a small number of on-disk bytes for quantized types | Partial | size vs elements are decoupled through `typeSize()/blockSize()` at `fs/ggml/ggml.go:513-515` |
| Middleware | gin CORS + `allowedHostsMiddleware` at `server/routes.go:1608-1643` blocks cross-origin unless Host is loopback/private/allowlisted | Partial | Does not block an attacker who already has HTTP access to the daemon |
| Application | `/api/create` (`server/routes.go:1703`) has NO auth. Quantize is reachable via `r.Quantize` on `CreateRequest`; requires the attacker to supply a malicious GGUF via `/api/blobs/:digest` + `/api/create` — which is the default unauthenticated local API surface | No | `server/create.go:496-507`, `server/routes.go:1703-1705` |
| Application | `useMmap: UseMmap && len(req.LoraPath) == 0` at `llm/server.go:175` — not relevant here, this is quantization not loading | N/A | — |
| Documentation | `SECURITY.md` does not state malicious-GGUF is accepted threat; no explicit exclusion | N/A — no docs | `SECURITY.md` lines 1-25 |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — path traced through `/api/blobs` -> `/api/create` -> `quantizeLayer` -> `ConvertToF32`. REACHABLE.
- Pattern 2 (phantom validation): checked — I looked for a shape-bound check in `fs/ggml/gguf.go` decode-tensor loop and `quantizer.WriteTo`; the only bound is on disk bytes (`tensorEnd > fileSize`), which does NOT constrain the `Elements()` product. Not a match.
- Pattern 3 (framework protection): checked — ggml_fp16_to_fp32_row is a raw row-copy with no internal size sanity. Not a match.
- Pattern 4 (same-origin): checked — not applicable; this is a server-side parsing bug, not a browser action.
- Pattern 5 (CVE reachability): checked — this is not a CVE-in-dependency claim but a first-party boundary bug. Not a match.
- Pattern 6 (config-as-vuln): checked — no admin config gate; `/api/create` is on by default bound to 127.0.0.1 but without auth. Not a match.
- Pattern 7 (test code): checked — `ml/backend/ggml/quantization.go` is production code path. Not a match.
- Pattern 8 (double-counting): partial — H-00.01 and H-00.07 both rely on attacker-planted model shapes and are chained in CHAIN-A. They are separable primitives (OOB read vs OOB disclosure); not a pure duplicate.

**Defense argument:** The strongest defense I can construct is that to reach `ConvertToF32` with an attacker-shape the attacker must already have HTTP access to the unauthenticated local `/api/create` endpoint (which Ollama's threat model treats as trusted-user territory). On a default loopback-bound daemon on a single-user workstation, no remote attacker reaches this path without first landing some local RCE vector, at which point OOB read is not the weakest primitive. Additionally, the `make([]float32, nelements)` allocation with `nelements = shape-product` will typically hit Go's allocator ceiling (either OOM panic or `fatal error: runtime: out of memory`) before the call enters cgo, converting the intended memory-disclosure primitive into a DoS. And the `tensorEnd > fileSize` guard in `gguf.go:258-262` ensures the on-disk tensor data length is bounded by the file, so `data[0]` -> `&data[0]` in the cgo call won't read past the mmap'd blob — the only source of OOB is through the `elems` count parameter controlling how many rows the C function reads from a bounded source buffer, which is a secondary (source-side) OOB and depends on cgo-level semantics of `ggml_fp16_to_fp32_row` reading past its input `data[0]` pointer.

Honest conclusion: the defense is weak. The file-size guard bounds the input byte-count but `elems = C.int64_t(nelements)` still passes an unbounded dim product to the C row-copy, which will read past the mmap'd buffer into adjacent process memory. `make()` will tolerate very large requests on 64-bit Linux with overcommit before panicking. Pre-seed label is CRITICAL and I cannot disprove it.

**Verdict recommendation:** Cannot disprove.

---

### [ADVOCATE] Defense Brief for H-00.02 -- 2026-04-17T14:53:00Z

Hypothesis: `C.CString(modelPath)` permanent C heap leak at `llama/llama.go:308` — no `defer C.free`. Useful as a chain primitive.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | cgo doesn't auto-free C.CString; Go GC does not reach into C heap | No | Go cgo documentation |
| Framework | Runner subprocess is per-model — killed on unload (`llm/server.go:764` sends `LoadOperationClose`) — so any leak is bounded by subprocess lifetime | Partial | `llm/server.go:764` |
| Middleware | Scheduler limits concurrent runners (`envconfig.MaxRunners()`) — heap spray requires repeated model load/unload, not simultaneous | Partial | `server/sched.go` |
| Application | The runner subprocess is a separate process; a heap leak in the subprocess does NOT corrupt the parent `ollama serve` memory. Subprocess exit reclaims all memory | Yes (for isolation) | subprocess model, see `llm/server.go:334` (`StartRunner`) |
| Documentation | No docs treat this as intended; no explicit stance | N/A — no docs | — |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — model path reaches `llama.LoadModelFromFile` only via parent-trusted IPC `/load` request; user does not directly control modelPath.
- Pattern 2 (phantom validation): checked — no validation claim at stake.
- Pattern 3 (framework protection): checked — subprocess isolation is the main mitigation. MATCH: subprocess boundary confines the leak.
- Pattern 4 (same-origin): checked — N/A.
- Pattern 5 (CVE reachability): checked — N/A.
- Pattern 6 (config-as-vuln): checked — N/A.
- Pattern 7 (test code): checked — production code.
- Pattern 8 (double-counting): checked — pre-seed explicitly says "useful as a chain primitive" not a standalone vuln. H-00.02 only becomes dangerous via CHAIN-F with H-00.10 (UAF).

**Defense argument:** Strongest defense: the leak is bounded by subprocess lifetime. `LoadModelFromFile` is invoked once per model load; the runner subprocess is the unit of isolation; when the model is unloaded the entire subprocess exits and the C heap is reclaimed by the OS. Within a single subprocess the same modelPath is leaked at most once per load call (and typical usage is one LoadModelFromFile per subprocess). To weaponize the leak you would need to load many models in rapid succession within one subprocess — which is not the normal path: `/load` is single-shot (see `runner/llamarunner/runner.go:884` — "model already loaded" guard). The leak is therefore a minor memory-sanitizer hygiene issue, not an exploitable DoS. For use as an allocator-shaping primitive for CHAIN-F, the attacker needs to repeatedly load within one runner subprocess, and the runner rejects re-load.

**Verdict recommendation:** Disproved by Application-layer subprocess isolation + runner single-load guard for standalone exploitation. For the CHAIN-F heap-shaping angle, the "model already loaded" guard at `runner/llamarunner/runner.go:884` prevents re-triggering inside one subprocess, so chaining requires a parent-side primitive to spawn fresh subprocesses on demand — adding a requirement that weakens the chain. Still, low-severity memory hygiene issue is real.

---

### [ADVOCATE] Defense Brief for H-00.03 -- 2026-04-17T14:54:00Z

Hypothesis: `NewGrammar` vocabIds/vocabValues length mismatch -> OOB read in `add_token_pieces` C code at `llama/llama.go:724-735`. Fragile: current callers are safe but contract violation is one refactor away from exploit.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `len()` is correct for both slices; pure-Go callers ensure equal length today | Yes (for current callers) | `llama/llama.go:724-735` |
| Framework | No framework-level equal-length assertion; Go type system cannot express "two slices of equal length" | No | — |
| Middleware | N/A | N/A | — |
| Application | Only caller of `NewGrammar` is in same package — audit shows slices are built in lock-step from vocab iteration | Yes (by construction) | to be traced |
| Documentation | Pre-seed itself acknowledges "current callers are safe"; the concern is a future refactor | N/A — intended behavior today | debate.md H-00.03 |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — attacker has no direct control over `vocabIds`/`vocabValues` (these come from the loaded model's vocab, built internally from parsed GGUF tokens in same function).
- Pattern 2 (phantom validation): checked — no phantom validation claim.
- Pattern 3 (framework protection): checked — no framework guard; the safety is by-construction.
- Pattern 4 (same-origin): N/A.
- Pattern 5 (CVE reachability): N/A.
- Pattern 6 (config-as-vuln): N/A.
- Pattern 7 (test code): production.
- Pattern 8 (double-counting): checked — no overlap.

**Defense argument:** Pre-seed concedes "current callers are safe". The vulnerability is speculative: it requires a future refactor to mismatch lengths. In a code-audit context, this is a latent invariant, not an exploitable bug today. The hypothesized attacker-input path does not exist: `vocabIds` and `vocabValues` are constructed from model vocab iteration, not from HTTP input. Calling this a vulnerability requires future-proofing semantics.

**Verdict recommendation:** Disproved by Application-layer by-construction invariant in current callers. Recommend this be logged as a DEFENSE-IN-DEPTH recommendation (add runtime length assertion) rather than a shipped finding.

---

### [ADVOCATE] Defense Brief for H-00.04 -- 2026-04-17T14:55:00Z

Hypothesis: `ollamarunner` multimodal lacks zero-length image guard at `ollamarunner/runner.go:274`. `EncodeMultimodal([]byte{})` may deref nil inside vision encoder cgo.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `image.Decode(bytes.NewReader([]byte{}))` returns Go error; no cgo entered | Yes | stdlib `image.Decode` rejects empty buffer |
| Framework | `EncodeMultimodal` implementations check `len(m.VisionModel.Layers) == 0` first, then call `image.Decode`. All vision models I sampled (gemma3, gemma4) follow this pattern | Yes | `model/models/gemma3/model.go:106-109`, `model/models/gemma4/model.go:134-137` |
| Framework | gemma4 audio branch: `decodeWAV(data)` returns error on `len(data) < 12` | Yes | `model/models/gemma4/process_audio.go:30-32` |
| Middleware | openai `decodeImageURL` accepts `data:;base64,` blank mime but still runs base64 decode and returns a byte slice; empty base64 decodes to `[]byte{}` | Partial | `openai/openai.go:683-704` |
| Application | llamarunner branch: `image.go:59-66` — `if len(data) <= 0 { return nil, errors.New("received zero length image") }` — explicit zero-length guard | Yes | `runner/llamarunner/image.go:64-66` |
| Documentation | No docs on empty-image handling | N/A — no docs | — |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — path: HTTP image -> openai middleware -> runner completion -> EncodeMultimodal. Reachable.
- Pattern 2 (phantom validation): MATCH — the specific line called out (`ollamarunner/runner.go:274`) does not itself check length, but EVERY downstream `EncodeMultimodal` implementation calls `image.Decode` or `decodeWAV` first and both reject empty input in pure Go before any cgo call. This is phantom-at-callsite / real-at-callee validation.
- Pattern 3 (framework protection): MATCH — Go stdlib `image.Decode` is the framework protection.
- Pattern 4 (same-origin): N/A.
- Pattern 5 (CVE reachability): N/A.
- Pattern 6 (config-as-vuln): N/A.
- Pattern 7 (test code): production.
- Pattern 8 (double-counting): overlap with H-00.11 (blank-MIME) — different stages of the same image-input pipeline.

**Defense argument:** Strongest defense: no cgo dereference occurs on `[]byte{}` input. The per-model `EncodeMultimodal` implementations in `model/models/*/model.go` uniformly call `image.Decode(bytes.NewReader(multimodalData))` as their first step (gemma3:106, gemma4:134, mllama, mistral3, llama4, deepseekocr, qwen3vl, lfm2 — audit all). `image.Decode` on an empty reader returns `io.EOF` / "image: unknown format" before any vision-model forward pass. For gemma4's audio branch, `decodeWAV` checks `len(data) < 12`. The llamarunner sibling at `runner/llamarunner/image.go:64-66` explicitly guards zero-length. The worst-case outcome on `EncodeMultimodal([]byte{})` is a graceful Go error, not a cgo nil-deref.

Honest conclusion: the specific line cited (ollamarunner/runner.go:274) indeed lacks an explicit length check, but the downstream callee guards are strong. The framing of the hypothesis as "cgo nil-deref" is not realized in any current model's EncodeMultimodal.

**Verdict recommendation:** Disproved by Language-layer `image.Decode` rejection + Framework-layer per-model implementations.

---

### [ADVOCATE] Defense Brief for H-00.05 -- 2026-04-17T14:56:00Z

Hypothesis: `mlxrunner.resolveManifestPath` no `filepath.IsLocal`. Component-level gap; upstream protects via `isValidPart` but defense-in-depth fragile. Traversal to read arbitrary manifests from mlxrunner.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Framework | Pre-seed acknowledges "upstream protects via `isValidPart`" — the `server/routes.go` layer validates model name components before they reach mlxrunner | Partial | `isValidPart(kindHost)` etc (per chamber-01 context) |
| Application | mlxrunner.resolveManifestPath is only reachable under `--mlx-engine` subprocess branch (`runner/runner.go:21-22`) which is Darwin-only Apple Silicon | Partial | `runner/runner.go:21-22` |
| Application | manifest name ultimately derives from the same `model.ParseName` -> `isValidPart` validation | Partial | upstream in parent daemon |
| Documentation | Chamber-01 pre-seed H-00.07 (PH-A-13) already flags the sibling `x/imagegen/manifest.BlobPath` same-class bug. Chambers-01 and -03 are double-counting the traversal class | N/A — explicitly flagged in chamber-01 | debate.md chamber-01 H-00.07 |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): partial — pre-seed calls the upstream `isValidPart` an existing defense, so path-trace is partly addressed.
- Pattern 2 (phantom validation): MATCH — the validation lives in parent (`server/`) not in mlxrunner; pre-seed acknowledges this.
- Pattern 3 (framework protection): N/A.
- Pattern 4 (same-origin): N/A.
- Pattern 5 (CVE reachability): N/A.
- Pattern 6 (config-as-vuln): partial — requires `--mlx-engine` path, Darwin-only.
- Pattern 7 (test code): production.
- Pattern 8 (double-counting): MATCH — chamber-01 H-00.07 already covers the `x/imagegen/manifest.BlobPath` sibling; this H-00.05 is the mlxrunner equivalent. Report should fold both into one finding or explicitly carry both paths.

**Defense argument:** Defense is based on the upstream-validates-first argument: by the time a manifest ref reaches mlxrunner's resolver, it has already been through `model.ParseName` and `isValidPart` character gates in the parent daemon. No HTTP endpoint passes a raw traversal string directly to mlxrunner; mlxrunner is a runner subprocess whose inputs arrive as structured model refs. The "defense-in-depth fragile" framing in the pre-seed is correct: it's a code-hygiene issue about missing `filepath.IsLocal`, not a today-exploitable traversal.

**Verdict recommendation:** Cannot disprove as an individual code-hygiene finding, but flag as double-counted with chamber-01 H-00.07 / PH-A-13. Report should clarify this is a defense-in-depth hardening, not an independent exploit path.

---

### [ADVOCATE] Defense Brief for H-00.06 -- 2026-04-17T14:57:00Z

Hypothesis: Runner subprocess trusts `LoraPath` from IPC at `runner/llamarunner/runner.go:852` -> `C.llama_adapter_lora_init` on arbitrary path. Local attacker (or IPC-impersonator) can load arbitrary file as LoRA adapter -> cgo parse attack surface.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Framework | Runner `/load` endpoint binds to 127.0.0.1 only (`runner/llamarunner/runner.go:983` — `addr := "127.0.0.1:" + strconv.Itoa(*port)`). Not reachable from network | Partial | `runner/llamarunner/runner.go:983` |
| Middleware | Parent daemon builds `LoraPath` from `model.AdapterPaths` which is derived from `manifest.BlobsPath(layer.Digest)` at `server/images.go:348` — so Lora paths are themselves blobs fetched via registry pull | Partial | `server/images.go:334-348` |
| Application | Same-user assumption: runner subprocess and parent daemon run as the same Unix user; if a local attacker can already write to a random port on 127.0.0.1 they are already same-user and own the whole process tree | Yes | OS process model |
| Application | Runner guards against re-load: `runner/llamarunner/runner.go:884-887` `if s.status != llm.ServerStatusLaunched { return "model already loaded" }` — single-shot load per subprocess | Partial | `runner/llamarunner/runner.go:884-887` |
| Documentation | No docs | N/A — no docs | — |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): partial — "IPC-impersonator" requires local attacker on same host.
- Pattern 2 (phantom validation): checked — upstream BlobsPath is the validation point (chamber-01 H-00.07 flags traversal there).
- Pattern 3 (framework protection): MATCH — runner loopback binding prevents remote IPC impersonation.
- Pattern 4 (same-origin): MATCH — runner subprocess trusts its parent; same user context.
- Pattern 5 (CVE reachability): N/A.
- Pattern 6 (config-as-vuln): N/A.
- Pattern 7 (test code): production.
- Pattern 8 (double-counting): overlap with H-00.12 (port TOCTOU) — H-00.06 is the payload, H-00.12 is the precondition.

**Defense argument:** Strongest defense: the runner's `/load` endpoint binds to `127.0.0.1` (`runner/llamarunner/runner.go:983`), which restricts the IPC attack surface to same-host local attackers. Same-host attackers who can bind a loopback port are by definition running as the same Unix user as `ollama serve` (because other users cannot send to a process-owned loopback socket on linux/macOS under normal permissions — the socket is not user-isolated but the ephemeral port range is shared; however an attacker on the same host could open a socket of their own on the same port only if the runner has not yet called `Listen`). The runner trust-boundary is "parent daemon speaks for me"; the LoraPath smuggling requires either (a) a compromised parent daemon, in which case LoRA parsing is the least of our problems, or (b) a port-TOCTOU impersonation (H-00.12), which is a separate primitive. Without H-00.12 this is not exploitable.

Additionally, the LoRA path originates from a registry-pulled blob, and chamber-01's H-00.01 already covers how that digest-to-path translation can be attacker-controlled. So the "arbitrary file" is really "attacker-planted blob in the blobs dir", which is a separate attack.

**Verdict recommendation:** Disproved in isolation (no direct IPC path to runner from unauthenticated network). Valid ONLY in CHAIN-B (H-00.06 + H-00.12). Mark as chain-only, not standalone.

---

### [ADVOCATE] Defense Brief for H-00.07 -- 2026-04-17T14:58:00Z

Hypothesis: `GetEmbeddingsSeq`/`GetLogitsIth` `unsafe.Slice` on C-returned size at `llama/llama.go:211-243`. Crafted model sets `NEmbd()` huge -> Go slice over C heap -> disclosure via API response.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `unsafe.Slice((*float32)(e), c.Model().NEmbd())` — NEmbd is a C int from `C.llama_model_n_embd(m.c)`; if the model reports huge value, Go `make([]float32, NEmbd())` allocates huge buffer, leading to allocator ceiling or panic first | Partial | `llama/llama.go:217, 228, 241` |
| Framework | NEmbd is read from model's embedding dim (`n_embd` key in GGUF). Upstream GGUF parser does not bound this value | No | `fs/ggml/ggml.go` — no bound on `llama.embedding_length` |
| Application | `/api/embed` is unauthenticated on localhost default. Attacker needs to have loaded a malicious model first (same precondition as H-00.01) | Partial | `server/routes.go:1714` |
| Application | `c.Model().NEmbd()` is called TWICE (line 217 and 218) — if a concurrent model reload changes NEmbd between the `make` and the `unsafe.Slice` there is a TOCTOU, but same-shot the two reads are equal | Partial | `llama/llama.go:217-218` |
| Documentation | No docs on trust model for GGUF n_embd | N/A — no docs | — |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — attacker must first load a crafted model (same as H-00.01). Reachable via `/api/create` + `/api/generate`/`/api/embed`.
- Pattern 2 (phantom validation): checked — no validation claim.
- Pattern 3 (framework protection): checked — Go `make` ceiling is a weak mitigation.
- Pattern 4 (same-origin): N/A.
- Pattern 5 (CVE reachability): N/A.
- Pattern 6 (config-as-vuln): N/A.
- Pattern 7 (test code): production.
- Pattern 8 (double-counting): partial overlap with H-00.01 — both require malicious-GGUF as precondition. CHAIN-A chains them; they represent separable primitives.

**Defense argument:** Strongest defense: `C.llama_get_embeddings_seq` returns a pointer that lives in the C-allocated context buffer whose size is determined by the same n_embd value at model-load time — the C side allocated `n_embd * sizeof(float)` bytes when it created the context. So the `unsafe.Slice(..., NEmbd())` Go view covers exactly the buffer the C side allocated; it is NOT reading past the C allocation, because the C allocator used the same n_embd. For this to be an OOB read, the attacker would need n_embd to be different at allocation time vs retrieval time — a TOCTOU requiring a reload that changes n_embd without re-allocating the context (which doesn't happen: a reload recreates the context).

Second defense: `make([]float32, NEmbd())` is called BEFORE the `unsafe.Slice`, so if n_embd is absurd, Go's runtime will panic (or the OS OOM-kill) before the `unsafe.Slice` ever executes. This degrades the primitive from information-disclosure to DoS.

Honest conclusion: the hypothesis rests on "C-returned pointer + Go-provided length might disagree". In practice, C allocated with the same n_embd value, so the two lengths match. For H-00.07 to be real, you need a scenario where C side uses a different dimension than NEmbd() returns — which would be a llama.cpp bug, not an ollama bug.

**Verdict recommendation:** Disproved by Language-layer: C buffer and Go slice use the same n_embd source. The `unsafe.Slice` stays within the C allocation. Not exploitable as an information-disclosure primitive on its own. Note: if CHAIN-A argues that H-00.01's OOB read leaves stale F32 data in the Go buffer, then H-00.07 adds nothing — the disclosure has already happened in H-00.01.

---

### [ADVOCATE] Defense Brief for H-00.08 -- 2026-04-17T14:59:00Z

Hypothesis: `MultimodalTokenize` no upper bound at `llama/llama.go:566`: `C.size_t(len(data))` passes 2GB image straight into mtmd cgo -> potential integer overflow in vendored mtmd (CVE-2025-15514 class).

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | Go `int` is 64-bit; `len(data)` fits in `size_t` on 64-bit platforms (no truncation) | Yes (for amd64/arm64) | Go spec |
| Framework | llamarunner sibling at `runner/llamarunner/image.go:64-66` guards zero-length but has no upper bound | Partial | — |
| Middleware | HTTP body size: gin/net/http has no default max body size; attacker can post 2GB image | No | `server/routes.go:1674` `gin.Default()` — no body-size middleware |
| Middleware | openai `decodeImageURL` does base64-decode; input is base64 text so 2GB image means ~2.7GB of POST body | Partial | `openai/openai.go:683-704` |
| Application | `/api/chat` / `/api/generate` image inputs hit this path. No size cap observed | No | — |
| Documentation | No docs on max image size | N/A — no docs | — |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — POST `/api/chat` with giant image -> EncodeMultimodal -> mtmd_helper_bitmap_init_from_buf. Reachable.
- Pattern 2 (phantom validation): checked — `image.Decode` for vision path may reject malformed giant images, but for a valid-looking 2GB JPEG it will happily try to decode. Not a real guard.
- Pattern 3 (framework protection): checked — no framework body-size cap.
- Pattern 4 (same-origin): N/A.
- Pattern 5 (CVE reachability): partial — pre-seed cites CVE-2025-15514 as a representative class; I did not verify the specific vendored mtmd version. This is Pattern-5-adjacent.
- Pattern 6 (config-as-vuln): N/A.
- Pattern 7 (test code): production.
- Pattern 8 (double-counting): partial overlap with H-00.11 (blank-MIME) routing arbitrary payload to mtmd.

**Defense argument:** On 64-bit platforms, `C.size_t(len(data))` does not truncate. The real attack would require the vendored `mtmd_helper_bitmap_init_from_buf` C code itself to have an internal integer overflow when multiplying `width * height * channels`. That is a vendored-dependency bug, not an ollama bug — ollama's surface is just the size_t pass-through. If mtmd is CVE-free at the pinned vendored commit, there is no bug here. If it is CVE-vulnerable, that is a dependency-update issue (Pattern 5).

Additionally, DoS via RAM exhaustion from a 2GB POST is also mitigated by Go's HTTP request context cancellation and the process-level memory ceiling (mmap fails, allocator panics), not by any explicit cap — a best-effort limitation.

Honest conclusion: the "no upper bound" framing is accurate as a defense-in-depth gap, but without a confirmed CVE in the pinned mtmd version, the hypothesis is speculative.

**Verdict recommendation:** Cannot disprove without version-pinned vendored mtmd CVE audit. Recommend tracer-03 to pin the vendored mtmd commit and confirm presence/absence of CVE-2025-15514 class bugs in that specific commit. If the vendored version pre-dates the fix, finding is real.

---

### [ADVOCATE] Defense Brief for H-00.09 -- 2026-04-17T15:00:00Z

Hypothesis: `ggml.go` int64 overflow in `io.NewSectionReader` offset computed from sum of `uint64` tensor offsets; may wrap to negative offset -> read from beginning of file or panic.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Framework | `fs/ggml/gguf.go:258-262` — `tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size(); if tensorEnd > uint64(fileSize)` — bounds the tensor-end against file size in uint64 arithmetic | Partial | `fs/ggml/gguf.go:258-262` |
| Language | However, the check uses uint64 arithmetic that can wrap: if `tensor.Offset` is near MaxUint64, `tensorOffset + tensor.Offset + tensor.Size()` wraps below `fileSize` and PASSES the guard | No | Go unsigned wrap semantics |
| Language | Downstream consumer: `quantizer.WriteTo` at `server/quantization.go:26` uses `io.NewSectionReader(q, int64(q.offset), int64(q.from.Size()))`. `int64(uint64)` may wrap negative. `io.NewSectionReader` docs say it does not restrict length; a negative length "is used as-is" but `SectionReader.Read` typically clamps | Partial | `server/quantization.go:26` |
| Middleware | N/A | N/A | — |
| Application | Requires crafted GGUF with attacker-chosen tensor.Offset — same precondition as H-00.01 | Partial | — |
| Documentation | No docs | N/A — no docs | — |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — reachable via `/api/create` + crafted GGUF.
- Pattern 2 (phantom validation): MATCH — the `tensorEnd > fileSize` guard at gguf.go:258-262 is phantom protection when uint64 wrap is considered.
- Pattern 3 (framework protection): checked.
- Pattern 4 (same-origin): N/A.
- Pattern 5 (CVE reachability): N/A.
- Pattern 6 (config-as-vuln): N/A.
- Pattern 7 (test code): production.
- Pattern 8 (double-counting): overlaps precondition with H-00.01 (malicious GGUF), but distinct primitive (offset wrap vs dim wrap).

**Defense argument:** The strongest defense is that the `tensorEnd > uint64(fileSize)` check DOES catch most cases. For the uint64 wrap to succeed, the attacker needs `tensor.Offset` near `MaxUint64` so that `tensorOffset + tensor.Offset + tensor.Size()` wraps below `fileSize`. That's a specific pattern, not arbitrary. Additionally, when `int64(q.offset)` wraps negative in `io.NewSectionReader`, Go's `SectionReader.Read` compares `s.off >= s.limit` and returns `io.EOF`, so a negative offset typically yields an empty read rather than a read-from-start.

The `io.ReadAll(sr)` on a negative-offset section reader returns an empty byte slice, which then fails the `uint64(len(data)) < q.from.Size()` check at `server/quantization.go:37-39`, returning an error instead of invalid data.

Honest conclusion: the tensor-end guard is present but bypassable via uint64 wrap. Downstream `io.NewSectionReader` plus the `len(data) < Size()` mismatch check likely causes an error rather than exploitable misread, but I cannot rule out that specific carefully-chosen offsets produce a partial read that slips past that check.

**Verdict recommendation:** Cannot disprove — uint64 wrap in bounds check is a real concern; downstream error checks likely mitigate to DoS rather than memory disclosure, but tracer needs to confirm the exact wrap scenario.

---

### [ADVOCATE] Defense Brief for H-00.10 -- 2026-04-17T15:01:00Z

Hypothesis: `ggml-alloc.c:894` use-after-free — `galloc->leaf_allocs` freed then accessed in `ggml_gallocr_alloc_graph`. Triggered by normal inference on any graph that re-runs allocation. Potential RCE via freelist shaping.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | C — no language protection | No | — |
| Framework | Vendored ggml-alloc.c in `llama/llama.cpp/src/` — ollama inherits upstream fixes as part of rsync-filter updates | Partial | `llama/llama.cpp/.rsync-filter` |
| Framework | ASAN/UBSan are not part of production builds; the UAF is silent unless exploited | No | build config |
| Middleware | N/A | N/A | — |
| Application | Runner subprocess isolation — if ggml-alloc UAF crashes the runner, only the runner dies; parent `ollama serve` keeps running (subprocess reaps at `llm/server.go:312-325`) | Partial | `llm/server.go:311-325` |
| Application | ASLR + Go runtime randomness in the runner process complicates freelist shaping | Partial | OS ASLR |
| Documentation | No docs | N/A — no docs | — |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): partial — "triggered by normal inference" but tracer-03 must confirm the specific graph construction required. Pre-seed says SAST-UAF-01.
- Pattern 2 (phantom validation): N/A.
- Pattern 3 (framework protection): N/A.
- Pattern 4 (same-origin): N/A.
- Pattern 5 (CVE reachability): MATCH — this is a vendored C-library UAF. Pattern 5: has the vulnerable function been called with attacker-influenced data? "Normal inference" means YES, but whether the attacker can SHAPE the freelist to make it RCE (vs just crash) is very different.
- Pattern 6 (config-as-vuln): N/A.
- Pattern 7 (test code): production.
- Pattern 8 (double-counting): CHAIN-C and CHAIN-F both rely on this. Not double-counted in pre-seeds.

**Defense argument:** Strongest defense: "potential RCE via freelist shaping" is aspirational. A Go runtime + C heap UAF exploitation requires defeating:
(1) ASLR (32-bit positional entropy on most Linux)
(2) Go's garbage collector's own heap which is not contiguous with C's libc heap
(3) Runner subprocess is killed on crash — attacker gets one shot per process lifetime
(4) CFI on recent Clang/GCC builds (depends on distributor)
(5) W^X on code pages

And for a UAF to be a RCE primitive the freed struct must be reallocated as an attacker-controlled struct with a function-pointer in it, typed confusion — none of which the pre-seed demonstrates. More realistically, this is a reliable-DoS (SIGSEGV crash of the runner) which the scheduler respawns.

Honest conclusion: the UAF is real per SAST; the RCE framing is speculative. Severity is probably DoS + potential info-leak, not RCE, unless tracer-03 can demonstrate a heap-shaping primitive in the same process.

**Verdict recommendation:** Cannot disprove existence of UAF; strongly contest the "RCE" severity framing. Recommend downgrading severity unless tracer can show shaping path. Also flag CHAIN-C pre-condition (blank-MIME) and CHAIN-F pre-condition (CString leak) both have weaker chains than the synthesizer lists.

---

### [ADVOCATE] Defense Brief for H-00.11 -- 2026-04-17T15:02:00Z

Hypothesis: Blank MIME `data:;base64,` bypass reaches mtmd cgo with arbitrary binary payload — MIME validation gates image-vs-audio dispatch but empty mediatype treated as default.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Language | `base64.StdEncoding.DecodeString` rejects invalid base64 and returns bytes for valid base64; cannot be used to sneak non-base64 content | Partial | `openai/openai.go:700-703` |
| Framework | EncodeMultimodal for vision models calls `image.Decode(bytes.NewReader(...))` which sniffs magic bytes: PNG/JPEG/WEBP/GIF headers. Non-image bytes rejected with "image: unknown format" | Yes | `model/models/gemma3/model.go:106`, `model/models/gemma4/model.go:134` |
| Framework | gemma4 audio branch: `isAudioData(data)` checks `RIFF....WAVE` magic at `process_audio.go:278+`. Non-WAV rejected | Yes | `model/models/gemma4/process_audio.go:277+` |
| Framework | `decodeImageURL` explicitly accepts `data:;base64,` to match `/api/chat` behavior (which takes unadorned base64) | N/A — intended behavior | `openai/openai.go:682-684` |
| Middleware | — | — | — |
| Application | mtmd cgo entry (`llama/llama.go:566`) is only reached for llama.cpp runner with a loaded vision model; the data bytes have already passed through `image.Decode` in callers that use the ollamarunner path | Partial | — |
| Documentation | Comment at `openai/openai.go:682` explicitly calls out `Support blank mime type to match /api/chat's behavior of taking just unadorned base64` | N/A — intended behavior | `openai/openai.go:682` |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — data:;base64,<arbitrary> -> decodeImageURL -> EncodeMultimodal -> image.Decode rejects non-image. Path ends at image.Decode rejection.
- Pattern 2 (phantom validation): checked — `image.Decode` is the real validation.
- Pattern 3 (framework protection): MATCH — stdlib `image.Decode` is the framework guard; magic-byte validation is built-in.
- Pattern 4 (same-origin): N/A.
- Pattern 5 (CVE reachability): N/A.
- Pattern 6 (config-as-vuln): N/A.
- Pattern 7 (test code): production.
- Pattern 8 (double-counting): CHAIN-C leverages this to reach H-00.10 (UAF). If the data is a valid PNG that happens to trigger the UAF in ggml-alloc, the blank-MIME bypass adds nothing: a valid `data:image/png;base64,` URI would reach the same code.

**Defense argument:** Strongest defense: the blank-MIME acceptance is INTENTIONAL (explicit comment at `openai/openai.go:682` says "Support blank mime type to match /api/chat's behavior of taking just unadorned base64"). `/api/chat` has always accepted unadorned base64. The MIME tag is a cosmetic type hint, not a security boundary. The real security boundary is `image.Decode`'s magic-byte sniffing (PNG, JPEG, GIF, WEBP) — which is in the Go stdlib and is well-tested.

For the hypothesis to be real, an attacker would need to supply bytes that: (a) are valid base64, (b) pass `image.Decode` magic check (so the bytes must look like a supported image format), AND (c) trigger a bug downstream. The blank-MIME tag doesn't change (b) or (c). A well-formed `data:image/png;base64,<malicious-png>` reaches exactly the same code path.

Honest conclusion: the blank-MIME framing is a red herring. The real attack would be "malicious PNG reaches mtmd" regardless of the MIME tag. Worth flagging for CHAIN-C, but as a chain amplifier rather than a primitive.

**Verdict recommendation:** Disproved as standalone (MIME tag is not a security boundary; `image.Decode` is). The CHAIN-C framing is also weak: any valid image MIME tag works the same way. Finding has no additional attack value over "malicious image -> mtmd".

---

### [ADVOCATE] Defense Brief for H-00.12 -- 2026-04-17T15:03:00Z

Hypothesis: Runner IPC port TOCTOU — ephemeral port selection race; another local process can bind the chosen port before the runner claims it -> IPC impersonation.

**Protection search results:**

| Layer | Protection Found | Blocks Attack? | Evidence |
|-------|-----------------|----------------|----------|
| Framework | Linux/macOS: binding to `localhost:0` picks an ephemeral port. The parent daemon closes the listener at `llm/server.go:350` before spawning the child: `if l, err = net.ListenTCP("tcp", a); err == nil { port = l.Addr().(*net.TCPAddr).Port; l.Close() }`. There IS a TOCTOU window between `l.Close()` and the child's `net.Listen` on the same port | No (bug confirmed) | `llm/server.go:345-352` |
| Framework | On Linux, `SO_REUSEADDR` is NOT the default; a bind to an occupied port fails with EADDRINUSE. If an attacker wins the race, the runner's Listen fails and `runner/llamarunner/runner.go:985-988` — `return err` — the parent sees startup failure and aborts that runner | Partial | `runner/llamarunner/runner.go:985-988` |
| Middleware | Same-user assumption: only processes running as the same Unix user can bind a loopback port without root; on a single-user workstation this is moot. On multi-user hosts, the attacker would need to already have local accounts | Partial | OS process model |
| Application | If attacker wins, parent's HTTP POST to `http://127.0.0.1:<port>/load` lands on attacker's imposter server. Attacker can log `LoadRequest` (contains LoraPath, etc) or return fake responses | No (bug confirmed) | `llm/server.go:1211` |
| Application | Loopback-only means no remote attack; requires local process | Partial | — |
| Documentation | No docs | N/A — no docs | — |

**Claude FP Pattern Check:**
- Pattern 1 (no path trace): checked — precondition: local attacker on same host with same UID.
- Pattern 2 (phantom validation): checked.
- Pattern 3 (framework protection): checked — SO_REUSEADDR default on Linux means attacker wins the race (runner's second bind fails).
- Pattern 4 (same-origin): MATCH — this is entirely same-host, same-user attack.
- Pattern 5 (CVE reachability): N/A.
- Pattern 6 (config-as-vuln): N/A.
- Pattern 7 (test code): production.
- Pattern 8 (double-counting): CHAIN-B chains this with H-00.06. Not otherwise duplicated.

**Defense argument:** Strongest defense: same-user threat model. A local attacker process that wins the ephemeral port race to impersonate the runner is already running as the same Unix user as `ollama serve`. At that trust level, the attacker can:
- Read/write all of `ollama serve`'s memory (ptrace)
- Overwrite the on-disk binary before restart
- Replace `os.Executable()` path
- Send SIGKILL and replace the process
IPC impersonation is a strictly weaker primitive than what same-user already provides. Ollama's threat model (loopback-bind, no runner auth) explicitly targets single-user local usage.

On Linux, bind with default `SO_REUSEADDR` off means only ONE process can hold the port. If attacker wins the race, runner's `net.Listen` fails, parent sees error, backs off — no confused deputy because the parent doesn't blindly continue. If attacker LOSES the race (runner binds first), attacker cannot impersonate at all.

Honest conclusion: the TOCTOU exists but is exploitable only by a same-UID local attacker, which is already outside the threat model. For CHAIN-B this is the weakest link.

**Verdict recommendation:** Disproved by Application-layer same-user trust boundary. The TOCTOU is real but lands below the threat-model floor. Recommend flagging as defense-in-depth (use unix-domain socket with restrictive permissions, or child-side handshake/token), not shipping as a finding.

---

## Round 2 -- Tracing (tracer-03)

**Completed**: 2026-04-17T07:00:00Z

Method 2.6 applied: CodeQL DB at `archon/codeql-artifacts/db/`. DFD-6-multimodal-cgo slice in `call-graph-slices.json` is `reachable: false` (C side unmodeled by Go extractor). All cgo sinks traced manually. `flow-paths-all-severities.md` confirmed `go/uncontrolled-allocation-size` and `go/allocation-size-overflow` findings. `entry-points.json` confirms runner body sources at `runner/llamarunner/runner.go:890` and `runner/ollamarunner/runner.go:1285`.

---

### [TRACER] Evidence for H-00.01 -- 2026-04-17T07:01:00Z

**Reachability: REACHABLE (DoS via OOM/runtime-panic; memory-disclosure conditional on allocator behavior)**

Code path:
1. `server/routes.go:1703` -- `POST /api/create` unauthenticated; `CreateHandler` dispatches to `server/create.go`
2. `server/create.go:496` -- `quantType := strings.ToUpper(cmp.Or(r.Quantize, r.Quantization))` — attacker-supplied quantize type; triggers quantization branch
3. `server/create.go:507` -- `layer, err = quantizeLayer(layer, quantType, fn)` — GGUF layer processed
4. `server/create.go:640` -- `quantize(fp, temp, layer.GGML, ftype, fnWrap)` — iterates tensors, calls `WriteTo` per tensor
5. `server/quantization.go:26` -- `sr := io.NewSectionReader(q, int64(q.offset), int64(q.from.Size()))` — `q.from.Size()` = `Elements() * typeSize / blockSize`; if `Elements()` overflowed to a small value, `Size()` is small and this line is benign
6. `server/quantization.go:37-38` -- `if uint64(len(data)) < q.from.Size() { return 0, fmt.Errorf(...) }` — guard passes when `Size()` wraps to a value <= actual on-disk bytes
7. `server/quantization.go:43` -- **F32 path**: `f32s = unsafe.Slice((*float32)(unsafe.Pointer(&data[0])), q.from.Elements())` — `q.from.Elements()` is the un-wrapped large uint64 (e.g., 2^62); `unsafe.Slice` creates a Go slice of length 2^62 pointing to `data[0]`; no allocation, but the slice header lies about its bounds
8. `server/quantization.go:47` -- `data = ggml.Quantize(newType, f32s, q.from.Shape)` — iterates `f32s` for `shape[0]*shape[1]*...` elements which equals `2^62`; reads past `data`'s backing array into adjacent Go heap
9. `server/quantization.go:45` -- **Non-F32 path**: `f32s = ggml.ConvertToF32(data, q.from.Kind, q.from.Elements())` called instead
10. `ml/backend/ggml/quantization.go:20` -- `f32s := make([]float32, nelements)` — `nelements = 2^62` → `make` requests `2^62 * 4 bytes ≈ 16 EiB` → Go runtime panics with `runtime: out of memory` or `makeslice: len out of range` (non-recoverable)

Supporting chain for `Elements()` overflow:
- `fs/ggml/gguf.go:141-200` -- tensor `Shape` fields are raw `uint64` from the GGUF file; no per-dim bound enforced
- `fs/ggml/ggml.go:505-511` -- `Elements()` multiplies all shape dims without overflow check; `{2^32, 2^32}` → product = 0; `{2^31+1, 2}` → product = `2^32+2`; `{2^62, 1, 1, 1}` → product = `2^62`
- `fs/ggml/gguf.go:258-262` -- bounds check: `tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()` — uint64 arithmetic; if `tensor.Offset` chosen to put `tensorEnd` just below `fileSize`, check passes even though `Elements()` is enormous for a quantized type with large `blockSize()`

Sanitizers on path:
- `fs/ggml/gguf.go:258-262` -- `tensorEnd > fileSize` check — **bypassable** via uint64 wraparound: choose `tensor.Offset` near MaxUint64 so product wraps below fileSize; OR choose a type with large `blockSize` so `Size() = Elements() * typeSize / blockSize` is small even with huge `Elements()`
- `server/quantization.go:37-38` -- `uint64(len(data)) < q.from.Size()` -- **bypassable** by the same mechanism (Size() small due to type/blockSize division)
- `ml/backend/ggml/quantization.go:20` -- `make([]float32, nelements)` -- Go runtime OOM cap; **NOT a security boundary**, converts disclosure to DoS on most inputs; for F32 type (line 43) no allocation occurs and the `unsafe.Slice` + iteration is the actual OOB read primitive

CodeQL slice: `call-graph-slices.json` entry DFD-2-blob-upload-gguf-parse, `reachable: true`, `path_count: 4`. Sinks include `make([]byte, n)` in GGUF parser but NOT the `ConvertToF32` cgo path — that cgo path is confirmed by Semgrep custom rule `ollama-cgo-length-unchecked` (dropped as `duplicate-of-probe` in Phase 7 filter per `sast-filtered.json`).
On-demand query: none

**Assessment**: REACHABLE for DoS (OOM panic from make in ConvertToF32 non-F32 path). REACHABLE for OOB read primitive in F32 path via `unsafe.Slice` + iteration past `data`'s backing store. The DoS is the dominant outcome because `make([]float32, 2^62)` panics before the cgo call; the `allocModel` `defer recover()` does not protect (it only catches `ml.ErrNoMem`, not runtime panics). For the OOB-read primitive (F32 tensor path), the `Quantize` function iterates up to `shape[0]*shape[1]` elements, reading past `data`, potentially disclosing Go heap contents. The loop terminates when the C quantization call handles each row — whether it actually reads all `2^62` elements or truncates depends on the C implementation. Severity: HIGH DoS + potential memory disclosure (CRITICAL under shared-tenant deployment).

---

### [TRACER] Evidence for H-00.02 -- 2026-04-17T07:04:00Z

**Reachability: REACHABLE (bounded memory leak; exploitability limited by subprocess isolation)**

Code path:
1. `runner/llamarunner/runner.go:900-966` -- `/load` handler calls `llama.LoadModelFromFile(modelPath, ...)` at approximately line 940
2. `llama/llama.go:264-310` -- `LoadModelFromFile` calls `C.CString(modelPath)` at approximately line 308; no corresponding `defer C.free`
3. Every `LoadModelFromFile` invocation leaks the C heap allocation for `modelPath`

Sanitizers on path:
- Subprocess model: `llm/server.go:336` — runner is a subprocess; process exit reclaims all C heap. **Effective per-run bound.**
- Runner single-load guard: `runner/llamarunner/runner.go:884-887` — "model already loaded" prevents re-load within one subprocess. **Limits leak to one leak per subprocess lifetime.**
- `envconfig.MaxRunners()` caps concurrent runner processes.

CodeQL slice: `call-graph-slices.json` DFD-5-agent-bash (exec path, not directly relevant). No dedicated slice for this CString leak.
On-demand query: none

**Assessment**: REACHABLE but bounded. The C heap leak at `llama/llama.go:308` is real and produces one leak per runner subprocess launch. Since each subprocess handles one model and exits on unload, the leak is reclaimed at subprocess exit. Not directly exploitable for DoS without a mechanism to rapidly launch many subprocesses. As a chain primitive (H-CHAIN-F), it requires multiple subprocess launches which are admin-rate-limited by the scheduler.

---

### [TRACER] Evidence for H-00.07 -- 2026-04-17T07:06:00Z

**Reachability: PARTIAL (OOB read conditional on C buffer and NEmbd mismatch; Advocate argument credible but contains a gap)**

Code path:
1. `server/routes.go:1714` -- `POST /api/embed` unauthenticated; calls runner's embedding endpoint
2. `llm/server.go:1747-1750` -- `r, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/embedding", s.port), bytes.NewBuffer(data))`
3. `runner/llamarunner/runner.go:752` -- runner's `/embedding` handler; calls `s.lc.GetEmbeddingsSeq(seqId)` after llama decode
4. `llama/llama.go:211-219` -- `GetEmbeddingsSeq`: `e := unsafe.Pointer(C.llama_get_embeddings_seq(c.c, C.int(seqId)))`; `embeddings := make([]float32, c.Model().NEmbd())`; `copy(embeddings, unsafe.Slice((*float32)(e), c.Model().NEmbd()))`

Analysis of Advocate's defense:
- The Advocate argued that `C.llama_get_embeddings_seq` returns a pointer to a C-side buffer sized by the same `n_embd` value. This is generally correct for a well-formed model.
- However, if a crafted GGUF sets `llama.embedding_length = 2^31-1` (a valid uint32 in the GGUF KV), `c.Model().NEmbd()` returns 2^31-1, and `make([]float32, 2^31-1)` allocates a 8 GB buffer. The C side allocates the same amount (context buffer is sized by n_embd at context creation). Whether the C buffer is actually 8 GB depends on whether llama.cpp clamps or rejects the embedding length.
- The Advocate's "same n_embd source" argument holds when n_embd is small and consistent. When n_embd is attacker-crafted to a huge value, the OOM occurs before any copy — this degrades the primitive to DoS, as the Advocate correctly notes.
- For CHAIN-A: The F32 overflow in H-00.01 fills `f32s` with OOB memory; then `Quantize` writes this to the tensor blob on disk. When later loaded as the model's "embedding" tensor, `GetEmbeddingsSeq` returns the result of decoding those OOB bytes — which would be the normal decoded values, not the original heap bytes. The chain does NOT produce direct memory exfil via H-00.07 in the current form; the quantization step re-encodes the OOB bytes.

Sanitizers on path:
- `llama/llama.go:213-215` -- `if e == nil { return nil }` — nil check before unsafe.Slice; **bypassable** only if C function is non-nil but points to wrong size buffer
- `make([]float32, NEmbd())` -- allocator OOM cap; converts large-n_embd to DoS before copy

CodeQL slice: DFD-6-multimodal-cgo (`reachable: false`); `entry-points.json` confirms `runner/llamarunner/runner.go:752` as remote flow source.
On-demand query: none

**Assessment**: PARTIAL. The `unsafe.Slice` at `llama/llama.go:218` is only over the C-allocated embedding buffer whose size matches `NEmbd()`. For a legitimate model, this is safe. For a crafted model with giant `n_embd`, the `make([]float32, NEmbd())` at line 217 will OOM before the copy. The direct memory-disclosure primitive described in H-00.07 is not realized in isolation; it requires H-00.01's OOB write to produce false embedding values, which is a quantization-step encoding (not direct heap disclosure). Severity: MEDIUM DoS (giant n_embd OOM) from unauthenticated `/api/embed` with crafted model; potential for H-00.01 chain.

---

### [TRACER] Evidence for H-00.08 -- 2026-04-17T07:08:00Z

**Reachability: REACHABLE (NULL pointer dereference via invalid image data; see H-00.11 for blank-MIME variant)**

Code path (same as H-00.11 traced below; expanding with exact line references for the llamarunner path):
1. `server/routes.go:435-437` -- `POST /api/generate` with `"images":["<base64>"]`; `images[i] = llm.ImageData{ID: i, Data: req.Images[i]}`; no format validation
2. `llm/server.go:1612-1620` -- completion request forwarded to runner
3. `runner/llamarunner/runner.go:236` -- `chunks, err := s.image.MultimodalTokenize(s.lc, images[imageIndex].Data)`
4. `runner/llamarunner/image.go:59-66` -- `if len(data) <= 0 { return nil, ... }` — only zero-length guard; arbitrary non-zero bytes pass
5. `runner/llamarunner/image.go:75-76` -- `chunks, err = c.mtmd.MultimodalTokenize(llamaContext, data)`
6. `llama/llama.go:566` -- `bm := C.mtmd_helper_bitmap_init_from_buf(c.c, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))`
7. `llama.cpp/tools/mtmd/mtmd-helper.cpp:489` -- `stbi_load_from_memory(buf, len, ...)` — `stbi_load_from_memory` signature takes `int len`; from C++, `len` is `size_t` passed implicitly; if `len > INT_MAX`, implementation-defined truncation on some platforms; function returns NULL on unrecognized format
8. `llama.cpp/tools/mtmd/mtmd-helper.cpp:490-492` -- returns NULL
9. `llama/llama.go:566` -- `bm = nil`
10. `llama/llama.go:567` -- `defer C.mtmd_bitmap_free(bm)` — NULL-safe; safe
11. `llama/llama.go:570` -- `C.mtmd_tokenize(c.c, ic, it, &bm, 1)` — **passes pointer to nil pointer**
12. `llama.cpp/tools/mtmd/mtmd.cpp:465` -- `bitmap = bitmaps[0]` = NULL; `add_media(NULL)` called
13. `llama.cpp/tools/mtmd/mtmd.cpp:552` -- `img_u8->nx = bitmap->nx` — NULL deref → SIGSEGV in runner subprocess

Critical observation: there is **no nil-check on `bm` before `mtmd_tokenize` is called at `llama/llama.go:570`**. The only nil-check is in `defer C.mtmd_bitmap_free(bm)` which calls `if (bitmap) { delete bitmap; }` — but the tokenize call at line 570 happens BEFORE the deferred free.

Sanitizers on path:
- `runner/llamarunner/image.go:64-66` -- zero-length guard; **does not** block non-empty arbitrary bytes
- `llama/llama.go:567` -- `defer C.mtmd_bitmap_free(bm)` -- NULL-safe defer; **does not protect** `mtmd_tokenize` at line 570 from receiving a pointer to nil
- HTTP body size: no `http.MaxBytesReader` on `/api/generate`; 2GB image body accepted (separate DoS)

Alternate entry (OpenAI compatibility, blank MIME):
- `openai/openai.go:683-684` -- `data:;base64,` accepted, MIME allowlist skipped
- Reaches same sink via `/v1/chat/completions` → `ChatMiddleware` → `ChatHandler` → same runner path

CodeQL slice: DFD-6-multimodal-cgo entry (#6), `reachable: false` (C not modeled). Confirmed by Semgrep `ollama-cgo-length-unchecked` at `llama/llama.go:566`.
On-demand query: none

**Assessment**: REACHABLE. Any non-zero-length byte sequence that is not a recognized image or audio format (not PNG/JPEG/BMP/TGA/GIF/WAV/RIFF) causes `mtmd_helper_bitmap_init_from_buf` to return NULL. The missing nil-check at `llama/llama.go:570` then passes `&nil` to `mtmd_tokenize`, which dereferences it at `mtmd.cpp:552`. Runner subprocess crashes (SIGSEGV). Reachable from `/api/generate` (no MIME check) and from `/v1/chat/completions` with `data:;base64,` prefix. Severity: HIGH DoS — unauthenticated, any non-image payload.

---

### [TRACER] Evidence for H-00.10 -- 2026-04-17T07:10:00Z

**Reachability: UNREACHABLE as UAF (Semgrep false positive confirmed); underlying realloc pattern is correct**

Code path under examination:
1. `ml/backend/ggml/ggml/src/ggml-alloc.c:892` -- `if (galloc->n_leafs < graph->n_leafs) {`
2. `ml/backend/ggml/ggml/src/ggml-alloc.c:893` -- `free(galloc->leaf_allocs);`
3. `ml/backend/ggml/ggml/src/ggml-alloc.c:894` -- `galloc->leaf_allocs = calloc(graph->n_leafs, sizeof(galloc->leaf_allocs[0]));`

The Semgrep rule `c.lang.security.use-after-free` flagged `sizeof(galloc->leaf_allocs[0])` at line 894 as a use of the freed `galloc->leaf_allocs`.

Analysis:
- `sizeof(galloc->leaf_allocs[0])` is evaluated at **compile time**. The C `sizeof` operator applied to a lvalue like `ptr[0]` resolves the **type** of the expression at compile time; it does NOT dereference the pointer at runtime.
- The compiled instruction for `sizeof(galloc->leaf_allocs[0])` is a compile-time constant (the size of `struct leaf_alloc`) embedded directly in the instruction stream.
- No load from the freed memory address occurs.
- `galloc->leaf_allocs` is immediately overwritten at line 894 with the `calloc` result; subsequent accesses use the new allocation.
- This is the standard C `free(p); p = calloc(n, sizeof(p[0]))` idiom and is universally correct.

The freed pointer is not used after free. Semgrep's pattern-matching engine detected syntactic proximity (`free(p->field)` followed by `sizeof(p->field[0])`) without understanding C semantics of `sizeof`.

Sanitizers on path: N/A (no UAF exists).
CodeQL slice: no C-side modeling in CodeQL DB.
On-demand query: none

**Assessment**: UNREACHABLE / FALSE POSITIVE. SAST-UAF-01 should be closed. The `ggml_gallocr_reserve_n_impl` realloc pattern is correct C. No UAF exists at this location. The CHAIN-C and CHAIN-F hypotheses that depend on this as a UAF RCE primitive lose their foundation. Note: the existence of a real UAF in ggml would require separate confirmation via a different source (e.g., ASAN/valgrind run, upstream CVE, or manual trace of a double-free scenario). None of those are present at this code site.

---

### [TRACER] Evidence for H-00.11 -- 2026-04-17T07:12:00Z

**Reachability: REACHABLE (same sink as H-00.08; blank-MIME adds one additional entry path via OpenAI compat endpoint)**

See H-00.08 above for the full trace to the NULL-deref sink. The blank-MIME path is:

1. `POST /v1/chat/completions` with `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:;base64,AAAA"}}]}]}`
2. `openai/openai.go:507-519` -- `case "image_url"` branch; `url = "data:;base64,AAAA"`
3. `openai/openai.go:519` -- `decodeImageURL(url)` called
4. `openai/openai.go:683-684` -- `strings.HasPrefix(url, "data:;base64,")` → true; MIME allowlist block SKIPPED; `url = "AAAA"` (stripped prefix)
5. `openai/openai.go:700` -- `base64.StdEncoding.DecodeString("AAAA")` → `[]byte{0x00, 0x00, 0x00}` (valid base64, 3 bytes)
6. `openai/openai.go:703` -- `return img, nil` — returns 3 bytes of arbitrary data as `api.ImageData`
7. Continues to `runner/llamarunner/image.go:64-66` -- `len(data) = 3 > 0` — zero-length guard passes
8. Reaches `llama/llama.go:566-570` — NULL-deref as traced in H-00.08

Advocate's defense (image.Decode magic-byte check): This guard applies only to the `ollamarunner` path where `EncodeMultimodal` calls `image.Decode`. The `llamarunner` path does NOT call `image.Decode`; it calls `c.mtmd.MultimodalTokenize` directly at `runner/llamarunner/image.go:76`. So the Advocate's defense at `model/models/gemma3/model.go:106` is **not on the llamarunner code path**. The llamarunner path is used for older/CLIP-style vision models.

Sanitizers on path:
- `openai/openai.go:683-684` -- blank-MIME bypass: **intentional** but creates the vulnerability
- `runner/llamarunner/image.go:64-66` -- zero-length guard only; `len(data) = 3` passes
- `llama/llama.go:567` -- NULL-safe defer free; does NOT protect `mtmd_tokenize` at line 570

CodeQL slice: DFD-6-multimodal-cgo, `reachable: false`. Manual trace confirms reachability.
On-demand query: none

**Assessment**: REACHABLE. The blank-MIME `data:;base64,` path reaches the identical NULL-deref sink as H-00.08 via the OpenAI compatibility endpoint. The Advocate's `image.Decode` defense applies only to `ollamarunner` (new engine path) and not to `llamarunner` (old engine path with `mtmd`). Both entry paths (direct `/api/generate` and OpenAI compat `/v1/chat/completions`) are REACHABLE. The vulnerability is in the missing nil-check on `bm` at `llama/llama.go:570`.

---

### [TRACER] Evidence for H-CHAIN-A.1 -- 2026-04-17T07:15:00Z

**Reachability: PARTIAL (OOB read in F32 unsafe.Slice path is REACHABLE; exfil-via-embeddings requires additional conditions)**

Chain step 1 (OOB read via ConvertToF32):
- See H-00.01 above; the F32 path `server/quantization.go:43` with `unsafe.Slice(..., q.from.Elements())` creates an over-length slice. The subsequent `ggml.Quantize(newType, f32s, ...)` iterates through this over-length `f32s` reading up to `shape[0]` float32 values per row from adjacent Go heap. **REACHABLE** — `unsafe.Slice` creates the slice without allocation; `Quantize` iterates it.

Chain step 2 (exfil via `/api/embed`):
- After quantization, the on-disk tensor blob contains bytes from the Go heap that happened to be adjacent to `data`'s backing array. These bytes are encoded per the quantization format (e.g., Q4_0 block encoding). When the model is loaded and `/api/embed` is called, `GetEmbeddingsSeq` (`llama/llama.go:217-218`) returns the decoded float32 values of whatever weights the model has.
- The decoded float values are NOT the raw heap bytes — they are the result of the C dequantization function applied to the on-disk bytes (heap bytes treated as quantized blocks). The numerical values depend on the heap bytes' byte patterns but are not directly the original pointer/string values.
- For the exfil to convey meaningful secrets (ed25519 key bytes, auth token bytes), the attacker would need to: (a) know the precise heap layout, (b) reverse the quantization encoding, (c) map the float32 values back to original bytes.

Sanitizers on path:
- `server/quantization.go:37-38` -- `len(data) < Size()` guard: bypassable as described in H-00.01
- Quantization encoding: acts as a scrambling layer; not a security control but makes exfil non-trivial

CodeQL slice: DFD-2-blob-upload-gguf-parse + DFD-6-multimodal-cgo; neither covers the full chain.
On-demand query: none

**Assessment**: PARTIAL. Step 1 (OOB read producing heap bytes in quantized tensor) is REACHABLE. Step 2 (exfil via embeddings API) requires reversing the quantization encoding which adds attacker complexity. The chain is not a clean "send arbitrary heap bytes over JSON" primitive; the bytes are encoded. A skilled attacker with known heap layout could potentially recover secrets, but this is not a trivially-exploitable chain. Severity: HIGH (OOB read is the primary finding); exfil chain is THEORETICAL and requires significant attacker sophistication.

---

### [TRACER] Evidence for H-CHAIN-B.1 -- 2026-04-17T07:18:00Z

**Reachability: UNREACHABLE in normal threat model (same-UID local attacker only; runner bind fails if race lost)**

Code path:
1. `llm/server.go:345-351` -- `net.ListenTCP("tcp", "localhost:0")` picks ephemeral port `P`; listener `l` immediately closed; port `P` returned; runner child spawned with `--port P` on argv
2. TOCTOU window: between `l.Close()` (line 350) and runner's `net.Listen` on port `P`
3. `runner/llamarunner/runner.go:983-988` -- `addr := "127.0.0.1:" + strconv.Itoa(*port)`; `l, err = net.Listen("tcp", addr)` — if attacker bound port first: returns EADDRINUSE; runner exits with error; parent sees failure

Analysis: For a successful impersonation:
- Attacker must `bind(P)` in the TOCTOU window (typically microseconds)
- When attacker wins: runner's `net.Listen` fails; parent's `watchRunner` detects runner died and aborts the load — no confused deputy
- The parent does NOT retry with a different port automatically; it returns an error to the `/api/generate` caller
- Only if the attacker can simultaneously win the race AND intercept the parent's subsequent retry (if one exists) does impersonation succeed
- Requires same-UID local attacker by OS constraint (loopback is not user-isolated but the race window is extremely narrow)

CodeQL slice: no matching slice.
On-demand query: none

**Assessment**: UNREACHABLE in practice. The TOCTOU window exists but when the attacker wins the race, the runner fails to start and the parent aborts cleanly — no confused-deputy state. Impersonation requires winning both the timing race AND the parent's retry (which may not happen). Same-UID constraint means local privilege escalation is already available via simpler means. The Advocate's verdict (disproved by same-user trust boundary) is confirmed.

---

### [TRACER] Evidence for H-CHAIN-C.1 -- 2026-04-17T07:20:00Z

**Reachability: UNREACHABLE (ggml-alloc UAF is a false positive; blank-MIME path itself is REACHABLE for DoS)**

Chain analysis:
- Step 1 (blank-MIME bypass → audio dispatch): `mtmd_helper_bitmap_init_from_buf` at line 471 calls `audio_helpers::is_audio_file((const char *)buf, len)`. For a RIFF/WAVE magic header, the audio branch is taken. The audio decode path calls `decode_audio_from_buf` and then `mtmd_bitmap_init_from_audio`. For a non-WAV byte sequence, `is_audio_file` returns false → falls to `stbi_load_from_memory` → returns NULL → H-00.08/H-00.11 NULL-deref triggered. For a valid-looking RIFF/WAVE header, the audio branch is entered.
- Step 2 (audio branch triggers ggml-alloc UAF): The ggml-alloc pattern at `ggml-alloc.c:893-894` is a **false positive** (confirmed in H-00.10 trace above). There is no actual UAF at this code site. The CHAIN-C hypothesis therefore has no exploitable UAF to chain into.
- What IS reachable: sending a RIFF/WAVE magic header via blank-MIME (`data:;base64,<RIFF magic + garbage>`) reaches the audio decode path. `decode_audio_from_buf` likely fails on garbage audio data and returns NULL/false → `mtmd_bitmap_init_from_audio` not called → `mtmd_helper_bitmap_init_from_buf` returns NULL → same NULL-deref as H-00.08.

CodeQL slice: DFD-6 (`reachable: false`).
On-demand query: none

**Assessment**: UNREACHABLE as an RCE chain (no UAF to chain into). The blank-MIME audio dispatch path is reachable and also terminates in the same NULL-deref as H-00.08/H-00.11. The RCE severity claim in CHAIN-C.1 is not supported by evidence. The finding reduces to the same HIGH DoS as H-00.08.

---

### [TRACER] Evidence for H-NEW-40 (sampler-state carryover) -- 2026-04-17T07:22:00Z

**Reachability: PARTIAL (requires confirmation of sampler singleton per-model vs per-request lifecycle)**

Code path to examine:
1. `runner/ollamarunner/runner.go:857-966` -- completion handler; new `Sequence` created per request via `NewSequence`
2. `runner/ollamarunner/runner.go:862-897` -- sampler created per request: `sampler := NewSampler(...)` → `C.llama_sampler_chain_init(...)`
3. `runner/ollamarunner/runner.go:227` -- `func NewSequence(...)` allocates a new sampler chain per sequence

Key finding: sampler is allocated **per sequence** (per request), not as a global singleton. `llama_sampler_chain_init` is called freshly at each `NewSequence`. The sampler is freed when the sequence completes at `s.removeSequence(seqIdx, reason)` → `seq.sampler.Free()`.

Sanitizers on path:
- Per-request sampler allocation: each `NewSequence` creates a fresh sampler with no state from prior requests
- `seq.sampler.Free()` at sequence removal: sampler state is destroyed after each use

CodeQL slice: none relevant.
On-demand query: none

**Assessment**: UNREACHABLE. The sampler is per-request, not per-model. `NewSequence` calls `NewSampler` which calls `C.llama_sampler_chain_init` for every new inference request. No sampler state persists between requests. H-NEW-40's precondition (per-model sampler singleton) does not hold in the current codebase.

---

### [TRACER] Evidence for H-NEW-42 (embedding-model vs chat-model confusion) -- 2026-04-17T07:24:00Z

**Reachability: PARTIAL (behavior diverges based on runner type; GoLLM-level check absent)**

Code path:
1. `server/routes.go:1714` -- `POST /api/embed` unauthenticated; calls `EmbedHandler`
2. `server/routes.go:885` -- `r, _, _, err := s.scheduleRunner(...)` — schedules runner for any model, no embedding-capability check enforced
3. `llm/server.go:1739-1750` -- `Embedding` call → runner `/embedding` endpoint
4. `runner/llamarunner/runner.go:752-810` -- embedding handler calls `s.lc.GetEmbeddingsSeq` or `s.lc.GetEmbeddingsIth`
5. `llama/llama.go:211-219` -- `GetEmbeddingsSeq` returns `unsafe.Slice((*float32)(e), c.Model().NEmbd())` where `e = C.llama_get_embeddings_seq(...)` 

For a chat (non-embedding) model:
- `C.llama_get_embeddings_seq` may return NULL (embedding pooling disabled for chat models) → `GetEmbeddingsSeq` returns `nil` → empty embedding in response
- OR: if pooling type is set to a non-NONE value on a chat model, non-nil pointer returned → float32 vector of hidden-state values from the final transformer layer

The `scheduleRunner` at `server/routes.go:885` does NOT check `model.Capability("embedding")`. A chat model can be passed to `/api/embed`.

Sanitizers on path:
- `C.llama_get_embeddings_seq` NULL return for non-embedding models: acts as a soft barrier; `GetEmbeddingsSeq` returns nil → empty response
- No hard check in Ollama preventing a chat model from being used with `/api/embed`

CodeQL slice: none.
On-demand query: none

**Assessment**: PARTIAL. `/api/embed` with a chat model is accepted at the HTTP level. The C function `llama_get_embeddings_seq` returns NULL for models without embedding pooling, producing an empty response. Whether the function returns non-NULL for a chat model depends on the model's configuration — if `llama.pooling_type` KV is set to `LLAMA_POOLING_TYPE_NONE`, embeddings are unavailable and NULL is returned. For models with non-zero pooling, hidden-state values are returned. This is a functional/behavioral issue rather than a clear security bypass — the content-moderation filter bypass scenario requires the model to actually return logit-correlated values, which depends on pooling configuration. MEDIUM severity; the concern is valid but depends on model-specific configuration.

---

### [TRACER] Evidence for H-NEW-48 (n_ctx oversize allocation) -- 2026-04-17T07:26:00Z

**Reachability: REACHABLE (DoS via OOM in runner process; exact path through ollamarunner confirmed)**

This hypothesis is a variant of H-42 above with focus on `num_ctx`. The trace is:

1. `server/routes.go:127-141` -- user supplies `options.num_ctx` in JSON body; no upper bound in `opts.FromMap`
2. `llm/server.go:167-170` -- `trainCtx = f.KV().ContextLength()` = 0 if GGUF has no `context_length` KV; guard NOT entered; `opts.NumCtx` uncapped
3. `llm/server.go:175` -- `KvSize: opts.NumCtx * numParallel` — e.g., `2^30 * 2 = 2^31`; `int32(2^31) = -2147483648`
4. `runner/ollamarunner/runner.go:1223` -- `NewInputCache(model, kvCacheType, int32(-2147483648), parallel, batchSize, ...)` → `numCtx = -2147483648 / numSlots` = negative → `int(numCtx) < batchSize` = true → `NewInputCache` returns error → `allocModel` returns error → server returns 500
5. Alternative path: `opts.NumCtx = 2^29`, `numParallel = 2` → `KvSize = 2^30`; `int32(2^30) = 1073741824` (within int32); `NewInputCache` proceeds; `s.batchSize = opts.NumBatch = 2^29`; `reserveWorstCaseGraph` → `make([]*input.Input, 2^29)` → ~4GB allocation → OOM panic (non-recoverable)

Sanitizers on path:
- `llm/server.go:167-170` -- `trainCtx > 0` guard: bypassable when GGUF has no `context_length` key
- `runner/ollamarunner/cache.go:37-38` -- negative-int32 check: effective for `KvSize > math.MaxInt32`; does NOT protect for `KvSize` within int32 range with large `BatchSize`
- `allocModel defer recover()`: catches only `ml.ErrNoMem`, not `runtime.makeslice` panics

CodeQL slice: `flow-paths-all-severities.md` `go/uncontrolled-allocation-size` at `runner/ollamarunner/runner.go:1079`, confirmed.
On-demand query: none

**Assessment**: REACHABLE for DoS. A user setting `num_ctx=2^29` and `num_batch=2^29` with a GGUF that has no `context_length` KV triggers `make([]*input.Input, 2^29)` → ~4GB allocation → OOM → runner subprocess crash → all active sessions dropped. The `defer recover()` in `allocModel` does not catch this panic. Severity: HIGH DoS — unauthenticated, cross-user impact (all active inference sessions dropped), requires only a crafted GGUF (no `context_length` KV) or an attacker who has already pulled any model with zero/absent context length.

---

## Round 2 Tracer Summary Table

| Hypothesis | Verdict | Key finding |
|-----------|---------|-------------|
| H-00.01 | REACHABLE | OOM DoS via `make([]float32, 2^62)` in non-F32 path; OOB read via `unsafe.Slice` in F32 path |
| H-00.02 | REACHABLE (bounded) | C heap leak per runner subprocess; bounded by subprocess isolation |
| H-00.07 | PARTIAL | `unsafe.Slice` within C-allocated buffer (C and Go use same n_embd); OOM with huge n_embd |
| H-00.08 | REACHABLE | NULL deref at `mtmd.cpp:552` via missing nil-check on `bm` at `llama/llama.go:570` |
| H-00.10 | UNREACHABLE (FP) | `sizeof(freed_ptr[0])` is compile-time; no runtime UAF |
| H-00.11 | REACHABLE | Blank-MIME → same NULL-deref as H-00.08; `llamarunner` path skips `image.Decode` guard |
| H-CHAIN-A.1 | PARTIAL | OOB read step REACHABLE; exfil step requires reversing quantization encoding |
| H-CHAIN-B.1 | UNREACHABLE | Race-loser runner fails cleanly; parent aborts; no confused deputy |
| H-CHAIN-C.1 | UNREACHABLE (FP) | UAF premise false; audio dispatch path still leads to H-00.08 NULL-deref only |
| H-NEW-40 | UNREACHABLE | Sampler is per-request, not per-model singleton |
| H-NEW-42 | PARTIAL | `/api/embed` with chat model: NULL return from C for most models; pooling-config-dependent |
| H-NEW-48 | REACHABLE | Same path as H-00.01/H-42 DoS; `num_ctx=2^29`+`num_batch=2^29` → OOM panic in runner |

---

## Round 3 -- Extended Tracing (tracer-03)

**Completed**: 2026-04-17T10:00:00Z

Covering remaining hypotheses: H-00.03, H-00.04, H-00.05, H-00.06, H-00.09, H-00.12, H-CHAIN-D.1, H-CHAIN-E.1, H-NEW-41, H-NEW-43, H-NEW-44, H-NEW-45, H-NEW-46, H-NEW-47, H-NEW-49.

CodeQL: unavailable for C-side paths (Go extractor only). Manual tracing used for all cgo sinks.

---

### [TRACER] Evidence for H-00.03 -- 2026-04-17T10:01:00Z

**Reachability: UNREACHABLE (no attacker-controlled path to mismatched lengths; caller builds slices in lock-step)**

Code path:
1. `sample/samplers.go:171-179` -- `NewGrammarSampler(tok, grammarStr)` is the only caller of `llama.NewGrammar`. It builds `vocabIds` and `pieces` as parallel slices both with length `len(tok.Vocabulary().Values)`. They iterate the same range `[0, len(tok.Vocabulary().Values))`.
2. `llama/llama.go:715-735` -- `NewGrammar(grammar, vocabIds, vocabValues, eogTokens)`: `cTokens = make([]C.uint32_t, len(vocabIds))`; `cPieces = make([]*C.char, len(vocabValues))`; these are allocated separately with their respective lengths.
3. `llama/llama.go:735` -- `C.grammar_init(cGrammar, unsafe.SliceData(cTokens), C.size_t(len(cTokens)), unsafe.SliceData(cPieces), ...)` — passes `len(cTokens)` as the size for BOTH cTokens and cPieces arrays to C. If `len(vocabIds) != len(vocabValues)`, C reads `len(vocabIds)` elements from the `cPieces` array which may be shorter → OOB read.

Attacker path to mismatch: None. The only caller `sample/samplers.go:172-176` builds both slices from the same range iterator. `vocabIds[i] = uint32(i)` and `pieces[i] = tok.Decode(...)` are populated in the same loop body. The slices will always have equal length.

The only way to reach a mismatch would be a future refactor that adds a second caller. No attacker controls `vocabIds` or `vocabValues` from HTTP input; these are derived from the model vocabulary loaded from GGUF, not from request parameters.

Sanitizers on path:
- `sample/samplers.go:172-176` -- lock-step slice construction from same range; **effectively enforces len(vocabIds) == len(vocabValues)** at the only call site
- No runtime assertion; the C contract violation would be invisible until a future caller breaks the invariant

CodeQL slice: none relevant.
On-demand query: none

**Assessment**: UNREACHABLE in the current codebase. The design-level contract violation (missing runtime len assertion) is real and represents latent technical debt. However, there is no current code path by which an attacker can cause a length mismatch. Severity: DEFENSE-IN-DEPTH recommendation only (add `if len(vocabIds) != len(vocabValues) { panic(...) }` guard in `NewGrammar`).

---

### [TRACER] Evidence for H-00.04 -- 2026-04-17T10:03:00Z

**Reachability: UNREACHABLE (ollamarunner path; Go stdlib image.Decode guards against empty/invalid input before any cgo call)**

Code path examined:
1. `runner/ollamarunner/runner.go:274` -- `EncodeMultimodal(llamaContext, data, format)` called without zero-length check at callsite
2. Per-model `EncodeMultimodal` implementations: `model/models/gemma3/model.go:106` calls `image.Decode(bytes.NewReader(multimodalData))` as the FIRST operation
3. `image.Decode` on empty `[]byte{}` returns `io.EOF` error → `EncodeMultimodal` returns error → no cgo called

For the llamarunner path (H-00.08 / H-00.11): zero-length is explicitly checked at `runner/llamarunner/image.go:64-66`. The non-empty arbitrary-bytes case is the vulnerability (H-00.08), not the zero-length case.

The Advocate's analysis at line 446-458 in the debate is confirmed: phantom validation — the guard is real but lives one layer down (in the callee's `image.Decode`) rather than at the callsite.

Sanitizers on path:
- `model/models/gemma3/model.go:106` -- `image.Decode` on empty reader: returns error, blocks cgo
- `model/models/gemma4/model.go:134` -- same pattern
- `model/models/gemma4/process_audio.go:30-32` -- `decodeWAV` checks `len(data) < 12`

CodeQL slice: none.
On-demand query: none

**Assessment**: UNREACHABLE for zero-length input (H-00.04 as stated). The protection is real via Go stdlib. Note: H-00.08 (non-empty invalid bytes) IS reachable in the llamarunner path. These are distinct hypotheses.

---

### [TRACER] Evidence for H-00.05 -- 2026-04-17T10:05:00Z

**Reachability: PARTIAL (path traversal defense relies on upstream validation; mlxrunner itself has no filepath.IsLocal check)**

Code path:
1. `x/imagegen/manifest/manifest.go:71-97` -- `resolveManifestPath(modelName)` uses `strings.Split(name, "/")` to decompose the model name into `host`, `namespace`, `name` components; no `filepath.IsLocal` check; no `..` rejection; final path built via `filepath.Join(DefaultManifestDir(), host, namespace, name, tag)`
2. `x/create/create.go:51-74` -- identical pattern in the create package's `resolveManifestPath`
3. `filepath.Join` normalizes `..` components; a model name like `../../etc/passwd` would have `name = "../../etc/passwd"` after splitting on `/` (len = 1, single component), so `host = "registry.ollama.ai"`, `namespace = "library"`, `name = "../../etc/passwd"` → path = `<manifestDir>/registry.ollama.ai/library/../../etc/passwd` = `<manifestDir>/etc/passwd`

However, the mlxrunner/imagegen path is reached via the parent daemon's model scheduling, which validates model names upstream via `model.ParseName` → `isValidPart`. The `isValidPart` function (confirmed in chamber-01 KB) rejects components containing `.` sequences.

Sanitizers on path:
- Upstream `isValidPart` in parent daemon: validates model name components before they reach mlxrunner; **effective when the model name comes through normal scheduling**
- `filepath.Join` normalization: normalizes but does NOT block traversal in the component itself (e.g., `../../etc/passwd` as a single name component)
- mlxrunner subprocess: receives the already-validated name from parent via IPC — if parent validates, traversal is blocked before reaching mlxrunner

CodeQL slice: none.
On-demand query: none

**Assessment**: PARTIAL. The defense-in-depth argument is valid: the primary validation happens upstream in `isValidPart`. The `resolveManifestPath` function itself lacks `filepath.IsLocal` / `filepath.Clean` + abs-path check, so if any caller bypasses the upstream validator, traversal is directly reachable. Current threat: a regression in `isValidPart` or a new direct caller of `resolveManifestPath` exposes traversal. Not currently exploitable through normal HTTP paths. Severity: MEDIUM (defense-in-depth hardening; track with chamber-01 H-00.07).

---

### [TRACER] Evidence for H-00.06 -- 2026-04-17T10:07:00Z

**Reachability: PARTIAL (LoraPath from IPC to cgo; reachable only if IPC is compromised; IPC is localhost-only)**

Code path:
1. Parent daemon builds `loadRequest.LoraPath = adapters` from `server/images.go:334-348` — adapter paths are registry blob paths (digest-named files in blobs dir); these are not directly attacker-controlled strings from HTTP
2. `llm/server.go:1203` -- parent sends `LoadRequest{..., LoraPath: req.LoraPath, ...}` to runner via HTTP POST to `127.0.0.1:<port>/load`
3. `runner/llamarunner/runner.go:934` -- `go s.loadModel(params, s.modelPath, req.LoraPath, ...)` — LoraPath passes through
4. `runner/llamarunner/runner.go:852-856` -- `for _, path := range lpath { s.model.ApplyLoraFromFile(s.lc, path, ...) }`
5. `llama/llama.go:344-351` -- `ApplyLoraFromFile` → `C.llama_adapter_lora_init(m.c, cLoraPath)` — arbitrary path passed to C

If the parent's adapter path construction is correct (blobs dir), `cLoraPath` is a legitimate GGUF blob path. Attacker control requires either:
- Compromised parent (already full compromise)
- IPC impersonation (H-00.12 TOCTOU chain)
- Malicious blob registered under a legitimate-looking digest (supply chain)

The `C.llama_adapter_lora_init` function at `llama.cpp/src/llama-adapter.cpp:417-430` calls `gguf_init_from_file(path_lora)` → full GGUF parsing on the provided file. Any file at `path_lora` is parsed as a GGUF. If path is `/etc/passwd`, GGUF magic check fails and the function returns nullptr (line 159-161: `if (!ctx_gguf) { ... return nullptr }`). C++ exception is caught. No RCE from path traversal alone — but it enables probing file existence via timing.

Sanitizers on path:
- `server/images.go:334-348` -- adapter paths derived from manifest blob digests; **attacker cannot inject arbitrary paths without first compromising registry or model store**
- `runner/llamarunner/runner.go:983` -- runner binds to `127.0.0.1` only; IPC not network-accessible
- `llama.cpp/src/llama-adapter.cpp:159-161` -- GGUF magic check; non-GGUF files return nullptr gracefully; no direct RCE from path traversal

CodeQL slice: none.
On-demand query: none

**Assessment**: PARTIAL. The LoraPath cgo call at `llama/llama.go:348` is reachable, but the path value is controlled by the parent daemon (not the HTTP attacker) and derives from registry blob digests. Standalone exploitation requires IPC impersonation (H-00.12). For a supply-chain attacker who registered a malicious LoRA GGUF, this is the REACHABLE path into `llama_adapter_lora_init` cgo parsing — which may have its own vulnerabilities. Severity: MEDIUM (requires chain with H-00.12 or supply-chain attack to be exploitable).

---

### [TRACER] Evidence for H-00.09 -- 2026-04-17T10:09:00Z

**Reachability: PARTIAL (int64 cast wraps to negative for very large offsets; results in io.ReadAt error, not silent OOB read)**

Code path:
1. `server/quantization.go:252` -- `offset: orig.Tensors().Offset + tensor.Offset` — both `uint64`; if `orig.Tensors().Offset` is craft-chosen near `MaxUint64/2` and `tensor.Offset` is also large, their sum overflows uint64 to a small value (wrap to 0 range). Alternatively, a single large `tensorOffset` where `uint64 > MaxInt64`.
2. `server/quantization.go:26` -- `sr := io.NewSectionReader(q, int64(q.offset), int64(q.from.Size()))` — if `q.offset` is uint64 value > `MaxInt64` (e.g., `1<<63`), then `int64(q.offset)` = `-2^63` (negative). `io.NewSectionReader` with a negative offset stores it as a negative int64.
3. When `sr.Read` is called, it calls `q.ReadAt(buf, int64(q.offset) + position)` — on `*os.File`, `ReadAt` with a negative offset returns `syscall.EINVAL`. Error propagates up.

For the uint64-overflow (wraparound) case:
- If `Tensors().Offset + tensor.Offset` wraps uint64 to a small value (e.g., 0), then `int64(0)` = 0, and the SectionReader reads from offset 0 of the file — the GGUF header. This is the actual "read from beginning of file" scenario.
- However: `fs/ggml/gguf.go:258-262` validates `tensorEnd := tensorOffset + tensor.Offset + tensor.Size() > fileSize`. If `tensor.Offset` is crafted to cause wraparound, `tensorEnd` also wraps and the check may pass. The offset used in quantizer is `orig.Tensors().Offset + tensor.Offset` — same potential for wrap.

Sanitizers on path:
- `fs/ggml/gguf.go:258-262` -- `tensorEnd > fileSize` check: **bypassable** if `tensorEnd` wraps to a value ≤ fileSize via uint64 overflow (attacker controls both `tensor.Offset` and `tensor.Size` fields)
- `io.ReadAt` error on negative int64 offset: converts potential OOB read into an error → quantization fails; no silent OOB

CodeQL slice: `flow-paths-all-severities.md` does not flag this specific path (the `int64(q.offset)` cast from uint64 offset sum).
On-demand query: none

**Assessment**: PARTIAL. Two sub-cases: (1) If `q.offset > MaxInt64`, `int64(q.offset)` is negative → `ReadAt` returns error → quantization fails with error returned to caller. No silent OOB read. (2) If `q.offset` wraps uint64 to a small value, `SectionReader` reads from wrong position in file. This could cause the quantizer to read tensor data from the wrong location in the GGUF file (e.g., from the KV metadata section instead of the tensor data section), producing corrupted quantized output. Not a memory-disclosure primitive outside the GGUF file itself. Severity: LOW — the wraparound case produces corrupt model output; the negative-int64 case errors cleanly.

---

### [TRACER] Evidence for H-00.12 -- 2026-04-17T10:11:00Z

**Reachability: UNREACHABLE in practice (TOCTOU exists but attacker-wins scenario does not produce confused deputy)**

See H-CHAIN-B.1 trace above for the complete code path analysis. Summary:

1. `llm/server.go:346-350` -- parent opens `net.ListenTCP("localhost:0")`, records port P, calls `l.Close()` — TOCTOU window begins
2. `llm/server.go:362-363` -- `params = append(params, "--port", strconv.Itoa(port))` — port P passed to runner argv
3. Runner's `net.Listen("tcp", "127.0.0.1:P")` at `runner/llamarunner/runner.go:983` — if attacker already bound port P, runner's Listen returns EADDRINUSE → runner exits
4. `llm/server.go:324-325` -- parent goroutine detects runner exit, closes `done` channel
5. Parent's `waitUntilRunnerLaunched` at line 1182 times out or returns error — parent does NOT proceed to issue IPC requests to the attacker-controlled socket

Analysis: When attacker wins race, runner fails to start and parent aborts cleanly. No confused-deputy state is reached because the parent verifies the runner's startup via `/health` poll at `getServerStatusRetry` (line 1329). If port is held by attacker's process, runner never starts and health check times out. The parent returns error to the `POST /api/generate` caller.

Sanitizers on path:
- `runner/llamarunner/runner.go:983-988` -- EADDRINUSE causes runner exit; **effective at preventing the confused deputy**
- `llm/server.go:1329` -- `getServerStatusRetry` health-check loop; attacker's server would need to respond to `/health` with correct status to fool it

CodeQL slice: none.
On-demand query: none

**Assessment**: UNREACHABLE in practice for the full confused-deputy scenario. The TOCTOU window is real, but the race outcome where attacker wins leads to runner startup failure, not impersonation. The attacker would need to correctly serve the runner's `/health` HTTP endpoint with the expected `{"status":"ok"}` response AND win the TOCTOU race. Even if the attacker's fake server fools the health check, the `/load` request contents would need to be correctly processed. Same-UID constraint applies throughout. The Advocate's verdict (disproved by same-user trust boundary) is confirmed.

---

### [TRACER] Evidence for H-CHAIN-D.1 -- 2026-04-17T10:13:00Z

**Reachability: UNREACHABLE (Go flag.FlagSet parses --model value as positional argument; no flag injection possible)**

Code path:
1. `llm/server.go:361-364` -- `params = append(params, "--model", modelPath, "--port", strconv.Itoa(port))` — argv built as separate elements, NOT concatenated into a shell string
2. `exec.Command(exe, params...)` at `llm/server.go:383` — passes argv as a Go string slice directly to `execvp`; no shell interpretation; each element is a separate argv entry
3. Runner's argv at startup: `["runner", "--model", "<modelPath>", "--port", "<port>"]`
4. `runner/runner.go:10-13` -- `args = args[1:]` after consuming "runner" prefix; if first remaining arg is `--ollama-engine`, routes to ollamarunner
5. `runner/llamarunner/runner.go:951-955` -- `fs := flag.NewFlagSet("runner", flag.ExitOnError); mpath := fs.String("model", "", ...); port := fs.Int("port", ...)`

Flag injection analysis: For `modelPath = "--lora=/etc/shadow"`:
- argv becomes: `["runner", "--model", "--lora=/etc/shadow", "--port", "12345"]`
- Go's `flag.FlagSet.Parse` processes `--model` → reads NEXT element as value → `mpath = "--lora=/etc/shadow"`
- `--port` is then parsed normally
- `--lora` does NOT appear as a separate argv flag because it was consumed as the VALUE of `--model`
- No flag injection occurs

The only scenario where injection could occur is if modelPath does not follow `--model <value>` but uses `--model=<value>` form AND modelPath itself contains `=<something>`. But `exec.Command` always passes `["--model", modelPath]` as TWO separate elements, never as `["--model=<modelPath>"]`.

For modelPath starting with `--` but NOT containing `=`: consumed as value of `--model`, no effect on other flags.

Sanitizers on path:
- `exec.Command` argv element separation: **effectively prevents flag injection** (no shell processing, each element is an isolated argv string)
- Go `flag.FlagSet` value-parsing: `--flag value` form means `value` is next argv element regardless of content

CodeQL slice: none.
On-demand query: none

**Assessment**: UNREACHABLE. The Ideator's hypothesis about Go's `exec.Command` being "not shell-quoted" is correct in that there is no shell quoting involved — but the consequence is the opposite of what the hypothesis claims: without shell processing, there is NO mechanism for a value passed as a separate argv element to be re-interpreted as additional flags. The `--model` flag unconditionally consumes the next argv element as its value. No flag injection is possible via modelPath.

---

### [TRACER] Evidence for H-CHAIN-E.1 -- 2026-04-17T10:15:00Z

**Reachability: PARTIAL (shape overflow to GPU backend is REACHABLE; uninitialized-page disclosure depends on GPU driver behavior outside Go/cgo code)**

Code path for shape overflow reaching GPU:
1. H-00.01 establishes that GGUF tensor `Shape = [2^31-1, 2]` passes `tensorEnd > fileSize` check (per-dim values are within uint64; product overflows to 0 on uint32 multiply or wraps on uint64 multiply; choice of `typeSize/blockSize` can make `Size()` small enough to pass the check)
2. `ml/backend/ggml/ggml.go:526` -- `sr := io.NewSectionReader(file, int64(b.meta.Tensors().Offset+t.Offset), int64(t.Size()))` — `t.Size()` wraps small; reads a small number of bytes from disk
3. `ml/backend/ggml/ggml.go:497-544` -- tensor loading path; for CUDA backend (`tts[0]._type != 39`), tensor data is sent to GPU via cgo

The GPU-specific claim in H-CHAIN-E.1:
- If `cudaMalloc(size)` is called with `size=0` (from `t.Size()=0` due to overflow), CUDA returns a valid non-NULL pointer per CUDA spec (small allocation). The tensor struct records dims as declared (2^31-1 × 2) but allocation is 0 bytes.
- When a kernel is launched on this tensor and reads/writes `(2^31-1) × 2 = 2^32-2` float32 elements, it reads from memory that was not allocated for this tensor → CUDA kernel reads device memory beyond the allocation.
- Whether this reads other tenants' data depends on CUDA driver behavior: on discrete GPUs, `cudaMalloc(0)` behavior is implementation-defined; some drivers return a sentinel pointer that reads zeroed pages; others return from a pre-allocated small pool.

The Go/cgo code itself cannot confirm or deny GPU driver behavior. This requires empirical testing.

Sanitizers on path:
- `fs/ggml/gguf.go:258-262` -- `tensorEnd > fileSize`: **bypassable** via shape overflow (product wraps to small `Size()`)
- `ml/backend/ggml/ggml.go:526` -- `int64(t.Size())` — wraps-to-small means SectionReader reads very few bytes; tensor data on GPU is fabricated from those few bytes tiled/truncated
- CUDA runtime: `cudaMalloc(0)` behavior is driver-specific; NOT a code-level sanitizer

CodeQL slice: none (CUDA backend not modeled by Go extractor).
On-demand query: none

**Assessment**: PARTIAL. The shape overflow reaching the GPU backend (step 1 of the chain) is REACHABLE via H-00.01's primitive. Whether GPU device memory from other tenants is disclosed depends on CUDA/Metal driver behavior for zero-size or small allocations. This requires hardware-level testing. The Go+cgo layer has no sanitizer that would prevent the malformed tensor from reaching the GPU backend. On dedicated single-GPU hosts (typical Ollama deployment), there are no other tenants to disclose from. The threat is relevant only on shared-GPU cloud hosts. Severity: HIGH theoretical on shared GPU; LOW on single-tenant deployment.

---

### [TRACER] Evidence for H-NEW-41 -- 2026-04-17T10:17:00Z

**Reachability: UNREACHABLE (KV cache lookup uses exact token-sequence match, not hash; no collision attack)**

Code path:
1. `runner/ollamarunner/cache.go:96-149` -- `LoadCacheSlot(prompt []*input.Input, ...)` iterates `slots` and calls `countCommonPrefix(slot.Inputs, prompt)`
2. `runner/ollamarunner/cache.go:229-245` -- `countCommonPrefix` compares `a[i].Token != b[i].Token || a[i].MultimodalHash != b[i].MultimodalHash` element-by-element; no hash-of-sequence, just direct integer token ID comparison
3. If attacker sends a prompt that exactly matches the token prefix of victim B's cached slot, the cache IS reused — but this requires sending the EXACT same token sequence, not exploiting a hash collision

The H-NEW-41 hypothesis posits "hash collision, or prefix-match-by-length rather than exact content". The implementation uses EXACT content comparison (`Token` is an int32 token ID; `MultimodalHash` is the image hash). No probabilistic data structure. No hash collision possible.

The "timing oracle" sub-hypothesis: a cached response is returned faster (no recompute) than an uncached one. An attacker who can measure response latency precisely could infer whether their prefix matches B's cached tokens. However, this requires B's session to have completed AND the attacker to know approximately what tokens to try — and any true match reveals only that two requests shared a common prefix, not the content beyond the prefix.

Sanitizers on path:
- Exact token-ID comparison: **prevents any collision-based attack**
- Cache slot `InUse` flag: prevents access to a slot currently being used by another session

CodeQL slice: none.
On-demand query: none

**Assessment**: UNREACHABLE as described (hash collision). The cache reuse on exact-prefix-match is intended behavior and is not a security boundary violation. A timing side-channel exists in theory (cache-hit latency vs. cache-miss latency), but requires the attacker to know the victim's exact token prefix to observe it, which is circular. The hypothesis's core premise (hash collision / prefix-match-by-length) is incorrect. Severity: NOT A FINDING (cache works as designed; timing side-channel is theoretical and requires knowing the content to exploit).

---

### [TRACER] Evidence for H-NEW-43 -- 2026-04-17T10:19:00Z

**Reachability: PARTIAL (cgo callback architecture exists; deadlock requires specific mutex ordering that was not confirmed)**

Code path:
1. `llama/llama.go:34-56` -- `SetLogCallback(fn func(level api.LogLevel, text string))` registers a Go function as the C-side log callback via `C.llama_log_set`. This Go function is exported via cgo.
2. When `C.llama_decode(...)` is executing in C and triggers a log message, the C code calls back into the registered Go function — while the cgo goroutine's OS thread is in a C call.
3. The Go log callback at `llama/llama.go:42-55` calls `slog.Log(...)` → standard library logging.
4. If `slog.Log` acquires a mutex that is also held by any goroutine currently waiting on a cgo call to return, a deadlock is possible.

Checking for mutex ordering:
- `slog` default handler uses an internal `sync.Mutex` for its output buffer. This mutex is NOT shared with any ollama runner mutex.
- The runner's own mutexes (e.g., `s.mu` in llamarunner) are held around HTTP handler processing, NOT around the raw `C.llama_decode` call.
- The cgo runtime restriction: a goroutine blocked in a C call holds its OS thread (M) but NOT any Go-side mutex. Other goroutines can run freely.

The H-NEW-43 deadlock requires: (a) goroutine A holds mutex X and is waiting for cgo call to return; (b) C callback fires and calls Go function that tries to acquire mutex X. In the current codebase, no runner mutex is held across a blocking cgo call and also acquired inside the log callback. The log callback acquires only `slog`'s internal mutex, which is not held by any runner HTTP handler.

Sanitizers on path:
- Runner mutex discipline: runner mutexes are released before or not held during `C.llama_decode`
- `slog` mutex is disjoint from runner mutexes; no cross-acquisition

CodeQL slice: none.
On-demand query: none

**Assessment**: PARTIAL — the cgo-callback architecture creates a potential for deadlock if mutex discipline is violated in a future refactor, but current code does not exhibit the circular wait. The log callback (`slog.Log`) acquires only `slog`'s internal lock, which is not held by any concurrent goroutine calling into C. No confirmed deadlock path in current codebase. Severity: DEFENSE-IN-DEPTH note (document mutex discipline; add comment that log callback must not acquire runner locks).

---

### [TRACER] Evidence for H-NEW-44 -- 2026-04-17T10:21:00Z

**Reachability: REACHABLE (DoS via panic from negative-length allocation; integer cast truncation confirmed)**

Code path:
1. `POST /api/create` with crafted GGUF having a KV string entry with `uint64 length = 2^63 + 1` (larger than MaxInt64)
2. `fs/ggml/gguf.go:354-359` -- `buf = llm.scratch[:8]; io.ReadFull(r, buf); length := int(llm.ByteOrder.Uint64(buf))` — `Uint64(buf) = 2^63+1`; `int(2^63+1)` on amd64 = `-2^63+1` = `-9223372036854775807` (negative due to int64 sign bit)
3. `fs/ggml/gguf.go:360-361` -- `if length > len(llm.scratch) { buf = make([]byte, length) }` — `length` is negative; negative is NOT `> len(scratch)` (scratch is 16384); so the `if` branch is NOT taken
4. `fs/ggml/gguf.go:362-363` -- `buf = llm.scratch[:length]` — `llm.scratch[:negative_length]` panics with `runtime error: slice bounds out of range`
5. Panic propagates up through GGUF parse, unrecovered → server returns 500 OR crashes subprocess depending on where catch is

Wait — let me re-check. `length` is negative. `llm.scratch[:length]` where `length < 0` causes a slice bounds panic immediately at line 363.

However, this panic occurs in the GGUF parser during model loading. In the server context, `LoadModel` is called and errors are returned: `fs/ggml/gguf.go` returns an error on panic? Actually Go does NOT catch panics in sub-functions unless there's a `recover()` in the call stack. Let me trace more carefully.

`server/create.go` calls the GGUF parse path. Does `create.go` have a recover? No — panics from GGUF parsing would crash the HTTP handler goroutine. For the `/api/create` endpoint, a panic in the goroutine serving that request would cause `net/http` to recover it (Go's HTTP server has a default panic recovery that returns 500). The panic does NOT crash `ollama serve` itself.

So the consequence is: `POST /api/create` with crafted GGUF → GGUF parser panics → gin recovers → 500 Internal Server Error. Not a server crash.

Alternative path where the string length is `2^63 - 1` (MaxInt64): `length = MaxInt64 = 9223372036854775807 > 16384 = len(scratch)` → `buf = make([]byte, 9223372036854775807)` → `makeslice: len out of range` panic → gin recovers → 500.

Sanitizers on path:
- `if length > len(llm.scratch)` -- check intended to allocate larger buffer; **does not check for negative length**
- Go runtime: `makeslice` bounds check catches huge positive lengths; slice-bounds check catches negative lengths
- gin panic recovery: HTTP server recovers panic → 500 response; process does NOT crash

CodeQL slice: `go/allocation-size-overflow` did NOT flag this specific cast (uint64→int). Flow paths in `flow-paths-all-severities.md` cover different allocation sites.
On-demand query: none

**Assessment**: REACHABLE for DoS. A GGUF with a KV string entry having `uint64 length > MaxInt64` causes a panic in the GGUF parser. The panic is recovered by gin's HTTP middleware and returns a 500 error. However, any in-progress work (partial model state) may be leaked. More importantly, this confirms that the `int(uint64_val)` cast at `fs/ggml/gguf.go:359` is vulnerable to negative-wrap for values > MaxInt64. The downstream `llm.scratch[:length]` panics on negative length. The DoS is request-scoped (500 error), not process-level. Severity: LOW DoS (500 per request); MEDIUM if similar patterns exist in hot paths not protected by gin recovery.

---

### [TRACER] Evidence for H-NEW-45 -- 2026-04-17T10:23:00Z

**Reachability: PARTIAL (LoRA stacking path exists; C heap leak per adapter; cap on adapter count not confirmed)**

Code path:
1. `runner/llamarunner/runner.go:852-856` -- `for _, path := range lpath { s.model.ApplyLoraFromFile(s.lc, path, 1.0, threads) }` — iterates ALL paths in `req.LoraPath` slice
2. `llama/llama.go:344-356` -- `ApplyLoraFromFile`: `cLoraPath := C.CString(loraPath); defer C.free(unsafe.Pointer(cLoraPath))` — CString is freed via defer; NO CString leak here (unlike `H-00.02`'s `LoadModelFromFile`)
3. `C.llama_adapter_lora_init(m.c, cLoraPath)` -- C parses the LoRA file; adapter is allocated on C heap; `C.llama_set_adapter_lora` applies it

Wait — `defer C.free(unsafe.Pointer(cLoraPath))` at line 346 DOES free the CString. So the H-00.02-class leak does NOT apply to `ApplyLoraFromFile`. The CString leak mentioned in H-NEW-45 is incorrect.

What DOES accumulate: `C.llama_adapter_lora_init` allocates a `llama_adapter_lora` struct on the C heap. `llama_set_adapter_lora` registers it with the context. The adapter is NOT freed after `ApplyLoraFromFile` returns (no `defer C.llama_adapter_lora_free`). So each call to `ApplyLoraFromFile` leaks a `llama_adapter_lora` struct.

Cap on adapter count: The `LoraPath` slice comes from `server/images.go:334-348` which derives from manifest adapter layers. The number of adapter layers is bounded by the manifest structure (which is attacker-controllable if the attacker can create a model with many adapter entries). However, the runner's `/load` endpoint is called by the parent daemon only, and the parent builds `LoraPath` from the model's manifest.

The critical question: can an attacker cause 10,000 adapter paths to be sent? Only if they create a manifest with 10,000 adapter layer entries. This requires `POST /api/create` with a Modelfile that references 10,000 adapter blobs. Each blob upload is via `POST /api/blobs/:digest`. This is feasible for a local attacker with HTTP access.

Sanitizers on path:
- `defer C.free(unsafe.Pointer(cLoraPath))` -- frees the CString; **NOT a source of C heap leak**
- Missing `defer C.llama_adapter_lora_free(loraAdapter)` after `llama_adapter_lora_init` -- **real leak of adapter struct** per call
- No cap on `len(req.LoraPath)` in runner or parent daemon

CodeQL slice: none.
On-demand query: none

**Assessment**: PARTIAL. The CString leak claimed in H-NEW-45 is INCORRECT (CString is freed via defer). However, there IS a real leak of the `llama_adapter_lora` C struct per `ApplyLoraFromFile` call (no free after `llama_adapter_lora_init`). With a crafted manifest having many adapter layers, each model load leaks one `llama_adapter_lora` struct per adapter. This is bounded per subprocess by subprocess lifetime. For amplification DoS, the attacker would need repeated model loads with many adapters — constrained by the scheduler's runner limits. Severity: LOW (bounded leak per subprocess; requires crafted manifest with many adapters).

---

### [TRACER] Evidence for H-NEW-46 -- 2026-04-17T10:25:00Z

**Reachability: PARTIAL (audio data reaches multimodal tokenization path; integer overflow in mel-compute not confirmed at code level)**

Code path:
1. `POST /v1/audio/transcriptions` → `middleware/openai.go:724-788` — `TranscriptionMiddleware` reads audio file (up to 25MB limit at line 729), calls `FromTranscriptionRequest`
2. `openai/openai.go:857-877` -- `FromTranscriptionRequest` wraps `r.AudioData` as `Images: []api.ImageData{r.AudioData}` in a chat request
3. Chat request reaches `server/routes.go:2417` -- `r.Completion(ctx, llm.CompletionRequest{..., Images: req.Images, ...})`
4. For llamarunner: `runner/llamarunner/runner.go:236` -- `c.mtmd.MultimodalTokenize(s.lc, images[imageIndex].Data)` — audio bytes passed directly to mtmd
5. `llama/llama.go:566` -- `C.mtmd_helper_bitmap_init_from_buf(c.c, data_ptr, C.size_t(len(data)))` — audio bytes passed
6. `llama/llama.cpp/tools/mtmd/mtmd-helper.cpp:471` -- `audio_helpers::is_audio_file(buf, len)` — for WAV/RIFF header, enters audio branch
7. `audio_helpers::decode_audio_from_buf(buf, len)` → audio decode → mel-spectrogram computation

For H-NEW-46's specific overflow claim (`sample_count = int(file_size / 4)` → integer overflow in mel computation):
- The `is_audio_file` check at line 471 requires valid RIFF/WAVE magic bytes
- The 25MB middleware cap limits audio size to 25MB = 26,214,400 bytes; `sample_count = 25MB / 4 = 6,553,600` 16-bit samples; `n_mels = 80`; `6553600 * 80 = 524,288,000` — within int32 range (MaxInt32 = 2,147,483,647). No overflow at 25MB.
- Without the 25MB cap (e.g., if audio comes via a direct /api/generate route), maximum body size is constrained by available memory

Sanitizers on path:
- `middleware/openai.go:729` -- `ParseMultipartForm(25 << 20)` -- 25MB multipart form limit; **constrains sample_count to ~6.5M**; no int32 overflow at this size
- `is_audio_file` check: limits audio path to valid RIFF/WAV input only
- H-00.08 NULL-deref path: for a non-audio payload, falls through to `stbi_load_from_memory` → NULL → H-00.08 NULL-deref

CodeQL slice: none (mtmd audio path not modeled).
On-demand query: none

**Assessment**: PARTIAL. The audio data does reach the mtmd audio decode path via `/v1/audio/transcriptions`. The integer overflow in mel-compute is constrained by the 25MB multipart limit to a safe range (~6.5M samples; no int32 overflow). However, for audio sent via `/api/generate` directly (no 25MB limit), larger payloads could potentially trigger deeper mtmd audio processing with larger sample counts. The exact C code for mel-spectrogram in the vendored mtmd (whisper-style) was not traced to confirm overflow at line-level. Severity: MEDIUM (needs vendored C trace for mel-compute overflow; 25MB cap mitigates the `/v1/audio/transcriptions` path; direct `/api/generate` audio path lacks size limit).

---

### [TRACER] Evidence for H-NEW-47 -- 2026-04-17T10:27:00Z

**Reachability: UNREACHABLE (Go tokenize path passes byte length; C tokenize validates return value; invalid UTF-8 handled by replacement character)**

Code path:
1. `server/routes.go` prompt → `llm/server.go:Completion` → runner `/completion` endpoint
2. `runner/llamarunner/runner.go` → `s.model.Tokenize(prompt, addSpecial, parseSpecial)`
3. `llama/llama.go:481-513` -- `Tokenize`:
   - `maxTokens := len(text) + 2` — `len(text)` is BYTE count (Go semantics)
   - `C.int32_t(len(text))` passed as `text_len` parameter to `C.llama_tokenize`
   - `C.int32_t(maxTokens)` = `len(text) + 2` as the output buffer size
4. `llama.cpp/src/llama-vocab.cpp:3792` -- `llama_tokenize(vocab, text, text_len, tokens, n_tokens_max, ...)` — C function receives byte-length `text_len`; operates on bytes, not code points
5. `llama/llama.go:498-512` -- if `result < 0` (buffer too small), reallocates and retries with `int(-result)` as the new `maxTokens`

The H-NEW-47 hypothesis about normalization expanding byte count:
- `llama.cpp/src/unicode.cpp:898-907` -- invalid UTF-8 bytes are replaced with U+FFFD (replacement character, 3 bytes in UTF-8); a lone surrogate `\xED\xA0\x80` (3 bytes input) normalizes to U+FFFD (3 bytes output) — same byte count
- NFC normalization of ASCII and common characters does NOT expand byte count
- The `result < 0` handling: if C returns a negative value indicating buffer overflow, Go retries with the correct size. This is a correct dynamic resizing pattern, not a vulnerability.
- C `text_len` is the INPUT byte count; the OUTPUT buffer (`n_tokens_max`) is allocated for `len(text) + 2` tokens. The number of output tokens is always ≤ input bytes (tokenization merges; never expands). A 100-byte input produces at most 100+2 output tokens.

The hypothesis's concern about "C code writes normalized output back into a buffer sized by Go's `len(s)`" does not match the actual implementation: the output buffer is for TOKENS (int32), not for the input text. Token count cannot exceed input byte count.

Sanitizers on path:
- `result < 0` → resize-and-retry pattern: **correctly handles any tokenization overflow**
- Unicode replacement character normalization: byte count cannot increase from lone surrogate substitution (3 bytes → 3 bytes)
- `C.int32_t(len(text))` for `text_len`: passes byte count which is what the C function expects

CodeQL slice: none.
On-demand query: none

**Assessment**: UNREACHABLE. The hypothesis's premise (normalization expanding byte count past output buffer) does not match the implementation. The output buffer holds token IDs, not normalized text bytes. The `result < 0` resize pattern correctly handles any output overflow. Unicode handling replaces invalid sequences with U+FFFD at equal or smaller byte count. No tokenizer buffer overflow is reachable via Unicode crafting.

---

### [TRACER] Evidence for H-NEW-49 -- 2026-04-17T10:29:00Z

**Reachability: PARTIAL (runner crash during streaming IS detectable by error in NDJSON stream; hypothesis's "invisible error" claim is INCORRECT; but truncation IS detectable by client behavior)**

Code path:
1. `llm/server.go:1619-1626` -- `http.DefaultClient.Do(serverReq)` → HTTP connection to runner subprocess; if runner crashes mid-stream, connection EOF detected
2. `llm/server.go:1694-1707` -- `scanner.Err()` after scan loop ends: `if strings.Contains(err.Error(), "unexpected EOF") || strings.Contains(err.Error(), "forcibly closed") { s.Close(); return fmt.Errorf("an error was encountered...") }` — returns an error to caller
3. `server/routes.go:622-628` -- `Completion` error is caught: `if err != nil { var serr api.StatusError; if errors.As(err, &serr) { ch <- gin.H{"error": ..., "status": ...} } else { ch <- gin.H{"error": err.Error()} } }`
4. `server/routes.go:1899-1928` -- `streamResponse`: if `c.Writer.Written()` is true (some chunks already sent with 200 OK), error is encoded as `{"error": "..."}` inline in the NDJSON stream at line 1922

So the actual behavior: the error IS emitted as a JSON line `{"error": "an error was encountered while running the model: unexpected EOF"}` in the NDJSON stream. It is NOT silently emitted as `{"done": true, "done_reason": "stop"}`.

HOWEVER — the truncation scenario still has a validity concern:
- The last partial NDJSON chunk before EOF may NOT be terminated with newline — `scanner.Scan()` returns false on EOF without calling the error path if the scanner exhausted normally. Actually: if the runner crashes mid-token, the HTTP body truncates mid-chunk. `scanner.Scan()` would return false (EOF), loop exits, and then `scanner.Err()` is `nil` (clean EOF from scanner's perspective) or `io.ErrUnexpectedEOF`.
- If `scanner.Err() == nil` (clean EOF from scanner), the loop exits normally and `Completion` returns `nil`. The parent then returns no more chunks to the channel, and `streamResponse` sees channel close → `c.Stream` returns false → response ends. The client sees a clean NDJSON stream that ends WITHOUT a final `{"done": true}` chunk.
- A client that does not receive `done: true` may interpret this as "stream ended unexpectedly" — but this is distinct from being deceived by a false `done_reason: stop`.

The hypothesis's claim that the server sends `{"done":true,"done_reason":"stop"}` is INCORRECT. The server emits an error message in the stream.

Sanitizers on path:
- `server/routes.go:1922` -- `json.NewEncoder(c.Writer).Encode(gin.H{"error": e})` — error IS sent in stream body; **clients CAN detect it** if they parse all NDJSON lines
- `if !c.Writer.Written()` check: for early errors (before any chunks), proper HTTP 500 is returned

CodeQL slice: none.
On-demand query: none

**Assessment**: PARTIAL. The specific claim in H-NEW-49 that the server silently sends `done_reason: stop` instead of an error is INCORRECT. The server correctly emits an error JSON line in the NDJSON stream. However, the correctness failure IS real in a different form: (1) streaming clients that don't parse all NDJSON lines may not see the final error; (2) the HTTP status code is already 200 and cannot be changed; (3) if `scanner.Err()` is nil despite truncation (clean EOF from scanner), `Completion` returns nil and the parent treats the stream as complete without emitting an error object. This third scenario — where scanner sees clean EOF due to runner crash timing — means some runner crashes ARE silently treated as normal completion by the parent. The severity is MEDIUM for observability/reliability, not HIGH for security.

---

## Round 3 Extended Tracing Summary

| Hypothesis | Verdict | Key finding |
|-----------|---------|-------------|
| H-00.03 | UNREACHABLE | No attacker-controlled path to mismatch vocabIds/vocabValues lengths; single caller builds lock-step |
| H-00.04 | UNREACHABLE | `image.Decode` guard in each `EncodeMultimodal` implementation blocks cgo before empty-data reaches it |
| H-00.05 | PARTIAL | `resolveManifestPath` lacks `filepath.IsLocal`; upstream `isValidPart` is the primary defense |
| H-00.06 | PARTIAL | `llama_adapter_lora_init` cgo reachable; path controlled by parent daemon (blobs); requires IPC chain |
| H-00.09 | PARTIAL | `int64(uint64_offset)` wraps to negative → `ReadAt` error; or uint64 wraparound reads wrong file offset |
| H-00.12 | UNREACHABLE | Runner fails to start (EADDRINUSE) when attacker wins race; no confused deputy achieved |
| H-CHAIN-D.1 | UNREACHABLE | Go `flag.FlagSet` consumes modelPath as value of `--model`; no flag injection possible |
| H-CHAIN-E.1 | PARTIAL | Shape overflow reaches GPU backend (REACHABLE); uninitialized GPU page disclosure is driver-specific |
| H-NEW-41 | UNREACHABLE | Cache uses exact token-ID comparison; no hash collision; timing side-channel exists but not exploitable |
| H-NEW-43 | PARTIAL | cgo log callback architecture allows deadlock if mutex discipline violated; current code is safe |
| H-NEW-44 | REACHABLE | `int(uint64_len)` at `fs/ggml/gguf.go:359` wraps negative → `scratch[:negative]` panic → gin recovers 500 |
| H-NEW-45 | PARTIAL | `llama_adapter_lora` struct leak per adapter (no free); CString is correctly freed; bounded per subprocess |
| H-NEW-46 | PARTIAL | Audio path reaches mtmd; 25MB multipart cap prevents mel-compute overflow; direct `/api/generate` lacks cap |
| H-NEW-47 | UNREACHABLE | Output buffer is for tokens not text bytes; `result < 0` resize handles any overflow; no injection via Unicode |
| H-NEW-49 | PARTIAL | Error IS emitted in NDJSON stream; but clean-EOF scenario (scanner.Err()==nil) can silently truncate |

---

## Round 4 -- Synthesis

**Synthesizer (chamber-synthesizer-03)**: 2026-04-17T15:30:00Z

All hypotheses have traversed the prosecution (Tracer) and defense (Advocate) rounds. Verdicts follow, then the chamber closes with a summary table.

---

### [SYNTHESIZER] Verdict for H-00.01 -- 2026-04-17T15:30:00Z

**Prosecution summary**: Tracer Round 2 confirmed REACHABLE for (a) OOM DoS via `make([]float32, 2^62)` in non-F32 branch, (b) OOB read via `unsafe.Slice` + `Quantize` iteration in F32 branch at `server/quantization.go:43`. Primary root cause is unchecked uint64 multiply in `fs/ggml/ggml.go:505-514`.

**Defense summary**: Advocate Round 1 acknowledged the guard at `fs/ggml/gguf.go:258-262` is bypassable through typeSize/blockSize division and conceded "the defense is weak... cannot disprove it." The `make` ceiling argument degrades one branch to DoS but the F32 `unsafe.Slice` branch has no allocation.

**Pre-FP Gate**: all checks passed.

**Verdict: DUPLICATE** of chamber-02 p8-020 `gguf-shape-uint64-overflow-oob` (the root `Elements()/Size()` overflow is already logged under AP-020). However, the F32-branch quantize sink described by the tracer is a distinct secondary sink reaching Go heap (not mmap'd tensor); that is logged separately as p8-043 to capture the chamber-03 specific escalation.

**Finding draft written to**: (root cause) chamber-02 p8-020; (chamber-03 escalation of the same primitive) `archon/findings-draft/p8-043-quantize-unsafe-slice-elements-oob.md`
**Registry updated**: AP-020 (existing) + AP-044 new.

---

### [SYNTHESIZER] Verdict for H-00.02 -- 2026-04-17T15:31:00Z

**Prosecution summary**: Tracer REACHABLE (bounded) — real CString leak per runner-subprocess launch, missing `defer C.free`.

**Defense summary**: Advocate: bounded by subprocess lifetime + single-load guard; standalone not exploitable.

**Pre-FP Gate**: all checks passed; flagged `check-3-bounded`.

**Verdict: VALID** at MEDIUM — correctness hygiene finding; one-line fix; future-fragile.

**Finding draft written to**: `archon/findings-draft/p8-049-cstring-leak-load-model-from-file.md`
**Registry updated**: AP-049 new.

---

### [SYNTHESIZER] Verdict for H-00.03 -- 2026-04-17T15:32:00Z

**Prosecution summary**: Tracer UNREACHABLE — single caller builds vocabIds/vocabValues in lock-step; no attacker path.

**Defense summary**: Advocate: disproved by Application-layer by-construction invariant.

**Verdict: DROP**. Latent technical debt only; filed as a defense-in-depth recommendation in the knowledge base, not as a finding.

---

### [SYNTHESIZER] Verdict for H-00.04 -- 2026-04-17T15:33:00Z

**Prosecution summary**: Tracer UNREACHABLE — `image.Decode` in every `EncodeMultimodal` blocks empty input before cgo.

**Defense summary**: Advocate: phantom-at-callsite / real-at-callee validation; Go stdlib `image.Decode` is the guard.

**Verdict: FALSE POSITIVE**. The callsite at `ollamarunner/runner.go:274` lacks an explicit check but is guarded one layer down in all known vision model implementations. Note: the non-empty-arbitrary-bytes case is a distinct hypothesis (H-00.08) that IS valid.

---

### [SYNTHESIZER] Verdict for H-00.05 -- 2026-04-17T15:34:00Z

**Prosecution summary**: Tracer PARTIAL — `resolveManifestPath` lacks `filepath.IsLocal`; currently protected by upstream `isValidPart`.

**Defense summary**: Advocate: "cannot disprove as individual code-hygiene finding"; duplicate-class with chamber-01 AP-001R.

**Pre-FP Gate**: passed; flagged `check-2-duplicate-class`.

**Verdict: VALID** at MEDIUM (defense-in-depth).

**Finding draft written to**: `archon/findings-draft/p8-047-mlxrunner-manifest-path-traversal-defense-in-depth.md`
**Registry updated**: AP-047 new (distinct from AP-001R which covers blob-path traversal).

---

### [SYNTHESIZER] Verdict for H-00.06 -- 2026-04-17T15:35:00Z

**Prosecution summary**: Tracer PARTIAL — LoRA path cgo reachable; attacker control via supply chain.

**Defense summary**: Advocate: disproved in isolation; chain-only via H-00.12 (also unreachable). BUT supply-chain vector survives.

**Verdict: VALID** at MEDIUM — supply-chain attack surface on a distinct cgo parser (`llama_adapter_lora_init`) not covered by main-model parser hardening.

**Finding draft written to**: `archon/findings-draft/p8-048-lora-path-ipc-to-cgo-passthrough.md`
**Registry updated**: AP-048 new.

---

### [SYNTHESIZER] Verdict for H-00.07 -- 2026-04-17T15:36:00Z

**Prosecution summary**: Tracer PARTIAL — `unsafe.Slice` within C-allocated buffer for matched n_embd; OOM DoS with crafted huge n_embd.

**Defense summary**: Advocate: disproved as disclosure primitive (C and Go share n_embd source); accepted as DoS.

**Pre-FP Gate**: passed; flagged `check-2-partial`.

**Verdict: VALID** at MEDIUM — DoS only; disclosure claim disproved.

**Finding draft written to**: `archon/findings-draft/p8-046-embeddings-seq-unsafe-slice-nembd.md`
**Registry updated**: AP-046 new.

---

### [SYNTHESIZER] Verdict for H-00.08 -- 2026-04-17T15:37:00Z

**Prosecution summary**: Tracer REACHABLE — confirmed NULL-deref at `llama.cpp:mtmd.cpp:552` via missing nil-check on `bm` at `llama/llama.go:570`. Zero-length guard does not protect against non-empty invalid bytes.

**Defense summary**: Advocate: "no upper bound framing is accurate"; cannot disprove without version-pinned mtmd CVE audit. Synth note: the concrete finding is NULL-deref, not CVE-class size_t overflow.

**Pre-FP Gate**: all checks passed.

**Verdict: VALID** at HIGH — unauthenticated DoS on any multimodal deployment.

**Finding draft written to**: `archon/findings-draft/p8-040-mtmd-null-deref-image-bitmap.md`
**Registry updated**: AP-042 new.

---

### [SYNTHESIZER] Verdict for H-00.09 -- 2026-04-17T15:38:00Z

**Prosecution summary**: Tracer PARTIAL — `int64(uint64_offset)` wraps negative → `ReadAt` error; or uint64 wrap reads wrong file offset; produces corrupt model output, not silent OOB.

**Defense summary**: Advocate: cannot disprove completely; downstream error checks convert to DoS.

**Verdict: DROP** — tracer confirmed the impact is bounded to "reads from wrong position in the same GGUF file" (corrupt model) and error-path on negative int64. Below MEDIUM threshold; severity is LOW. Mark for defense-in-depth hardening in the same fix as p8-020/p8-043 root cause.

---

### [SYNTHESIZER] Verdict for H-00.10 -- 2026-04-17T15:39:00Z

**Prosecution summary**: Tracer UNREACHABLE — `sizeof(freed_ptr[0])` is compile-time; Semgrep SAST-UAF-01 is a false positive on the specific code site.

**Defense summary**: Advocate: contested the RCE severity framing; even if UAF existed it would be DoS-class on subprocess.

**Verdict: FALSE POSITIVE** for the specific SAST-UAF-01 location. The tracer's Round 2 analysis is dispositive: `sizeof` does not dereference. No chamber-03 finding draft.

Note: this disposition conflicts with the orchestrator's pre-seed severity hint (HIGH DoS). The synth honors the tracer's line-level disproof because the evidence is concrete (C semantics of `sizeof`). If a real UAF exists elsewhere in ggml-alloc, a separate Semgrep/ASAN pass is required — out of scope for this chamber.

---

### [SYNTHESIZER] Verdict for H-00.11 -- 2026-04-17T15:40:00Z

**Prosecution summary**: Tracer REACHABLE — blank-MIME reaches same NULL-deref as H-00.08; the `llamarunner` path skips `image.Decode` guard that the advocate cited.

**Defense summary**: Advocate: "red herring; `image.Decode` is the real boundary; blank-MIME is intentional." Synth disposition: advocate's `image.Decode` guard does NOT apply to the llamarunner path per tracer.

**Pre-FP Gate**: all checks passed.

**Verdict: VALID** at HIGH — disputed by advocate, but tracer evidence is dispositive. Complementary half of p8-040.

**Finding draft written to**: `archon/findings-draft/p8-041-blank-mime-mtmd-null-deref.md`
**Registry updated**: AP-042 confirmed-instances extended; cross-ref chamber-02 AP-032.

---

### [SYNTHESIZER] Verdict for H-00.12 -- 2026-04-17T15:41:00Z

**Prosecution summary**: Tracer UNREACHABLE — EADDRINUSE causes runner startup failure; no confused deputy.

**Defense summary**: Advocate: disproved by same-user trust boundary.

**Verdict: DROP** — TOCTOU exists but lands below the threat-model floor. Defense-in-depth note only.

---

### [SYNTHESIZER] Verdict for H-CHAIN-A.1 -- 2026-04-17T15:42:00Z

**Prosecution summary**: Tracer PARTIAL — step 1 (OOB read) REACHABLE; step 2 (exfil) blocked by quantization encoding acting as scrambler.

**Defense summary**: Advocate: chain produces memory disclosure only for attackers with known heap layout and reverse-engineered quantization — speculative but not disprovable.

**Verdict: VALID** at HIGH for step 1 (OOB read primitive); step 2 is theoretical and does not add severity.

**Finding draft written to**: `archon/findings-draft/p8-043-quantize-unsafe-slice-elements-oob.md` (captures the OOB read step; exfil-via-embed chain is documented as theoretical in the Impact section).
**Registry updated**: AP-044 new.

---

### [SYNTHESIZER] Verdict for H-CHAIN-B.1 -- 2026-04-17T15:43:00Z

**Prosecution summary**: Tracer UNREACHABLE — race-loser runner fails cleanly.

**Defense summary**: Advocate: same-user threat boundary.

**Verdict: DROP**.

---

### [SYNTHESIZER] Verdict for H-CHAIN-C.1 -- 2026-04-17T15:44:00Z

**Prosecution summary**: Tracer UNREACHABLE as RCE — ggml-alloc UAF is FP; audio dispatch leads to same NULL-deref as H-00.08.

**Defense summary**: Advocate contested RCE severity; agreed with FP finding.

**Verdict: DROP** — the chain collapses to H-00.08/H-00.11 which are already VALID.

---

### [SYNTHESIZER] Verdict for H-CHAIN-D.1 -- 2026-04-17T15:45:00Z

**Prosecution summary**: Tracer UNREACHABLE — Go `flag.FlagSet` consumes modelPath as value of `--model`; no flag injection.

**Verdict: DROP**.

---

### [SYNTHESIZER] Verdict for H-CHAIN-E.1 -- 2026-04-17T15:46:00Z

**Prosecution summary**: Tracer PARTIAL — shape overflow reaches GPU backend; cross-tenant disclosure is driver-specific.

**Defense summary**: None filed; advocate did not brief the novel hypothesis.

**Pre-FP Gate**: passed; flagged `check-2-ambiguous` (GPU driver behavior not verified at code level).

**Verdict: VALID** at HIGH on shared-GPU deployments; severity MEDIUM on single-tenant.

**Finding draft written to**: `archon/findings-draft/p8-044-gpu-backend-shape-overflow-disclosure.md`
**Registry updated**: AP-045 new.

---

### [SYNTHESIZER] Verdict for H-NEW-40 (sampler-state carryover) -- 2026-04-17T15:47:00Z

**Prosecution summary**: Tracer UNREACHABLE — sampler is per-request, not per-model.

**Verdict: DROP**.

---

### [SYNTHESIZER] Verdict for H-NEW-41 (KV-cache reuse) -- 2026-04-17T15:48:00Z

**Prosecution summary**: Tracer UNREACHABLE — exact token-ID compare; no hash collision.

**Verdict: DROP**.

---

### [SYNTHESIZER] Verdict for H-NEW-42 (embedding/chat model confusion) -- 2026-04-17T15:49:00Z

**Prosecution summary**: Tracer PARTIAL — `/api/embed` accepts chat model; C returns NULL for most non-embedding models; hidden-state disclosure is pooling-config-dependent.

**Defense summary**: None formal (novel).

**Verdict: MERGED** into p8-046 — the underlying `GetEmbeddingsSeq` / `unsafe.Slice` concerns are covered there; the specific "wrong model type" issue is a behavioral/API-contract nit that does not meet MEDIUM severity standalone.

---

### [SYNTHESIZER] Verdict for H-NEW-43 (cgo callback deadlock) -- 2026-04-17T15:50:00Z

**Prosecution summary**: Tracer PARTIAL — architecture allows deadlock in future refactor; current code safe.

**Verdict: VALID** at MEDIUM (defense-in-depth; one-change-away hazard).

**Finding draft written to**: `archon/findings-draft/p8-053-cgo-log-callback-reentrancy-deadlock-latent.md`
**Registry updated**: AP-053 new.

---

### [SYNTHESIZER] Verdict for H-NEW-44 (uint64→int cast) -- 2026-04-17T15:51:00Z

**Prosecution summary**: Tracer REACHABLE — panic recovered by gin → 500. Pattern-family with chamber-02 AP-022/AP-030.

**Verdict: VALID** at MEDIUM — bounded DoS but a confirmed instance of a known class.

**Finding draft written to**: `archon/findings-draft/p8-045-gguf-string-int-cast-panic-dos.md`
**Registry updated**: AP-022 confirmed-instance extended (reuse chamber-02 pattern).

---

### [SYNTHESIZER] Verdict for H-NEW-45 (adapter leak) -- 2026-04-17T15:52:00Z

**Prosecution summary**: Tracer PARTIAL — CString correctly freed; `llama_adapter_lora` struct leak is real (no free).

**Verdict: VALID** at MEDIUM — Ideator's original CString claim was wrong, but tracer found the real leak in the same code.

**Finding draft written to**: `archon/findings-draft/p8-051-llama-adapter-lora-struct-leak.md`
**Registry updated**: AP-051 new.

---

### [SYNTHESIZER] Verdict for H-NEW-46 (audio mel overflow) -- 2026-04-17T15:53:00Z

**Prosecution summary**: Tracer PARTIAL — `/v1/audio/transcriptions` has 25 MB cap (safe); `/api/generate` audio-as-images path has NO cap; mel-compute int32 overflow plausible but not line-verified.

**Verdict: VALID** at MEDIUM — unauthenticated uncapped-body DoS confirmed on `/api/generate` audio path; mel overflow flagged with `Pre-FP-Flag`.

**Finding draft written to**: `archon/findings-draft/p8-050-audio-mel-path-uncapped-api-generate.md`
**Registry updated**: AP-050 new.

---

### [SYNTHESIZER] Verdict for H-NEW-47 (tokenizer UTF-8) -- 2026-04-17T15:54:00Z

**Prosecution summary**: Tracer UNREACHABLE — output buffer is for tokens, not text bytes; `result < 0` resize pattern correct.

**Verdict: DROP**.

---

### [SYNTHESIZER] Verdict for H-NEW-48 (num_ctx DoS) -- 2026-04-17T15:55:00Z

**Prosecution summary**: Tracer REACHABLE — `opts.NumCtx` uncapped when `trainCtx = 0`; `make([]*input.Input, 2^29)` OOMs runner. CodeQL flagged `go/uncontrolled-allocation-size` at `runner/ollamarunner/runner.go:1079`.

**Verdict: VALID** at HIGH — unauthenticated, cross-user impact.

**Finding draft written to**: `archon/findings-draft/p8-042-num-ctx-uncapped-runner-oom.md`
**Registry updated**: AP-043 new.

---

### [SYNTHESIZER] Verdict for H-NEW-49 (silent truncation) -- 2026-04-17T15:56:00Z

**Prosecution summary**: Tracer PARTIAL — original `done_reason:stop` claim incorrect; refined finding is clean-EOF scenario where stream closes with neither error nor done sentinel.

**Verdict: VALID** at MEDIUM — refined scope; agentic-era correctness bug.

**Finding draft written to**: `archon/findings-draft/p8-052-streaming-response-clean-eof-silent-truncation.md`
**Registry updated**: AP-052 new.

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-00.01 | DUPLICATE | CRITICAL (via chamber-02 p8-020) | p8-043 captures chamber-03 escalation at quantize sink |
| H-00.02 | VALID | MEDIUM | p8-049-cstring-leak-load-model-from-file.md |
| H-00.03 | DROP | -- | -- (latent invariant only) |
| H-00.04 | FALSE POSITIVE | -- | -- (phantom-at-callsite; real guard in callee) |
| H-00.05 | VALID | MEDIUM | p8-047-mlxrunner-manifest-path-traversal-defense-in-depth.md |
| H-00.06 | VALID | MEDIUM | p8-048-lora-path-ipc-to-cgo-passthrough.md |
| H-00.07 | VALID | MEDIUM | p8-046-embeddings-seq-unsafe-slice-nembd.md |
| H-00.08 | VALID | HIGH | p8-040-mtmd-null-deref-image-bitmap.md |
| H-00.09 | DROP | LOW | -- (below MEDIUM threshold; covered by p8-020 root fix) |
| H-00.10 | FALSE POSITIVE | -- | -- (Semgrep FP; `sizeof` is compile-time) |
| H-00.11 | VALID | HIGH | p8-041-blank-mime-mtmd-null-deref.md |
| H-00.12 | DROP | -- | -- (below threat-model floor) |
| H-CHAIN-A.1 | VALID | HIGH | p8-043-quantize-unsafe-slice-elements-oob.md |
| H-CHAIN-B.1 | DROP | -- | -- (race-loser aborts cleanly) |
| H-CHAIN-C.1 | DROP | -- | -- (UAF FP; collapses to H-00.08) |
| H-CHAIN-D.1 | DROP | -- | -- (no flag injection) |
| H-CHAIN-E.1 | VALID | HIGH | p8-044-gpu-backend-shape-overflow-disclosure.md |
| H-NEW-40 | DROP | -- | -- (per-request sampler) |
| H-NEW-41 | DROP | -- | -- (exact-match cache) |
| H-NEW-42 | MERGED | -- | -- (merged into p8-046) |
| H-NEW-43 | VALID | MEDIUM | p8-053-cgo-log-callback-reentrancy-deadlock-latent.md |
| H-NEW-44 | VALID | MEDIUM | p8-045-gguf-string-int-cast-panic-dos.md |
| H-NEW-45 | VALID | MEDIUM | p8-051-llama-adapter-lora-struct-leak.md |
| H-NEW-46 | VALID | MEDIUM | p8-050-audio-mel-path-uncapped-api-generate.md |
| H-NEW-47 | DROP | -- | -- (output buffer holds tokens, not text) |
| H-NEW-48 | VALID | HIGH | p8-042-num-ctx-uncapped-runner-oom.md |
| H-NEW-49 | VALID | MEDIUM | p8-052-streaming-response-clean-eof-silent-truncation.md |

Findings written: 14 (p8-040 through p8-053)
  - HIGH: 5 (p8-040, p8-041, p8-042, p8-043, p8-044)
  - MEDIUM: 9 (p8-045, p8-046, p8-047, p8-048, p8-049, p8-050, p8-051, p8-052, p8-053)
  - CRITICAL referenced via cross-chamber: chamber-02 p8-020 (H-00.01 root)

Patterns added to registry: 12 new (AP-042 through AP-053) + 2 extended (AP-020 confirmed-instance F32-quantize-sink note, AP-022 confirmed-instance at fs/ggml/gguf.go:359)

Variant candidates tracked in registry (untested_candidates fields across 12 new patterns):
  - llama/llama.go complete audit of C.CString call sites (AP-049)
  - llama/llama.go all //export functions (AP-053)
  - ml/backend/ggml/*.go cgo wrappers (multiple patterns)
  - x/mlxrunner/*.go manifest path helpers (AP-047)
  - vendored mtmd/whisper mel-compute int32 arithmetic (AP-050)
  - all cgo init/free pairs (AP-042, AP-051)
  - runner streaming loops in openai SSE, x/mlxrunner, additional /api routes (AP-052)

Status: CLOSED
Chamber closed: 2026-04-17T15:58:00Z


