Finding: p8-040-mtmd-null-deref-image-bitmap
Reviewed: 2026-04-17

## Step 1 — Restatement and Decomposition

Claim: A NULL pointer return from `mtmd_helper_bitmap_init_from_buf` is not
checked before being forwarded to `mtmd_tokenize` in the llamarunner cgo
bridge, allowing an unauthenticated POST request containing a few bytes of
arbitrary non-image data to crash the runner subprocess with SIGSEGV.

Sub-claims:
- A: Attacker can submit arbitrary bytes as an "image" via unauthenticated
  HTTP (`/api/generate`, `/api/chat`, `/v1/chat/completions`).
- B: Those bytes reach `MtmdContext.MultimodalTokenize` on the llamarunner
  path without any image-magic / decode validation that would reject
  non-image input.
- C: `mtmd_helper_bitmap_init_from_buf` returns NULL when input is not a
  supported image or audio format, and the subsequent call to
  `mtmd_tokenize(&bm, 1)` dereferences the NULL bitmap while processing
  the `<__media__>` marker in the default input text, causing SIGSEGV.

All three are coherent and verifiable.

## Step 2 — Independent Code Path Trace

Entry HTTP: `server/routes.go` GenerateHandler / ChatHandler accept
`Images []api.ImageData` as raw `[]byte` under the JSON key `images`
(`routes.go:435-438`, `routes.go:554`). No image decoding is performed at
the HTTP layer; data is wrapped into `llm.ImageData{ID, Data}` and passed
through to the runner subprocess via `Completion`.

Runner entry (llamarunner): `runner/llamarunner/runner.go:236` calls
`s.image.MultimodalTokenize(s.lc, images[imageIndex].Data)`.

`runner/llamarunner/image.go:59-88` validates only `len(data) <= 0` and
then hands the bytes to `c.mtmd.MultimodalTokenize` (line 76). There is
NO image-magic / `image.Decode` check on this path.

`llama/llama.go:556-571` (`MtmdContext.MultimodalTokenize`):
  - Builds `it` from `mtmd_default_marker()` → `<__media__>`
  - `bm := C.mtmd_helper_bitmap_init_from_buf(c.c, &data[0], len(data))`
  - `defer C.mtmd_bitmap_free(bm)` — this IS NULL-safe
    (`mtmd.cpp:954-958`: `if (bitmap) { delete bitmap; }`)
  - NO `if bm == nil` check
  - `C.mtmd_tokenize(c.c, ic, it, &bm, 1)` is called unconditionally

C side: `mtmd_helper_bitmap_init_from_buf` at `mtmd-helper.cpp:470-498`
first attempts `audio_helpers::is_audio_file` (RIFF/WAVE), then falls
back to `stbi_load_from_memory`. For 3 bytes of `\0\0\0`,
`stbi_load_from_memory` returns NULL → function returns `nullptr`.

`mtmd_tokenize` at `mtmd.cpp:790-797` wraps a tokenizer and calls
`tokenize(output)`. In `tokenize()` at `mtmd.cpp:453-508`:
  - `split_text("<__media__>", "<__media__>")` returns
    `["<__media__>"]` (per `split_text` at `mtmd.cpp:749-765`).
  - Loop encounters `part == ctx->media_marker` → grabs
    `bitmaps[0]` which is NULL → `add_media(NULL)`.

`add_media` at `mtmd.cpp:537-538`:
```
int32_t add_media(const mtmd_bitmap * bitmap) {
    if (!bitmap->is_audio) {   // NULL-deref here
```
This is the SIGSEGV sink. (The finding pointed at line 552 specifically
for `img_u8->nx = bitmap->nx`; an even earlier crash occurs at the
`bitmap->is_audio` read on line 538. Either way the outcome is the same.)

Transformations on path: none that would validate image content.

Controls found on the path: only `len(data) <= 0` in `image.go:64`.

## Step 3 — Protection Surface Search

| Layer        | Control                                  | Blocks attack? |
|--------------|------------------------------------------|----------------|
| Language     | Go stdlib `image.Decode` magic sniff     | No — not called on llamarunner path; only called from per-model `EncodeMultimodal` in `model/models/*/model.go` (ollamarunner path only). |
| Framework    | gin / HTTP JSON decode                   | No — accepts any base64 bytes as `[]byte`. |
| Middleware   | Authentication                           | No — default deployment has no auth on `/api/generate`. |
| Application  | Zero-length guard at `runner/llamarunner/image.go:64` | No — `>= 1 byte` passes. |
| Application  | mllama 1-image limit `routes.go:430`     | No — only limits count, not content. |
| C side       | `mtmd_bitmap_free` NULL-safe             | Yes for the `free` call only — does NOT protect `mtmd_tokenize`. |
| Documentation | SECURITY.md                             | Not checked; no known-risk note cited in finding. |

`OllamaEngineRequired` list in `fs/ggml/ggml.go:277` includes `mllama`,
`gemma3`, `gemma4`, `mistral3`, `qwen25vl`, `qwen3vl`, `qwen3vlmoe`,
`llama4`, etc. These go through ollamarunner where `EncodeMultimodal`
calls `image.Decode` (confirmed at `model/models/qwen3next/model.go:302`,
`model/models/qwen3vl/model.go:33`). However, any model NOT in that list
that has a separate projector (architecture "clip") will land in
llamarunner — e.g. classic llava, moondream, minicpm-v, bakllava, and
any custom CLIP-projected GGUF. See `runner/llamarunner/image.go:34`
which explicitly supports `arch == "clip"`.

Decisive point: the `image.Decode` protection is NOT on the path in
question. The defense that the chamber debate considered (from the
finding's "Evidence" section mentioning advocate Round 1) only applies
to ollamarunner.

## Step 4 — Real-Environment Reproduction

Environment: macOS 25.3.0, go1.26.1 darwin/arm64.
Repo HEAD: 57653b8e (current main).

Attempt 1 (build verification): `go build ./runner/llamarunner/...` and
`go build ./llama/...` succeed. The vulnerable function
`MtmdContext.MultimodalTokenize` and callsite
`runner/llamarunner/image.go:76` both compile as inspected.

Attempt 2 (end-to-end HTTP reproduction): BLOCKED. A full runtime
reproduction requires (a) a CLIP-projected vision model GGUF with a
separate projector (llava/moondream style), total ~3-7 GB to fetch,
and (b) a GPU or sufficient CPU/RAM to actually load mmproj + base
model. Cold verification does not have provisioned model artifacts or
network egress to HuggingFace for multi-GB downloads within the review
window.

Attempt 3 (focused unit-style repro): Constructing a cgo-level harness
that calls `C.mtmd_helper_bitmap_init_from_buf` with non-image bytes
and then `C.mtmd_tokenize` requires an initialized `mtmd_context`,
which requires loading a real CLIP projector. The `mtmd.cpp` static
analysis above shows the NULL bitmap path is taken as soon as the
media_marker is present in the input text, which it unconditionally is
in `MtmdContext.MultimodalTokenize` (`llama.go:562`).

PoC-Status: theoretical (blocked by model-artifact availability, not by
code-level protections). The claim is strongly supported by direct
inspection of the three files: `llama/llama.go`,
`llama/llama.cpp/tools/mtmd/mtmd-helper.cpp`,
`llama/llama.cpp/tools/mtmd/mtmd.cpp`.

## Step 5 — Prosecution Brief

1. Unauthenticated entry: `server/routes.go:435-438` copies request
   `Images` bytes into `llm.ImageData.Data` without decoding. Default
   deployment has no auth on `/api/generate` or `/v1/chat/completions`.
2. Path reaches `MultimodalTokenize` with raw bytes: the llamarunner
   path handles any model with a separate projector file (see
   `llm/server.go:143-158`: if `projectors` slice is non-empty, the
   else-branch falls through to the legacy llama engine /
   llamarunner). `runner/llamarunner/image.go:59-88` only validates
   `len(data) > 0` before calling `c.mtmd.MultimodalTokenize`.
3. NULL return: `mtmd-helper.cpp:470-498` returns `nullptr` whenever
   `stbi_load_from_memory` cannot recognize the image bytes and
   `is_audio_file` is false. Three bytes of `\0\0\0` satisfy both.
4. Missing check: `llama/llama.go:566-570` does NOT gate `mtmd_tokenize`
   on `bm != nil`. Only the `defer mtmd_bitmap_free(bm)` is NULL-safe,
   which protects the cleanup path but not the tokenize call.
5. NULL deref: `mtmd.cpp:538` reads `bitmap->is_audio` on the NULL
   pointer inside `add_media`, triggered by the default
   `<__media__>` marker in `it` (`llama.go:562`). SIGSEGV.
6. Impact: any in-flight inference on that runner is terminated;
   re-loading a multi-GB vision model on SIGHUP/respawn is measured in
   seconds-to-minutes. A single ~50-byte request per reload interval
   suffices for a persistent DoS on the multimodal model.

## Step 6 — Defense Brief

1. The Go `image.Decode` magic-byte sniff does reject unrecognized
   input BEFORE cgo — but only in per-model `EncodeMultimodal`
   implementations (`model/models/qwen3next/model.go:302`,
   `model/models/qwen3vl/model.go:33`). These run inside the
   ollamarunner, not the llamarunner. So the strongest-looking defense
   simply does not exist on the path in question.
2. The chamber's `mllama` example (llama3.2-vision) goes through the
   ollamarunner because `mllama` is in the `OllamaEngineRequired`
   list (`fs/ggml/ggml.go:277-302`). The finding's reproduction
   recipe uses `llama3.2-vision`, which would NOT reproduce on the
   current codebase.
3. To exploit, the deployer must have a model with a separate
   projector file (architecture "clip") loaded. This is a non-default
   situation: the user must explicitly `ollama pull` a CLIP-projected
   vision model like llava/moondream/minicpm-v. Not all deployments
   serve such models.
4. The runner is a subprocess of `ollama serve`; crashing it does not
   compromise the parent process and the scheduler respawns the
   runner. So this is DoS-class, not RCE.
5. The chamber/finding notes real-env reproduction is pending; without
   a concrete repro the behaviour is inferred from static trace. A
   reviewer cannot verify that `stbi_load_from_memory` returns NULL
   for all non-image inputs without executing the decoder.

Defense strength: The defense lowers severity (preconditions require
a specific model family to be served) but does not identify a
blocking protection on the vulnerable path. The `image.Decode` guard
is verifiably absent from llamarunner, and the zero-length guard does
not help for `len(data) >= 1`.

## Step 7 — Severity Challenge

Starting at MEDIUM.

Factors:
- Remotely triggerable via unauthenticated HTTP: YES (+)
- Meaningful trust-boundary crossing (HTTP bytes → subprocess
  SIGSEGV): YES (+)
- Preconditions: requires a CLIP-projected vision model loaded (not
  default; non-trivial) (-)
- Crash is subprocess-local; parent `ollama serve` survives (-)
- Single-request permanent DoS on model inference: YES for that model
  on that runner (+)

Upgrading to HIGH is warranted: internet-exposed unauthenticated DoS
on a serviced model with a tiny payload meets the HIGH bar despite
the model-selection precondition. The finding's original severity of
HIGH is preserved.

Not upgraded to CRITICAL: no RCE, no data exfiltration, not all
deployments are affected (only those serving CLIP-projector models
on the legacy engine).

Severity-Final: HIGH.

## Step 7 — Verdict

CONFIRMED.

Rationale: Static trace verifies all three sub-claims; no blocking
protection exists on the llamarunner path (the `image.Decode` defense
applies only to ollamarunner). Reproduction is blocked by
model-artifact availability in this review environment, not by any
protection in the code. PoC-Status: theoretical.
