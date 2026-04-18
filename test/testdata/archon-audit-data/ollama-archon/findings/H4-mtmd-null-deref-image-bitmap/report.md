## Summary

`llama/llama.go:566-570` passes arbitrary bytes to `C.mtmd_helper_bitmap_init_from_buf`, which returns NULL when the bytes are not a supported image (PNG/JPEG/BMP/TGA/GIF) or audio (RIFF/WAVE) format. The code sets up a deferred `C.mtmd_bitmap_free(bm)` (which is NULL-safe) but then unconditionally calls `C.mtmd_tokenize(c.c, ic, it, &bm, 1)` at line 570 — passing a pointer to a NULL pointer. In `mtmd.cpp:465` the function reads `bitmap = bitmaps[0]` = NULL and then `mtmd.cpp:538` dereferences it (`bitmap->is_audio`), producing SIGSEGV in the runner subprocess. Any unauthenticated request with any non-image, non-audio base64 payload (≥ 1 byte) crashes the runner.

## Details

`llama/llama.go:566-570` passes arbitrary bytes to `C.mtmd_helper_bitmap_init_from_buf`, which returns NULL when the bytes are not a supported image (PNG/JPEG/BMP/TGA/GIF) or audio (RIFF/WAVE) format. The code sets up a deferred `C.mtmd_bitmap_free(bm)` (which is NULL-safe) but then unconditionally calls `C.mtmd_tokenize(c.c, ic, it, &bm, 1)` at line 570 — passing a pointer to a NULL pointer. In `mtmd.cpp:465` the function reads `bitmap = bitmaps[0]` = NULL and then `mtmd.cpp:538` dereferences it (`bitmap->is_audio`), producing SIGSEGV in the runner subprocess. Any unauthenticated request with any non-image, non-audio base64 payload (≥ 1 byte) crashes the runner.

### Location

- `llama/llama.go:566` -- `bm := C.mtmd_helper_bitmap_init_from_buf(...)` — returns NULL on unrecognized format
- `llama/llama.go:567` -- `defer C.mtmd_bitmap_free(bm)` — NULL-safe; does NOT protect the tokenize call
- `llama/llama.go:570` -- `C.mtmd_tokenize(c.c, ic, it, &bm, 1)` — no nil check before passing &bm
- `llama.cpp/tools/mtmd/mtmd.cpp:538` -- `bitmap->is_audio` — SIGSEGV sink (first, earlier)
- `llama.cpp/tools/mtmd/mtmd.cpp:552` -- `img_u8->nx = bitmap->nx` — SIGSEGV sink (second)
- `runner/llamarunner/image.go:59-66` -- only zero-length guard; arbitrary non-zero bytes pass

### Attacker Control

Unauthenticated `POST /api/generate` or `POST /api/chat` with `"images":["<base64 of 3-byte garbage>"]`; also via OpenAI-compat `POST /v1/chat/completions` with `image_url.url = "data:;base64,AAAA"` (see p8-041 for the blank-MIME path). Entry point is anywhere the llamarunner multimodal path is active: any CLIP-projected GGUF (llava, moondream, minicpm-v, bakllava) served by the legacy engine.

### Trust Boundary Crossed

Unauthenticated HTTP request body -> runner subprocess virtual memory (SIGSEGV in vendored cgo).

### Evidence

Tracer verification (Round 2, 2026-04-17T07:08:00Z):

```
runner/llamarunner/image.go:64-66
    if len(data) <= 0 {
        return nil, errors.New("received zero length image")  // only guard
    }
    // len(data) = 3 passes; arbitrary bytes proceed

llama/llama.go:566-570
    bm := C.mtmd_helper_bitmap_init_from_buf(c.c, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
    defer C.mtmd_bitmap_free(bm)         // NULL-safe
    // NO nil check here
    ic := ...
    res := C.mtmd_tokenize(c.c, ic, it, &bm, 1)  // passes &nil

llama.cpp/tools/mtmd/mtmd.cpp:465
    bitmap = bitmaps[0]  // = NULL

llama.cpp/tools/mtmd/mtmd.cpp:538
    if (!bitmap->is_audio)   // NULL-deref, SIGSEGV (first sink)

llama.cpp/tools/mtmd/mtmd.cpp:552
    img_u8->nx = bitmap->nx   // NULL-deref, SIGSEGV (second sink)
```

Advocate's Round 1 defense relied on `image.Decode` magic-byte sniffing in per-model `EncodeMultimodal` implementations (gemma3, gemma4). Tracer's Round 2 analysis showed these guards are NOT on the llamarunner code path: `runner/llamarunner/image.go:76` calls `c.mtmd.MultimodalTokenize` directly, bypassing any Go-level image decode. Advocate defense applies to the ollamarunner (new engine) path only.

CodeQL: DFD-6-multimodal-cgo slice is `reachable: false` (C side unmodeled). Semgrep custom rule `ollama-cgo-length-unchecked` fires at `llama/llama.go:566`.

## Root Cause

Validated rationale: Tracer confirmed `mtmd_helper_bitmap_init_from_buf` returns NULL for any non-image byte payload and `llama/llama.go:570` calls `mtmd_tokenize(&bm, 1)` without checking `bm == NULL`, dereferencing a null `llama_image_u8*` at `mtmd.cpp:552` — advocate's `image.Decode` defense applies only to the ollamarunner path, not the llamarunner/mtmd path.

Primary cited code reference: `llama/llama.go:566`.

Merge extraction sink line: - `llama/llama.go:566` -- `bm := C.mtmd_helper_bitmap_init_from_buf(...)` — returns NULL on unrecognized format

An adversarial review was preserved alongside the draft and should be consulted for counter-arguments and any severity challenge.

## Proof of Concept

Merge-normalized status: `theoretical (blocked by model-artifact availability, not by`.

PoC script present: `poc.py`.

Supporting evidence is present under `evidence/`.

1. `ollama pull llava` (or moondream, minicpm-v, bakllava — any CLIP-projected model with separate projector file; NOT llama3.2-vision which routes to ollamarunner).
2. `curl -X POST http://127.0.0.1:11434/api/chat -H 'Content-Type: application/json' -d '{"model":"llava","messages":[{"role":"user","content":"x","images":["AAAA"]}]}'` (`AAAA` = base64 of 3 null bytes).
3. Observe runner subprocess SIGSEGV in `ollama serve` stderr; HTTP 500 or broken stream returned; concurrent inference sessions dropped.
4. Fix direction: add `if bm == nil { return nil, fmt.Errorf("invalid image bytes") }` between lines 567 and 570 in `llama/llama.go`.

Note: `llama3.2-vision` uses architecture `mllama` which is in `fs/ggml/ggml.go:277` `OllamaEngineRequired` list and therefore goes through the ollamarunner (new engine), NOT the llamarunner. Use a CLIP-projected model (architecture "clip") to reproduce.

Related: p8-041 (blank-MIME alternate entry), p8-032 (chamber-02 blank-MIME at openai/openai.go:682). Also registered as pattern AP-042.

## Impact

Runner subprocess SIGSEGV. Every concurrent inference session on that runner is dropped. The scheduler respawns the runner, but the model must re-load from disk (seconds to minutes), and the crash is triggerable by a single ~50-byte request. An attacker can hold the runner permanently unavailable with a request rate lower than the cold-start time. Parent `ollama serve` keeps running but cannot service any inference. The HTTP client receives an internal-server-error / broken-stream response. Cross-user impact: a single malicious request drops all active sessions on that model.

_Synthesized during merge normalization from `archon/findings/H4-mtmd-null-deref-image-bitmap/draft.md`._
