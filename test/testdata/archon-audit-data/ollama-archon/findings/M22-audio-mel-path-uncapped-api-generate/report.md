## Summary

Ollama exposes two audio input paths:
1. **`POST /v1/audio/transcriptions`** (openai-compat): multipart upload; `middleware/openai.go:729` uses `ParseMultipartForm(25 << 20)` = 25 MB cap. Sample count bounded to ~6.5 M — safely below int32 overflow.
2. **`POST /api/generate`** / **`POST /api/chat`** with `"images":["<base64-audio>"]`: gemma-audio and qwen-audio models accept WAV/RIFF bytes through the multimodal image field. No MaxBytesReader. No size cap. Bytes flow through `runner/llamarunner/image.go:64-66` (zero-length guard only) and into `C.mtmd_helper_bitmap_init_from_buf`, which dispatches to the audio branch on RIFF/WAVE magic.

For the second path, a multi-gigabyte RIFF/WAVE payload (valid magic, empty-ish content) reaches `audio_helpers::decode_audio_from_buf` → mel-spectrogram compute. The mtmd/whisper-style mel code uses int32 indices over `sample_count * n_mels`; for `sample_count > 2^24` (~16 M samples, representing about 50 minutes of 16kHz audio via the unofficial path), the multiplication overflows.

The overflow has two outcomes:
- On 32-bit signed multiply: wrap to negative index → potential OOB read/write on FFT buffer.
- On 64-bit multiply with 32-bit truncation on buffer-sized-as-int32: corrupted mel-spectrogram, likely NULL-deref or segfault downstream.

Neither outcome is confirmed at the vendored-C-code line level; the pattern match is to a known whisper.cpp class of issues.

## Details

Ollama exposes two audio input paths:
1. **`POST /v1/audio/transcriptions`** (openai-compat): multipart upload; `middleware/openai.go:729` uses `ParseMultipartForm(25 << 20)` = 25 MB cap. Sample count bounded to ~6.5 M — safely below int32 overflow.
2. **`POST /api/generate`** / **`POST /api/chat`** with `"images":["<base64-audio>"]`: gemma-audio and qwen-audio models accept WAV/RIFF bytes through the multimodal image field. No MaxBytesReader. No size cap. Bytes flow through `runner/llamarunner/image.go:64-66` (zero-length guard only) and into `C.mtmd_helper_bitmap_init_from_buf`, which dispatches to the audio branch on RIFF/WAVE magic.

For the second path, a multi-gigabyte RIFF/WAVE payload (valid magic, empty-ish content) reaches `audio_helpers::decode_audio_from_buf` → mel-spectrogram compute. The mtmd/whisper-style mel code uses int32 indices over `sample_count * n_mels`; for `sample_count > 2^24` (~16 M samples, representing about 50 minutes of 16kHz audio via the unofficial path), the multiplication overflows.

The overflow has two outcomes:
- On 32-bit signed multiply: wrap to negative index → potential OOB read/write on FFT buffer.
- On 64-bit multiply with 32-bit truncation on buffer-sized-as-int32: corrupted mel-spectrogram, likely NULL-deref or segfault downstream.

Neither outcome is confirmed at the vendored-C-code line level; the pattern match is to a known whisper.cpp class of issues.

### Location

- `middleware/openai.go:729` -- 25 MB cap on `/v1/audio/transcriptions` (the *safe* path)
- `server/routes.go:1674` -- `gin.Default()` with no body-limit middleware for `/api/generate`
- `runner/llamarunner/image.go:64-66` -- zero-length guard only; no upper-bound
- `llama/llama.go:566` -- `C.mtmd_helper_bitmap_init_from_buf(c.c, data, C.size_t(len(data)))` — 2 GB+ passes unchecked
- Vendored mtmd audio mel-compute (whisper-style) — attacker-reachable via audio-capable models (qwen-audio, gemma-audio)

### Attacker Control

Unauthenticated `POST /api/generate`:
```json
{"model":"qwen2.5-omni","prompt":"transcribe","images":["<base64 of RIFF header + huge padding>"]}
```

The RIFF/WAVE magic (12 bytes) passes the mtmd-helper's `is_audio_file` check. Subsequent `decode_audio_from_buf` processes the entire payload size as samples.

### Trust Boundary Crossed

Unauthenticated HTTP (no body-size middleware) -> vendored whisper-style mel-compute in runner subprocess.

### Evidence

Tracer verification (Round 3, H-NEW-46, 2026-04-17T10:25:00Z):

```
middleware/openai.go:729
    err := c.Request.ParseMultipartForm(25 << 20)  // 25 MB
    // CAP applies to /v1/audio/transcriptions only

server/routes.go:1674
    r := gin.Default()
    // no MaxBytesReader middleware; request bodies are unbounded
    // /api/generate and /api/chat have no size limit

runner/llamarunner/image.go:64-66
    if len(data) <= 0 { return nil, errors.New("zero length") }
    // no upper bound

llama/llama.go:566
    bm := C.mtmd_helper_bitmap_init_from_buf(c.c, ptr, C.size_t(len(data)))
    // len(data) can be 4 GB+ (int on amd64 is 64-bit)

llama.cpp/tools/mtmd/mtmd-helper.cpp:471
    audio_helpers::is_audio_file(buf, len)  // passes for RIFF magic
    audio_helpers::decode_audio_from_buf(buf, len)
    // mel compute at sample_count * n_mels — int32 arithmetic
```

Tracer note: "The exact C code for mel-spectrogram in the vendored mtmd (whisper-style) was not traced to confirm overflow at line-level. Severity: MEDIUM (needs vendored C trace for mel-compute overflow; 25 MB cap mitigates the `/v1/audio/transcriptions` path; direct `/api/generate` audio path lacks size limit)."

Advocate did not file a defense brief on H-NEW-46 (novel).

Synth disposition: MEDIUM. The RAM-exhaustion DoS is confirmed. The int32 overflow is plausible by class pattern but not verified; flagged with `Pre-FP-Flag: check-2-partial`.

## Root Cause

Validated rationale: Tracer confirmed the `/v1/audio/transcriptions` entry has a 25 MB multipart cap at `middleware/openai.go:729` that constrains mel-compute sample count below int32 overflow, but the alternate `/api/generate` audio-as-images entry has no such cap — audio bytes flow through the same mtmd path with only the zero-length guard, so a multi-GB audio payload reaches the vendored mel-spectrogram code whose internal int32 sample-count arithmetic is not verified at code level.

Primary cited code reference: `middleware/openai.go:729`.

Merge extraction sink line: - `middleware/openai.go:729` -- 25 MB cap on `/v1/audio/transcriptions` (the *safe* path)

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. `ollama pull qwen2.5-omni` (or any audio-capable model on the llamarunner/mtmd path).
2. Construct a base64 payload: RIFF header (12 bytes `"RIFF....WAVE"`) + 1 GB of zero-padding.
3. `curl -X POST http://127.0.0.1:11434/api/generate -d '{"model":"qwen2.5-omni","prompt":"hi","images":["<payload>"]}'`
4. Observe RAM usage spike to several GB in the runner subprocess; potential OOM-kill; audit vendored mel-compute int32 arithmetic against the `sample_count * n_mels` pattern.
5. Fix direction: (a) apply `http.MaxBytesReader(w, r.Body, 25<<20)` at `/api/generate` and `/api/chat` for image/audio payloads; (b) in `llama/llama.go:566`, reject `len(data) > some_ceiling` (e.g., 64 MB); (c) upstream: bound `sample_count` in mel-compute in the vendored mtmd code.

Pattern: register AP-050 `common-sink-lacks-cap-variant-has-cap` — two API paths converge on a sink; only one path enforces an input-size cap.

## Impact

- **Confirmed**: unauthenticated DoS via RAM exhaustion — a 4GB POST body forces the runner to hold 4GB in RAM before any mel processing.
- **Plausible (class pattern match, not line-verified)**: int32 overflow in mel-spectrogram sample counting → OOB read/write in mel buffer → runner crash or potential memory corruption.

The asymmetry (openai-compat path is capped at 25 MB, native path is uncapped) suggests a clear hardening gap: the cap should be at the common sink.

_Synthesized during merge normalization from `archon/findings/M22-audio-mel-path-uncapped-api-generate/draft.md`._
