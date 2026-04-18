## Summary

`openai/openai.go:682-684` explicitly accepts `data:;base64,<payload>` with an empty MIME type (commented "Support blank mime type to match /api/chat's behavior"). This intentionally skips the MIME allowlist block. The decoded bytes flow through `api.ImageData` into the llamarunner multimodal path and reach the same null-deref sink documented in p8-040. The OpenAI-compat endpoint is the preferred migration path for ecosystem clients, making this a remote-DoS vector distinct from the native `/api/generate` entry.

The two findings (p8-040 and this one) share a sink but have distinct entry surfaces and distinct fix points: p8-040's fix is a nil check in cgo glue; this finding's additional fix is a MIME allowlist at the openai middleware (or parity with chamber-02's p8-032 which documents the same allowlist bypass class).

## Details

`openai/openai.go:682-684` explicitly accepts `data:;base64,<payload>` with an empty MIME type (commented "Support blank mime type to match /api/chat's behavior"). This intentionally skips the MIME allowlist block. The decoded bytes flow through `api.ImageData` into the llamarunner multimodal path and reach the same null-deref sink documented in p8-040. The OpenAI-compat endpoint is the preferred migration path for ecosystem clients, making this a remote-DoS vector distinct from the native `/api/generate` entry.

The two findings (p8-040 and this one) share a sink but have distinct entry surfaces and distinct fix points: p8-040's fix is a nil check in cgo glue; this finding's additional fix is a MIME allowlist at the openai middleware (or parity with chamber-02's p8-032 which documents the same allowlist bypass class).

### Location

- `openai/openai.go:682-684` -- `strings.HasPrefix(url, "data:;base64,")` → skips MIME allowlist
- `openai/openai.go:700-703` -- `base64.StdEncoding.DecodeString` returns arbitrary bytes as `api.ImageData`
- `runner/llamarunner/image.go:64-66` -- zero-length guard passes for 3-byte base64
- `llama/llama.go:570` -- same null-deref as p8-040

### Attacker Control

Unauthenticated `POST /v1/chat/completions`:
```json
{"model":"llama3.2-vision","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:;base64,AAAA"}}]}]}
```

Same DoS primitive as p8-040 but through an endpoint that many ecosystem clients use by default (LangChain OpenAI wrapper, LiteLLM, etc.). An attacker sending this once per minute holds the runner unavailable.

### Trust Boundary Crossed

Unauthenticated HTTP -> runner subprocess SIGSEGV.

### Evidence

Tracer verification (Round 2, 2026-04-17T07:12:00Z):

```
openai/openai.go:682-684
    // Support blank mime type to match /api/chat's behavior
    if strings.HasPrefix(url, "data:;base64,") {
        url = strings.TrimPrefix(url, "data:;base64,")
    } else {
        // MIME allowlist enforced only for non-blank types
        ...
    }

openai/openai.go:700
    img, err := base64.StdEncoding.DecodeString(url)
    // "AAAA" -> []byte{0x00, 0x00, 0x00}

runner/llamarunner/image.go:64-66
    if len(data) <= 0 { ... }  // passes for len=3

llama/llama.go:570 -- same NULL-deref as p8-040
```

Advocate defense brief for H-00.11 (Round 1): "blank-MIME acceptance is INTENTIONAL". Synth disposition: the intent is legitimate (echoing `/api/chat`'s behavior), but the intent does not extend to accepting non-image bytes into cgo without validation. The real fix is either:
(a) Nil check in `llama/llama.go` (same as p8-040), OR
(b) Run `image.Decode` / `is_audio_file` in Go before passing to cgo on the llamarunner path, OR
(c) Reject `data:;base64,` without a recognizable magic-byte header.

Cross-ref: chamber-02 p8-032 documents `openai/openai.go:682` as `blank-mime-allowlist-bypass` with severity HIGH, confirming the openai-side pattern. This chamber-03 finding documents the runner-side sink reached via that bypass — they are complementary halves of the same attack, not a duplicate.

## Root Cause

Validated rationale: Tracer confirmed the OpenAI-compat `data:;base64,` blank-MIME branch at `openai/openai.go:683-684` produces a non-empty byte slice of arbitrary content that reaches the same `llama/llama.go:570` null-deref as p8-040; advocate argued blank-MIME is intentional, but the intentional acceptance + missing nil-check at the cgo boundary combine into a DoS reachable via `/v1/chat/completions`.

Primary cited code reference: `openai/openai.go:682`.

Merge extraction sink line: - `openai/openai.go:682-684` -- `strings.HasPrefix(url, "data:;base64,")` → skips MIME allowlist

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Ensure a multimodal model is loaded on the legacy llamarunner path.
2. `curl -X POST http://127.0.0.1:11434/v1/chat/completions -H 'Content-Type: application/json' -d '{"model":"<vision-model>","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:;base64,AAAA"}}]}]}'`
3. Observe runner crash.
4. Fix: apply p8-040's nil-check AND strengthen `openai/openai.go:682` per chamber-02 p8-032.

## Impact

Identical runtime impact to p8-040: runner SIGSEGV, concurrent sessions dropped, repeated triggers hold the model effectively offline. Delivery is one line of JSON. The OpenAI-compat endpoint is frequently exposed in production because it is what most SDKs target.

_Synthesized during merge normalization from `archon/findings/H12-blank-mime-mtmd-null-deref/draft.md`._
