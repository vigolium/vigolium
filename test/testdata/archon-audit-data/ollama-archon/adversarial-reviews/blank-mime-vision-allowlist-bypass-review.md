Adversarial Review: blank-mime-vision-allowlist-bypass
Reviewer: Independent cold verifier (Phase 8)
Finding draft: archon/findings-draft/p8-032-blank-mime-vision-allowlist-bypass.md
Verdict: DISPROVED
Severity-Final: LOW
PoC-Status: executed (both branches produce identical attacker-controlled bytes)

## Step 1 — Restated claim and decomposition

Restated: a special branch in the OpenAI-compat image decoder (openai/openai.go:682-684) trims `data:;base64,` and forwards whatever bytes decode afterward. The finding alleges this "bypasses" a jpeg/jpg/png/webp allowlist, letting an attacker ship non-image binary into mtmd cgo and thereby "expand the cgo image-library attack surface."

Sub-claims:
- A: attacker can reach the endpoint (`/v1/chat/completions`) with an image_url content block.
- B: the blank-MIME branch lets decoded bytes reach a cgo image parser without Go-side format validation.
- C: this expands attack surface beyond what was already reachable.

## Step 2 — Independent code path trace

- `openai/openai.go:498-524` — `image_url` path extracts the URL string, then calls `decodeImageURL(url)` at line 519.
- `openai/openai.go:674-705` — `decodeImageURL`:
  - Rejects http/https.
  - Special-cases `data:;base64,` by trimming the prefix and skipping the declared-MIME allowlist.
  - Otherwise validates the declared MIME prefix against {jpeg,jpg,png,webp}.
  - CRITICAL: the MIME allowlist is a *textual prefix check on the URL string*. The decoded bytes themselves are never inspected for format.
  - Both branches converge at `base64.StdEncoding.DecodeString(url)` and return the raw decoded bytes.
- Bytes flow into `api.Message.Images` ([]api.ImageData).
- `server/prompt.go:86-91` — raw bytes are wrapped into `llm.ImageData` and forwarded to the runner unchanged.

Two downstream runner paths exist:
1. ollamarunner (new Go-native engine) — used for modern vision models (gemma3, gemma4, qwen25vl, qwen3vl, qwen3next, mllama, llama4, mistral3, lfm2, glmocr, deepseekocr). `runner/ollamarunner/runner.go:274` calls `multimodalProcessor.EncodeMultimodal(ctx, images[imageIndex].Data)`. Every model's `EncodeMultimodal` calls `image.Decode(bytes.NewReader(multimodalData))` FIRST. Go's `image.Decode` is a strict magic-byte sniff against registered formats. Non-registered bytes return `image: unknown format` and the function aborts before any cgo call.
2. llamarunner (legacy clip-arch path) — `runner/llamarunner/runner.go:236` calls `s.image.MultimodalTokenize(s.lc, images[imageIndex].Data)`. `runner/llamarunner/image.go:76` calls `c.mtmd.MultimodalTokenize(llamaContext, data)` directly. `llama/llama.go:566` passes the raw buffer to `C.mtmd_helper_bitmap_init_from_buf`, which eventually calls `stbi_load_from_memory` (stb_image, single-header) — see `llama.cpp/tools/mtmd/mtmd-helper.cpp:485-498`. The only Go-side guard before cgo is a `len(data) <= 0` check in llamarunner/image.go:64.

## Step 3 — Protection surface

- Framework (Go stdlib `image.Decode`): ollamarunner path. Blocks arbitrary bytes.
- Cgo (stb_image `stbi_load_from_memory`): llamarunner path. Returns NULL on unrecognized format; the helper also pre-checks `audio_helpers::is_audio_file` before falling back to stb_image. Not a "libjpeg-turbo/libpng/libwebp" surface as the finding claims — this is stb_image.
- Trust-boundary note: on default loopback binding, `/v1/chat/completions` is unauthenticated; this is by design of the project.
- Documentation: none explicitly accepts this as known risk.

Critical protection observation missed by the finding: the allowlist it claims is "bypassed" is NOT a content-validation mechanism. It only checks the declared MIME string (a prefix of the URL text). An attacker can pass arbitrary bytes through that same allowlist by simply prefixing them with `data:image/jpeg;base64,`. The blank-MIME branch therefore does not expand attack surface; it is functionally equivalent to lying about the MIME type.

## Step 4 — Real-environment reproduction

Attempted via isolated Go reproduction of `decodeImageURL` (the function is pure; no network setup needed).

File: `archon/real-env-evidence/blank-mime-vision-allowlist-bypass/decode_repro.go`

Output:
```
Case 1 (blank MIME): url="data:;base64,AAECf//+yv4=" err=<nil> bytesOut=0001027ffffecafe
Case 2 (lied MIME):  url="data:image/jpeg;base64,AAECf//+yv4=" err=<nil> bytesOut=0001027ffffecafe
Case 3 (gif MIME):   url="data:image/gif;base64,AAECf//+yv4=" err=invalid image input
Case 4 (octet-stream): url="data:application/octet-stream;base64,AAECf//+yv4=" err=invalid image input
```

Case 1 and Case 2 produce IDENTICAL output bytes. Removing the blank-MIME branch (Case 1) still leaves Case 2 open. The "allowlist" does not protect against arbitrary-binary content reaching downstream consumers — it only guards the textual declared MIME.

Additionally verified `image.Decode(<arbitrary bytes>)` returns `image: unknown format`, confirming the ollamarunner path's downstream magic-byte filter.

## Step 5 — Prosecution brief

The `decodeImageURL` function explicitly trims the `data:;base64,` prefix and hands raw decoded bytes to the downstream pipeline. For the llamarunner (clip-arch) path, these bytes reach `mtmd_helper_bitmap_init_from_buf` → `stbi_load_from_memory` without any Go-side magic-byte check. stb_image is a well-known source of historical image-parsing memory-safety issues. The inline comment admits intent but not security posture. On default loopback, the route is unauthenticated. Any future CVE in stb_image becomes remotely reachable.

## Step 6 — Defense brief

The claim of "allowlist bypass" mischaracterizes the function. The allowlist verifies only the declared MIME string, not the actual content. Reproduction proves identical output bytes for `data:;base64,<bytes>` (blank branch) and `data:image/jpeg;base64,<bytes>` (claimed-allowlisted branch). The attack surface is identical with or without the blank-MIME branch.

For the ollamarunner path (modern models), `image.Decode` is a pre-cgo magic-byte filter — non-PNG/JPEG/WEBP bytes are rejected in pure Go before any cgo call. For the llamarunner path (legacy clip models), the cgo library is stb_image (not libjpeg-turbo/libpng/libwebp as the finding claims). The finding misidentifies the underlying library.

The Impact section concedes "The bypass does not directly produce a concrete exploit in the Go layer." Attack-surface arguments require that the surface actually be wider after the bug than before — and this one is not, because the trivially-bypassable MIME-string allowlist offers no content protection in either branch.

## Step 7 — Severity challenge

Start at MEDIUM. 
- No concrete exploit; the finding is explicit about this.
- Attack surface is NOT expanded by the cited branch (proven by reproduction).
- Requires hypothetical future CVE in a cgo library (stb_image, not the libs the finding names).
- On the ollamarunner path, Go-side `image.Decode` filters arbitrary bytes before cgo.
- Preconditions require vision model loaded + an unpatched cgo image-parser 0-day.

Downgrade to LOW. The theoretical concern (arbitrary bytes to cgo image parser) is real in a general sense, but removing the blank-MIME branch does not close it; the fix direction is misdirected. If any hardening is appropriate, it would be Go-side `image.Decode` or magic-byte check applied uniformly to ALL data URLs (both branches), not just removal of the blank-MIME branch. That is a hardening recommendation, not a vulnerability.

## Verdict

DISPROVED. The "bypass" does not materially expand attack surface because the allowlist does not validate content. Reproduction demonstrates identical behavior for both branches. Finding is a false positive as written. The underlying suggestion to add a Go-side magic-byte sniff is a reasonable defense-in-depth hardening but does not justify a vulnerability claim.
