# Merged Spec Gap Report

## Included Sources

- `.archon-merge-staging-1765496804/spec-gap-report.md`
- `ollama-with-opus-4.7/spec-gap-report.md`

## Source 1

## Spec Gap Analysis

---

### Gap: OCI Distribution Spec — Manifest Response Content-Type Not Validated

- **RFC/Spec**: OCI Distribution Specification v1.1.0, Section 4.3 (Pulling Manifests); also OCI Image Layout Specification; mirrors Docker Distribution Spec v2 §https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pulling-manifests
- **Requirement**: "The registry MUST return a `Content-Type` header specifying the media type of the manifest. The client MUST reject manifests with an unexpected or missing `Content-Type` response header."
- **Code Path**: `server/images.go:835–856` (`pullModelManifest`) — The client sends `Accept: application/vnd.docker.distribution.manifest.v2+json` but never reads or validates the `Content-Type` of the response. The raw body is parsed directly as JSON regardless of what the server declares it to be.
- **Gap Type**: missing-check
- **Attack Vector**: An attacker operating a malicious registry (or performing a MITM on an HTTP registry connection) can return a response with `Content-Type: text/html` or `Content-Type: application/vnd.oci.image.index.v1+json` (an image index / fat manifest), causing the client to parse a fundamentally different document type as a flat manifest. A fat manifest response's JSON has a `manifests` array instead of `layers`; the client's `json.Unmarshal` into `manifest.Manifest` will silently produce an empty `Layers` slice, skipping all blob integrity checks and writing an effectively empty manifest to disk. The new OCI registry client (`server/internal/client/ollama/registry.go:791`) also never checks the `Content-Type` on the manifest `GET` response.
- **Exploit Conditions**: Attacker controls the registry endpoint (custom registry via model name like `http://attacker.com/model:tag`) or can MITM an insecure HTTP registry. No authentication is required since the victim is pulling from a registry they control.
- **Impact**: A fat-manifest response tricks the client into caching a manifest with zero layers. The model appears locally installed. When loaded, the runner gets an empty/missing blob, leading to either silent failure or fallback to an attacker-supplied config blob. Alternatively, the attacker can substitute a different manifest type to redirect the client to download different blobs while the digest verification window expects the original blobs — integrity bypass.
- **Severity**: HIGH
- **Evidence**:
  - `server/images.go:839` — only sets `Accept` header, never reads response `Content-Type`
  - `server/images.go:851–853` — `json.Unmarshal(data, &m)` with no content-type gate
  - `server/internal/client/ollama/registry.go:791–805` — `r.send(ctx, "GET", manifestURL, nil)` then `io.ReadAll(res.Body)` then `json.Unmarshal` with no `Content-Type` check

---

### Gap: OCI Distribution Spec — `Docker-Content-Digest` Response Header Not Verified

- **RFC/Spec**: OCI Distribution Specification v1.1.0, Section 4.3 (Pulling Manifests); Docker Distribution Spec §"Pulling an Image Manifest"
- **Requirement**: "The registry SHOULD include a `Docker-Content-Digest` header in the response. Clients SHOULD verify that the digest of the response body matches the digest in this header to detect tampering or corruption in transit."
- **Code Path**: `server/images.go:840–856` — response body is read via `io.ReadAll` and unmarshalled, but `resp.Header.Get("Docker-Content-Digest")` is never checked. `server/internal/client/ollama/registry.go:791–805` — same pattern; the `// TODO(bmizerany): return digest here` comment at line 800 acknowledges this omission.
- **Gap Type**: missing-check
- **Attack Vector**: A MITM attacker on an HTTP or TLS-MITM'd HTTPS registry connection can substitute the manifest body in transit. Because the client never checks `Docker-Content-Digest`, the altered manifest is accepted. The attacker can swap layers (replacing a model blob digest reference with a malicious digest), change the config blob digest to point to attacker-controlled configuration including an `Entrypoint` field (supply-chain RCE), or remove layers to defeat blob integrity.
- **Exploit Conditions**: Requires MITM capability on the registry transport (possible for custom `http://` registries, corporate proxies, or when using `https+insecure` scheme which disables certificate verification).
- **Impact**: Combined with the missing Content-Type check above, this creates a complete manifest substitution attack: the manifest body can be replaced without detection. This is the gateway to supply-chain RCE via Entrypoint injection (already noted in Phase 3 as an attack scenario, but here the spec gap is the missing in-transit integrity check that prevents detection).
- **Severity**: HIGH
- **Evidence**:
  - `server/images.go:846` — `io.ReadAll(resp.Body)` with no digest comparison
  - `server/internal/client/ollama/registry.go:800` — `// TODO(bmizerany): return digest here` (acknowledged technical debt)
  - For contrast, the blob-level verification at `server/images.go:639–654` correctly verifies SHA-256 against the manifest-declared digest — but this protection is only on blobs, not the manifest itself

---

### Gap: GGUF Format — Unbounded `dims` Allocation in Tensor Decode

- **RFC/Spec**: GGUF Format Specification (llama.cpp implementation spec); GGML_MAX_DIMS is defined as 4 in `llama.cpp/ggml.h`
- **Requirement**: "The number of dimensions (n_dims) for a tensor MUST be in the range [1, GGML_MAX_DIMS] (i.e., 1–4). A parser MUST reject tensors with n_dims outside this range."
- **Code Path**: `fs/ggml/gguf.go:201–206` — `dims` is read as `uint32` from the file. No upper bound is checked before `shape := make([]uint64, dims)` allocates a slice of exactly `dims` 8-byte uint64 values.
- **Gap Type**: missing-check
- **Attack Vector**: A malicious GGUF file sets `dims = 0xFFFFFFFF` (4,294,967,295) for a tensor. The Go runtime attempts to allocate `4,294,967,295 * 8 = ~32 GiB` of memory. This causes either an OOM kill of the ollama server process or a Go runtime panic from failed allocation, both resulting in a server crash and denial of service.
- **Exploit Conditions**: Attacker can upload a GGUF blob via `/api/blobs/:digest` (unauthenticated POST) and then trigger parsing via `/api/create`. Alternatively the malicious GGUF can be pulled from an attacker-controlled registry. No special privileges required.
- **Impact**: Reliable server crash (DoS). On systems with memory overcommit disabled, immediate OOM kill. On systems with overcommit, Go's allocator will panic. Either way, the ollama service is terminated.
- **Severity**: HIGH
- **Evidence**:
  ```go
  // fs/ggml/gguf.go:201-206
  dims, err := readGGUF[uint32](llm, rs)
  if err != nil {
      return fmt.Errorf("failed to read tensor dimensions: %w", err)
  }
  shape := make([]uint64, dims)  // NO BOUNDS CHECK — dims up to 4294967295
  ```
  - The GGUF spec (defined in llama.cpp) mandates `GGML_MAX_DIMS = 4`; valid tensors have 1–4 dimensions.

---

### Gap: GGUF Format — Unbounded String Length Allocation

- **RFC/Spec**: GGUF Format Specification; the GGUF spec document (https://github.com/ggerganov/ggml/blob/master/docs/gguf.md) states string lengths are 64-bit but notes implementations should sanity-check against file size
- **Requirement**: Implementations SHOULD validate that string lengths do not exceed the remaining file size before allocating memory for the string content.
- **Code Path**: `fs/ggml/gguf.go:359–371` (`readGGUFString`) — reads a `uint64` length, then allocates `make([]byte, length)` with no maximum. On a 64-bit system, `length` can be up to 2^63-1. The `int()` cast at line 359 (`length := int(llm.ByteOrder.Uint64(buf))`) will be negative on 32-bit platforms when the high bit is set, but on 64-bit it successfully allocates a huge buffer.
- **Gap Type**: missing-check
- **Attack Vector**: A GGUF file with a KV key string whose encoded length field is `0x0000000020000000` (512 MB) will cause `make([]byte, 536870912)` — a 512 MB allocation just for one string. A KV array with thousands of such strings exhausts memory without triggering the `maxArraySize` limiter (which only applies to typed arrays, not strings). A single tensor name with length 0x7FFFFFFFFFFFFFFF attempts a 9.2 EB allocation and panics immediately.
- **Exploit Conditions**: Same as the dims gap: reachable via `/api/blobs` upload + `/api/create`, or via registry pull.
- **Impact**: DoS via OOM. Unlike the dims issue, this affects any string field including KV keys and tensor names, making it exploitable with a 4-byte GGUF file (magic + version + 1 KV entry with oversized length).
- **Severity**: HIGH
- **Evidence**:
  ```go
  // fs/ggml/gguf.go:359-363
  length := int(llm.ByteOrder.Uint64(buf))
  if length > len(llm.scratch) {
      buf = make([]byte, length)  // NO CAP — up to 2^63 bytes allocated
  }
  ```
  - Note: This pattern has already produced multiple CVEs (CVE-2025-66960, CVE-2024-12055) suggesting structural recurrence rather than one-off bugs.

---

### Gap: OCI Distribution Spec — Manifest Fetch Uses Blob Endpoint for Digest-Addressed Pulls

- **RFC/Spec**: OCI Distribution Specification v1.1.0, Section 4.3 (Pulling Manifests)
- **Requirement**: "To pull a manifest by digest, clients MUST use the endpoint `GET /v2/<name>/manifests/<digest>`. Using the blob endpoint (`/v2/<name>/blobs/<digest>`) to fetch manifests is NOT compliant." 
- **Code Path**: `server/internal/client/ollama/registry.go:786–789` — when a digest is provided, the client fetches from the *blobs* endpoint: `fmt.Sprintf("%s://%s/v2/%s/%s/blobs/%s", ...)`. This is the wrong endpoint per spec.
- **Gap Type**: parsing
- **Attack Vector**: When an OCI-compliant registry (not the custom ollama registry) is used, fetching a manifest via the blobs endpoint may return a 4xx error or return blob data rather than a manifest. A registry that silently serves whatever is at that digest (regardless of content type) could return a blob mistaken for a manifest, leading to deserialization of arbitrary binary data as JSON. The spec requires manifests to be served through the manifest endpoint which validates the content type.
- **Exploit Conditions**: Only exploitable against OCI Distribution Spec-compliant registries (not registry.ollama.ai which is a custom protocol). Medium-term concern as ollama adds compatibility with standard OCI registries.
- **Impact**: Silent fetch-of-wrong-resource when digest-addressed pull is requested against a spec-compliant OCI registry. May result in accepting arbitrary blobs as manifests.
- **Severity**: MEDIUM
- **Evidence**:
  ```go
  // server/internal/client/ollama/registry.go:786-789
  manifestURL := fmt.Sprintf("%s://%s/v2/%s/%s/manifests/%s", ...)  // tag-addressed: correct
  if d.IsValid() {
      manifestURL = fmt.Sprintf("%s://%s/v2/%s/%s/blobs/%s", ...)  // digest-addressed: WRONG endpoint
  }
  ```

---

### Gap: HTTP CORS — `Vary: Origin` Header Not Set on Non-Wildcard Responses

- **RFC/Spec**: W3C CORS Specification (Fetch Standard), Section 3.2; RFC 7234 (HTTP Caching)
- **Requirement**: "If the `Access-Control-Allow-Origin` value is not `*` (i.e., it echoes back the request's Origin), the response MUST include `Vary: Origin` to prevent caching of origin-specific responses."
- **Code Path**: `server/routes.go:1639–1669` — uses `github.com/gin-contrib/cors`. When `AllowOrigins` contains a list (not `*`), the gin-cors middleware echoes back the matching origin in `Access-Control-Allow-Origin`. Whether `Vary: Origin` is set depends entirely on the gin-contrib/cors library version in use. The `corsConfig.AllowWildcard = true` applies only when the origin matches a pattern, not a literal — the echoed response still omits `Vary` in some gin-contrib/cors versions.
- **Gap Type**: missing-check
- **Attack Vector**: If an intermediate HTTP cache (corporate proxy, CDN, nginx reverse proxy in front of an exposed ollama instance) caches a CORS preflight or simple response without `Vary: Origin`, a subsequent request from a different (potentially malicious) origin receives the cached response that was intended for a trusted origin. The cached `Access-Control-Allow-Origin: https://trusted.example.com` is served to an attacker's origin, granting cross-origin access without validation.
- **Exploit Conditions**: Requires an HTTP cache between client and server. More relevant when ollama is exposed via a proxy or load balancer. Less relevant for the default localhost-only deployment.
- **Impact**: Cache poisoning enables cross-origin request forgery to all API endpoints (including model deletion, pulling) from origins that should be denied. Complements the already-documented CORS permissiveness.
- **Severity**: MEDIUM
- **Evidence**:
  - `server/routes.go:1664` — `corsConfig.AllowOrigins = envconfig.AllowedOrigins()` (a list of specific origins, not `*`)
  - gin-contrib/cors library does not unconditionally add `Vary: Origin` in all versions; depends on whether AllowAllOrigins is false

---

### Gap: OpenAI API — `tool_choice` Parameter Silently Ignored

- **RFC/Spec**: OpenAI Chat Completions API Specification (https://platform.openai.com/docs/api-reference/chat/create), `tool_choice` parameter
- **Requirement**: "If `tool_choice` is set to `{\"type\": \"function\", \"function\": {\"name\": \"...\"}}`  the model MUST call the specified function. If `tool_choice` is `\"required\"`, the model MUST call one or more tools." The spec mandates server-side enforcement of tool selection, not advisory behavior.
- **Code Path**: `openai/openai.go:98–117` (`ChatCompletionRequest`) — `tool_choice` field is absent from the struct definition entirely. `openai/openai.go:477–658` (`FromChatRequest`) — the conversion to `api.ChatRequest` never processes `tool_choice`. The field is silently dropped.
- **Gap Type**: missing-check
- **Attack Vector**: A client using the OpenAI compat layer to enforce mandatory tool invocation (e.g., a security-sensitive agentic pipeline that relies on `tool_choice: required` to guarantee a safety-check tool is always called) receives no error but also gets no enforcement. The downstream model may choose to respond with plain text instead of calling any tool. The security control the client believes it has is entirely absent.
- **Exploit Conditions**: Applicable whenever a client (particularly agentic clients like LangChain, AutoGen, or custom orchestrators) uses the `/v1/chat/completions` endpoint with `tool_choice` expecting enforcement. No special attacker-controlled input required; the gap is architectural.
- **Impact**: Silent bypass of caller-mandated tool enforcement. In agentic security architectures that use `tool_choice: required` to ensure compliance checks, logging tools, or authorization tools are always invoked, this means those checks are silently skipped. The API presents false assurance to the caller.
- **Severity**: MEDIUM
- **Evidence**:
  - `openai/openai.go:98–117` — `ChatCompletionRequest` struct has no `ToolChoice` field
  - `docs/api/openai-compatibility.mdx:214` — `- [ ] tool_choice` (documented as unimplemented)
  - `openai/responses.go:313` — comment: "TODO(drifkin): tool_choice is not supported"
  - Same gap exists in Anthropic compat: `docs/api/anthropic-compatibility.mdx:321` — `- [ ] tool_choice`

---

### Gap: Anthropic Messages API — `tool_choice` Parameter Silently Ignored

- **RFC/Spec**: Anthropic Messages API (https://docs.anthropic.com/en/api/messages), `tool_choice` object
- **Requirement**: "If `tool_choice.type` is `\"any\"` Claude MUST use one of the provided tools. If `tool_choice.type` is `\"tool\"`, Claude MUST call the specified tool."
- **Code Path**: `anthropic/anthropic.go:78` — `ToolChoice *ToolChoice` is present in the `MessagesRequest` struct and deserialized, but `anthropic/anthropic.go:292–392` (`FromMessagesRequest`) never maps `r.ToolChoice` to any field in the resulting `api.ChatRequest`.
- **Gap Type**: missing-check
- **Attack Vector**: Same class as the OpenAI `tool_choice` gap. Security-enforcing tool call patterns (e.g., `{"type": "tool", "name": "safety_check"}`) are silently dropped by the translation layer.
- **Exploit Conditions**: Any Anthropic API client relying on `tool_choice` enforcement via the ollama compat layer.
- **Impact**: Bypasses mandatory tool enforcement in agentic pipelines using the Anthropic compat endpoint. Particularly relevant since the Anthropic compat layer is used by Claude Code and similar agentic tools that may embed tool_choice for safety functions.
- **Severity**: MEDIUM
- **Evidence**:
  - `anthropic/anthropic.go:78` — `ToolChoice *ToolChoice` field in struct (deserialized but unused)
  - `anthropic/anthropic.go:380–388` — `convertedRequest` construction does not include ToolChoice
  - `docs/api/anthropic-compatibility.mdx:321` — `- [ ] tool_choice`

---

### Gap: GGUF Format — `numKV` Not Validated Against File Size Before Iteration

- **RFC/Spec**: GGUF Format Specification; the spec notes that count fields describe the actual number of elements present in the file
- **Requirement**: Implementations SHOULD validate that `num_kv` and `num_tensors` do not exceed what is physically possible given the file size before beginning iteration, to prevent unbounded loop execution on malformed files.
- **Code Path**: `fs/ggml/gguf.go:141–191` — `llm.numKV()` returns a raw `uint64` from the file header. The loop `for i := 0; uint64(i) < llm.numKV(); i++` iterates without any pre-check. If `numKV` is `0xFFFFFFFFFFFFFFFF`, the loop runs until every read attempt fails (end of file), executing billions of iterations before returning an error. Same applies to `numTensor()` at line 194.
- **Gap Type**: missing-check
- **Attack Vector**: A GGUF file with `num_kv = 0x7FFFFFFFFFFFFFFF` (9.2 * 10^18) causes the parser to enter a near-infinite loop. Even with IO errors terminating the loop early (because the file has few actual bytes after the header), the overhead of `numKV()` iterations with error-path allocations may be significant. Combined with other KV fields, this enables CPU-exhaustion DoS.
- **Exploit Conditions**: Same as the dims and string length gaps. Reachable unauthenticated.
- **Impact**: CPU exhaustion / server hang leading to DoS. A file of just 32 bytes can trigger this.
- **Severity**: HIGH
- **Evidence**:
  ```go
  // fs/ggml/gguf.go:141-143
  for i := 0; uint64(i) < llm.numKV(); i++ {
      k, err := readGGUFString(llm, rs)
      // numKV() could be 2^64-1 with no pre-validation
  ```
  - The file-size-based tensor bounds check (`fs/ggml/gguf.go:248–276`) only validates tensor data offsets AFTER all KV and tensor header parsing is complete — it provides no pre-iteration guard.



## Source 2

# Spec Gap Analysis — Ollama Security Audit Phase 6

**Target:** github.com/ollama/ollama
**HEAD:** 57653b8e
**Date:** 2026-04-17

## Summary Table

| Gap | Spec | Severity | Gap Type | Key Code Path |
|-----|------|----------|----------|---------------|
| 1 | safetensors format (uint64→int64) | HIGH | parsing | `convert/reader_safetensors.go:34-40` |
| 2 | GGUF spec (alignment=0 divide-by-zero) | HIGH | missing-check | `fs/ggml/gguf.go:238,687-689` |
| 3 | GGUF spec (array count uint64→int overflow) | HIGH | parsing | `fs/ggml/gguf.go:437` |
| 4 | OCI Distribution spec (Content-Type not validated) | MEDIUM | missing-check | `server/images.go:857-874` |
| 5 | OCI Distribution spec (sha512 digest bypasses validation) | MEDIUM | canonicalization | `x/imagegen/transfer/transfer.go:165-169` |
| 6 | RFC 7233 (Content-Range not validated on 206) | HIGH | missing-check | `server/download.go:338,345` |
| 7 | RFC 6750 (auth token body unbounded) | HIGH | missing-check | `server/auth.go:81` |
| 8 | SSE de-facto standard (no `id:` field) | MEDIUM | error-handling | `middleware/openai.go:93` |
| 9 | OpenAI API compat (`reasoning` field not in schema) | MEDIUM | parsing | `openai/openai.go:310` |
| 10 | GGUF V1 string (uint64 length→int64 wrap) | HIGH | parsing | `fs/ggml/gguf.go:296-311` |
| 11 | RFC 2397 data URI (blank MIME bypass) | HIGH | normalization | `openai/openai.go:683-684` |
| 12 | OCI Distribution spec (no manifest signature verification) | HIGH | missing-check | `server/images.go:720-792` |
| 13 | RFC 7235 WWW-Authenticate (custom parser, comma injection) | HIGH | parsing | `server/images.go:995-1026` |
| 14 | GGUF spec (numKV unbounded iteration) | HIGH | missing-check | `fs/ggml/gguf.go:143` |

## Gap 1: safetensors Spec — Header Length Read as int64 Instead of spec-mandated uint64
- Spec: safetensors format §"File Format" — uint64 little-endian header size
- Code: `convert/reader_safetensors.go:34-40` declares `var n int64`, then `io.CopyN(b, f, n)`
- Attack: header length `0x80...` → negative n → `io.CopyN` copies until EOF → unbounded buffer growth → OOM
- Severity: HIGH

## Gap 2: GGUF general.alignment=0 → divide-by-zero panic
- Spec: GGUF spec — alignment must be multiple of 8 (>0 implicit)
- Code: `fs/ggml/gguf.go:238,687-689` — `(align - offset%align) % align` panics when align=0
- Attack: upload GGUF with `general.alignment = 0` → goroutine panic → DoS
- Severity: HIGH

## Gap 3: GGUF Array Count uint64→int Wrap → Negative-Size make
- Code: `fs/ggml/gguf.go:430-437` — `int(n)` after `readGGUF[uint64]` then `make` panics
- Attack: array count `0x8000000000000001` → negative int → makeslice panic → DoS
- Severity: HIGH (CVE-2025-66959 class)

## Gap 4: OCI Manifest Content-Type Not Validated
- Code: `server/images.go:857-874` — sets Accept but ignores response Content-Type
- Attack: malicious registry returns alt media type → routing to un-verified pullWithTransfer path
- Severity: MEDIUM

## Gap 5: sha512 Digest Bypass via digestToPath
- Code: `x/imagegen/transfer/transfer.go:165-169` — naive `digest[:6] + "-" + digest[7:]`
- Attack: parser differential between `BlobsPath` (sha256-only regex) and `digestToPath` (any algo)
- Severity: MEDIUM

## Gap 6: HTTP Range/Content-Range Not Validated
- Code: `server/download.go:338,345` and `x/imagegen/transfer/download.go:189-209` write to client-computed offset
- Attack: malicious CDN returns mismatched Content-Range → targeted byte-section corruption
- Severity: HIGH

## Gap 7: Auth Token Response Body Unbounded
- Code: `server/auth.go:81` — `io.ReadAll(response.Body)` no size limit, no timeout
- Attack: malicious auth endpoint sends multi-GB response → OOM (CVE-2024-12886 class)
- Severity: HIGH

## Gap 8: SSE Stream Missing `id:` Field
- Code: `middleware/openai.go:93`, `middleware/anthropic.go:936`
- Attack: client cannot reconnect with Last-Event-ID → DoS on long streams
- Severity: MEDIUM

## Gap 9: OpenAI API Schema — `reasoning` Field Non-Compliant
- Code: `openai/openai.go:310` — `Reasoning: r.Message.Thinking` in delta
- Impact: strict-validating clients reject responses → users disable validation → security weakening
- Severity: MEDIUM

## Gap 10: GGUF V1 String Length uint64→int64 Wrap
- Code: `fs/ggml/gguf.go:296-311` — `var length uint64`, `io.CopyN(&b, r, int64(length))`, then `b.Truncate(b.Len()-1)` panics
- Attack: V1 string length `0x8000000000000001` → CopyN no-op → Truncate(-1) panic
- Severity: HIGH

## Gap 11: Blank MIME Type Data URI Bypass
- Code: `openai/openai.go:683-684` — `data:;base64,` short-circuits MIME allowlist
- Attack: send arbitrary binary as image, reaches mtmd_helper_bitmap_init_from_buf cgo sink → CVE-2025-15514 class
- Severity: HIGH

## Gap 12: pullWithTransfer Has No Manifest-Signature Verification
- Code: `server/images.go:720-792` — circular sha256 verify against attacker-supplied digest
- Impact: model poisoning when registry compromised (no Notation/Sigstore)
- Severity: HIGH

## Gap 13: WWW-Authenticate Custom Parser — Quoted-Comma Injection
- Code: `server/images.go:995-1026` — `getValue` confused by embedded comma in quoted realm URL
- Attack: malicious registry serves `realm="https://evil.example.com/a,b"` → truncated realm passes host check → CVE-2025-51471 partial bypass
- Severity: HIGH

## Gap 14: GGUF numKV Unbounded Iteration
- Code: `fs/ggml/gguf.go:143` — `for i:=0; uint64(i) < llm.numKV(); i++` no upper limit
- Attack: large NumKV with valid partial entries → CPU/memory exhaustion (CVE-2025-0315 class)
- Severity: HIGH

---

**Files examined:** `fs/ggml/gguf.go`, `fs/gguf/gguf.go`, `convert/reader_safetensors.go`, `server/auth.go`, `server/download.go`, `server/images.go`, `x/imagegen/transfer/*`, `middleware/openai.go`, `middleware/anthropic.go`, `openai/openai.go`, `manifest/*`

