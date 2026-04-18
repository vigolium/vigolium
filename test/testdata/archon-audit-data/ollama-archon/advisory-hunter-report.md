# Advisory Hunter Report — Ollama Security Audit Phase 1

**Target:** github.com/ollama/ollama  
**HEAD:** 57653b8e42d69ec35f68a59857bad4d0f07994a3 (branch: audit)  
**Audit date:** 2026-04-17  
**Analyst:** Advisory Hunter (Phase 1)

---

## Advisory Intelligence

### Collection Metadata

- **Tier reached:** Tier 2 (all-time, expanded from 2-year window due to richness of pre-2024 history)
- **Total advisories collected:** 30 unique records (Ollama-direct: 23; llama.cpp/ggml/ecosystem: 7)
- **Recent 2yr (2024-04-17 to 2026-04-17):** 25 advisories
- **Older (pre-2024):** 5 advisories (DNS rebinding, golang.org/x/net CVEs)
- **Severity distribution:** CRITICAL: 4, HIGH: 20, MEDIUM: 4, LOW: 0
- **Sources consulted:** Repo (git log + SECURITY.md), OSV API (27 Ollama records found), NVD REST API, GitHub Advisory Database, Wiz, Oligo Security, Gecko Security, Sonar, Cisco Talos, NCC Group, huntr.com

---

### Advisory Inventory

#### Part A — Ollama Core Advisories (Direct CVEs)

| ID | GHSA | Severity | CVSS | Affected Versions | Patched Version | CWE(s) | Component | Description |
|----|------|----------|------|-------------------|-----------------|---------|-----------|-------------|
| CVE-2024-28224 | GHSA-5jx5-hqx5-2vrj | MEDIUM | 6.6 | < 0.1.29 | 0.1.29 | CWE-346 | HTTP server / Host validation | DNS rebinding allows unauthenticated API access, model deletion, DoS via browser SOP bypass |
| CVE-2024-37032 | GHSA-8hqg-whrw-pv92 | HIGH | 8.8 | < 0.1.34 | 0.1.34 | CWE-22 | Blob digest validation / model pull | Path traversal via malformed sha256 digest (e.g. "../" prefix) in /api/pull → arbitrary file write → RCE ("Probllama") |
| CVE-2024-39719 | GHSA (no dedicated record) | HIGH | 7.5 | <= 0.1.47 (unpatched at 0.3.14) | 0.1.47+ | CWE-209 | /api/create endpoint | Error message "File does not exist" discloses server file-system paths to unauthenticated callers |
| CVE-2024-39720 | GHSA-95j2-w8x7-hm88 | HIGH | 8.2 | <= 0.1.45 | 0.1.46 | CWE-125 | GGUF parser / /api/create | 4-byte malformed GGUF triggers out-of-bounds read → segfault → DoS |
| CVE-2024-39721 | — | HIGH | 7.5 | <= 0.1.33 | 0.1.34 | CWE-404 | /api/create resource handling | Passing "/dev/random" as model path causes infinite goroutine read → CPU exhaustion (80–90%) |
| CVE-2024-39722 | — | HIGH | 7.5 | <= 0.1.45 | 0.1.46 | CWE-22 | /api/push path handling | Path traversal in push endpoint exposes server directory structure and file existence |
| CVE-2024-45436 | GHSA-846m-99qv-67mg | HIGH | 7.5 | < 0.1.47 | 0.1.47 | CWE-22 | ZIP extraction (model.go) | extractFromZipFile() allows ZipSlip — members extracted outside parent directory → arbitrary file write (also tracked as CVE-2024-7773, rejected as duplicate) |
| CVE-2024-8063 | GHSA-2xf2-gjm6-g2c6 | HIGH | 7.5 | <= 0.3.3 | not specified | CWE-369 | GGUF parser / Modelfile ingestion | Divide-by-zero via crafted block_count in Modelfile → server crash DoS |
| CVE-2024-12055 | GHSA-89qx-m49c-8crf | HIGH | 7.5 | <= 0.3.14 | not specified | CWE-125 | gguf.go out-of-bounds read | Out-of-bounds read via malicious GGUF → DoS (server crash) |
| CVE-2024-12886 | GHSA-v464-r2r9-www7 | HIGH | 7.5 | = 0.3.14 | not specified | CWE-409 | makeRequestWithRetry / getAuthorizationToken | Gzip bomb via malicious API response → io.ReadAll memory exhaustion → crash |
| CVE-2025-0312 | GHSA-p2wh-w96x-w232 | HIGH | 7.5 | <= 0.3.14 | not specified | CWE-476 | GGUF parser (gguf.go) | Null pointer dereference via malicious GGUF → server crash DoS |
| CVE-2025-0315 | GHSA-fccc-8m69-8r78 | HIGH | 7.5 | <= 0.3.14 | not specified | CWE-770 | GGUF parser / blob upload | Unlimited memory allocation from crafted GGUF → OOM → DoS |
| CVE-2025-0317 | GHSA-9gcr-28rp-cc24 | HIGH | 7.5 | <= 0.3.14 | not specified | CWE-369 | ggufPadding function | Divide-by-zero in ggufPadding() via crafted GGUF → server crash |
| CVE-2025-1975 | GHSA-wrh5-cmwx-q2qr | HIGH | 7.5 | = 0.5.11 | not specified | CWE-129 | /api/pull manifest handler | Improper array index validation during model download → crash DoS via malicious manifest |
| CVE-2025-15514 | — | HIGH | 7.5 | 0.11.5-rc0 – 0.13.5 | 0.13.6+ | CWE-395 | /api/chat vision / multimodal | Null pointer dereference in mtmd_helper_bitmap_init_from_buf() via malformed base64 image → runner crash |
| CVE-2025-44779 | GHSA-93jv-pvg8-hf3v | MEDIUM | 6.6 | = 0.1.33 | not specified | CWE-20, CWE-552 | /api/pull endpoint | Arbitrary file deletion via crafted packet to /api/pull |
| CVE-2025-51471 | GHSA-x9hg-5q6g-q3jr | MEDIUM | 6.9 | = 0.6.7 / <= 0.9.6 | 0.9.7 | CWE-345, CWE-384 | server/auth.go getAuthorizationToken | Cross-domain token exposure: WWW-Authenticate realm not validated → auth tokens sent to attacker-controlled domain |
| CVE-2025-63389 | GHSA-f6mr-38g8-39rg | CRITICAL | 9.8 | <= 0.12.3 / <= 0.13.5 | not patched (disclosed 2025-12-18) | CWE-306, CWE-284 | Multiple API endpoints | Multiple API endpoints lack authentication → unauthorized model management operations |
| CVE-2025-66959 | — | HIGH | 7.5 | = 0.12.10 | not specified | CWE-20, CWE-400 | fs/ggml/gguf.go GGUF decoder | Unchecked length field in GGUF decoder → panic → DoS |
| CVE-2025-66960 | — | HIGH | 7.5 | = 0.12.10 | not specified | CWE-20, CWE-400 | fs/ggml/gguf.go readGGUFV1String | Untrusted GGUF V1 string length → Go panic → DoS |
| CVE-2026-5530 | GHSA-r4wp-gg33-whwg | MEDIUM | 6.3 | <= 18.1 | unpatched (vendor no response) | CWE-918 | server/download.go model pull | SSRF via Model Pull API — authenticated attacker can trigger arbitrary internal/external requests |
| Sonar-OOB-2025 | — | CRITICAL | ~9.x | < 0.7.0 | 0.7.0 (2025-05-13) | CWE-787 | mllama vision model parser (C++) | Out-of-bounds write in mllama intermediate_layers_indices metadata → std::vector<bool> bit-flip → RCE; CVE pending/not yet assigned publicly |
| x/agent path traversal | — | — (internal fix) | — | pre-c8b599bd | c8b599bd | CWE-22 | x/agent/approval.go | Hierarchical prefix matching allowed ".." components to escalate approved paths (e.g., approve "tools/file.go" → permit "tools/../../etc/passwd") |

#### Part B — Auth redirect fix (in-repo commit, matches CVE-2025-51471 root cause class)

| Commit | Date | Component | Description |
|--------|------|-----------|-------------|
| 7601f0e9 | 2026-01-16 | server/auth.go | Reject auth realm redirects to different host than original request — direct fix for CVE-2025-51471 class |
| c8b599bd | 2026-01-06 | x/agent/approval.go | Fix path traversal in agent tool approval prefix matching |
| bb8464c0 | 2023-10-25 | go.mod | Update golang.org/x/net → fixes CVE-2023-3978, CVE-2023-39325, CVE-2023-44487 |
| f02f8366 | 2024-07-17 | Dockerfile | Bump Go to 1.22.5 for Go runtime security fixes |

#### Part C — llama.cpp / ggml Ecosystem Advisories (Ollama embeds llama.cpp)

| ID | GHSA | Severity | CVSS | Affected Versions | Patched | CWE(s) | Component | Description |
|----|------|----------|------|-------------------|---------|---------|-----------|-------------|
| CVE-2024-34359 | GHSA-56xg-wfcc-g829 | CRITICAL | 9.7 | llama-cpp-python 0.2.30–0.2.71 | 0.2.72 | CWE-76 | Jinja2ChatFormatter / GGUF metadata | SSTI via Jinja2 chat template in GGUF metadata → RCE (affects llama-cpp-python, but demonstrates GGUF metadata injection risk) |
| TALOS-2024-1913 | — | HIGH | 8.8 | llama.cpp commit 18c2e17 | post-2024-01-29 | CWE-122, CWE-680 | gguf_fread_str | Heap buffer overflow in GGUF string reader (integer overflow in p->n + 1 → calloc under-allocation) → code execution |
| TALOS-2024-1914 | — | HIGH | 8.8 | llama.cpp | patched | CWE-122 | gguf tensor info ne[] | Heap buffer overflow via oversized n_dims (> GGML_MAX_DIMS=4) — out-of-bounds write in tensor info array |
| TALOS-2024-1915 | — | HIGH | 8.8 | llama.cpp | patched | CWE-122, CWE-190 | gguf_tensor_info allocation | Integer overflow in n_tensors * sizeof(gguf_tensor_info) → heap OOB |
| CVE-2025-49847 | GHSA-8wwf-w4qm-gpqr | HIGH | 8.8 | llama.cpp < b5662 | b5662 | CWE-119, CWE-195 | llama_vocab::impl::token_to_piece _try_copy | Signed-to-unsigned conversion: token size > INT32_MAX → int32_t negative → length check bypass → unchecked memcpy → memory corruption → potential RCE |
| CVE-2025-53630 | GHSA-vgg9-87g3-85w8 | HIGH | — | llama.cpp < 26a48ad | 26a48ad | CWE-122, CWE-680 | gguf_init_from_file_impl size accumulation | Integer overflow in cumulative tensor size (ctx->size += GGML_PAD(...)) → undersized heap allocation → OOB read/write |
| CVE-2026-21869 | GHSA-8947-pfff-2f3c | HIGH | 8.8 | llama.cpp <= 55d4206c8 | unpatched | CWE-787 | llama-server KV cache shift | Negative n_discard via /completions or /chat/completions → reversed memory range → OOB write beyond std::vector end → crash / RCE |
| CVE-2026-33298 | GHSA-96jg-mvhq-q7q7 | HIGH | 7.8 | llama.cpp < b7824 | b7824 | CWE-122, CWE-190 | ggml_nbytes | Integer overflow in (ne[i]-1)*nb[i] → undersized allocation → heap OOB when tensor is accessed |

---

### Dependency-Linked CVEs (golang.org/x packages — from commit bb8464c0)

| CVE | Severity | Component | Impact |
|-----|----------|-----------|--------|
| CVE-2023-3978 | MEDIUM | golang.org/x/net/html | Cross-site scripting via html parser |
| CVE-2023-39325 | HIGH | golang.org/x/net/http2 | HTTP/2 rapid reset → DoS (CVE-2023-44487 in Go) |
| CVE-2023-44487 | HIGH | golang.org/x/net/http2 | HTTP/2 Rapid Reset Attack |

---

## Vulnerability Pattern Analysis

### 2a. Component Vulnerability Heatmap

| Rank | Component | Advisory Count | Severity Dist. | Dominant Bug Types |
|------|-----------|---------------|----------------|--------------------|
| 1 | **GGUF Parser** (gguf.go, ggml/src/gguf.cpp, fs/ggml/gguf.go) | 13 | CRITICAL:1, HIGH:11, MEDIUM:1 | OOB read/write, integer overflow, divide-by-zero, null deref, resource exhaustion, string length unchecked |
| 2 | **Model Pull/Push/Create API** (/api/pull, /api/push, /api/create) | 8 | HIGH:6, MEDIUM:2 | Path traversal, file existence disclosure, arbitrary deletion, SSRF, auth bypass, resource exhaustion |
| 3 | **Authentication / Token Flow** (server/auth.go getAuthorizationToken) | 3 | CRITICAL:1, MEDIUM:2 | Cross-domain token exposure, gzip bomb DoS, missing auth for critical functions |
| 4 | **ZIP / Archive Extraction** (model.go extractFromZipFile) | 2 | HIGH:2 | ZipSlip path traversal → arbitrary file write, RCE |
| 5 | **Vision / Multimodal Image Processing** (mllama parser, /api/chat) | 2 | CRITICAL:1, HIGH:1 | OOB write in C++ mllama handler, null ptr deref in base64 bitmap init |
| 6 | **HTTP Server Host Validation** (DNS rebinding, Host header) | 1 | MEDIUM:1 | Origin validation error |
| 7 | **Agent Tool Approval** (x/agent/approval.go) | 1 | internal | Path traversal in hierarchical prefix matching |

**High-heat components (3+ advisories or any CRITICAL):** GGUF Parser, Model Pull/Push/Create API, Authentication/Token Flow, Vision/Multimodal Processing.

---

### 2b. Bug Type Recurrence

| Bug Class | CWEs | Count | Examples |
|-----------|------|-------|---------|
| **Path Traversal / Directory Traversal** | CWE-22 | 6 | CVE-2024-37032 (digest → RCE), CVE-2024-39722 (push), CVE-2024-45436 (ZipSlip), CVE-2024-39719 (create/disclosure), x/agent (approval bypass), CVE-2025-44779 (delete) |
| **DoS / Resource Exhaustion / Crash** | CWE-400, CWE-770, CWE-404, CWE-476, CWE-395, CWE-369, CWE-409 | 11 | CVE-2024-39720/21, CVE-2024-12886, CVE-2025-0312/0315/0317, CVE-2024-8063, CVE-2024-12055, CVE-2025-1975, CVE-2025-66959/66960, CVE-2025-15514 |
| **Integer Overflow / Buffer Overflow (Memory Corruption)** | CWE-122, CWE-190, CWE-680, CWE-787, CWE-119 | 8 | TALOS-2024-1913/1914/1915, CVE-2025-49847, CVE-2025-53630, CVE-2026-21869, CVE-2026-33298, Sonar-OOB-2025 |
| **Missing / Broken Authentication** | CWE-306, CWE-284 | 2 | CVE-2025-63389 (no auth on API), CVE-2024-28224 (DNS rebinding bypasses auth) |
| **Auth Token / Credential Exposure** | CWE-345, CWE-384, CWE-601 | 2 | CVE-2025-51471 (cross-domain realm redirect), CVE-2024-12886 (gzip bomb on auth endpoint) |
| **SSRF** | CWE-918 | 1 | CVE-2026-5530 (model pull API download.go) |
| **Info Disclosure** | CWE-200, CWE-209 | 2 | CVE-2024-39719 (file existence error msgs), CVE-2024-37032 (file content via path traversal) |
| **Injection / Code Execution** | CWE-78, CWE-76 | 2 | CVE-2025-15063 (MCP server cmd injection), CVE-2024-34359 (SSTI in llama-cpp-python Jinja2/GGUF) |
| **Origin Validation Error** | CWE-346 | 1 | CVE-2024-28224 (DNS rebinding Host header) |

**Recurring bug types (2+ advisories):** Path Traversal (6), DoS/Resource Exhaustion (11), Memory Corruption/Integer Overflow (8), Auth issues (4 combined). Path traversal and GGUF-triggered crashes are the dominant structural patterns.

---

### 2c. Attack Surface Trends

| Rank | Input Vector | Times Exploited | Notes |
|------|-------------|----------------|-------|
| 1 | **Malicious GGUF model file via /api/create, /api/blobs upload** | 13 | Every variant of DoS, OOB read/write, integer overflow, null deref, divide-by-zero. The GGUF format is a persistent attack surface. |
| 2 | **HTTP API endpoints without authentication** | 8 | /api/pull, /api/push, /api/create — all historically accepted unauthenticated requests; attackers exploited them for file traversal, resource exhaustion, model theft/poisoning |
| 3 | **Registry/manifest pull from attacker-controlled host** | 4 | CVE-2024-37032 (path traversal via digest), CVE-2025-51471 (cross-domain token), CVE-2024-12886 (gzip bomb), CVE-2025-1975 (array index) — the pull endpoint's trust of remote manifest content is repeatedly abused |
| 4 | **ZIP/archive upload** | 2 | CVE-2024-45436 (ZipSlip) via /api/create — any ZIP-based model creation path is suspect |
| 5 | **Multimodal / vision API (/api/chat with images)** | 2 | Malformed base64 image data (CVE-2025-15514), mllama metadata OOB write (Sonar-OOB-2025) |
| 6 | **DNS rebinding / Host header manipulation** | 1 | CVE-2024-28224 — browser-based attacker abuses DNS rebinding to proxy requests to localhost Ollama |
| 7 | **WWW-Authenticate header realm manipulation** | 1 | CVE-2025-51471 — server follows untrusted realm URL for token fetch |
| 8 | **Agent tool execution path** | 1 | c8b599bd — tool command strings with ".." escape approval prefix matching |

---

### 2d. Patch Quality Signals (Structural Recurrence)

The following components have been patched multiple times for the same bug class, signaling structurally incomplete fixes:

| Component | Patch History | Bug Class | Signal |
|-----------|--------------|-----------|--------|
| **GGUF Parser (gguf.go / ggml/src/gguf.cpp)** | CVE-2024-39720, CVE-2024-12055, CVE-2025-0312, CVE-2025-0315, CVE-2025-0317, CVE-2024-8063, CVE-2025-66959, CVE-2025-66960 — 8 separate advisories | OOB read, null deref, divide-by-zero, resource exhaustion | STRUCTURAL RECURRENCE — each patch fixed one specific check without a holistic GGUF validation framework. The parser is the #1 structural-recurrence candidate. |
| **Model Pull /api/pull endpoint** | CVE-2024-37032, CVE-2025-1975, CVE-2025-44779, CVE-2025-51471, CVE-2024-12886 — 5 advisories | Path traversal, array OOB, arbitrary deletion, token exposure, gzip bomb | STRUCTURAL RECURRENCE — the pull pipeline repeatedly trusts external manifest/header data. Holistic input validation and output sanitization were not applied globally after each fix. |
| **Auth token acquisition (getAuthorizationToken / server/auth.go)** | CVE-2024-12886 (gzip bomb on auth), CVE-2025-51471 (realm redirect), commit 7601f0e9 (host validation fix) | Resource exhaustion, credential exposure | RECURRENT AUTH SURFACE — the auth flow was patched twice (gzip limit, host validation) but other untrusted-input paths in that function warrant review. |
| **Path traversal (filesystem access across multiple endpoints)** | CVE-2024-37032 (blob digest), CVE-2024-39722 (push), CVE-2024-45436 (ZIP), CVE-2024-39719 (create/info leak), CVE-2025-44779 (delete), c8b599bd (agent) | CWE-22 | STRUCTURAL RECURRENCE — path traversal has appeared in blob handling, push, create, ZIP extraction, and agent approval. There is no single sanitization layer; each endpoint was patched individually. |

---

### Audit Targeting Recommendations

Based on the pattern analysis above:

**Phase 3 (DFD/Architecture)** should prioritize slicing:
- The GGUF ingest pipeline: /api/blobs -> blob store -> gguf.go parser -> llama runner invocation
- The /api/pull manifest fetch pipeline: remote registry -> digest validation -> file write -> model activation
- The auth token acquisition flow: challenge parsing -> realm URL handling -> token fetch -> request signing

**Phase 5 (Deep Probe)** should target entry points:
- GGUF metadata fields (all numeric and string fields in GGUF header) via /api/create and /api/blobs
- The WWW-Authenticate realm value in any 401 response from a registry-facing request
- Base64-encoded image payloads in /api/chat (multimodal path)
- ZIP archive content in /api/create blob ingestion
- The "name" field in /api/pull (model reference parsing)

**Phase 8 (Review Chambers)** must include as mandatory attack modes:
- CWE-22 Path Traversal (persistent across 6 advisories, multiple endpoints)
- CWE-122/CWE-190 Integer Overflow to Buffer Overflow (GGUF parser, llama.cpp)
- CWE-306 Missing Authentication / CWE-346 Origin Validation (DNS rebinding, API endpoint exposure)
- CWE-918 SSRF (model pull download.go — only 1 CVE but architecturally significant given the pull-from-URL design)
- CWE-400 Resource Exhaustion / CWE-409 Data Amplification (gzip bomb pattern in auth and pull flows)

**Patch-bypass-checker** should flag as structural-recurrence candidates:
- fs/ggml/gguf.go (GGUF parser) — 8 separate advisories, each a point fix
- server/download.go (model pull/manifest handling) — 5 advisories across 4 different bug classes
- server/auth.go (getAuthorizationToken) — 2 advisories plus 1 in-repo fix

---

## Architecture Inventory

### Components

| Component | Role | Trust Level |
|-----------|------|-------------|
| `server/routes.go` + gin HTTP server | REST API router (default :11434) | Internet-facing if misconfigured; localhost by default |
| `server/images.go` | Model manifest management, blob operations | Internal |
| `server/model.go` | Model loading, ZIP extraction, blob resolution | Internal (processes untrusted model content) |
| `server/download.go` | Model pull from registry, chunked HTTP download | External network trust boundary |
| `server/auth.go` | Registry authentication, bearer token fetch | External (communicates with registry.ollama.ai and arbitrary auth realms) |
| `server/create.go` | Modelfile parsing and model creation | Internal; processes user-supplied Modelfile and file paths |
| `server/sched.go` | Model scheduler, GPU/CPU resource allocation | Internal |
| `llama/` (llama.go + llama.cpp subdir) | Go bindings to llama.cpp inference engine | Internal; loads GGUF files from disk |
| `fs/ggml/gguf.go` | Pure-Go GGUF file parser | Internal; processes untrusted model binary data |
| `runner/` | llama.cpp-based inference runner process | Internal subprocess; spawned by scheduler |
| `mlxrunner/` | MLX inference runner (Apple Silicon) | Internal subprocess |
| `x/agent/` | Agentic tool approval, tool invocation gating | Internal; new addition — processes user tool commands |
| `api/` | Go client SDK types and OpenAI-compat layer | Used by CLI and integrations |
| `cmd/` | CLI entry points (run, pull, push, create, serve) | User-facing |
| `anthropic/`, `openai/` | Cloud LLM proxy handlers | External cloud API trust boundary |
| `middleware/` | HTTP middleware (CORS, logging, etc.) | Cross-cutting |
| `convert/` | Model weight conversion (safetensors, GGUF, etc.) | Internal; processes arbitrary model formats |
| `app/` | Desktop app (Electron/system tray) | Local desktop trust |

### Transports and Protocols

| Transport | Endpoints | Notes |
|-----------|-----------|-------|
| HTTP/1.1 (gin) | /api/generate, /api/chat, /api/pull, /api/push, /api/create, /api/blobs/:digest, /api/tags, /api/delete, /api/show, /api/copy | No auth by default; TLS only if explicitly configured |
| HTTP SSE | /api/generate, /api/chat | Streaming responses |
| OpenAI-compat HTTP | /v1/chat/completions, /v1/models, /v1/completions | REST, no auth by default |
| HTTP to registry | registry.ollama.ai (HTTPS), HuggingFace endpoints | Bearer token auth, but realm not fully validated until 7601f0e9 fix |
| HTTP to cloud providers | Anthropic, OpenAI APIs | Via proxy handler |
| Unix/OS subprocess IPC | runner process spawned by scheduler | stdin/stdout piping for inference |
| File system | Model blobs at ~/.ollama/models, GGUF files | Trust boundary: any user/process with FS access can place malicious GGUF |
| CLI | cobra commands | Local user trust |

### Trust Boundaries

| Boundary | Description | Risk Level |
|----------|-------------|------------|
| Internet → HTTP API | Ollama binds to 0.0.0.0 in Docker by default; no auth required | CRITICAL — historically exploited |
| Browser (DNS rebinding) → localhost API | Browser SOP can be bypassed via DNS rebinding against localhost:11434 | HIGH |
| Remote registry → model manifest + blobs | Manifest data (digests, layers, URLs) fully trusted for file operations | HIGH |
| Auth realm (WWW-Authenticate) → token fetch | Realm URL followed without host validation until recent fix | HIGH |
| Model file (GGUF) → inference engine | GGUF format parsed with insufficient bounds checking historically | CRITICAL |
| Agent tool approval → OS command execution | Path traversal can bypass approval policy | HIGH |
| ZIP archive → file system | ZipSlip allows writes outside extraction directory | HIGH |
| Cloud proxy → external LLM APIs | Credentials passed through; supply chain trust | MEDIUM |

### Execution Environments

- **Go HTTP server** (gin): main server process, handles all REST API traffic
- **llama.cpp runner** (C++): spawned subprocess for GGUF inference; C++ memory safety risks
- **MLX runner** (Python/Swift): Apple Silicon subprocess
- **Docker container**: historically ran as root with 0.0.0.0 binding — critical exposure amplifier
- **Desktop app**: Electron wrapper, system tray, auto-update surface

### Highest-Risk Flows

1. **Unauthenticated POST /api/create with malformed GGUF path** → file existence oracle + DoS (10 CVEs)
2. **POST /api/pull with attacker-controlled manifest** → path traversal via digest field → arbitrary file write → RCE (CVE-2024-37032, the Probllama attack)
3. **POST /api/blobs/sha256:... with malicious GGUF content** → parser crash, OOB read/write, integer overflow (8+ CVEs)
4. **POST /api/pull with attacker-controlled registry** → crafted WWW-Authenticate realm → token exfiltration (CVE-2025-51471)
5. **DNS rebinding of browser → GET /api/tags or DELETE /api/delete** → model enumeration, deletion without auth (CVE-2024-28224)
6. **POST /api/chat with malformed base64 image** → mllama vision OOB write → RCE; or null deref → crash (Sonar-OOB-2025, CVE-2025-15514)
7. **Agent tool execution with ".." in command** → approval bypass → OS command execution (c8b599bd)

---

## Dependency Intelligence

### Security-Critical Dependencies (go.mod)

| Dependency | Version in go.mod | Security Relevance | Pattern Cross-Reference |
|------------|------------------|--------------------|------------------------|
| `github.com/gin-gonic/gin` | v1.10.0 | HTTP routing; historically vulnerable to H2 reset attack via x/net transitive dep; handles all API input parsing | Cross-refs CVE-2023-44487 (HTTP/2 rapid reset via golang.org/x/net) |
| `golang.org/x/net` | v0.46.0 (indirect) | HTTP/2, HTML parsing; previously patched via commit bb8464c0 for CVE-2023-3978, CVE-2023-39325, CVE-2023-44487 | DoS (CVE-2023-39325/44487), XSS (CVE-2023-3978) — older versions in Ollama were vulnerable |
| `golang.org/x/crypto` | v0.43.0 | Cryptographic operations; used in auth signing | Historically had numerous vulns; version 0.43.0 is relatively recent |
| `github.com/klauspost/compress` | v1.18.3 | Compression/decompression; handles gzip in responses | Cross-refs CVE-2024-12886 (gzip bomb via io.ReadAll) — compress library itself not directly at fault but usage pattern matters |
| `github.com/mattn/go-sqlite3` | v1.14.24 | SQLite C bindings; potential SQL injection or memory corruption surface | CWE-89 risk if queries use user-supplied model names; memory safety concern (C FFI) |
| `github.com/ledongthuc/pdf` | v0.0.0-20250511090121-5959a4027728 | PDF parsing; recent addition | Novel attack surface for crafted PDF-based model data; no known CVEs but pdf parsers have historical vuln patterns |
| `github.com/nlpodyssey/gopickle` | v0.3.0 | Python pickle deserialization | CWE-502 (Unsafe Deserialization) risk — pickle is a known RCE vector for PyTorch model files; if used in safetensors/convert path, represents significant risk |
| `github.com/google/flatbuffers` | v24.3.25+incompatible | FlatBuffers serialization | Used in model conversion; FlatBuffers parsers have had OOB read vulns historically |
| `llama.cpp` (embedded, C++) | See llama/llama.cpp subdir | Core inference engine; all GGUF/ggml parsing at C++ level | Cross-refs ALL TALOS-2024-1913/14/15, CVE-2025-49847, CVE-2025-53630, CVE-2026-21869, CVE-2026-33298 — the embedded llama.cpp version determines which of these affect this repo |
| `github.com/bytedance/sonic` | v1.11.6 | Fast JSON serializer (uses unsafe operations) | Uses Go unsafe package — potential memory safety concerns in high-throughput JSON paths |
| `github.com/gin-contrib/cors` | v1.7.2 | CORS middleware | Misconfigured CORS can amplify DNS rebinding / CSRF; cross-refs CVE-2024-28224 pattern |

### Embedded llama.cpp Version Assessment

The repo contains llama.cpp as a git submodule/subtree under `llama/llama.cpp/`. The patches directory (`llama/patches/`) contains 36 Ollama-specific patches applied on top of upstream llama.cpp. The key security question is which upstream llama.cpp commit the current code is based on, which determines exposure to:

- TALOS-2024-1913/14/15 (heap buffer overflows in GGUF string/tensor parsing)
- CVE-2025-49847 (signed-to-unsigned conversion → memcpy overflow in vocab loading)
- CVE-2025-53630 (integer overflow in cumulative tensor size)
- CVE-2026-21869 (OOB write in llama-server KV cache shift via negative n_discard)
- CVE-2026-33298 (integer overflow in ggml_nbytes)

Patch `0010-fix-string-arr-kv-loading.patch` modifies `ggml/src/gguf.cpp` directly, indicating active maintenance of the GGUF C++ parser by the Ollama team. However, without a clear upstream commit pin visible, all the above llama.cpp CVEs should be treated as potentially applicable until verified.

### Dependency Risk Summary

- **CRITICAL RISK:** Embedded llama.cpp C++ code (GGUF parser, vocab loader, KV cache shift) — 7+ upstream CVEs, direct exploitation path via model upload
- **HIGH RISK:** `golang.org/x/net` gzip handling via `io.ReadAll` (gzip bomb pattern, CVE-2024-12886 class) — mitigated in current version but usage patterns in auth and download code warrant review
- **HIGH RISK:** `github.com/nlpodyssey/gopickle` — Python pickle deserialization is a notorious RCE vector; if reachable via API with attacker-controlled input, this is a severity-critical finding
- **MEDIUM RISK:** `github.com/mattn/go-sqlite3` — C FFI; SQL injection risk if model names or user inputs are interpolated into queries
- **MEDIUM RISK:** `github.com/ledongthuc/pdf` — new dependency; PDF parsers are historically vulnerability-prone

---

## Patch Commit Summary (First-Party Security Fixes)

| Commit SHA | Date | Description | CVE Reference |
|------------|------|-------------|---------------|
| `bb8464c0` | 2023-10-25 | Update golang.org/x/net | CVE-2023-3978, CVE-2023-39325, CVE-2023-44487 |
| `f02f8366` | 2024-07-17 | Bump Go runtime to 1.22.5 | Go stdlib security fixes |
| `7601f0e9` | 2026-01-16 | Reject auth realm redirects to different host | CVE-2025-51471 class / cross-domain token exposure |
| `c8b599bd` | 2026-01-06 | Reject ".." in agent tool approval prefix paths | Internal path traversal fix (x/agent) |
| `6b2abfb4` | ~2026 | server: add tests and fix isHuggingFaceURL edge case | Trust boundary for HuggingFace URL origin validation |

---

*Report generated by Advisory Hunter — Phase 1, Ollama Security Audit 2026-04-17*
