# Merged Advisory Report

## Included Sources

- `.archon-merge-staging-1765496804/advisory-report.md`
- `ollama-with-opus-4.7/advisory-report.md` not present

## Source 1

# Ollama Security Advisory Report

Generated: 2026-04-07
Repository: ollama/ollama
Commit: 8c8f8f3450d39735355fc6cd7f2e436c8aa42ab1

---

## Architecture Inventory

### Primary Language and Runtime
- **Language**: Go 1.24.1 (primary), C/C++ (GGML/llama.cpp inference backend via CGo)
- **Web Framework**: gin-gonic/gin v1.10.0
- **Platform**: Multi-platform binary (Linux, macOS, Windows); macOS app wrapper (Objective-C/Swift)

### Component Map

| Component | Path | Description |
|-----------|------|-------------|
| HTTP API Server | `server/` | REST endpoints for model management and inference |
| GGUF/GGML Parser | `fs/ggml/gguf.go`, `llm/gguf/` | Binary model file format reader (C++ + Go) |
| Model Manager | `server/images.go`, `server/model.go` | Pull, push, create, delete model operations |
| Download Engine | `server/download.go` | HTTP model blob download with redirect handling |
| Authentication | `server/auth.go`, `auth/` | Bearer token auth to registry, key signing |
| LLM Runner | `llm/`, `runner/` | Inference process management (llama.cpp via CGo) |
| OpenAI Compat Layer | `openai/`, `middleware/` | Translates OpenAI API calls to Ollama internals |
| Anthropic Compat Layer | `middleware/` | `/v1/messages` endpoint |
| CLI | `cmd/` | Cobra-based CLI, `ollama run`, `serve`, `pull`, etc. |
| Agent/Tool Engine | `x/agent/` | Agentic tool-call orchestration with file-path approval |
| Template Engine | `template/` | Go text/template-based prompt rendering |
| ZIP Extractor | `server/model.go` | Extracts GGUF files from ZIP archives |
| Blob Store | `server/` | Content-addressed local file store for model blobs |
| SQLite Store | (via `mattn/go-sqlite3`) | Dependency; used internally |
| Cloud Proxy | `server/cloud_proxy.go` | Passes requests to Ollama cloud inference |
| Web Search/Fetch | `server/routes.go` (experimental) | Proxies web search/fetch requests |

### API Endpoints (Attack Surface)

| Method | Path | Function | Auth |
|--------|------|----------|------|
| POST | `/api/pull` | PullHandler | None (default) |
| POST | `/api/push` | PushHandler | Token |
| POST | `/api/create` | CreateHandler | None |
| POST | `/api/blobs/:digest` | CreateBlobHandler | None |
| DELETE | `/api/delete` | DeleteHandler | None |
| POST | `/api/show` | ShowHandler | None |
| GET | `/api/tags` | ListHandler | None |
| POST | `/api/generate` | GenerateHandler | None |
| POST | `/api/chat` | ChatHandler | None |
| POST | `/api/embed` | EmbedHandler | None |
| GET | `/api/ps` | PsHandler | None |
| POST | `/api/copy` | CopyHandler | None |
| POST | `/api/me` | WhoamiHandler | Token |
| POST | `/api/signout` | SignoutHandler | Token |
| POST | `/v1/chat/completions` | (OpenAI compat) | None |
| POST | `/v1/responses` | (OpenAI compat) | None |
| POST | `/v1/messages` | (Anthropic compat) | None |
| POST | `/api/experimental/web_search` | WebSearchExperimentalHandler | None |
| POST | `/api/experimental/web_fetch` | WebFetchExperimentalHandler | None |

### Transports and Trust Boundaries

- **Primary transport**: HTTP/1.1 over TCP (default: localhost:11434; can be configured via `OLLAMA_HOST`)
- **External network access**: `server/download.go` makes outbound HTTP to model registries (ollama.com, HuggingFace)
- **Trust model**: By default binds to localhost only. `allowedHostsMiddleware` enforces Host header validation to mitigate DNS rebinding. When exposed on 0.0.0.0, the API is unauthenticated by default.
- **Inference subprocess**: llama.cpp runner launched as a subprocess; CGo bridge to C++ GGML/GGUF library
- **File system trust boundary**: blob files stored at `~/.ollama/models`; ZIP extraction and digest validation guard against path traversal

### Execution Environments
- Local daemon process (not containerized by default)
- Docker supported via Dockerfile
- macOS native app wrapper
- Cloud/Kubernetes deployments (no RBAC or multi-tenancy out of box)

### Highest-Risk Flows
1. **`/api/pull` + `/api/create` + `/api/blobs/:digest`**: unauthenticated, accepts user-controlled URLs (pull) and file paths (create), feeds data to GGUF parser — direct path from network to crash-prone C++ parser
2. **GGUF blob upload → parser**: malformed GGUF triggers OOB read, null deref, divide-by-zero in C++ code
3. **`/api/pull` redirect chain**: `download.go` follows redirects; host-pinning check present but historically incomplete
4. **Auth token forwarding (`server/auth.go`)**: `getAuthorizationToken` fetches a bearer realm URL from WWW-Authenticate header — SSRF/token theft vector (CVE-2025-51471 exploited exactly this)
5. **Agent tool approval (`x/agent/approval.go`)**: path prefix matching for command approval bypassed via `../` (fixed in c8b599bd)

---

## Dependency Intelligence

### Direct Security-Relevant Dependencies

| Dependency | Version | Role | Risk Notes |
|------------|---------|------|-----------|
| `github.com/gin-gonic/gin` | v1.10.0 | HTTP router/middleware | Stable; handles all request parsing |
| `golang.org/x/net` | v0.46.0 | HTTP/2, net utilities | Updated; was vuln to CVE-2023-44487 (HTTP/2 rapid reset), CVE-2023-39325, CVE-2023-3978 — now patched |
| `golang.org/x/crypto` | v0.43.0 | Cryptographic primitives | Used for auth key signing |
| `github.com/mattn/go-sqlite3` | v1.14.24 | SQLite via CGo | CGo boundary; SQL injection risk if user input reaches queries |
| `github.com/klauspost/compress` | v1.18.3 | gzip/zip compression | Handles decompression of model archives — historically a DoS vector (GHSA-v464-r2r9-www7: crafted GZIP) |
| `github.com/gin-contrib/cors` | v1.7.2 | CORS middleware | Config matters for cross-origin access control |
| `github.com/gabriel-vasile/mimetype` | v1.4.3 | MIME sniffing | Used in multimodal image handling |
| `github.com/gogo/protobuf` | v1.3.2 | Protobuf (indirect) | Historical deserialization issues in older versions |
| `github.com/nlpodyssey/gopickle` | v0.3.0 | Python pickle deserializer | HIGH RISK: deserializes Python pickle format for model conversion — pickle deserialization is a well-known RCE vector |
| `github.com/ledongthuc/pdf` | v0.0.0-20250511090121-5959a4027728 | PDF parsing | Untrusted document parsing; parsing bugs common |
| `github.com/tree-sitter/go-tree-sitter` | v0.25.0 | Code parsing | C library via CGo; memory safety risk on untrusted input |
| `golang.org/x/image` | v0.22.0 | Image decoding | Used for multimodal image input; historically has parsing bugs |
| `github.com/pdevine/tensor` | v0.0.0-20240510204454 | Tensor math | Used in model conversion |

### Pattern Cross-References
- `nlpodyssey/gopickle`: directly relevant to CWE-502 (Deserialization of Untrusted Data) — `convert/` package uses this for PyTorch model import
- `golang.org/x/net` was previously vulnerable and was updated (commit bb8464c0) — currently at v0.46.0 which is recent
- `klauspost/compress` zip decompression: ZIP path traversal fixed in CVE-2024-45436; same library handles gzip bombs (GHSA-v464-r2r9-www7)
- CGo boundaries (llama.cpp, sqlite3, tree-sitter): memory-unsafe C code reachable from Go API handlers

---

## Known Advisories

### All-Time Advisory Inventory (Tier 2 — All Time)

**Historical coverage metadata**:
- Tier reached: 2 (all-time, expanded from 2yr due to material older advisories)
- Total unique advisories: 22
- Severity distribution: CRITICAL: 1, HIGH: 14, MEDIUM: 4, LOW: 0, UNSCORED: 3

| CVE/GHSA ID | Severity | CVSS | Affected Versions | Patch Version | CWE | Component | Summary |
|-------------|----------|------|-------------------|---------------|-----|-----------|---------|
| CVE-2025-63389 / GHSA-f6mr-38g8-39rg | CRITICAL | 9.3 (CVSS:4.0) | <= v0.12.3 | v0.12.4 | CWE-306 | API Server (all endpoints) | Missing authentication on model management API endpoints; remote unauthenticated attackers can manage models |
| CVE-2026-5530 | HIGH | — | <= 18.1 (sic) | — | CWE-918 | `server/download.go` | SSRF via Model Pull API; user-controlled URL reaches internal network |
| CVE-2025-15514 | HIGH | — | 0.11.5-rc0 – 0.13.5 | — | CWE-476 | Multimodal image handler | Null pointer deref in `mtmd_helper_bitmap_init_from_buf` on malformed base64 image input via `/api/chat`; DoS |
| CVE-2025-66960 | HIGH | — | <= 0.12.10 | — | CWE-400 | `fs/ggml/gguf.go` | Unchecked string-length read from untrusted GGUF metadata in `readGGUFV1String`; DoS |
| CVE-2025-66959 | HIGH | — | <= 0.12.10 | — | CWE-125 | GGUF decoder | Out-of-bounds read / DoS via crafted GGUF file |
| CVE-2025-51471 / GHSA-x9hg-5q6g-q3jr | MEDIUM | 6.1 (CVSS:3.1) | <= 0.6.7 | 0.6.8 | CWE-200 | `server/auth.go` (getAuthorizationToken) | Cross-domain token exposure: malicious WWW-Authenticate realm URL causes auth token forwarded to attacker's server |
| CVE-2025-44779 / GHSA-93jv-pvg8-hf3v | MEDIUM | 6.1 (CVSS:3.1) | <= v0.1.33 | — | CWE-22 | `/api/pull` endpoint | Arbitrary file deletion via crafted packet to `/api/pull` |
| CVE-2025-1975 / GHSA-wrh5-cmwx-q2qr | HIGH | 7.5 (CVSS:3.0) | 0.5.11 | — | CWE-129 | `/api/pull` (manifest handling) | DoS via spoofed manifest with out-of-bounds array index during model download |
| CVE-2025-0317 / GHSA-9gcr-28rp-cc24 | HIGH | 7.5 (CVSS:3.0) | <= 0.3.14 | — | CWE-369 | GGUF parser (`ggufPadding`) | Divide-by-zero in `ggufPadding` via crafted GGUF; server crash / DoS |
| CVE-2025-0315 / GHSA-fccc-8m69-8r78 | HIGH | 7.5 (CVSS:3.0) | <= 0.3.14 | — | CWE-770 | GGUF parser | Unlimited memory allocation from crafted GGUF metadata; DoS |
| CVE-2025-0312 / GHSA-p2wh-w96x-w232 | HIGH | 7.5 (CVSS:3.0) | <= 0.3.14 | — | CWE-476 | GGUF parser | Null pointer deref from crafted GGUF; server crash / DoS |
| CVE-2024-8063 / GHSA-2xf2-gjm6-g2c6 | HIGH | 7.5 (CVSS:3.0) | <= v0.3.3 | — | CWE-369 | GGUF parser (`block_count`) | Divide-by-zero when importing GGUF model with crafted `block_count`; DoS |
| CVE-2024-12055 / GHSA-89qx-m49c-8crf | HIGH | 7.5 (CVSS:3.0) | <= 0.3.14 | — | CWE-125 | `gguf.go` | Out-of-bounds read from malicious GGUF model file; server crash / DoS |
| CVE-2024-12886 / GHSA-v464-r2r9-www7 | HIGH | 7.5 (CVSS:3.0) | <= 0.3.14 | — | CWE-400 | GGUF/GZIP handler | DoS via crafted GZIP content fed through model pipeline |
| CVE-2024-39722 | HIGH | 7.5 (CVSS:3.1) | < 0.1.46 | 0.1.46 | CWE-22 | `/api/push` (path traversal) | File existence oracle + path traversal via `api/push` route; discloses server filesystem paths |
| CVE-2024-39721 | HIGH | 7.5 (CVSS:3.1) | < 0.1.34 | 0.1.34 | CWE-400 | `/api/create` (`req.Path`) | Resource exhaustion: `req.Path=/dev/random` causes goroutine to spin indefinitely; DoS |
| CVE-2024-39720 / GHSA-95j2-w8x7-hm88 | HIGH | 7.5 (CVSS:3.1) | < 0.1.46 | 0.1.46 | CWE-125 | GGUF parser (CreateModel) | OOB read from 4-byte malformed GGUF; segfault via CreateModel route; DoS |
| CVE-2024-39719 | HIGH | 7.5 (CVSS:3.1) | <= 0.3.14 | — | CWE-209 | `/api/create` | File existence disclosure via error message reflection in CreateModel route |
| CVE-2024-45436 / GHSA-846m-99qv-67mg | HIGH | 7.5 (CVSS:3.1) | < 0.1.47 | 0.1.47 | CWE-22 | ZIP extractor (`server/model.go`) | Zip slip: GGUF-in-ZIP can extract files outside parent directory |
| CVE-2024-37032 / GHSA-8hqg-whrw-pv92 | MEDIUM | 6.3 (CVSS:3.1) | < 0.1.34 | 0.1.34 | CWE-20 | Digest validation (`server/modelpath.go`) | Path traversal via unvalidated digest (no sha256 format enforcement); `../` prefix in digest bypasses blob path |
| CVE-2024-28224 / GHSA-5jx5-hqx5-2vrj | MEDIUM | 8.8 (CVSS:3.1) | < 0.1.29 | 0.1.29 | CWE-290 | Host validation middleware | DNS rebinding: attacker causes browser to send requests to localhost Ollama API; full API access |
| CVE-2023-44487 + CVE-2023-39325 + CVE-2023-3978 | HIGH/MED | — | dep: golang.org/x/net < updated | commit bb8464c0 | CWE-400, CWE-79 | golang.org/x/net (HTTP/2) | HTTP/2 rapid reset DoS (CVE-2023-44487), HTTP/2 DoS, HTML injection in net/html |

**Additional (internal/agent):**

| ID | Severity | Component | Summary | Fix Commit |
|----|----------|-----------|---------|-----------|
| (no CVE) | MEDIUM | `x/agent/approval.go` | Path traversal in agent tool-call approval: `../`-relative paths bypass prefix allowlist | c8b599bd |
| CVE-2025-15063 | HIGH (ZDI) | Ollama MCP Server (`execAsync`) | Command injection via unsanitized shell string in `execAsync` (ZDI-CAN-27683); affects the MCP server component, not core ollama binary | — |

---

## Patch List

The following commit SHAs are confirmed or inferred security fixes for known vulnerabilities:

```
fc8c0445  - CVE-2024-28224: DNS rebinding — add allowedHostsMiddleware
2a21363b  - CVE-2024-37032: digest format validation (sha256 enforcement)
b7ce14c7  - CVE-2024-45436: ZIP slip — prevent extracting files outside parent dir
bb8464c0  - CVE-2023-44487, CVE-2023-39325, CVE-2023-3978: golang.org/x/net update
f02f8366  - Go 1.22.5 bump to fix security vulnerabilities
7601f0e9  - CVE-2025-51471: reject unexpected auth hosts (cross-domain token exposure)
9239a254  - abort download on empty digest (integrity / DoS mitigation)
c8b599bd  - (no CVE): path traversal in x/agent approval prefix matching
```

Additional version-bump patches (no single commit identified, fixed in version boundary):
- CVE-2024-39720 / CVE-2024-39721 / CVE-2024-39722: fixed at v0.1.46
- CVE-2025-0312 / CVE-2025-0315 / CVE-2025-0317 / CVE-2024-8063 / CVE-2024-12055 / CVE-2024-12886: fixed at unspecified version after 0.3.14
- CVE-2025-63389: fixed at v0.12.4

---

## Vulnerability Pattern Analysis

### 2a. Component Vulnerability Heatmap

| Component | Advisory Count | Severity Distribution | Dominant Bug Types |
|-----------|---------------|----------------------|-------------------|
| GGUF/GGML Parser (`fs/ggml/gguf.go`, llama.cpp) | 9 | HIGH x8, MED x1 | OOB read, null deref, div-by-zero, resource exhaustion |
| API Server — model management endpoints | 5 | CRITICAL x1, HIGH x3, MED x1 | Missing auth, path traversal, info disclosure, DoS |
| Download / Pull pipeline (`server/download.go`) | 3 | HIGH x2, MED x1 | SSRF, DoS via manifest spoofing, arbitrary file deletion |
| Auth subsystem (`server/auth.go`) | 2 | MED x2 | Token exposure (SSRF-adjacent), DNS rebinding |
| ZIP extractor (`server/model.go`) | 2 | HIGH x1, MED x1 | Zip slip (path traversal) |
| Agent tool approval (`x/agent/`) | 1 | MED x1 | Path traversal in allowlist |
| golang.org/x/net (dep) | 3 | HIGH x2, MED x1 | HTTP/2 DoS, HTML injection |

**High-heat components** (flagged for Phase 3 DFD and Phase 5 deep probe):
- GGUF Parser: 9 advisories, repeated structural issues in bounds checking
- Model management API: CRITICAL auth bypass + repeated path traversal patterns
- Download/pull pipeline: SSRF + DoS + file manipulation recurring theme

### 2b. Bug Type Recurrence

| Bug Class | CWEs | Count | Key Examples |
|-----------|------|-------|-------------|
| DoS / resource exhaustion (GGUF-triggered) | CWE-400, CWE-770, CWE-369, CWE-476, CWE-125 | 9 | CVE-2024-39720, CVE-2025-0312, CVE-2025-0315, CVE-2024-12055, CVE-2024-8063, CVE-2024-12886, CVE-2025-0317, CVE-2025-66959, CVE-2025-66960 |
| Path traversal / file access | CWE-22 | 4 | CVE-2024-45436, CVE-2024-37032, CVE-2024-39722, CVE-2025-44779, internal agent |
| Missing / broken auth | CWE-306, CWE-287, CWE-290 | 3 | CVE-2025-63389, CVE-2024-28224, CVE-2025-51471 |
| SSRF / request forgery | CWE-918 | 2 | CVE-2026-5530, CVE-2025-51471 |
| Info disclosure | CWE-200, CWE-209 | 2 | CVE-2024-39719, CVE-2024-39722 |
| DoS via unvalidated input (non-GGUF) | CWE-400, CWE-129 | 2 | CVE-2024-39721, CVE-2025-1975 |
| Command injection | CWE-77, CWE-78 | 1 | CVE-2025-15063 (MCP Server) |
| Null pointer deref (image) | CWE-476 | 1 | CVE-2025-15514 |

**Recurring classes** (2+ advisories):
- DoS via GGUF parsing: 9 instances — structurally recurring, root cause is absent bounds-checking in GGUF reader
- Path traversal: 4+ instances — digest paths, ZIP extraction, API push, agent paths
- Auth bypass: 3 instances including a CRITICAL

### 2c. Attack Surface Trends

| Input Vector | Exploit Count | Most Recent | Notes |
|-------------|--------------|-------------|-------|
| GGUF binary file upload (via `/api/blobs`, `/api/create`) | 9 | 2026-01 | All GGUF parser DoS bugs |
| HTTP API (model management, unauthenticated) | 5 | 2025-12 | Auth bypass, info disclosure |
| HTTP redirect / WWW-Authenticate header (registry auth) | 2 | 2025-07 | SSRF, token theft |
| ZIP archive in model pull | 2 | 2024-08 | Zip slip, gzip bomb |
| URL/path parameters (`req.Path`, digest, push path) | 4 | 2025-08 | Path traversal, file oracle |
| DNS / Host header | 1 | 2024-04 | DNS rebinding |
| Image data (base64 via `/api/chat`) | 1 | 2025-11 | Null deref on malformed image |
| Shell command (MCP execAsync) | 1 | 2026-01 | Command injection |

### 2d. Patch Quality Signals — Structural Recurrence

**GGUF Parser (CRITICAL structural recurrence)**:
Nine separate advisories for the same component (GGUF binary parser in `fs/ggml/gguf.go` and llama.cpp). Bug classes span OOB read, null deref, div-by-zero, and unbounded allocation — this strongly indicates the root cause is absent systematic input validation at the GGUF parser boundary, not individually patched bugs. Each CVE was fixed individually rather than via a comprehensive hardening of the parser's trust boundary.

**Path Traversal (structural recurrence)**:
Four separate path traversal bugs across digest validation, ZIP extraction, API push, and agent approval. Each was fixed independently. The pattern suggests missing centralized path sanitization.

### Audit Targeting Recommendations

- **Phase 3 DFD slices**: Prioritize (1) the blob upload → GGUF parse pipeline, (2) the `/api/pull` download + manifest processing flow, (3) the auth token acquisition in `server/auth.go`.
- **Phase 5 deep probe**: Target (1) GGUF binary parsing entry points (`/api/blobs/:digest`, `/api/create`), (2) HTTP redirect and WWW-Authenticate header handling in `server/download.go` and `server/auth.go`, (3) image decoding via `/api/chat` with multimodal models.
- **Phase 8 chambers**: Mandatory attack modes — DoS via malformed binary input (GGUF/GZIP), path traversal across all file-handling APIs, SSRF in download and auth flows, missing authentication on model management endpoints.
- **Patch-bypass-checker**: Flag GGUF parser as structural-recurrence candidate — diff all patch commits from v0.1.34 through v0.3.14+ for `fs/ggml/gguf.go` to identify unpatched root cause; flag `server/model.go` ZIP extractor similarly.

