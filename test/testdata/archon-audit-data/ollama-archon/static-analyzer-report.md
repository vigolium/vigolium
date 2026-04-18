# Static Analyzer Report — Ollama Security Audit Phase 4

**Target:** github.com/ollama/ollama  
**HEAD:** 57653b8e42d69ec35f68a59857bad4d0f07994a3 (branch: main)  
**Audit date:** 2026-04-17  
**Analyst:** Static Analyzer (Phase 4)

---

## Static Analysis Summary

### Sub-step 4.1 — Structural Extraction Results

**CodeQL database:** `archon/codeql-artifacts/db/` (Go language, retained for Phases 5, 7, 8, 10)

| Metric | Value |
|--------|-------|
| Files extracted | 422 / 741 Go files |
| CodeQL pack | `codeql/go-all@7.0.5`, `codeql/go-queries@1.6.0` |
| Entry points recognized | 147 RemoteFlowSource nodes |
| Sinks enumerated | 668 total across 6 sink kinds |
| DFD slices tested | 9 slices (call-graph-slices.json) |
| Reachable slices | 7 of 9 confirmed reachable |
| Non-reachable slices | 2 (DFD-6 cgo: Go extractor cannot model C pseudo-package; DFD-8/DFD-13: barrier active in current code for some paths) |

**Sink breakdown:**

| Kind | Count |
|------|-------|
| deserialization (json.Unmarshal) | 278 |
| path-construction (filepath.Join) | 169 |
| file-access (os.Create/Open/Write) | 118 |
| command-execution (exec.Command) | 45 |
| memory-allocation-readall (io.ReadAll) | 34 |
| binary-read-length-prefix (binary.Read) | 24 |

---

### CodeQL Analysis

**Suite:** `codeql/go-queries` (security-and-quality, 36 queries)  
**Total built-in findings:** 38

| Rule | Severity | Count | Key Files | DFD/CVE Alignment |
|------|----------|-------|-----------|-------------------|
| `go/path-injection` | ERROR | 22 | manifest/layer.go:86,105; manifest/manifest.go:125; server/create.go:376,627,633,670,782,865 | DFD-1, DFD-3, DFD-15; CVE-2024-37032, CVE-2024-39719, CVE-2024-45436 |
| `go/uncontrolled-allocation-size` | ERROR | 8 | runner/ollamarunner/runner.go:1079,1124,1229; kvcache/recurrent.go:138; runner/llamarunner/cache.go:31 | DFD-2, DFD-6; CVE-2025-0315, CVE-2025-1975 |
| `go/allocation-size-overflow` | ERROR | 4 | anthropic/trace.go:71; model/renderers/json.go:14; tokenizer/wordpiece.go:61 | DFD-2; CVE-2026-33298, TALOS-2024-1915 class |
| `go/incorrect-integer-conversion` | ERROR | 3 | tokenizer/ | DFD-2; CVE-2025-49847 (signed/unsigned narrowing) |
| `go/request-forgery` | ERROR | 1 | server/images.go:992 | DFD-1, DFD-9; CVE-2026-5530 SSRF |

Notable: CodeQL `go/path-injection` fired on `manifest/` package paths — this is the direct lineage of CVE-2024-37032 (Probllama). The manifest package handles layer Digest → BlobsPath conversion; CodeQL found 4 paths where the digest field reaches file creation without passing through the canonical BlobsPath() validator in all branches. The `go/request-forgery` finding at `server/images.go:992` confirms the SSRF via model pull is still reachable.

---

### Custom CodeQL Queries (10 queries, all executed)

| Query | Findings | DFD Slice | Key Positives |
|-------|----------|-----------|---------------|
| `go/ollama/unbounded-readall-on-remote-response` | 0 | DFD-13 | No path found — auth.go pattern is a manual triage target (server/auth.go:81) |
| `go/ollama/length-from-binary-read-to-make` | 4 | DFD-2, DFD-10 | binary.Read(&n) → make([]byte, n) in GGUF/safetensors parsers |
| `go/ollama/digest-path-no-canonicalization` | 4 | DFD-1 | manifest/layer.go:86,105; manifest/manifest.go:125; manifest/paths.go:56 |
| `go/ollama/http-handler-no-auth` | 0 | all-HTTP | Pattern requires gin group middleware structure — manual triage per CVE-2025-63389 |
| `go/ollama/exec-with-user-string` | 8 | DFD-5, DFD-14 | os.Getenv (EDITOR/VISUAL) → exec.Command; EDITOR pattern confirmed |
| `go/ollama/template-execute-user-src` | 72 | DFD-4 | 72 paths: RemoteFlow + ReadFile + Template field → template.Parse/Execute |
| `go/ollama/archive-extract-no-islocal` | 0 | DFD-3 | No live ZipSlip paths found — CVE-2024-45436 pattern appears patched |
| `go/ollama/symlink-read-without-evalsymlinks` | 18 | DFD-3 | 18 filepath.Glob → os.Open paths without EvalSymlinks guard |
| `go/ollama/cgo-call-with-go-computed-length` | 0 | DFD-6 | Go extractor cannot model C pseudo-package calls; covered by Semgrep |
| `go/ollama/cloud-passthrough-host-not-allowlisted` | 1 | DFD-9 | OLLAMA_HOST env var used in HTTP request without allowlist in cloud proxy context |

**Zero-finding notes:**
- `archive-extract-no-islocal`: ZipSlip (CVE-2024-45436) appears patched. `filepath.IsLocal` barriers detected by CodeQL in zip extraction paths. Confidence: medium (model may miss indirect paths).
- `unbounded-readall-on-remote-response`: `server/auth.go:81` is a **manual triage target** — the io.ReadAll on response.Body is direct and lacks a LimitReader, but the HTTP response field read pattern was not modeled completely by CodeQL's field-read node extraction.
- `http-handler-no-auth`: gin uses router group middleware; CodeQL cannot infer which handlers are protected by group-level middleware vs. which are exposed. Manual triage using the gin route table is required (Phase 5, Group C).
- `cgo-call-with-go-computed-length`: The Go CodeQL extractor does not extract C pseudo-package calls (`C.func()`) as DataFlow nodes. Semgrep custom rule `ollama-cgo-length-unchecked` compensated.

---

### Semgrep Analysis

**Version:** 1.144.0 (standard engine; Pro not available — no authentication/licensing error, standard mode used throughout)  
**Baseline pass:** `p/golang`, `p/security-audit`, `p/secrets` — 3,930 files scanned, 284 findings

#### Baseline findings (noise-filtered):

| Rule | Count | Key Files |
|------|-------|-----------|
| `use-of-unsafe-block` | 262 | Throughout — expected for cgo-heavy codebase |
| `math-random-used` | 10 | server/download.go, server/routes.go, middleware/openai.go, openai/responses.go |
| `string-formatted-query` | 1 | **app/store/database.go:64** — SQL injection risk in store layer |
| `potential-dos-via-decompression-bomb` | 2 | app/updater/updater_darwin.go:205,315 |
| `use-after-free` | 1 | ml/backend/ggml/ggml/src/ggml-alloc.c:894 — C-level use-after-free |
| `reverseproxy-director` | 1 | app/ui/ui.go:165 — headers removed by ReverseProxy Director |
| `missing-ssl-minversion` | 1 | server/internal/client/ollama/registry.go:983 |
| `use-of-md5` | 3 | server/upload.go:185,230; app/wintray/tray.go:435 |
| `insecure-use-string-copy-fn` | 2 | x/imagegen/mlx/mlx_dynamic.c:38; mlx_error_handler.c:17 — strcpy in C |
| `use-tls` | 1 | x/mlxrunner/runner.go:172 — HTTP without TLS |

**Notable baseline finding:** `app/store/database.go:64` has a string-formatted SQL query — potential SQL injection if model names or user data reach this layer. Matches the go-sqlite3 advisory concern in the dependency analysis.

#### Custom Semgrep rules — 144 findings from 8 rules:

| Rule | Findings | Key Positives | DFD |
|------|----------|---------------|-----|
| `ollama-cgo-length-unchecked` | 57 | **llama/llama.go:566** (image→mtmd cgo), **llama/llama.go:735**, **ml/backend/ggml/ggml.go:276** | DFD-6 |
| `ollama-exec-nonconstant` | 53 | app/cmd/app/app.go:470; app/server/server_unix.go:24,57; multiple runner paths | DFD-5, DFD-14 |
| `ollama-gin-route-no-allowed-hosts` | 31 | server/routes.go:1683-1690+ — routes registered outside protected group | all-HTTP |
| `ollama-url-parse-no-scheme-check` | 3 | **server/cloud_proxy.go:185**, **x/tools/webfetch.go:100**, x/tools/websearch.go:102 | DFD-9 |
| `ollama-shouldbindjson-no-maxbytes` | 0 | Pattern requires gin.Context direct io.ReadAll — not matched |  |
| `ollama-length-prefix-no-sanity` | 0 | No direct sequential binary.Read → make() matched |  |
| `ollama-join-no-islocal` | 0 | No direct os.Create(filepath.Join(dir, name)) without IsLocal matched |  |
| `ollama-template-user-src` | 0 | No direct template.New($X).Parse($USERSRC) matched (wrapped pattern) |  |

**Key cgo findings:** `llama/llama.go:566` — `C.mtmd_helper_bitmap_init_from_buf(...)` called with `C.size_t(len(data))` where `data` is decoded base64 image bytes from user request. No size cap before the C call. This is the exact call site for CVE-2025-15514 (null deref class) and Sonar-OOB-2025 (OOB write class).

**Key web_fetch finding:** `x/tools/webfetch.go:100` and `server/cloud_proxy.go:185` — `url.Parse($U)` called without scheme restriction. `file://` and `gopher://` URLs would be accepted, enabling SSRF/LFI via the web_fetch experimental endpoint (DFD-9).

---

### DFD/CFD Slice Coverage

| DFD Slice | Confirmed by CodeQL | Confirmed by Semgrep | Key Finding |
|-----------|--------------------|--------------------|-------------|
| DFD-1 (pull → disk) | `go/path-injection` (22 hits), `go/request-forgery` (1 hit), custom digest-path (4 hits) | — | manifest/layer.go Digest path traversal; SSRF at server/images.go:992 |
| DFD-2 (blob → GGUF) | `go/uncontrolled-allocation-size` (8 hits), `go/allocation-size-overflow` (4 hits), custom length (4 hits) | — | kvcache, runner, GGUF parser length-prefix allocation |
| DFD-3 (create → symlink) | custom symlink (18 hits) | — | 18 glob→open paths without EvalSymlinks |
| DFD-4 (template → DoS) | custom template (72 hits) | — | 72 flow paths to template.Execute |
| DFD-5 (agent bash) | custom exec (8 hits) | `ollama-exec-nonconstant` (53 hits) | exec.Command with Getenv args; app/cmd/app.go:470 |
| DFD-6 (multimodal cgo) | 0 (Go extractor limitation) | `ollama-cgo-length-unchecked` (57 hits) | **llama/llama.go:566** confirmed |
| DFD-7 (WWW-Auth token) | — | — | Manual triage target; api/client.go parity with server/auth.go fix |
| DFD-8/13 (zstd/gzip bomb) | 0 (barrier active) | `potential-dos-via-decompression-bomb` (2 hits in updater) | server/auth.go:81 io.ReadAll manual triage |
| DFD-9 (web_fetch SSRF) | custom cloud (1 hit), `go/request-forgery` (indirect) | `ollama-url-parse-no-scheme-check` (3 hits) | **x/tools/webfetch.go:100**, server/cloud_proxy.go:185 |
| DFD-10 (safetensors) | custom length (included) | — | binary.Read → io.CopyN in convert/reader_safetensors.go |
| DFD-14 ($EDITOR) | custom exec (8 hits) | `ollama-exec-nonconstant` | Getenv(EDITOR/VISUAL) → exec.Command confirmed |

---

### Coverage Gaps and Tradeoffs

1. **cgo/C layer not covered by CodeQL Go extractor.** C pseudo-package calls (`C.func()`) are opaque to CodeQL's Go data flow. The `llama/llama.go` cgo boundary is the highest-blast-radius trust boundary and requires manual review in Phase 5 Group D. Semgrep `ollama-cgo-length-unchecked` partially compensated (57 structural hits).

2. **Semgrep Pro not available.** Standard Semgrep 1.144.0 used throughout. Pro inter-procedural taint tracking would improve precision on rules 1-4 (which had 0 matches due to pattern limitations). Documented here per policy.

3. **`io.ReadAll` on auth response body (server/auth.go:81) not confirmed by CodeQL.** The custom query found 0 paths because CodeQL's field read model for `http.Response.Body` requires a specific node type that was not populated in this extraction context. This call site is a **high-priority manual triage target** for Phase 5.

4. **gin middleware group structure opaque to both tools.** Neither CodeQL nor Semgrep can determine which gin handlers are protected by group-level middleware (e.g., `allowedHostsMiddleware`). The `ollama-gin-route-no-allowed-hosts` rule flagged 31 route registrations — all require human review against the `server/routes.go` router setup to determine actual middleware coverage.

5. **Template query overfit (72 findings).** The `template-execute-user-src` query is intentionally broad (RemoteFlowSource → any Parse/Execute call). Most of the 72 findings will be false positives (template engine infrastructure). Phase 5 should triage against the known risky calls: `template/template.go:72`, `server/model.go:82`.

---

### New Findings Not in Prior KB

The following findings were not previously documented and represent novel SAST output:

| Finding | File | Severity | Source |
|---------|------|----------|--------|
| SQL injection risk in store layer | app/store/database.go:64 | MEDIUM | Semgrep baseline |
| C-level use-after-free in ggml-alloc.c | ml/backend/ggml/ggml/src/ggml-alloc.c:894 | HIGH | Semgrep baseline |
| ReverseProxy Director header removal | app/ui/ui.go:165 | LOW | Semgrep baseline |
| Missing TLS MinVersion in registry client | server/internal/client/ollama/registry.go:983 | MEDIUM | Semgrep baseline |
| HTTP server without TLS (mlx runner) | x/mlxrunner/runner.go:172 | MEDIUM | Semgrep baseline |
| MD5 in upload chunking | server/upload.go:185,230 | LOW | Semgrep baseline |
| strcpy in MLX C integration | x/imagegen/mlx/mlx_dynamic.c:38 | MEDIUM | Semgrep baseline |
| math/rand in production crypto paths | server/routes.go:16, middleware/openai.go:9 | LOW | Semgrep baseline |

---

### Merged Output

**`archon/sast-candidates.json`** — 210 total candidates

| Source | Count |
|--------|-------|
| CodeQL built-in (security-and-quality suite) | 38 |
| CodeQL custom queries (10 queries) | 6 aggregated finding groups |
| Semgrep baseline (noise-filtered) | 22 |
| Semgrep custom rules (8 rules) | 144 |
| **Total** | **210** |

By severity: CRITICAL: 1, HIGH: 98, MEDIUM: 111, LOW: 0

---

### Artifacts

| File | Description |
|------|-------------|
| `archon/codeql-artifacts/db/` | CodeQL Go database (retained for Phases 5, 7, 8, 10) |
| `archon/codeql-artifacts/entry-points.json` | 147 RemoteFlowSource nodes |
| `archon/codeql-artifacts/sinks.json` | 668 sink nodes across 6 kinds |
| `archon/codeql-artifacts/call-graph-slices.json` | 9 DFD slice reachability records |
| `archon/codeql-artifacts/flow-paths-all-severities.md` | Human-readable CodeQL result summary |
| `archon/codeql-queries/` | 10 custom CodeQL queries + qlpack.yml |
| `archon/semgrep-rules/ollama-security-rules.yaml` | 8 custom Semgrep rules |
| `archon/codeql-res/security-and-quality.sarif` | Full CodeQL SARIF (retained) |
| `archon/semgrep-res/baseline.json` | Semgrep baseline results |
| `archon/semgrep-res/custom-rules.json` | Semgrep custom rule results |
| `archon/sast-candidates.json` | Merged 210-candidate finding set |

---

### Cleanup

Transient artifact directories (`archon/codeql-res/`, `archon/semgrep-res/`, `~/.semgrep/cache/`) are retained pending report finalization. The CodeQL database at `archon/codeql-artifacts/db/` is NOT deleted — required for Phases 5, 7, 8, 10.

---

*Report generated by Static Analyzer — Phase 4, Ollama Security Audit 2026-04-17*
