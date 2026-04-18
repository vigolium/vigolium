# CodeQL Flow Paths — All Severities Summary

**Database:** `archon/codeql-artifacts/db/` (Go, 422/741 files extracted)
**Suite run:** `codeql/go-queries` (security-and-quality)
**Generated:** 2026-04-17

---

## Rule-by-Rule Summary

### go/path-injection — 22 findings (ERROR severity)

Path traversal via user-controlled data reaching file system access.

| File | Line | Notes |
|------|------|-------|
| manifest/layer.go | 86 | User-provided value flows to file path |
| manifest/layer.go | 105 | User-provided value flows to file path |
| manifest/manifest.go | 125 | User-provided value flows to file path (2 paths) |
| manifest/paths.go | 56 | User-provided value flows to file path (2 paths) |
| server/create.go | 376 | User-provided value flows to file path |
| server/create.go | 627 | User-provided value flows to file path |
| server/create.go | 633 | User-provided value flows to file path |
| server/create.go | 670 | User-provided value flows to file path |
| server/create.go | 782 | User-provided value flows to file path |
| server/create.go | 865 | User-provided value flows to file path |
| (12 more across server/ and x/imagegen/) | — | — |

**DFD alignment:** DFD-1 (manifest path construction), DFD-3 (create → file access), DFD-15 (x/create directory walk).
**CVE alignment:** CVE-2024-37032, CVE-2024-39719, CVE-2024-39722, CVE-2024-45436.

---

### go/uncontrolled-allocation-size — 8 findings (ERROR severity)

Memory allocation size controlled by user-provided value without upper bound.

| File | Line | Notes |
|------|------|-------|
| kvcache/recurrent.go | 138 | KV cache size from model parameters |
| runner/llamarunner/cache.go | 31 | KV cache allocation from request |
| runner/llamarunner/runner.go | 903 | Runner buffer from user request params |
| runner/ollamarunner/cache.go | 41 | KV cache allocation from request |
| runner/ollamarunner/runner.go | 1079 | Runner buffer allocation |
| runner/ollamarunner/runner.go | 1124 | Runner buffer allocation |
| runner/ollamarunner/runner.go | 1229 | Runner buffer allocation |
| x/imagegen/models/flux2/flux2.go | 316 | Image model allocation from request |

**DFD alignment:** DFD-6 (multimodal sizing), DFD-2 (GGUF uncontrolled allocation). Runner KV cache sizing.
**CVE alignment:** CVE-2025-0315, CVE-2025-1975 (improper array index validation → crash).

---

### go/allocation-size-overflow — 4 findings (ERROR severity)

Integer overflow in an expression used as allocation size.

| File | Line | Notes |
|------|------|-------|
| anthropic/trace.go | 71 | Arithmetic in allocation may overflow |
| model/renderers/json.go | 14 | Arithmetic in allocation may overflow (2 paths) |
| tokenizer/wordpiece.go | 61 | Token arithmetic in allocation may overflow |

**DFD alignment:** DFD-2 (tokenizer OOB — CVE-2025-49847class), DFD-6 (vision multimodal).
**CVE alignment:** CVE-2026-33298 (ggml_nbytes integer overflow class), TALOS-2024-1913/1915.

---

### go/incorrect-integer-conversion — 3 findings (ERROR severity)

Signed-to-unsigned or width-narrowing conversion risks.

**DFD alignment:** tokenizer/wordpiece.go — CVE-2025-49847 (signed/unsigned narrowing in token_to_piece).

---

### go/request-forgery — 1 finding (ERROR severity)

SSRF via user-controlled URL in HTTP request.

| File | Line | Notes |
|------|------|-------|
| server/images.go | 992 | URL of request depends on user-provided value |

**DFD alignment:** DFD-1 (pull model manifest — attacker-controlled registry URL), DFD-9 (web_fetch SSRF).
**CVE alignment:** CVE-2026-5530 (SSRF via Model Pull API).

---

## Custom Query Results Summary

| Query | Findings | Key Files |
|-------|----------|-----------|
| `go/ollama/unbounded-readall-on-remote-response` | 0 | Server/auth.go io.ReadAll is a manual triage target |
| `go/ollama/length-from-binary-read-to-make` | 4 | GGUF parser binary.Read → make() without bounds |
| `go/ollama/digest-path-no-canonicalization` | 4 | manifest/layer.go, manifest/manifest.go Digest→file |
| `go/ollama/http-handler-no-auth` | 0 | Pattern requires manual review (gin group structure) |
| `go/ollama/exec-with-user-string` | 8 | os.Getenv→exec.Command (EDITOR/VISUAL pattern) |
| `go/ollama/template-execute-user-src` | 72 | Broad: RemoteFlow→template.Execute across template/ |
| `go/ollama/archive-extract-no-islocal` | 0 | ZipSlip: no live instances found (likely patched) |
| `go/ollama/symlink-read-without-evalsymlinks` | 18 | Glob paths → os.Open without EvalSymlinks |
| `go/ollama/cgo-call-with-go-computed-length` | 0 | cgo not modeled by Go extractor; Semgrep covered |
| `go/ollama/cloud-passthrough-host-not-allowlisted` | 1 | OLLAMA_HOST env var used without allowlist check |

---

## Informational Nodes — Where CodeQL Tracking Terminated

The following source → barrier patterns were observed where CodeQL tracked data but did not reach a sink (indicating potential sanitization or modeling gap):

1. **manifest.BlobsPath()** — CodeQL recognized as a sanitizer barrier on Digest values flowing through manifest package. Confirms the fix for CVE-2024-37032 is partially modeled.
2. **filepath.IsLocal()** — Recognized as a barrier in path join operations. Confirms d931ee8f mitigation in production paths.
3. **http.MaxBytesReader** — Not seen as an active barrier in the auth response reading path (server/auth.go:81), consistent with the known gap from DFD-13 analysis.
4. **exec.Command with constant args** — Filtered by CodeQL taint tracking; only non-constant args flagged.

---

*Generated from CodeQL database query results. Retained for Phase 7 review.*
