# Merged Commit Recon Report

## Included Sources

- `.archon-merge-staging-1765496804/commit-recon-report.md` not present
- `ollama-with-opus-4.7/commit-recon-report.md`

## Source 2

# Commit Archaeology Report

**Repository**: github.com/ollama/ollama (remote: origin/main)
**Commit range**: all history (no time bound)
**HEAD SHA**: 57653b8e42d69ec35f68a59857bad4d0f07994a3
**Branch searched**: audit (+ remote branches sampled)
**Languages detected**: Go (743 files), C++ (179 files), TypeScript (34 files), C (14 files), JS (2 files)
**Scan date**: 2026-04-17T00:00:00Z
**Total commits in repo**: 5,324

## Project Security Vocabulary Discovered

**PROJECT_VOCAB_VALIDATORS**: `sanitize`, `sanitizeFilename`, `sanitizeConvWeight`, `sanitizeExpertWeights`, `sanitizeMLAWeights`, `sanitizeNonFiniteJSON`, `sanitizeRouteForFilename`, `verifyBlob`, `verifyDownload`, `verifyExtractedBundle`, `parseAndValidateModelRef`, `allowedHost`, `allowedHostsMiddleware`, `filepath.IsLocal`, `filepath.EvalSymlinks`, `os.OpenRoot`, `filepath.Clean`

**PROJECT_VOCAB_AUTH**: `ensureAuth`, `getAuthorizationToken`, `parseAuthChallenge`, `makeAuthToken`, `signCloudProxyRequest`, `writeCloudUnauthorized`, `allowedHostsMiddleware`, `chownWithAuthorization`

**PROJECT_VOCAB_CONFIG**: `cors`, `corsConfig`, `denylist`, `allowlist`, `allowlisted`, `InsecureSkipVerify` (behind `https+insecure` opt-in), `throttle`, `cloudProxyBaseURL`, `OLLAMA_NO_CLOUD`

## Deduplication Note

Commits already fully covered by `@advisory-hunter` (archon/advisory-hunter-report.md) and excluded from this report:
- `7601f0e9` — auth host validation (maps to CVE-2025-51471)
- `c8b599bd` — agent path traversal fix (noted as internal fix in advisory report)
- `6b2abfb4` — HuggingFace URL subdomain bypass (noted in advisory report)

---

## Summary Statistics

| Category | Commits Found | HIGH | MEDIUM | LOW |
|----------|--------------|------|--------|-----|
| 1. Dangerous Pattern Introduction | 4 | 2 | 1 | 1 |
| 2. Security Control Weakening | 3 | 2 | 1 | 0 |
| 3. Silent Security Fixes | 6 | 4 | 2 | 0 |
| 4. Reverted Security Fixes | 1 | 1 | 0 | 0 |
| 5. Secret Archaeology | 0 | 0 | 0 | 0 |
| 6. CI/CD Pipeline Weakening | 0 | 0 | 0 | 0 |
| 7. Suspicious Patterns | 1 | 0 | 1 | 0 |
| **Total (deduplicated)** | **15** | **9** | **5** | **1** |

---

## Priority Commits (top 30, ordered by risk)

| # | SHA | Category | Risk | Confidence | Author | Date | Description | Recommended Phase |
|---|-----|----------|------|-----------|--------|------|-------------|-------------------|
| 1 | `d931ee8f` | 3 Silent Fix | HIGH | HIGH | mxyng@pm.me | 2025-05-05 | Symlink path traversal escape: `filepath.EvalSymlinks` + `filepath.IsLocal` gate added to model creation blob enumeration — previously symlinks could point outside model directory | Phase 2 (undisclosed-fix), Phase 5 |
| 2 | `9d902d63` | 3 Silent Fix | HIGH | HIGH | brucewmacdonald@gmail.com | 2026-02-24 | GGUF tensor OOB: bounds check `tensorEnd > fileSize` added — before fix, crafted GGUF with oversized offset+size silently caused io.Seek past EOF on decode | Phase 2 (undisclosed-fix), Phase 5 |
| 3 | `44179b7e` | 3 Silent Fix | HIGH | HIGH | parth.sareen@ollama.com | 2026-01-06 | Agent approval sibling-escape: `path.Clean` + sibling base comparison plugs second-order traversal (`tools/a/b/../../../etc` → `etc`) that c8b599bd missed | Phase 2 (undisclosed-fix), Phase 5 |
| 4 | `1ed2881e` | 3 Silent Fix | HIGH | HIGH | patrick@infrahq.com | 2025-10-02 | Template nil-node panic: `Vars()` / `Identifiers()` now return error on nil pipeline/branch/action nodes — malformed Modelfile template crashes server | Phase 2 (undisclosed-fix), Phase 5 |
| 5 | `64883e3c` | 3 Silent Fix | HIGH | MEDIUM | patrick@infrahq.com | 2025-09-22 | Auth keypair multi-bug: fixed incorrect pubkey file reading, 500→401 status leak, removed system-path key fallback `/usr/share/ollama/.ollama` — this fallback allowed privilege confusion attacks | Phase 2 (undisclosed-fix), Phase 5 |
| 6 | `2aee6c17` | 2 Control Weakening | HIGH | HIGH | jmorganca@gmail.com | 2025-12-20 | Post-download `verifyBlob()` removed in favour of streaming hash — architectural shift; streaming hasher only runs if part completes, earlier abort paths may skip digest check | Phase 2 (undisclosed-fix), Phase 5 |
| 7 | `62d29b21` | 1 Dangerous Pattern | HIGH | MEDIUM | quinn@slack.org | 2023-09-01 | `html/template` → `text/template` swap in prompt rendering — disables Go's automatic HTML entity escaping for all LLM prompt templates; downstream HTML-context consumers now receive raw `<`, `>`, `&` | Phase 5 |
| 8 | `d931ee8f` | 1 Dangerous Pattern | HIGH | HIGH | mxyng@pm.me | 2025-05-05 | (dual-category) Before this commit, `filesForModel()` glob output was enumerated with no symlink resolution or `filepath.IsLocal` check — local model creation accepted symlinks pointing to `/etc/passwd` etc. | Phase 2, Phase 5 |
| 9 | `9770e3b3` | 1 Dangerous Pattern | MEDIUM | MEDIUM | pdevine@sonic.net | 2023-08-11 | Ed25519 private key generated and stored in `~/.ollama/id_ed25519` with permissions `0600` — uses vendored OpenSSH format implementation (removed later by `fd10a2ad`); custom crypto code risk window | Phase 5 |
| 10 | `fc8c0445` | 3 Silent Fix | MEDIUM | MEDIUM | jmorganca@gmail.com | 2024-03-08 | `allowedHostsMiddleware` added — previously no Host header validation; DNS rebinding risk window confirmed (aligns with CVE-2024-28224 root cause, but this specific commit also removed WorkDir middleware side-channel) | Phase 5 |
| 11 | `39982a95` | 4 Reverted Fix | HIGH | HIGH | jmorganca@gmail.com | 2026-03-03 | Reverted cloud auth proxy (460-line `cloud_proxy.go` removed) — removes `writeCloudUnauthorized`, `parseAndValidateModelRef` guards, and model resolver checks; 2843 lines deleted covering auth enforcement | Phase 2, Phase 5 |
| 12 | `8207e55e` | 2 Control Weakening | MEDIUM | MEDIUM | drifkin@drifkin.net | 2026-03-03 | "don't require pulling stubs for cloud models" — large new cloud passthrough proxy; `hop-by-hop` header forwarding logic; auth failure handling surface expanded; later reverted by 39982a95 | Phase 5 |
| 13 | `61086083` | 1 Dangerous Pattern | MEDIUM | MEDIUM | parth.sareen@ollama.com | 2026-03-09 | New `/api/experimental/web_search` and `/api/experimental/web_fetch` routes — proxy body directly to cloud without URL validation or SSRF control; request body passes opaque to `proxyCloudRequestWithPath` | Phase 5 |
| 14 | `bf198c39` | 3 Silent Fix | LOW | LOW | mxyng@pm.me | 2023-07-20 | `verifyBlob()` added post-pull — confirms that *before* this commit, downloaded blobs had no digest verification, enabling substitution attacks | Phase 5 |
| 15 | `0aaf6119` | 1 Dangerous Pattern | LOW | LOW | patrick@infrahq.com | 2026-02-11 | `$VISUAL`/`$EDITOR` env var split-on-whitespace and passed to `exec.Command(args[0], args[1:]...)` — if env vars contain embedded shell metacharacters, binary name is controlled by env | Phase 5 |

---

## Category 1: Dangerous Pattern Introduction

### [62d29b21] html/template replaced with text/template for all prompt rendering

- **Commit**: `62d29b2157d8fec5ec45de7a9fa70fc6fcf02408`
- **Author**: Quinn Slack <quinn@slack.org>
- **Date**: 2023-09-01
- **Files**: `server/images.go`
- **Pattern**: Switched import from `html/template` to `text/template` — disables Go's automatic contextual HTML escaping
- **Discovery source**: generic baseline (template injection pattern)
- **Risk**: HIGH
- **FP assessment**: The change is intentional (LLM prompts should not HTML-escape `<h1>`) but creates a permanent supply of unescaped HTML/JS content flowing from user prompts into all downstream renders. Any component that later embeds template output in an HTML context (e.g., the Electron app, web UIs) will receive raw angle brackets. Not a direct server-side injection, but removes a safety layer.
- **Diff hunk**:
  ```
  -"html/template"
  +"text/template"
  ```
- **Downstream**: Phase 5 (deep-probe: trace template output into HTML rendering contexts in app/)

---

### [d931ee8f] "create blobs in parallel" — silently adds symlink escape prevention

- **Commit**: `d931ee8f22d38a87d4ff1886ccf56c38697f3fa0`
- **Author**: Michael Yang <mxyng@pm.me>
- **Date**: 2025-05-05
- **Files**: `parser/parser.go`
- **Pattern**: `filepath.EvalSymlinks` + `filepath.Rel` + `filepath.IsLocal` gate on every file enumerated by `filesForModel()`
- **Discovery source**: project-vocab discovery (`filepath.IsLocal`, `EvalSymlinks`)
- **Risk**: HIGH (dual-category: also Category 3)
- **FP assessment**: Commit message says "error on out of tree files" as a subpoint — the security fix was buried. Before this, `filesForModel()` returned glob results without symlink resolution. A model directory containing `symlink -> /etc/shadow` would be uploaded as a legitimate blob.
- **Diff hunk**:
  ```go
  +for _, f := range fs {
  +    f, err := filepath.EvalSymlinks(f)
  +    rel, err := filepath.Rel(path, f)
  +    if !filepath.IsLocal(rel) {
  +        return nil, fmt.Errorf("insecure path: %s", rel)
  +    }
  ```
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

---

### [61086083] New experimental web_fetch and web_search proxy routes

- **Commit**: `61086083eb8c558bc14c61d6df630c3bf6e690b4`
- **Author**: Parth Sareen <parth.sareen@ollama.com>
- **Date**: 2026-03-09
- **Files**: `server/routes.go`, `server/routes_web_experimental_test.go`
- **Pattern**: `exec.Command` equivalent: new HTTP POST endpoints at `/api/experimental/web_search` and `/api/experimental/web_fetch` — body forwarded directly to `proxyCloudRequestWithPath` with no URL sanitization or SSRF control on the body content
- **Discovery source**: generic baseline (exec/subprocess / SSRF analog)
- **Risk**: MEDIUM
- **FP assessment**: The routes proxy to a fixed cloud base URL (`cloudProxyBaseURL`), so SSRF via path manipulation is constrained. However, the request body is opaque JSON forwarded without schema validation — a crafted `url` field in the body could trigger server-side fetch of attacker URLs if the cloud endpoint reflects it.
- **Downstream**: Phase 5

---

### [0aaf6119] ctrl-g editor integration — $VISUAL/$EDITOR exec.Command

- **Commit**: `0aaf6119ecbfce50d774e2a02e004c754b45b521`
- **Author**: Patrick Devine <patrick@infrahq.com>
- **Date**: 2026-02-11
- **Files**: `cmd/interactive.go`
- **Pattern**: `exec.Command(args[0], args[1:]...)` where `args = strings.Fields(os.Getenv("VISUAL") or os.Getenv("EDITOR"))`
- **Discovery source**: generic baseline (exec.Command)
- **Risk**: LOW
- **FP assessment**: Standard UNIX editor invocation. Attacker must control `$VISUAL`/`$EDITOR`, which requires prior env compromise. Low attack surface in threat model.
- **Downstream**: Phase 5 (low priority)

---

## Category 2: Security Control Weakening

### [2aee6c17] Streaming hash verification replaces post-download verifyBlob()

- **Commit**: `2aee6c172b019bfe3f3b5a54b4feaa84bcf89dd6`
- **Author**: jmorganca@gmail.com
- **Date**: 2025-12-20
- **Files**: `server/download.go`, `server/images.go`
- **Pattern**: Removed explicit `verifyBlob()` call loop after pull; replaced with inline `streamHasher` during download
- **Discovery source**: project-vocab discovery (`verifyBlob`, `sha256`)
- **Risk**: HIGH
- **FP assessment**: The streaming hash is architecturally correct for the happy path, but raises a concern: the old `verifyBlob()` ran unconditionally for *every* layer after pull complete. The new streaming hash only runs for parts that successfully complete via `MarkComplete()`. If a part stalls, races, or errors mid-stream, the final `sh.Digest()` call may compute a hash over partial data. The comment in test confirms: "digest verification now happens inline during download in blobDownload.run()" — this is a verification architecture change with unverified equivalence for all error branches.
- **Diff hunk**:
  ```go
  -fn(api.ProgressResponse{Status: "verifying sha256 digest"})
  -for _, layer := range layers {
  -    if err := verifyBlob(layer.Digest); err != nil {
  ```
- **Downstream**: Phase 2 (undisclosed-fix — verify all error branches still produce hash mismatch), Phase 5

---

### [8207e55e] Cloud model passthrough proxy — new auth surface (later reverted)

- **Commit**: `8207e55ec7eb3a2cf4cb20917518514d981a6a01`
- **Author**: Devon Rifkin <drifkin@drifkin.net>
- **Date**: 2026-03-03
- **Files**: `server/cloud_proxy.go` (+460 lines), `server/routes.go` (+150 lines), 21 other files
- **Pattern**: New cloud proxy with hop-by-hop header forwarding; `parseAndValidateModelRef` called for model names but proxy body content unvalidated; later reverted by `39982a95`
- **Discovery source**: generic baseline (auth control changes)
- **Risk**: MEDIUM
- **FP assessment**: This commit was reverted. However, the revert (39982a95) itself is suspicious — 2843 lines of auth enforcement code deleted. The current codebase is in a state where cloud proxy logic was removed wholesale, not refactored. The auth surface exposed by 8207e55e (even briefly) may have real-world impact given the commit was live on main for the period between 8207e55e and 39982a95.
- **Downstream**: Phase 5

---

### [39982a95] REVERT cloud proxy removes writeCloudUnauthorized + model resolver auth

- **Commit**: `39982a954e056b73fb071212715913a1f0cd4dcc`
- **Author**: Jeffrey Morgan <jmorganca@gmail.com>
- **Date**: 2026-03-03
- **Files**: 23 files, -2843 lines including `server/cloud_proxy.go`, `server/model_resolver.go`, `internal/modelref/modelref.go`
- **Pattern**: Wholesale deletion of `writeCloudUnauthorized`, `parseAndValidateModelRef`, cloud model resolver, and 988-line test file covering auth scenarios
- **Discovery source**: generic baseline (auth control removal)
- **Risk**: HIGH (Category 4: Reverted Security Fix, also Category 2)
- **FP assessment**: The reverted commit (799e51d4) introduced auth enforcement code that was then stripped. The remaining codebase has no `writeCloudUnauthorized` or `model_resolver`. If cloud proxy functionality is re-added in the future (as teased by commit message "first in a series"), the auth layer may not be reimplemented correctly.
- **Downstream**: Phase 2 (type: undisclosed-fix — verify cloud model access enforcement post-revert), Phase 5

---

## Category 3: Silent Security Fixes

### [d931ee8f] "create blobs in parallel" — symlink escape prevention (also Category 1)

- **Commit**: `d931ee8f22d38a87d4ff1886ccf56c38697f3fa0`
- **Author**: Michael Yang <mxyng@pm.me>
- **Date**: 2025-05-05
- **Files**: `parser/parser.go`, `cmd/cmd.go`, `cmd/cmd_test.go`
- **Pattern**: `filepath.EvalSymlinks` + `filepath.IsLocal` gate — Signal A (adds protective pattern), Signal B (message is "create blobs in parallel", no security keyword), Signal C (parser.go is security-critical path for model creation)
- **Confidence**: HIGH (all 3 signals)
- **Risk**: HIGH
- **FP assessment**: The security fix (`error on out of tree files`) is buried as a sub-bullet in the commit message under a performance feature. No CVE or GHSA assigned. The pre-fix state allowed model directories with symlinks pointing outside the directory to be uploaded as blobs, potentially exfiltrating server filesystem content.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

---

### [9d902d63] "ggml: ensure tensor size is valid" — OOB bounds check

- **Commit**: `9d902d63ce9e741c8c9f0b9716183905785e132e`
- **Author**: Bruce MacDonald <brucewmacdonald@gmail.com>
- **Date**: 2026-02-24
- **Files**: `fs/ggml/gguf.go`, `server/quantization.go`
- **Pattern**: `tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size(); if tensorEnd > uint64(fileSize) { return error }` — Signal A (bounds check added), Signal B ("ensure tensor size is valid" is vague, no CVE/security keyword), Signal C (gguf.go is the highest-risk parser component per advisory heatmap)
- **Confidence**: HIGH (all 3 signals)
- **Risk**: HIGH
- **FP assessment**: Before this commit, `Decode()` would `io.Seek` to `tensor.Offset + tensor.Size()` past EOF without validation, causing `io.ErrUnexpectedEOF` or potentially triggering the GGUF OOB read class (aligns with CVE-2024-39720, CVE-2024-12055, CVE-2025-0315 pattern, but for a different code path — tensor offset validation vs. string length). Not in any public advisory. Co-authored with Gecko Security (same firm that found CVE-2025-51471).
- **Diff hunk**:
  ```go
  +tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()
  +if tensorEnd > uint64(fileSize) {
  +    return fmt.Errorf("tensor %q offset+size (%d) exceeds file size (%d)", ...)
  ```
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

---

### [44179b7e] "use stdlib path package for path normalization" — sibling escape fix

- **Commit**: `44179b7e53b8a5755e305876a9d1be68f7544672`
- **Author**: Parth Sareen <parth.sareen@ollama.com>
- **Date**: 2026-01-06
- **Files**: `x/agent/approval.go`, `x/agent/approval_test.go`
- **Pattern**: Adds sibling-escape detection: `tools/a/b/../../../etc` normalizes to `etc` (escaping `tools/`). The first fix (c8b599bd) only blocked raw `..` in the string — path.Clean resolves them first, then sibling comparison catches the escape. Signal A (adds protective pattern), Signal B ("use stdlib path package for path normalization" sounds like refactoring), Signal C (approval.go is the agent tool security gate)
- **Confidence**: HIGH (all 3 signals)
- **Risk**: HIGH
- **FP assessment**: This was a second-order bypass of c8b599bd. An input like `tools/a/b/../../../etc/passwd` contains `..` but the *cleaned* result `etc/passwd` does not start with `..`, so the first fix would have passed it through. This commit is the actual complete fix. No public CVE for this bypass.
- **Diff hunk**:
  ```go
  +// Security: if original had "..", verify cleaned path didn't escape to sibling
  +if strings.Contains(arg, "..") {
  +    origBase := strings.SplitN(arg, "/", 2)[0]
  +    cleanedBase := strings.SplitN(cleaned, "/", 2)[0]
  +    if origBase != cleanedBase {
  +        return "" // Path escaped to sibling directory
  +    }
  }
  ```
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

---

### [1ed2881e] "templates: fix crash in improperly defined templates"

- **Commit**: `1ed2881ef05cd62d97f3fc3687301f9c69249e3b`
- **Author**: Patrick Devine <patrick@infrahq.com>
- **Date**: 2025-10-02
- **Files**: `server/images.go`, `template/template.go`, `template/template_test.go`
- **Pattern**: `Vars()` and `Identifiers()` return `([]string, error)` instead of `[]string`; nil pipeline/branch/action nodes now return explicit errors instead of panicking — Signal A (nil-dereference guard), Signal B ("fix crash in improperly defined templates" — no security keyword, could be user-triggered), Signal C (template.go parses Modelfile TEMPLATE directive from untrusted model metadata)
- **Confidence**: HIGH (all 3 signals)
- **Risk**: HIGH
- **FP assessment**: Modelfile templates are pulled from the registry and parsed on the server. A malformed template with a nil action node (`{{if}}{{end}}` with empty condition) would crash the goroutine. This is DoS via crafted model. The commit has no CVE; the pattern matches CVE-2025-0312 (null deref via GGUF) but in the template parser path.
- **Diff hunk**:
  ```go
  +if n.Pipe == nil {
  +    return nil, errors.New("undefined template specified")
  +}
  ```
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

---

### [64883e3c] "auth: fix problems with the ollama keypairs"

- **Commit**: `64883e3c4c0238dc70fddcc456af569d1489415d`
- **Author**: Patrick Devine <patrick@infrahq.com>
- **Date**: 2025-09-22
- **Files**: `auth/auth.go`, `api/client.go`, `cmd/cmd.go`, `server/routes.go`
- **Pattern**: (1) Removed system-path key fallback `/usr/share/ollama/.ollama/id_ed25519` — a shared-installation scenario where the system service key could be used to impersonate a user; (2) Fixed pubkey reading (was calling wrong function, returning wrong key type); (3) HTTP 500 on pubkey error → 401. Signal A (auth fix), Signal B ("fix problems with keypairs" — vague), Signal C (auth.go is the signing path)
- **Confidence**: MEDIUM (Signals A+C)
- **Risk**: HIGH
- **FP assessment**: The system-path fallback (`/usr/share/ollama/.ollama/id_ed25519`) in `keyPath()` was removed. This path is writable by the `ollama` system user but readable by all users in some Linux installations. A local user could substitute a key at that path to impersonate the Ollama service's identity in registry operations.
- **Diff hunk**:
  ```go
  -systemPath := filepath.Join("/usr/share/ollama/.ollama", defaultPrivateKey)
  -if fileIsReadable(systemPath) {
  -    return systemPath, nil
  -}
  ```
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

---

### [fc8c0445] "add allowed host middleware"

- **Commit**: `fc8c0445843859726776dc0ff632b32ea664306b`
- **Author**: Jeffrey Morgan <jmorganca@gmail.com>
- **Date**: 2024-03-08
- **Files**: `server/routes.go`, `server/routes_test.go`
- **Pattern**: Adds `allowedHostsMiddleware` checking `Host` header for localhost/local TLD. Signal A (host validation guard), Signal B ("add allowed host middleware" — mild security keyword present), Signal C (routes.go is the HTTP server entry point)
- **Confidence**: MEDIUM (Signals A+C; Signal B borderline)
- **Risk**: MEDIUM
- **FP assessment**: This is the fix that closed the DNS rebinding window (pre-dates CVE-2024-28224 advisory). Before this commit, the Ollama API had no Host header validation, meaning any website could issue cross-origin requests to `http://localhost:11434` via DNS rebinding. The commit also removed `WorkDir` middleware that was setting a temp working directory per request — removing that middleware may have had a side effect of eliminating a sandboxing primitive.
- **Downstream**: Phase 5

---

## Category 4: Reverted Security Fixes

### [39982a95] Revert cloud auth proxy — removes 2843 lines of auth enforcement

- **Commit**: `39982a954e056b73fb071212715913a1f0cd4dcc`
- **Author**: Jeffrey Morgan <jmorganca@gmail.com>
- **Date**: 2026-03-03
- **Original commit**: `799e51d4` ("Reapply don't require pulling stubs for cloud models")
- **Files**: `server/cloud_proxy.go` (deleted), `server/model_resolver.go` (deleted), `server/routes_cloud_test.go` (deleted, 988 lines of auth tests), `internal/modelref/modelref.go` (deleted)
- **Risk**: HIGH
- **FP assessment**: The original commit message does not contain "security" but the reverted code included explicit auth enforcement (`writeCloudUnauthorized`, 401 handling, model reference validation). The revert deleted these without replacement. This is a genuine security control removal, even if the motivation was functional (the cloud proxy feature was being reworked). The `server/routes_cloud_test.go` deletion removed 988 lines of auth scenario coverage.
- **Downstream**: Phase 2 (undisclosed-fix), Phase 5

---

## Category 5: Secret Archaeology

No hardcoded credentials, AWS keys, or GitHub PATs found in git history. One false positive: commit `51082535` contained base64-encoded test image data that matched the AKIA pattern substring but was not an AWS key (appears mid-base64 string, no surrounding AWS context).

---

## Category 6: CI/CD Pipeline Weakening

No genuine security step removals found. CI changes were version upgrades (golangci-lint v6→v9 in `718961de`) and configuration migrations — not removals of security scanners.

---

## Category 7: Suspicious Patterns

### Large multi-file commits on auth/cloud path

- **Commit**: `8207e55e` (23 files, 2843 lines added to auth/cloud/routes)
- **Risk**: MEDIUM
- **Note**: Already covered in Category 2. The size and scope (new cloud proxy, model resolver, 23-file change) with vague message made it a Category 7 candidate. The subsequent revert (39982a95) compounds suspicion.

---

## Phase 2 Candidate SHAs (type: undisclosed-fix)

HIGH priority for `@patch-bypass-checker`:

1. `d931ee8f` — symlink escape in model creation (`filesForModel`, `filepath.IsLocal`)
2. `9d902d63` — GGUF tensor OOB bounds check (`tensorEnd > fileSize`)
3. `44179b7e` — agent approval sibling-escape bypass (second-order path traversal)
4. `1ed2881e` — template nil-node panic (Modelfile TEMPLATE directive DoS)
5. `64883e3c` — auth keypair system-path privilege confusion
6. `2aee6c17` — streaming hash replaces verifyBlob (verify error-branch coverage)
7. `39982a95` — revert that removed cloud auth enforcement

MEDIUM priority:
- `fc8c0445` — allowedHosts middleware (context: DNS rebinding window)
- `61086083` — web_fetch/web_search proxy routes (SSRF surface)

---

## Phase 5 Attack Surface Hints (HIGH-risk commit paths)

| Component | File(s) | Issue Class | Lead Commit |
|-----------|---------|-------------|-------------|
| Model creation blob enumeration | `parser/parser.go` → `filesForModel()` | Symlink escape / path traversal | `d931ee8f` |
| GGUF decoder tensor bounds | `fs/ggml/gguf.go` → `Decode()` | OOB read via crafted GGUF | `9d902d63` |
| Agent tool approval prefix | `x/agent/approval.go` → `extractBashPrefix()` | Path traversal bypass | `44179b7e` |
| Modelfile template parser | `template/template.go` → `Vars()`, `Identifiers()` | Nil-node crash / DoS | `1ed2881e` |
| Registry auth keypair | `auth/auth.go` → `keyPath()` | System-path privilege confusion | `64883e3c` |
| Download integrity | `server/download.go` → `blobDownload.run()` | Hash skip on error-abort paths | `2aee6c17` |
| Cloud model auth (absent) | `server/routes.go` | Missing auth enforcement post-revert | `39982a95` |
| Web fetch/search proxy | `server/routes.go`, `server/cloud_proxy.go` | SSRF via opaque body forward | `61086083` |

---

## Cross-reference

Full details: `archon/commit-recon-report.md` (this file)
Advisory intelligence: `archon/advisory-hunter-report.md`


