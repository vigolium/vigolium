# Cross-Model Seeds: Team-01

Cross-pollination between backward-reasoner (round-1) and contradiction-reasoner (round-2) findings.

---

## CROSS-01: DNS Rebinding + Split Security Model → Complete registry.Local Middleware Bypass

Source-A: PH-01 (backward-reasoner) — DNS rebinding reaches /api/pull via registry.Local without Host check
Source-B: PH-10 (contradiction-reasoner) — registry.Local creates split security model; gin middleware is dead code for /api/pull and /api/delete

Connection: Both findings target the same code point (`server/internal/registry/server.go:118-121`). PH-01 provides the attack vector (DNS rebinding delivers the request). PH-10 explains WHY the bypass is structural (defender configures protection on gin `r`, but `registry.Local` intercepts before `r`). Together they confirm that the bypass is not just a DNS rebinding issue — ANY HTTP client (local script, browser with `file://` origin, same-machine curl) can reach `/api/pull` and `/api/delete` without middleware.

Combined hypothesis: The `registry.Local` interception of `/api/delete` and `/api/pull` creates a permanent, unconditional bypass of ALL gin middleware (CORS, allowedHostsMiddleware, future auth middleware) for these two most-dangerous endpoints. This is not contingent on DNS rebinding — it affects ALL request origins. The `file://` CORS origin (PH-02) can also deliver requests directly to these endpoints without any middleware filtering.

Test direction for causal-verifier: Confirm that when `rc != nil` in `GenerateRoutes`, the gin middleware stack (`r.Use(cors, allowedHostsMiddleware)`) is NEVER invoked for `/api/delete` and `/api/pull`. Specifically: does a request with `Host: evil.attacker.com` to `/api/pull` reach `handlePull` (yes, confirming bypass) or get blocked by allowedHostsMiddleware (no)?

---

## CROSS-02: Blob Cache Poisoning + Symlink Attack → Persistent Integrity Bypass Across Pulls

Source-A: PH-05 (backward-reasoner) — blob cache hit path skips integrity; same-size GGUF replacement bypasses `copyNamedFile`
Source-B: PH-11 (contradiction-reasoner) — `os.Stat` follows symlinks; symlink at blob path tricks `downloadBlob` into cache-hit path

Connection: Both target the integrity verification skip in `downloadBlob` (`server/download.go:478`) and `copyNamedFile` (`server/internal/cache/blob/cache.go:458`). PH-05 requires same-size file replacement. PH-11 provides a stronger attack: a symlink can point to ANY file, not just one of the same size. The symlink attack bypasses BOTH the old cache path (PH-05) AND the new cache path (PH-05's `copyNamedFile` size check), since the symlink target can be any size and `os.Stat` still succeeds.

Combined hypothesis: A symlink placed at the blob path is a stronger and more persistent poisoning vector than direct file replacement: (1) it bypasses the old `downloadBlob` path with no size constraint, (2) it bypasses the new `copyNamedFile` path's size check if the symlink target has the same size, AND (3) it persists across model re-downloads because `downloadBlob` returns early on `os.Stat` success (the blob is "already there") — a new download would overwrite a file, but a symlink remains until explicitly removed.

Test direction for causal-verifier: At `server/download.go:478`, verify `os.Stat` is called (not `os.Lstat`). Check whether any code in the blob path between `downloadBlob` and model loading calls `os.Lstat` or detects symlinks. Verify that a symlink at the blob path causes `downloadBlob` to return `cacheHit=true` without reading the file contents.

---

## CROSS-03: file:// CORS + registry.Local Bypass → Unauthenticated Model Deletion and Replacement Chain

Source-A: PH-02 (backward-reasoner) — `file://*` CORS allows local HTML file to delete models
Source-B: PH-09 (contradiction-reasoner) — AllowedOrigins is immutable; `file://*` cannot be removed

Connection: PH-02 identifies the attack vector (malicious HTML file triggering DELETE). PH-09 explains why there is no remediation path for operators. Together they reveal that the attack is not just possible — it is PERMANENT and UNCONFIGURABLE. An operator who discovers this cannot fix it without modifying the source code.

Combined hypothesis: The `file://*` CORS origin is a hardcoded, irremovable default in `AllowedOrigins()`. Combined with the total absence of API authentication, any local HTML file has permanent, unconditional, unconfigurable DELETE/PULL/PUSH access to the Ollama API. This is a design-level security gap, not a misconfiguration.

Further chain: Browser opens `file://evil.html` → DELETE `/api/delete` (removes existing trusted model) → POST `/api/pull` (installs attacker model via registry.Local, bypassing any middleware) → victim runs replaced model → malicious GGUF loaded → GGUF parser exploit or (on parth/agents branch) ENTRYPOINT RCE.

Test direction for causal-verifier: Verify the full chain: (1) `AllowedOrigins()` confirmed to include `file://*` unconditionally, (2) DELETE reaches handler without auth, (3) POST /api/pull reaches `registry.Local.handlePull` without Host check, (4) confirm no operator-configurable mechanism to restrict these behaviors.

---

## CROSS-04: GGUF ggufPadding Divide-by-Zero + GGUF Unbounded String Allocation → Combined Parser DoS Chain

Source-A: PH-04 (backward-reasoner) — `general.alignment=0` in GGUF KV → `ggufPadding` divide-by-zero panic
Source-A: PH-03 (backward-reasoner) — GGUF string with length 2^63 → OOM
Source-B: PH-12 (contradiction-reasoner) — `numKV` loop has no upper bound → CPU DoS

Connection: All three target `fs/ggml/gguf.go` and are triggered by the same attack vector (crafted GGUF uploaded via `/api/blobs/:digest` then `/api/create`). They represent three distinct crash modes from the same file. A crafted GGUF can exploit all three simultaneously: set numKV to a large value (CPU spin), include a long string (OOM), then set alignment=0 (panic) — whichever fires first achieves DoS.

Combined hypothesis: The GGUF parser has at least three independent DoS crash paths that can be triggered by a single malicious upload. All three require no authentication and are reachable via the same two-step upload+create flow. The parser has no resource budget, no per-field size limits (except the post-hoc tensor bounds check), and no sandbox — a crash kills the entire `ollama serve` process, terminating all active inference sessions.

Test direction for causal-verifier: (1) Confirm `ggufPadding` at line 688 panics on `align=0` by checking Go's modulo behavior with zero divisor, (2) confirm `readGGUFString:361` has no upper bound before `make([]byte, length)`, (3) confirm `numKV` loop at line 143 has no max iteration guard, (4) verify all three are reachable from `/api/create` + `/api/blobs` without auth.

---

## CROSS-05: pullWithTransfer Skips verifyBlob + SSRF → Integrity-Unverified Model via MITM

Source-A: PH-06 (backward-reasoner) — SSRF via pull URL targets internal/attacker-controlled hosts
Source-B: PH-16 (contradiction-reasoner) — `pullWithTransfer` returns before `verifyBlob` loop for tensor-layer models

Connection: PH-06 shows how attacker-controlled content reaches the download pipeline. PH-16 shows that for tensor-layer models (the vast majority), `verifyBlob` is never called after download. If `pullWithTransfer` (x/transfer package) does not independently verify blob digests, then an SSRF/MITM attack on the pull URL can deliver an arbitrary GGUF that is loaded without any integrity check.

Combined hypothesis: For tensor-layer models (virtually all modern LLMs), the `pullWithTransfer` code path downloads and processes blobs without calling `verifyBlob`. If the x/transfer package does not independently re-verify the SHA-256 digest, then any attacker who can MITM the pull (via SSRF to attacker-controlled server, DNS spoofing of registry, or network interception of HTTP pulls with `insecure:true`) can deliver an arbitrary GGUF that is loaded without hash verification.

Test direction for causal-verifier: Read `x/imagegen/transfer/download.go` or equivalent x/transfer package to determine whether `transfer.Download` calls SHA-256 verification on downloaded blobs. If yes: PH-16 is low severity. If no: combine with PH-06 for CRITICAL severity (unauthenticated SSRF + no integrity check = arbitrary GGUF injection).

---

## CROSS-06: Two Pull Implementations + No TLS Check in registry.Local → HTTP Pull Without Insecure Flag

Source-A: PH-07 (backward-reasoner) — registry.Local.handlePull lacks model name normalization vs PullHandler
Source-B: PH-15 (contradiction-reasoner) — `insecure: true` flag check exists in old PullModel path but may be absent in new registry.Local path

Connection: Both note that `registry.Local.handlePull` → `s.Client.Pull` bypasses validations present in `PullHandler` → `PullModel`. PH-07 focuses on name validation; PH-15 focuses on TLS enforcement. Together they indicate that `registry.Local.handlePull` may be a validation-free fast path that bypasses multiple security checks simultaneously.

Combined hypothesis: `registry.Local.handlePull` calling `s.Client.Pull(r.Context(), p.model())` bypasses: (1) `parseNormalizePullModelRef` name validation, (2) the `errInsecureProtocol` TLS enforcement check (if the new client doesn't independently enforce TLS), and (3) all gin middleware. This creates a "shadow pull" path that is both middleware-bypassing and validation-bypassing.

Test direction for causal-verifier: Read `server/internal/client/ollama/registry.go` (or equivalent) to find `Registry.Pull`. Determine: (a) does it validate model name format equivalently to `parseNormalizePullModelRef`? (b) does it enforce TLS or allow HTTP pulls? These two questions determine whether PH-07 and PH-15 are confirmed bypasses.
