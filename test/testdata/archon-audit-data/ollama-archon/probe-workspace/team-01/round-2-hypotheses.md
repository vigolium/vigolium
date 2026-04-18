# Round 2 Hypotheses: Contradiction Reasoner (TRIZ / Game-Theory / Assumption Inversion)

Reasoning approach: Identify the security assumptions embedded in each protection mechanism, then find contradictions — cases where the assumption is false, can be made false, or applies differently than the designer intended.

---

## PH-09: TRIZ — AllowedOrigins Immutability Creates Permanent Attack Surface

**Reasoning model**: TRIZ (Contradiction: "security config can be hardened" vs "AllowedOrigins is additive-only")
**Assumption broken**: Operators can restrict CORS origins to reduce attack surface
**Contradiction**: `AllowedOrigins()` ALWAYS appends `file://*`, `app://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*`. `OLLAMA_ORIGINS` only adds more. The function's design makes it impossible to remove dangerous defaults.

**Target**: `envconfig/config.go:99-105` — hardcoded origin append
**Contradiction evidence**: Line 99-105 runs unconditionally AFTER any OLLAMA_ORIGINS processing. No way to set `OLLAMA_ORIGINS=` to override. No allowlist-only mode.
**Attack input**: Any attack that relies on `file://*` being in the CORS list
**Security consequence**: Even security-hardened deployments cannot remove `file://*`. A user trying to secure their deployment has no recourse via configuration.
**Severity estimate**: HIGH (design flaw enabling all file://-based attacks permanently)
**Status**: VALIDATED

---

## PH-10: Game Theory — registry.Local Interception Creates Split Security Model

**Reasoning model**: Game-Theory (defender assumes uniform middleware; attacker exploits asymmetric handler dispatch)
**Assumption broken**: All API requests go through the same gin middleware chain
**Contradiction**: When `rc != nil` (the production configuration when registry client is enabled), `GenerateRoutes` returns `registry.Local` as the root handler. The gin router with all its middleware is demoted to `Fallback`. The defender configures protection on `r` (gin), but the attacker's request is handled by `registry.Local` before `r` is ever consulted for `/api/delete` and `/api/pull`.

**Target**: `server/routes.go:1727-1736` — `registry.Local` wrapping; `server/internal/registry/server.go:116-128` — pre-fallback dispatch
**Contradiction evidence**: `r.Use(cors.New(corsConfig), allowedHostsMiddleware(s.addr))` applies protection to `r`. But `registry.Local.serveHTTP` never calls `r.ServeHTTP` for the two most dangerous endpoints.
**Amplification**: The gin router ALSO registers `/api/pull` (line 1681) and `/api/delete` (line 1686). These are dead code for these paths — they will never be reached by actual requests when `rc != nil`.
**Attack input**: Any direct HTTP request (DNS rebinding, local script, curl from same machine) to `/api/pull` or `/api/delete`
**Security consequence**: Complete bypass of CORS, allowedHostsMiddleware, and any future middleware added to gin for these two endpoints
**Severity estimate**: HIGH
**Status**: VALIDATED

---

## PH-11: Assumption Inversion — "Cache Hit = Trusted" Is Wrong Under Symlink Attack

**Reasoning model**: Assumption Inversion
**Assumption broken**: If a file exists at the expected blob path, it is the correct blob
**Inversion**: An attacker can place a symlink at the blob path pointing to arbitrary content. `os.Stat` follows symlinks and returns success. `downloadBlob` returns `cacheHit=true`. Symlink is never detected (`os.Lstat` is never called).

**Target**: `server/download.go:478` — `os.Stat(fp)` used as integrity check
**Attack scenario**: Attacker (local co-tenant or via a prior path traversal) creates symlink at `~/.ollama/models/blobs/sha256-[expected-digest]` pointing to a crafted GGUF file
**Code path**: `downloadBlob:478` → `os.Stat(fp)` succeeds (follows symlink) → returns `cacheHit=true` → `verifyBlob` skipped in `PullModel:640` → GGUF parser reads symlink target → arbitrary GGUF executed
**Sanitizers on path**: `BlobsPath` validates path format (digest regex). No symlink check. No `O_NOFOLLOW` on file open.
**Security consequence**: Arbitrary GGUF content loaded without verification; enables all GGUF CVE classes; persistent — symlink survives future pulls of same model
**Severity estimate**: HIGH
**Status**: VALIDATED — `os.Stat` (not `os.Lstat`) confirmed; no symlink detection anywhere in blob path

---

## PH-12: TRIZ — numKV/numTensor Loop Without Upper Bound Enables O(N) Resource Exhaustion

**Reasoning model**: TRIZ (Contradiction: parser needs to handle variable-length model files vs. need to bound resource consumption)
**Assumption broken**: The GGUF loop count from the header is a reasonable number
**Contradiction**: `numKV()` and `numTensor()` return raw uint64 values from the file. The parse loops iterate this many times. An attacker sets numKV=2^63 to cause the server to spin reading empty/zero bytes from the file until it either hits EOF or exhausts CPU/memory.

**Target**: `fs/ggml/gguf.go:143` — `for i := 0; uint64(i) < llm.numKV(); i++` and `fs/ggml/gguf.go:194` — tensor loop
**Attack input**: GGUF with `numKV = 1000000000` (1 billion); even if each KV read is minimal, this spins for a very long time
**Code path**: GGUF upload → create model → `gguf.Decode` → inner loop runs ~10^9 times → CPU DoS (even if I/O fails early due to EOF, the loop overhead is still significant before error propagation)
**Sanitizers on path**: No max iteration count. Loop exits only on read error (EOF) or completion.
**Security consequence**: CPU DoS; server unresponsive during parsing; all inference requests blocked
**Severity estimate**: HIGH
**Status**: VALIDATED — loop at line 143 has no max-iteration guard

---

## PH-13: Contradiction — /api/pull Registered in BOTH registry.Local AND gin, Creating Confusion

**Reasoning model**: Contradiction analysis
**Assumption broken**: There is one canonical handler for each API endpoint
**Contradiction**: When `rc != nil`, BOTH `registry.Local` AND gin handle `/api/pull` — gin's handler (`PullHandler`) is registered but unreachable via this path, while `registry.Local`'s `handlePull` is reachable without middleware. This creates a behavioral inconsistency:
- Requests reaching gin's `PullHandler` go through `parseNormalizePullModelRef` and `getExistingName`
- Requests reaching `registry.Local.handlePull` skip both

**Deeper concern**: The two pull handlers may have different behavior for the same model name input, creating a handler-differential attack surface where inputs accepted by one are rejected by the other and vice versa.

**Target**: Dual registration — `server/routes.go:1681` (gin) and `server/internal/registry/server.go:120` (Local)
**Attack input**: Model name that passes `registry.Local`'s `p.model()` but would fail `PullHandler`'s `parseNormalizePullModelRef`
**Code path**: Direct request → `registry.Local.handlePull` → `s.Client.Pull(ctx, p.model())` where `p.model()` is an unvalidated string
**Security consequence**: Depends on `ollama.Registry.Pull` validation completeness; at minimum, name normalization that prevents homoglyph/lookalike attacks in PullHandler is absent in registry.Local path
**Severity estimate**: MEDIUM
**Status**: NEEDS-DEEPER — need to trace `ollama.Registry.Pull` validation

---

## PH-14: Game Theory — CORS Preflight Exposes Endpoint Enumeration via allowedHostsMiddleware

**Reasoning model**: Game-Theory
**Assumption broken**: Rejected CORS preflight OPTIONS requests reveal no information
**Analysis**: `allowedHostsMiddleware` at line 1624-1628 returns HTTP 204 for OPTIONS requests to allowed hosts. For disallowed hosts, it returns 403. This creates an oracle: an attacker can determine whether a Host value is in the allowlist by sending OPTIONS requests. The response code difference (204 vs 403) reveals whether the Host is accepted.
**Note**: This is a lower-severity information leak, not a direct bypass.

**Target**: `server/routes.go:1625-1628`
**Attack input**: OPTIONS requests with various Host headers to enumerate allowed hosts
**Severity estimate**: LOW (information disclosure only)
**Status**: VALIDATED (minor)

---

## PH-15: Assumption Inversion — "Insecure Flag Requires Explicit Opt-In" Is False via registry.Local

**Reasoning model**: Assumption Inversion
**Assumption broken**: HTTP (non-TLS) registry connections require explicit `insecure: true` in the request
**Contradiction**: In `PullModel` (images.go:597): `if n.ProtocolScheme == "http" && !regOpts.Insecure { return errInsecureProtocol }` — this check exists in the gin PullHandler path. But `registry.Local.handlePull` calls `s.Client.Pull(r.Context(), p.model())` which uses the new ollama registry client. Whether the new client enforces TLS requires checking `ollama.Registry.Pull` implementation.

**Target**: `server/internal/registry/server.go:271` — `s.Client.Pull(r.Context(), p.model())`
**Attack input**: `POST /api/pull` body `{"model":"http://attacker.com/model:tag"}` via registry.Local path
**Code path**: registry.Local.handlePull → `s.Client.Pull` — does this client check TLS?
**Security consequence**: If `ollama.Registry.Pull` allows HTTP without explicit insecure flag, the attacker can pull from HTTP registries (enabling MITM on the pull) without needing to set `insecure: true`
**Severity estimate**: HIGH (if confirmed) / MEDIUM (if Client.Pull enforces TLS)
**Status**: NEEDS-DEEPER — requires reading server/internal/client/ollama package

---

## PH-16: TRIZ — pullWithTransfer Skips verifyBlob Entirely for Tensor-Layer Models

**Reasoning model**: TRIZ (Contradiction: integrity verification is critical vs. pullWithTransfer bypasses verifyBlob)
**Assumption broken**: All model blobs are verified after download
**Contradiction**: In `PullModel` (images.go:615-620):
```go
if hasTensorLayers(layers) {
    if err := pullWithTransfer(ctx, n, layers, manifestData, regOpts, fn); err != nil {
        return err
    }
    fn(api.ProgressResponse{Status: "success"})
    return nil  // <-- returns before verifyBlob loop
}
```
Models with tensor layers (i.e., most modern models) use `pullWithTransfer` and return BEFORE the `verifyBlob` loop. The integrity verification code at lines 638-655 is entirely skipped.

**Target**: `server/images.go:615-620` — early return after `pullWithTransfer`
**Amplification**: `pullWithTransfer` may do internal verification in the `x/transfer` package — this needs checking. But even if it does, the old path's `verifyBlob` is not called.
**Attack input**: Any model with a tensor-type layer (virtually all LLMs in GGUF format)
**Code path**: `PullModel` → `hasTensorLayers` returns true → `pullWithTransfer` → return (skip verifyBlob)
**Security consequence**: If `x/transfer` package does not independently verify digest, tensor-layer models are pulled without integrity verification. Enables MITM/supply-chain attacks on all modern LLM pulls.
**Severity estimate**: CRITICAL (if x/transfer skips verification) / LOW (if x/transfer verifies)
**Status**: NEEDS-DEEPER — requires reading x/transfer package implementation

---

## PH-17: Contradiction — makeRequestWithRetry Uses requestURL.Host for Token, But Redirects Change Response Source

**Reasoning model**: Contradiction analysis
**Assumption broken**: The auth token is always sent to the original registry host
**Analysis**: In `makeRequestWithRetry` (images.go:889), if a 401 response is received, `getAuthorizationToken` is called with `requestURL.Host`. However, Go's `http.Client` follows redirects by default. If the registry redirects to a different host before returning 401, the 401 comes from the redirected host, but `requestURL.Host` is still the original host. The comparison in `getAuthorizationToken` uses `originalHost = requestURL.Host` (the original), so the realm URL from the redirected host would fail the comparison — this FAILS CLOSED (safe).
**Note**: This is actually a false-positive direction (too strict), not a bypass.

**Status**: NOT A VULNERABILITY — fails closed. Documented for completeness.

---

## PH-18: Game Theory — Two Parallel Pull Implementations Create Security Regression Risk

**Reasoning model**: Game-Theory (future maintenance)
**Assumption broken**: Security fixes to one pull path automatically apply to the other
**Analysis**: Two implementations exist:
1. `PullHandler` → `PullModel` → `downloadBlob` / `pullWithTransfer` (old path, gin-routed)
2. `registry.Local.handlePull` → `ollama.Registry.Pull` (new path, middleware-bypassing)

Any future security fix to `PullHandler` (validation, rate limiting, auth) will NOT automatically apply to `registry.Local.handlePull`. The split handler model creates permanent security-regression risk — fixes to one path require manual mirroring to the other.

**Target**: Architecture-level gap spanning `server/routes.go` and `server/internal/registry/server.go`
**Severity estimate**: MEDIUM (systemic/design risk)
**Status**: VALIDATED (design concern)
