# Code Anatomy: Team-01 (DFD-1 + CFD-1)

## server/routes.go

### Key Functions

**`allowedHost(host string) bool`** (line 1573)
- Lowercases host
- Returns true for: empty string, "localhost", OS hostname, hosts ending in `.localhost`, `.local`, `.internal`
- Does NOT check IP addresses (that happens in `allowedHostsMiddleware`)
- Gap: accepts empty host string as valid

**`allowedHostsMiddleware(addr net.Addr) gin.HandlerFunc`** (line 1600)
- Returns `c.Next()` immediately if `addr == nil`
- Returns `c.Next()` immediately if server addr is NOT loopback (non-loopback binding disables all checks)
- Splits `c.Request.Host` via `net.SplitHostPort`; falls back to raw host if no port
- Allows loopback IPs, private IPs, unspecified addrs, local IPs, `allowedHost()` results
- Blocks all others with 403

**`GenerateRoutes(rc *ollama.Registry) (http.Handler, error)`** (line 1638)
- Builds `corsConfig` from `envconfig.AllowedOrigins()` — includes `file://*` hardcoded
- Applies cors and `allowedHostsMiddleware` to gin router `r` via `r.Use()`
- Registers `/api/pull` on gin (line 1681) AND `/api/delete` on gin (line 1686)
- **CRITICAL**: If `rc != nil`, wraps the entire gin router inside `registry.Local{Fallback: r}` — the returned handler is `registry.Local`, not `r` directly
- `registry.Local.ServeHTTP` intercepts `/api/delete` and `/api/pull` BEFORE `r.ServeHTTP` is called; gin middleware never runs for these paths

**`PullHandler(c *gin.Context)`** (line 914)
- Parses JSON body into `api.PullRequest`
- Calls `parseNormalizePullModelRef` for model name validation/normalization
- Calls `getExistingName` for name resolution
- Spawns goroutine calling `PullModel(ctx, name, regOpts, fn)`
- `regOpts.Insecure` is taken directly from request body `req.Insecure`

**`CreateBlobHandler(c *gin.Context)`**
- Accepts `POST /api/blobs/:digest` — raw binary body
- Validates digest via `manifest.BlobsPath(c.Param("digest"))` (regex check)
- Streams body to disk at the validated path

### Data Structures

- `registryOptions{Insecure bool, Token string, ...}` — controls HTTP vs HTTPS for registry connections
- `api.PullRequest{Model string, Name string, Insecure bool, Stream *bool}` — user-controlled pull parameters

---

## server/internal/registry/server.go

### Key Functions

**`Local.ServeHTTP(w http.ResponseWriter, r *http.Request)`** (line 108)
- Wraps `serveHTTP` with a `statusCodeRecorder`

**`Local.serveHTTP(rec *statusCodeRecorder, r *http.Request)`** (line 113)
- Switch on `r.URL.Path`:
  - `/api/delete` → `handleDelete` (returns without calling Fallback)
  - `/api/pull` → `handlePull` (returns without calling Fallback)
  - default → `s.Fallback.ServeHTTP(rec, r)` (gin router with all middleware)
- **This switch executes BEFORE any gin middleware fires**

**`Local.handleDelete(_ http.ResponseWriter, r *http.Request)`** (line 230)
- Checks `r.Method == "DELETE"` — minimal validation
- Decodes JSON body via `decodeUserJSON[*params]`
- Calls `s.Client.Unlink(p.model())` — deletes model from local cache
- No authentication, no Host header check, no CORS check

**`Local.handlePull(w http.ResponseWriter, r *http.Request)`** (line 259)
- Checks `r.Method == "POST"` — minimal validation
- Decodes JSON body via `decodeUserJSON[*params]`
- Calls `s.Client.Pull(r.Context(), p.model())` for non-streaming
- No authentication, no Host header check, no CORS check
- Model name validated only by `ollama.Registry.Pull` internals — no `parseNormalizePullModelRef` equivalent

### Data Structures

- `params{DeprecatedName string, Model string, AllowNonTLS bool, Stream *bool}` — parsed from request body
- `Local{Client *ollama.Registry, Logger *slog.Logger, Fallback http.Handler, Prune func() error}` — the middleware-bypass handler

---

## fs/ggml/gguf.go

### Key Functions

**`containerGGUF.Decode(rs io.ReadSeeker) (model, error)`** (line 46)
- Reads version (uint32), then V1/V2/V3 header struct
- Calls `newGGUF(c)` then `model.Decode(rs)`
- `maxArraySize` is zero-value (0) by default from calling code — means `newArray` will allocate ALL arrays regardless of size

**`gguf.Decode(rs io.ReadSeeker) error`** (line 141)
- Iterates `numKV()` times (uint64 from file header, NO upper bound check)
- For each KV: reads key string, reads type uint32, reads typed value
- For arrays: calls `readGGUFArray`
- Iterates `numTensor()` times (uint64 from file header, NO upper bound check)
- For each tensor: reads name, dims (uint32), shape ([]uint64 of length dims — `make([]uint64, dims)` with NO dims bound check), kind (uint32), offset (uint64)
- Validates tensor bounds against file size (lines 259-261) — post-read check
- Calls `ggufPadding(offset, int64(alignment))` where `alignment` comes from KV `general.alignment`; if 0, causes divide-by-zero at line 688

**`readGGUFString(llm *gguf, r io.Reader) (string, error)`** (line 348)
- Reads uint64 length from header
- If `length > len(llm.scratch)` (scratch is 16KB): `buf = make([]byte, length)` — **unbounded allocation from file header uint64**
- Allocates up to 2^64-1 bytes from a single malformed GGUF field

**`readGGUFArray(llm *gguf, r io.Reader) (any, error)`** (line 424)
- Reads type (uint32) and count (uint64 `n`)
- Calls `newArray[T](int(n), llm.maxArraySize)` — **converts uint64 n to int; on 32-bit this truncates**
- When `llm.maxArraySize == 0`: `newArray` allocates `make([]T, size)` with full attacker-controlled `size`

**`newArray[T any](size, maxSize int) *array[T]`** (line 416)
- If `maxSize < 0 || size <= maxSize`: allocates `make([]T, size)`
- When `maxSize == 0`: condition is `size <= 0` — so any positive size WILL allocate
- **Gap**: `maxSize == 0` means "no limit" (the sentinel for unlimited), not "max 0 elements". An attacker providing array count > 0 will always get a full allocation.

**`ggufPadding(offset, align int64) int64`** (line 687)
- Returns `(align - offset%align) % align`
- If `align == 0`: `offset % 0` → **divide-by-zero panic** (Go runtime panic)
- `alignment` is read from `general.alignment` KV field, default 32 — but KV value can be attacker-set to 0

**`readGGUFArrayData[T any]`** (line 481)
- Iterates `a.size` times reading elements from `r`
- No additional bounds check beyond what `newArray` provides

### Security-Relevant Patterns
- `uint64 → int` conversion for array sizes (int is 64-bit on amd64, but could truncate on 32-bit builds)
- Unbounded allocation from header-controlled string length
- Divide-by-zero from header-controlled alignment value
- No per-parse memory budget or total allocation limit
- `numKV()` and `numTensor()` are raw uint64 from file header — loop counter with no max

---

## cmd/cmd.go

**Note**: The `runEntrypoint` function referenced in KB and bypass analysis is on branch `parth/agents`, NOT on main. On current main, `RunHandler` does not call `runEntrypoint`.

**`RunHandler(cmd *cobra.Command, args []string)`** (line 571)
- Parses model name from `args[0]`
- Calls `PullModel` if model not found locally
- Calls `client.Generate` or `client.Chat` for interactive session
- On main branch: no `Entrypoint` field processing

**exec.Command usage** in cmd.go (main branch):
- `exec.CommandContext(ctx, exe, "serve")` (line 1958) — starts ollama server; uses the ollama binary itself, not user input

---

## envconfig/config.go

**`AllowedOrigins() []string`** (line 85)
- Always appends regardless of env: localhost variants, `127.0.0.1`, `0.0.0.0` with wildcard ports
- Always appends: `app://*`, `file://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*`
- `OLLAMA_ORIGINS` env var prepends additional origins but CANNOT remove defaults
- **No way for operator to remove `file://*` from the default list**

**`Host() *url.URL`** (line 21)
- Parses `OLLAMA_HOST` env var
- Returns URL used as bind address; if non-loopback (e.g., `0.0.0.0`), `allowedHostsMiddleware` will skip all host checks

---

## server/download.go

**`downloadBlob(ctx context.Context, opts downloadOpts) (cacheHit bool, _ error)`** (line 468)
- Validates digest via `manifest.BlobsPath(opts.digest)` — regex check prevents path traversal
- `os.Stat(fp)` — if file exists: returns `cacheHit=true`, NO hash verification
- **Integrity gap**: file existence alone = trust. No `os.Lstat`, no symlink check.
- If not cached: downloads from registry URL, stores to `fp`

**No `verifyBlob` function exists in download.go** — `verifyBlob` is called from `images.go` and defined separately.

---

## server/images.go

**`PullModel`** (line 578):
- Calls `pullModelManifest` to fetch manifest from registry
- If model has tensor layers: calls `pullWithTransfer` (skips `verifyBlob` entirely — transfer package handles verification internally)
- Otherwise: calls `downloadBlob` per layer, tracking `cacheHit` in `skipVerify` map
- **Critical**: `skipVerify[layer.Digest] = cacheHit` — cache hits skip `verifyBlob`
- `verifyBlob` is called for fresh downloads only

**`pullWithTransfer`** (line 703):
- Uses `x/transfer` package for download
- `getToken` closure captures `base.Host` for auth host validation
- No separate `verifyBlob` call — relies on transfer package's internal verification

---

## server/auth.go

**`getAuthorizationToken(ctx, challenge, originalHost string)`** (line 53)
- Parses realm URL from `challenge.Realm`
- **Validates**: `redirectURL.Host != originalHost` — fails if realm host differs from original registry host
- Sends Ed25519-signed request to realm URL to get token
- Fix for CVE-2025-51471 is present and sound

**`registryChallenge.URL() (*url.URL, error)`** (line 28)
- Parses `r.Realm` as URL — attacker-controlled if from malicious registry response
- Adds service, scope, timestamp, nonce as query params
- Returns URL for token request — host comparison in `getAuthorizationToken` gates whether this URL is contacted

---

## Call Graph: Critical Paths

```
Browser (file://) 
  → HTTP request to localhost:11434
  → registry.Local.ServeHTTP (if rc != nil)
    → [/api/delete] handleDelete → Client.Unlink  [NO middleware]
    → [/api/pull]   handlePull  → Client.Pull     [NO middleware]
    → [other]       gin router
      → cors middleware
      → allowedHostsMiddleware  [skipped if non-loopback]
      → PullHandler → PullModel → pullModelManifest (registry)
                               → downloadBlob (cache hit = no verify)
                               → GGUF Parser (readGGUFString = unbounded alloc)
                               → ggufPadding (div-by-zero if align=0)

DNS rebinding attacker
  → HTTP request with rebounded hostname
  → registry.Local.ServeHTTP
    → [/api/pull] handlePull → Pull attacker model [NO Host check]
```
