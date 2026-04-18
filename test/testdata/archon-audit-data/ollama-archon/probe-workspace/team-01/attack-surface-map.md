# Attack Surface Map: Team-01 (DFD-1 + CFD-1)

## Entry Points

- `server/routes.go:914` — `PullHandler` — JSON body with `model` name (attacker-controlled registry URL), `insecure` flag
- `server/routes.go:1686` — `DeleteHandler` (gin route) — JSON body with model name; also intercepted by `registry.Local.handleDelete` before gin middleware
- `server/routes.go:1681` — gin route `/api/pull` — registered on gin, but when `rc != nil`, overridden by `registry.Local.handlePull` which intercepts BEFORE gin middleware executes
- `server/internal/registry/server.go:118` — `registry.Local.serveHTTP` — raw `http.Handler.ServeHTTP` intercepts `/api/delete` and `/api/pull` before gin; accepts same JSON body as PullHandler
- `server/routes.go:1696` — `CreateBlobHandler` — `POST /api/blobs/:digest` — raw binary body (GGUF bytes) + URL digest param
- `server/routes.go:1695` — `CreateHandler` — `POST /api/create` — Modelfile/Agentfile text
- `server/routes.go:1697` — `HeadBlobHandler` — `HEAD /api/blobs/:digest` — digest param from URL
- `server/routes.go:1685` — `ShowHandler` — JSON body with model name
- `envconfig/config.go:85` — `AllowedOrigins` — `OLLAMA_ORIGINS` env var extends but never restricts default list (includes `file://*`, `app://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*`)
- `envconfig/config.go:21` — `Host()` — `OLLAMA_HOST` env var controls bind address; non-loopback disables `allowedHostsMiddleware`
- `cmd/cmd.go:571` — `RunHandler` — CLI arg `args[0]` is model name; triggers `PullModel` + `runEntrypoint` if model config has Entrypoint field (branch: parth/agents, not yet on main)

## Trust Boundary Crossings

- **TB1 (Browser -> API)**: `file://*` CORS origin allows any local HTML file to make unauthenticated XHR to `localhost:11434`; crosses into all destructive endpoints. Attacker provides Origin header, server accepts it.
- **TB2 (registry.Local bypass)**: `registry.Local.ServeHTTP` intercepts `/api/delete` and `/api/pull` before gin's middleware chain; attacker-controlled request reaches handler without Host header validation or CORS checks being applied by gin middleware.
- **TB3 (Registry -> GGUF Parser)**: Registry-supplied manifest provides layer digests; blobs downloaded and stored as GGUF files; attacker controlling a custom registry supplies arbitrary binary content that is then parsed by `fs/ggml/gguf.go`. Trust assumption: content will be structurally valid GGUF.
- **TB4 (Blob cache -> Model load)**: `downloadBlob` returns `cacheHit=true` on `os.Stat` success alone (no integrity re-verification). Attacker with write access to blob directory can substitute blob content; the cached file is loaded without re-hashing.
- **TB5 (Registry manifest -> ConfigV2 -> Exec)**: Model config JSON from registry is deserialized into `ConfigV2`; `Entrypoint` field passes directly to `exec.Command` (branch: parth/agents). No sanitization between registry-sourced string and OS subprocess.
- **TB6 (User prompt -> $PROMPT -> exec)**: `$PROMPT` placeholder substitution inserts raw user prompt into entrypoint command string BEFORE `strings.Fields` splits it; enables argument injection.
- **TB7 (DNS rebinding -> allowedHostsMiddleware)**: When attacker performs DNS rebinding, request Host becomes attacker-controlled domain; gin middleware would block it — but `registry.Local` intercepts `/api/pull` and `/api/delete` BEFORE gin, so the Host check never fires for those endpoints.

## Auth / AuthZ Decision Points

- `server/routes.go:1600` — `allowedHostsMiddleware` — checks `Host` header against loopback/local allowlist; skipped entirely when `OLLAMA_HOST` is non-loopback; also skipped for routes intercepted by `registry.Local` (never even called for `/api/delete` and `/api/pull` when `rc != nil`)
- `server/auth.go:53` — `getAuthorizationToken` — validates realm host matches original host to prevent cross-domain token forwarding; only called for outbound registry auth, not for inbound API auth
- `envconfig/config.go:85` — `AllowedOrigins` — CORS origin check (browser-side mitigation only; no server-side auth)
- No per-request authentication on ANY API endpoint; the entire API is unauthenticated

## Validation / Sanitization Functions

- `manifest/paths.go:40` — `BlobsPath()` — regex `^sha256[:-][0-9a-fA-F]{64}$` validates digest before filesystem path construction; called by HTTP handlers for `/api/blobs/:digest`
- `server/internal/cache/blob/digest.go:31` — `blob.ParseDigest()` — typed digest with hex validation and fixed-width binary storage; prevents path traversal in new cache layer
- `server/download.go:468` — `downloadBlob()` — `os.Stat(fp)` existence check ONLY; no content hash verification on cache hit (blob integrity skip)
- `server/internal/cache/blob/cache.go:458` — `copyNamedFile` — checks file size match as sufficient for cache hit; does not verify content hash
- `fs/ggml/gguf.go:141` — `gguf.Decode()` — validates GGUF magic/version, tensor bounds against file size; does NOT limit `numKV()` or `numTensor()` before iterating; string length from header is used directly for allocation (`make([]byte, length)` at line 361)
- `fs/ggml/gguf.go:416` — `newArray()` — bounds `maxArraySize` only if caller sets `llm.maxArraySize > 0`; default `maxArraySize=0` means ALL arrays are allocated regardless of size
- `fs/ggml/gguf.go:687` — `ggufPadding(offset, align)` — divides by `align`; if `align==0` (from `general.alignment` KV set to 0), produces divide-by-zero panic
- `server/auth.go:60` — `getAuthorizationToken` host check — validates realm URL host == original host; only applies to outbound registry auth

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|---|---|---|:---:|---|
| Browser (file://) | gin CORS middleware | `Origin` must be in allow list | YES for gin | registry.Local intercepts /api/delete, /api/pull — CORS middleware never called for those paths |
| gin CORS | allowedHostsMiddleware | Host header is loopback/local | YES for gin routes | registry.Local intercepts before allowedHostsMiddleware for /api/delete, /api/pull |
| allowedHostsMiddleware | PullHandler / DeleteHandler | Host validated | NO — skipped entirely if OLLAMA_HOST non-loopback | Any non-loopback binding; registry.Local path |
| PullHandler | PullModel | Model name is valid reference | YES (parseNormalizePullModelRef) | registry.Local.handlePull does its own model() parsing with no normalization |
| PullModel / registry.Local | downloadBlob | Registry provides authentic blobs | NO | Custom registry URL via `insecure` flag or DNS rebinding pull |
| downloadBlob | Blob filesystem | Blob on disk is authentic (matches digest) | NO | Cache hit path: `os.Stat` success = trust; no re-hash |
| Blob filesystem | GGUF Parser | File content is valid GGUF | NO | Any write to blob directory (0o777); symlink substitution; TOCTOU replacement |
| GGUF Parser | LLM Runner | Parsed model is safe to load | NO | 9 CVE classes: OOB read, null deref, unbounded alloc, div-by-zero all remain structurally possible |
| Registry manifest | ConfigV2 | Config JSON is trusted | NO | Attacker-controlled registry supplies arbitrary JSON; Entrypoint/MCP fields become exec arguments |
| ConfigV2 | exec.Command (runEntrypoint) | Entrypoint is a safe command | NO (branch: parth/agents) | No allowlist, no sandbox, no user prompt before execution |
| OLLAMA_HOST env | allowedHostsMiddleware | Bind to loopback = protected | NO | OLLAMA_HOST=0.0.0.0 disables Host check entirely |
| gin middleware chain | handler | All requests pass through middleware | NO | registry.Local.ServeHTTP bypasses entire gin chain for /api/delete and /api/pull |

## Trust Chain Gaps (rows where "Alternate Paths" column is NOT empty)

1. **registry.Local bypasses gin middleware entirely for /api/delete and /api/pull**: Both CORS and allowedHostsMiddleware are never executed for these endpoints when `rc != nil`. DNS rebinding attack can reach `/api/pull` without Host validation. Any cross-origin request from allowed CORS origin (e.g., `file://*`) to these endpoints also bypasses the gin middleware recording/logging chain.

2. **file:// CORS origin reaches destructive endpoints**: `file://*` is hardcoded in `AllowedOrigins()`. Any local HTML file can make unauthenticated requests to `/api/delete`, `/api/pull`, `/api/push`, `/api/create`. No way to disable this at runtime (OLLAMA_ORIGINS is additive only).

3. **OLLAMA_HOST=0.0.0.0 fully disables allowedHostsMiddleware**: When Ollama binds to any non-loopback address, `allowedHostsMiddleware` calls `c.Next()` immediately. Combined with file://* CORS, this creates a fully open API accessible from any browser on the network.

4. **Blob cache hit skips integrity verification**: `downloadBlob` and `copyNamedFile` both use existence/size as proxy for authenticity. An attacker with local write access (blob directory is 0o777 in new cache) can replace blobs with malicious content that persists through subsequent pulls.

5. **GGUF parser unbounded string allocation**: `readGGUFString` at line 361 performs `make([]byte, length)` where `length` comes directly from the file header (uint64). No upper bound check. An attacker-controlled GGUF with a 64-bit string length causes OOM/DoS.

6. **GGUF ggufPadding divide-by-zero**: `ggufPadding(offset, int64(alignment))` at lines 245,269 uses `general.alignment` from the KV store (attacker-controlled). If set to 0, `offset % align` panics. Current code reads alignment with default 32 but the KV value overrides.

7. **ConfigV2 Entrypoint field executes without consent**: On branch parth/agents, the `Entrypoint` field pulled from a registry model config is passed directly to `exec.Command`. No user prompt, no sandboxing, no allowlist. Supply-chain RCE vector.

8. **registry.Local.handlePull has no model name normalization parity with PullHandler**: `PullHandler` calls `parseNormalizePullModelRef` for normalization/validation; `registry.Local.handlePull` calls `p.model()` which is just `cmp.Or(p.Model, p.DeprecatedName)`. Any normalization or validation checks in PullHandler are absent in the registry.Local path.
