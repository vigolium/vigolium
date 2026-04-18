# Attack Surface Map: Team-04 (DFD-2 Cross-Origin + ENTRYPOINT/MCP Supply-Chain)

## Entry Points

- `envconfig/config.go:86` — `AllowedOrigins()` — hardcodes `file://*`, `app://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*` plus all localhost/127/0.0.0.0 variants into the CORS allowed-origins list; no env variable can remove these defaults
- `server/routes.go:1638` — `GenerateRoutes(rc)` — mounts CORS + `allowedHostsMiddleware` on gin router; when `rc != nil` wraps gin in `registry.Local`
- `server/routes.go:1681` — `r.POST("/api/pull", s.PullHandler)` — gin-routed pull endpoint (protected by middleware)
- `server/routes.go:1686` — `r.DELETE("/api/delete", s.DeleteHandler)` — gin-routed delete endpoint (protected by middleware)
- `server/routes.go:1695` — `r.POST("/api/create", s.CreateHandler)` — model creation (protected by middleware)
- `server/routes.go:1696` — `r.POST("/api/blobs/:digest", s.CreateBlobHandler)` — blob upload (protected by middleware)
- `server/internal/registry/server.go:109` — `registry.Local.ServeHTTP` — outer HTTP handler that intercepts `/api/delete` and `/api/pull` BEFORE gin; zero CORS, zero Host validation
- `server/internal/registry/server.go:118` — `s.handleDelete(rec, r)` — deletes any named model; accepts attacker-controlled JSON body; no auth
- `server/internal/registry/server.go:120` — `s.handlePull(rec, r)` — pulls any named model from any registry; accepts attacker-controlled JSON body; no auth
- `cmd/cmd.go:571` — `RunHandler()` — CLI entry for `ollama run <model>`; reads model info and (on parth/agents branch) branches to `runEntrypoint()`
- `parser/parser.go` — Modelfile parser — parses ENTRYPOINT, MCP directives from Modelfile text embedded in pulled OCI config blob (parth/agents branch)
- `types/model/config.go:4` — `ConfigV2` — OCI config JSON structure; Entrypoint and MCPRef fields deserialized from remote registry blob (parth/agents branch)

## Trust Boundary Crossings

1. **Browser to Ollama API via `file://` origin**: A local HTML file loaded in a browser (attacker-supplied download, phishing page, or XSS-delivered file) sends XHR/fetch to `http://localhost:11434`. The `file://*` wildcard in `AllowedOrigins()` causes gin's CORS middleware to emit `Access-Control-Allow-Origin: file://` and permit the browser to read the response. No credential or token required. Crosses from: untrusted local file → privileged local API.

2. **DNS rebinding bypass via registry.Local for `/api/delete` and `/api/pull`**: An attacker who can make the victim's browser issue a request to `localhost:11434/api/delete` or `/api/pull` — either via DNS rebinding or the `file://` origin CORS bypass — hits `registry.Local.ServeHTTP` directly. This handler has no CORS headers and no Host validation. It executes model deletion and model pull with full effect. Crosses from: attacker-controlled web content → privileged model management without any security middleware.

3. **OCI config blob deserialization (supply-chain / parth/agents branch)**: When `ollama pull malicious-agent` is run, the OCI config JSON blob is fetched from the registry and deserialized into `ConfigV2`. On the parth/agents branch, `Entrypoint` and `MCPRef` fields embedded in that blob are stored and later executed when the user runs `ollama run malicious-agent`. Crosses from: attacker-controlled registry → local code execution with user privileges.

4. **$PROMPT placeholder injection**: On the parth/agents branch, `runEntrypoint()` substitutes the user's prompt string into the entrypoint command via `strings.Replace` before splitting on whitespace, allowing prompt content to inject additional arguments or alter command structure.

## Auth / AuthZ Decision Points

- `server/routes.go:1668-1671` — `gin.Use(cors.New(corsConfig), allowedHostsMiddleware(s.addr))` — only middleware protecting gin routes; no token auth in default config (`OLLAMA_AUTH` is off by default)
- `server/routes.go:1600-1636` — `allowedHostsMiddleware` — validates `Host` header; **skipped entirely** when server is not listening on loopback (line 1607)
- `server/internal/registry/server.go:109-129` — `Local.serveHTTP` — has NO middleware whatsoever; no CORS check, no host check, no auth check
- `envconfig/config.go:234` — `UseAuth = Bool("OLLAMA_AUTH")` — authentication between client and server; **disabled by default**; even when enabled, registry.Local bypass still applies

## Validation / Sanitization Functions

- `envconfig/config.go:86-109` — `AllowedOrigins()` — NOT a sanitization function; actively ADDS dangerous defaults; `OLLAMA_ORIGINS` can only append, never restrict
- `server/routes.go:1573-1597` — `allowedHost(host)` — validates Host header for gin routes; not called for registry.Local paths
- `server/internal/registry/server.go:377-399` — `decodeUserJSON[T]()` — decodes JSON request body; validates JSON structure but does not validate model name for safety (uses `ollama.ErrNameInvalid` from name parsing only)
- `manifest/paths.go:40` — `BlobsPath()` — regex validates digest format on gin-routed blob endpoints; NOT applied in registry.Local paths
- `cmd/cmd.go:~588` — ENTRYPOINT arg splitting — `strings.Fields()` after `$PROMPT` substitution; no shell escaping, no allowlist, no sandboxing (parth/agents branch)

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|---|---|---|:---:|---|
| Browser (file:// origin) | gin CORS middleware | `AllowedOrigins` rejects file:// | NO — file:// IS in the default allowlist | None — this IS the broken layer |
| gin CORS middleware | gin routes (delete/pull/create) | CORS blocks cross-origin destructive requests | NO — file://* permits all same-machine HTML files | registry.Local intercepts /api/delete and /api/pull before gin |
| gin allowedHostsMiddleware | gin route handlers | Host header is loopback or trusted | NO — skipped when server binds 0.0.0.0 | registry.Local bypass: /api/delete and /api/pull skip middleware entirely |
| registry.Local ServeHTTP | handleDelete / handlePull | Caller is authenticated/trusted | NO — no check exists | N/A — this IS the handler with no protection |
| OCI manifest fetch | ConfigV2 deserialization | Registry content is trusted | NO — any registry can serve arbitrary config | Attacker-controlled registry or MITM; no signing enforced |
| ConfigV2 Entrypoint field | exec.Command (runEntrypoint) | Entrypoint is safe/vetted | NO — no validation exists | isExperimental flag retrieved but never gates execution |
| User prompt input | exec.Command args ($PROMPT) | User prompt does not alter command semantics | NO — whitespace split after substitution | Direct argument injection via prompt string |
| MCP Command+Args in config | subprocess spawn | Command is trusted | NO — same as Entrypoint, no validation | Same supply-chain vector as Entrypoint |

## Trust Chain Gaps

1. **GAP-1 (CRITICAL): file:// CORS + registry.Local double bypass** — `file://*` in `AllowedOrigins()` allows any local HTML file to send credentialed cross-origin requests to gin routes. More critically, `/api/delete` and `/api/pull` are handled by `registry.Local.ServeHTTP` BEFORE reaching gin, so they receive neither CORS enforcement nor Host header validation. An attacker who delivers a local HTML file (email attachment, download) achieves model deletion and arbitrary model pull with zero user interaction beyond opening the file.

2. **GAP-2 (CRITICAL): registry.Local exposes /api/delete and /api/pull with no security layer** — `registry.Local.ServeHTTP` at `server/internal/registry/server.go:109` intercepts these two routes before gin. It applies no CORS, no Host check, no authentication. A DNS rebinding attack or any cross-origin request that reaches the local port achieves direct model management without any security boundary.

3. **GAP-3 (CRITICAL): ENTRYPOINT supply-chain RCE** (parth/agents branch) — Model configs pulled from any registry can carry an `Entrypoint` field that is executed as an unrestricted shell command via `exec.Command`. No user confirmation, no allowlist, no sandbox. The `isExperimental` flag is read but never checked before execution.

4. **GAP-4 (HIGH): MCP Command+Args supply-chain RCE** (parth/agents branch) — `MCPRef.Command` and `MCPRef.Args` from pulled model config are spawned as subprocesses. Same trust gap as Entrypoint; arbitrary subprocess execution from registry-supplied data.

5. **GAP-5 (HIGH): $PROMPT argument injection into ENTRYPOINT** (parth/agents branch) — `strings.Replace(entrypoint, "$PROMPT", userPrompt, 1)` followed by `strings.Fields()` split allows user prompt content with whitespace to inject additional command arguments.

6. **GAP-6 (MEDIUM): OLLAMA_ORIGINS additive-only design** — There is no mechanism for security-conscious deployments to remove `file://*` from the allowed origins list. The env var only prepends; defaults are always appended regardless.

7. **GAP-7 (MEDIUM): allowedHostsMiddleware skips on non-loopback bind** — When `OLLAMA_HOST=0.0.0.0` (common in Docker, LAN deployments), the middleware exits at line 1607 without any check, allowing any Host header from any client.
