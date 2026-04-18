# Code Anatomy: Team-04 Components

## Source Files Analyzed

1. `server/routes.go` — Gin HTTP router, CORS config, allowedHostsMiddleware, GenerateRoutes, all route handlers
2. `server/internal/registry/server.go` — registry.Local ServeHTTP, handleDelete, handlePull, decodeUserJSON
3. `envconfig/config.go` — AllowedOrigins(), Host(), UseAuth, all environment config
4. `cmd/cmd.go` — RunHandler, CLI entrypoint (Entrypoint execution is on parth/agents branch, not main)
5. `parser/parser.go` — Modelfile/Agentfile parser
6. `types/model/config.go` — ConfigV2 struct (no Entrypoint/MCPRef on main branch)

## Control Flow Analysis

### Path 1: Browser cross-origin request to `/api/delete`

```
Browser (file:// origin) 
  -> HTTP GET/DELETE to localhost:11434
  -> [OS network stack: TCP to 127.0.0.1:11434]
  -> net/http.Server.ServeHTTP
  -> registry.Local.ServeHTTP (server/internal/registry/server.go:109)
       r.URL.Path == "/api/delete"  → handleDelete(rec, r)
       NOTE: NO CORS header check
       NOTE: NO Host header check
       NOTE: NO authentication check
  -> handleDelete:
       decodeUserJSON[*params](r.Body) → model name
       s.Client.Unlink(p.model())      → deletes model from disk
       s.Prune()                        → prunes orphaned blobs
```

**Security observation**: The browser's CORS pre-flight (OPTIONS) is sent to the same endpoint. `registry.Local.serveHTTP` does NOT handle OPTIONS specially, nor does it emit CORS headers. The browser's SOP/CORS check on the *response* headers would fail... EXCEPT: for DELETE with `Content-Type: application/json`, browsers send a preflight. The preflight goes to the same `registry.Local` handler which returns 405 (Method Not Allowed for non-DELETE methods on /api/delete). This means the DELETE request itself would be blocked by CORS preflight failure.

HOWEVER: For simple cross-origin requests (no preflight), if the attacker downgrades to a same-origin-request pattern (e.g., using `<form>` or `fetch` with `no-cors` mode), the request still executes server-side even without the browser reading the response.

More critically: when `rc == nil` (no registry client configured), gin handles `/api/delete` directly and DOES have CORS + Host middleware — but `file://` origin is allowed, so the response includes `Access-Control-Allow-Origin: file://` and preflight succeeds.

### Path 2: Browser cross-origin request to `/api/pull` via gin (when rc == nil)

```
Browser (file:// origin)
  -> POST localhost:11434/api/pull
  -> gin middleware chain:
       cors.New(corsConfig): Origin=file://* → MATCH → CORS headers emitted
       allowedHostsMiddleware: Host=localhost → allowedHost() → PASS
  -> PullHandler(c *gin.Context)
       c.ShouldBindJSON(&req) → model name from attacker
       PullModel() → fetches from attacker-controlled registry
       → downloads attacker GGUF to local blob store
       → executes GGUF parser on download
```

**Security observation**: When `rc == nil` (legacy mode), the file:// CORS origin allows a browser page to trigger a model pull from an attacker registry. The PullHandler → PullModel flow has no confirmation prompt in API mode. The pulled model's GGUF is parsed immediately, exposing all GGUF parser CVE classes.

### Path 3: registry.Local pull bypass (when rc != nil)

```
Browser (file:// origin) — or — DNS rebinding attack
  -> POST localhost:11434/api/pull
  -> registry.Local.ServeHTTP:
       r.URL.Path == "/api/pull" → handlePull(w, r)
       NOTE: No CORS, no Host check
  -> handlePull:
       decodeUserJSON[*params](r.Body) → model name
       s.Client.Pull(r.Context(), p.model())
         → OCI registry fetch
         → ConfigV2 deserialization from config blob
         → blob download + cache
```

**Critical**: For browsers making a cross-origin fetch to `/api/pull` via `registry.Local`, the response will NOT have CORS headers (registry.Local emits none). The browser will block the JS from *reading* the response, but the server-side pull **executes regardless**. The attacker doesn't need to read the response — the model is pulled and any GGUF data is parsed.

### Path 4: ENTRYPOINT execution (parth/agents branch)

```
ollama run <pulled-agent-model>
  -> RunHandler(cmd, args)
  -> client.Show(ctx, showReq) → ShowResponse including Entrypoint field
  -> opts.Entrypoint = info.Entrypoint
  -> isExperimental, _ = cmd.Flags().GetBool("experimental")  ← read but NOT checked
  -> if opts.Entrypoint != "" {
       runEntrypoint(opts)   ← fires BEFORE isExperimental gate
     }
  -> runEntrypoint:
       cmd = strings.Replace(opts.Entrypoint, "$PROMPT", opts.Prompt, 1)
       parts = strings.Fields(cmd)  ← whitespace split; $PROMPT can inject args
       execPath, _ = exec.LookPath(parts[0])
       exec.Command(execPath, parts[1:]...).Run()  ← inherited stdin/stdout/stderr
```

**Critical**: `isExperimental` is retrieved from CLI flags at line 748 of cmd.go but the `runEntrypoint` call at line 535-536 is reached UNCONDITIONALLY. The experimental flag only gates the `xcmd.GenerateInteractive` path at line 779.

### Path 5: MCP subprocess spawning (parth/agents branch)

```
ollama run <pulled-agent-model>
  -> ShowResponse.MCPRef.Command, .Args  ← from registry config JSON
  -> x/cmd/run.go: startMCPServers() or equivalent
  -> exec.Command(mcpRef.Command, mcpRef.Args...)
```

**Critical**: Same supply-chain issue as Entrypoint but for MCP servers. Command comes from OCI config blob, executes with no confirmation.

## Data Flow: Attacker-Controlled Model Name

In `registry.Local.handlePull`:
```go
p, err := decodeUserJSON[*params](r.Body)  // body from attacker
// ...
s.Client.Pull(r.Context(), p.model())       // p.model() = p.Model or p.DeprecatedName
```

The model name goes through `ollama.ErrNameInvalid` validation inside `s.Client.Pull`. This validates name format but does NOT validate:
- That the registry host is in any allowlist
- That the model is signed or trusted
- That the pulled config has no Entrypoint/MCP fields

## CORS Response Headers: What registry.Local Emits

`registry.Local.ServeHTTP` does NOT set any CORS-related headers:
- No `Access-Control-Allow-Origin`
- No `Access-Control-Allow-Methods`
- No `Access-Control-Allow-Headers`

This means:
- Preflight (OPTIONS) to registry.Local-handled routes returns 405, causing preflight failure
- Simple requests (no-cors mode, form submissions) bypass preflight and execute server-side
- Non-simple requests (JSON DELETE, JSON POST) trigger preflight which fails → browser blocks — but server has already processed in case of non-preflight

Wait — preflight is sent BEFORE the actual request. The actual request is sent only if preflight succeeds. So for cross-origin JSON DELETE to `/api/delete`:
1. Browser sends OPTIONS to `/api/delete` 
2. registry.Local returns 405 (method not allowed for DELETE is not OPTIONS, and serveHTTP path only matches DELETE for /api/delete)
3. Preflight fails → browser blocks actual DELETE

**HOWEVER**: `file://` is a null origin. Preflight from `file://` may behave differently across browsers. Some browsers (Chrome) send `Origin: null` for file:// pages.

## Null Origin Analysis

When `Origin: null` is sent:
- `corsConfig.AllowOrigins` contains `"file://*"` — this is a wildcard match
- The gin-cors library matches against `file://*` using wildcard matching
- With `Origin: null`, the gin-cors matching against `file://*` likely fails (null != file://something)

This is a **critical nuance**: the `file://*` entry in AllowedOrigins may NOT match `Origin: null` sent by browsers for file:// pages. Need to verify gin-contrib/cors behavior.

If `Origin: null` is not matched:
- CORS preflight returns 403 (no Access-Control-Allow-Origin header)
- Cross-origin requests from file:// pages would be blocked by the browser
- The file:// CORS attack vector is narrower: depends on browser behavior

If `Origin: null` IS matched by `file://*` (via AllowWildcard=true):
- Full attack surface as described

## Key Struct Relationships

```
ConfigV2 (types/model/config.go)
  ├── ModelFormat, ModelFamily, etc. (safe metadata)
  └── [parth/agents branch]: Entrypoint string, MCPRef struct

registry.Local (server/internal/registry/server.go)
  ├── Client *ollama.Registry  → handles actual pull logic
  ├── Fallback http.Handler    → gin router (gets /api/* except delete/pull)
  └── ServeHTTP()              → NO middleware, intercepts delete+pull

Server (server/routes.go)
  ├── addr net.Addr            → nil check in allowedHostsMiddleware
  └── GenerateRoutes(rc)       → if rc != nil, wraps gin in registry.Local
```

## Fragility Analysis

- **AllowedOrigins()** — `file://*` has been in defaults since at least 2024; route-group separation was attempted (f84cc993) and reverted — no current plan to fix
- **registry.Local bypass** — architectural: the wrapper pattern is intentional for the new registry client; CORS/Host middleware would need to be replicated or the wrapper needs its own enforcement
- **ENTRYPOINT** — new feature on unmerged branch; no security review evidence; isExperimental check presence-but-not-gating suggests incomplete implementation
- **$PROMPT injection** — structural: string replacement before arg split is the wrong order of operations
