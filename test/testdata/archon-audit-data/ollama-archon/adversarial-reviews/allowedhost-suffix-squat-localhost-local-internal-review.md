Adversarial Review: p8-061 allowedhost-suffix-squat-localhost-local-internal

Reviewer context: cold, no access to debate or chamber notes.

## Step 1 — Restate and Decompose

Restated claim: the host-header allowlist function used by the ollama HTTP server
permits any hostname whose rightmost label is `.localhost`, `.local`, or
`.internal` via plain string suffix matching with no check against the actual
resolved IP. Because RFC 6761 requires browsers to treat `*.localhost` as
loopback without consulting DNS, a webpage served from any origin can issue
requests to `http://anything.localhost:<ollama-port>/` which the browser sends
to 127.0.0.1 while the `Host` header `anything.localhost:<port>` passes the
ollama filter. This converts the host-filter DNS-rebinding defence into a
no-op for any browser context where the same-origin/CORS model does not also
block the request.

Sub-claims:
- A: an attacker can induce a victim browser to send an HTTP request whose
  Host header is `<anything>.localhost` (or `.local`/`.internal`) to the local
  ollama listener.
- B: that request traverses `allowedHostsMiddleware` and is accepted as a local
  host, instead of being rejected with 403.
- C: the accepted request reaches a handler on the ollama router and has
  security impact beyond what pure CORS would block (simple-request GETs,
  JSON POSTs from origins that are explicitly allowlisted in
  `envconfig.AllowedOrigins`).

## Step 2 — Independent Code Path Trace

Entry point: all routes are registered under `gin.Engine` in `GenerateRoutes`
at `/Users/bytedance/Desktop/demo/ollama/server/routes.go:1646`. Global
middleware installed at line 1676-1679 is `cors.New(corsConfig)` followed by
`allowedHostsMiddleware(s.addr)`.

The middleware at lines 1608-1644 computes the request host via
`net.SplitHostPort(c.Request.Host)`; if parsing fails, it uses the raw
`c.Request.Host`. If the host is a literal IP that is loopback, private,
unspecified, or matches a local interface, it passes through. Otherwise it
falls through to `allowedHost(host)` at line 1632. If that returns true, the
request is served (OPTIONS is short-circuited to 204). Otherwise 403.

`allowedHost` at lines 1581-1606:
1. lower-cases the host
2. returns true for empty or exactly `localhost`
3. returns true if host equals the machine hostname
4. iterates over `["localhost","local","internal"]` and returns true on any
   `strings.HasSuffix(host, "."+tld)` match

No DNS resolution, no reverse lookup, no IP sanity check at any point. The
claim that the suffix match is purely lexical is accurate.

CORS layer: `cors.DefaultConfig()` with `AllowWildcard=true`,
`AllowBrowserExtensions=true`, `AllowOrigins=envconfig.AllowedOrigins()`.
Allowed origins include `http[s]://localhost`, `http[s]://127.0.0.1`,
`http[s]://0.0.0.0`, plus `app://*`, `file://*`, `tauri://*`,
`vscode-webview://*`, `vscode-file://*` (envconfig/config.go:100-106).

## Step 3 — Protection Surface Search

- Language / framework: Go / Gin. No implicit host verification.
- `allowedHostsMiddleware` has no IP-pinning or DNS cross-check for hostnames.
- CORS partially limits cross-origin JSON POSTs from arbitrary web pages by
  preflight, but not simple requests (GET, HEAD, form-encoded POST, etc.), and
  does not limit any origin explicitly enumerated in `AllowedOrigins()`
  (including the wildcard `vscode-webview://*`, `vscode-file://*`, `app://*`,
  `tauri://*`, `file://*`).
- Auth: only `/api/me` requires a signin; many sensitive endpoints do not.
- No SECURITY.md note documenting acceptance of this risk was found in the
  call path.

No protection fully closes the attack path for simple-request endpoints or
for origins that are whitelisted in `AllowedOrigins`.

## Step 4 — Real-Environment Reproduction

Environment: built the current `main` checkout to `/tmp/ollama-poc-test`, ran
`serve` bound to `127.0.0.1:17434`. Healthcheck on `GET /` returned 200
`Ollama is running`.

Evidence saved under
`/Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/allowedhost-suffix-squat-localhost-local-internal/repro.txt`.

Attempt 1: `curl -H "Host: evil.localhost:11434" http://127.0.0.1:17434/`
Result: 200 `Ollama is running`. Filter bypassed.

Attempt 2: `curl -H "Host: attacker.local:11434" http://127.0.0.1:17434/`
Result: 200. Filter bypassed.

Attempt 3: `curl -H "Host: attacker.internal:11434" http://127.0.0.1:17434/`
Result: 200. Filter bypassed.

Control: `curl -H "Host: evil.example:11434" http://127.0.0.1:17434/`
Result: 403 Forbidden. Confirms the filter is active and that the bypass is
specific to the claimed suffix set.

Extra: `GET /api/tags` with `Host: x.localhost:11434` returned 200 with the
full model list. `GET /api/ps` with `Host: x.localhost:11434` returned 200.

Preflight chain: `OPTIONS /api/pull` with `Origin: vscode-webview://x` and
`Host: pwn.localhost:11434` returned 204 with
`Access-Control-Allow-Origin: vscode-webview://x`. A follow-up
`POST /api/me` with the same headers reached the handler (handler returned
401 for signin, confirming the middleware permitted it and the CORS layer
attached an allow-origin header).

A `chrome-extension://` origin preflight returned 403 because that origin is
not covered by the wildcard list; however `vscode-webview://*`, `app://*`,
`tauri://*`, `file://*`, `vscode-file://*` are all explicit allowlist entries
that would grant the same cross-origin POST capability to any page served from
those schemes (VSCode webviews, electron apps, tauri apps).

All reproduction attempts succeeded. PoC-Status: executed.

## Step 5 — Briefs

Prosecution brief:
The middleware at `server/routes.go:1632` delegates to `allowedHost`, which at
line 1600 performs a purely lexical `strings.HasSuffix(host, "."+tld)` against
`{"localhost","local","internal"}` with no DNS or IP verification. RFC 6761
requires browsers to resolve any `*.localhost` hostname to loopback without
consulting DNS, so any webpage the victim visits can cause the browser to
connect to 127.0.0.1:<ollama> and carry a matching host header. The
reproduction in Step 4 confirms a hostname like `evil.localhost` passes the
filter and reaches handlers that return model data (`/api/tags`, `/api/ps`
observed returning 200). CORS partially mitigates JSON POSTs from unknown web
origins via preflight, but (a) simple-request endpoints are reachable with a
plain `<img>` or form submission, (b) the explicit wildcard origins in
`envconfig/config.go:100-106` (`vscode-webview://*`, `file://*`, `app://*`,
`tauri://*`, `vscode-file://*`) combined with the host-filter bypass allow a
hostile extension / electron / tauri / vscode webview page to reach any POST
endpoint including `/api/pull`, `/api/experimental/web_search`,
`/api/experimental/web_fetch`. The `.internal` suffix additionally turns any
corporate split-horizon environment using `*.internal` into an attack
target; `.local` is the mDNS realm and any LAN device advertising
`attacker.local` via Bonjour/Avahi gets the same pass. There is no opt-in or
documentation flagging this as an accepted risk.

Defense brief:
The suffix list was a deliberate design choice to support local service-mesh
names and MDNS; per the gin CORS layer, cross-origin JSON POSTs from a
drive-by `http://evil.example/` are rejected during preflight because the
Origin is not on the allowlist. Browsers do not typically allow a page to
override the Host header directly; the attack relies on the browser resolving
`*.localhost` to loopback and sending the host header itself, which produces
a request the page can only read if CORS permits, so in practice GET-based
drive-by exfil requires no-cors `<img>` or `<script>` which do not allow
script-level read of the response body for most endpoints. However, the
defense does not cover (a) side-effectful endpoints where the response body
is not required by the attacker (e.g., `/api/pull` of an attacker-controlled
registry is a state change), (b) endpoints reachable from whitelisted non-HTTP
origins. Thus the defense only narrows impact, it does not eliminate it.

Defense conclusion: the filter bypass is real; the argument reduces to "CORS
limits blast radius but does not close it." That does not reach false-positive.

## Step 6 — Severity Challenge

Starting at MEDIUM.

- Remotely triggerable: yes, any webpage.
- Trust boundary crossed: browser origin -> local daemon (loopback-exposed).
- Preconditions: victim visits attacker page (or runs an attacker-authored
  VSCode / Electron / Tauri / Bonjour-advertising tool). No admin or
  non-default config needed; `.localhost` auto-resolve is RFC-mandated and
  default in all major browsers.
- Full impact requires either simple-request endpoints (real but limited) or
  an origin from the wildcard list (realistic for hostile extensions).

Upgrade criteria for HIGH: remotely triggerable + trust-boundary crossing +
no significant preconditions. The precondition of visiting a web page is
minimal and is the defining shape of DNS-rebinding-style host-filter bugs.
Cross-origin reach into a local AI daemon can execute sensitive handlers
(`/api/pull` can cause arbitrary model downloads; `/api/experimental/web_*`
endpoints can access network resources; `/api/tags` exposes installed models).

Not CRITICAL: no RCE, no full-auth bypass demonstrated, impact is mostly
read/state-change against local models rather than OS-level takeover.

Final severity: HIGH.

## Step 7 — Verdict

Both sub-claims A, B, C confirmed. Prosecution survives defense.
Reproduction executed with multiple variants and a control.

Verdict: CONFIRMED
Severity-Final: HIGH
PoC-Status: executed
