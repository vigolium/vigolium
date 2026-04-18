## Summary

`allowedHost()` at `server/routes.go:1581-1606` performs three purely-lexical suffix checks:

```go
tlds := []string{"localhost", "local", "internal"}
for _, tld := range tlds {
    if strings.HasSuffix(host, "."+tld) {
        return true
    }
}
```

There is no DNS resolution, no IP verification, no cross-check that the resolved address is actually a loopback or local network. Any attacker-controlled hostname ending in `.localhost`, `.local`, or `.internal` passes the filter.

Per RFC 6761 §6.3, browsers (Chrome, Firefox, Safari, Edge) resolve `*.localhost` hostnames to `127.0.0.1` locally WITHOUT consulting DNS. A page served from `http://evil.example/` can therefore issue requests to `http://pwn.localhost:11434/` and the browser will resolve it to the victim's loopback. The `Host` header sent is `pwn.localhost:11434`; Ollama's middleware accepts it because it ends in `.localhost`. No DNS-rebinding infrastructure is required.

`.internal` is especially dangerous in corporate deployments where split-horizon DNS resolves `*.internal` to the local network — an attacker on the internet who convinces a corporate user to visit their page gets cross-origin reach into `ollama.internal:11434` via that user's browser if the corp DNS resolves `*.internal` to loopback or an intranet Ollama.

`.local` is the mDNS realm (RFC 6762); any device on the same LAN advertising `attacker.local` via Bonjour/Avahi becomes an in-LAN Host-header-passing target.

## Details

`allowedHost()` at `server/routes.go:1581-1606` performs three purely-lexical suffix checks:

```go
tlds := []string{"localhost", "local", "internal"}
for _, tld := range tlds {
    if strings.HasSuffix(host, "."+tld) {
        return true
    }
}
```

There is no DNS resolution, no IP verification, no cross-check that the resolved address is actually a loopback or local network. Any attacker-controlled hostname ending in `.localhost`, `.local`, or `.internal` passes the filter.

Per RFC 6761 §6.3, browsers (Chrome, Firefox, Safari, Edge) resolve `*.localhost` hostnames to `127.0.0.1` locally WITHOUT consulting DNS. A page served from `http://evil.example/` can therefore issue requests to `http://pwn.localhost:11434/` and the browser will resolve it to the victim's loopback. The `Host` header sent is `pwn.localhost:11434`; Ollama's middleware accepts it because it ends in `.localhost`. No DNS-rebinding infrastructure is required.

`.internal` is especially dangerous in corporate deployments where split-horizon DNS resolves `*.internal` to the local network — an attacker on the internet who convinces a corporate user to visit their page gets cross-origin reach into `ollama.internal:11434` via that user's browser if the corp DNS resolves `*.internal` to loopback or an intranet Ollama.

`.local` is the mDNS realm (RFC 6762); any device on the same LAN advertising `attacker.local` via Bonjour/Avahi becomes an in-LAN Host-header-passing target.

### Location

- `server/routes.go:1581-1606` — `allowedHost()`
- `server/routes.go:1592-1603` — suffix loop over `["localhost","local","internal"]`
- `server/routes.go:1608-1644` — middleware that calls `allowedHost`

### Attacker Control

Any webpage the victim visits (drive-by) or any LAN device running mDNS (`.local`) or any corporate DNS entry on `.internal`. No local access required.

### Trust Boundary Crossed

B10 (network attacker) + cross-origin browser boundary.

### Evidence

Tracer: `strings.HasSuffix` at line 1600 is purely lexical and not a security control for the squatting vector. CORS allowOrigins at `envconfig/config.go:100-106` includes non-HTTP schemes explicitly — drive-by from an installed extension or Electron wrapper achieves preflight success.

Advocate defense: partial CORS protection for JSON POST drive-by from unknown origins. Synthesizer retains HIGH because (a) simple-request endpoints still reachable, (b) allowed non-HTTP origins still reachable, (c) `.localhost` auto-resolve is ubiquitous and requires zero infrastructure.

## Root Cause

Validated rationale: `server/routes.go:1592-1603` accepts ANY hostname ending in `.localhost`, `.local`, or `.internal` via `strings.HasSuffix` with no DNS resolution or IP verification — browsers per RFC 6761 auto-resolve `*.localhost` to 127.0.0.1 without DNS, turning every visited webpage into an on-host cross-origin primitive against local Ollama; Advocate notes CORS blocks preflighted JSON POSTs from non-allowed origins, but simple-request endpoints and allowed-origin contexts (browser extensions, vscode-webview, electron) remain exploitable.

Primary cited code reference: `server/routes.go:1581`.

Merge extraction sink line: - `server/routes.go:1581-1606` — `allowedHost()`

An adversarial review was preserved alongside the draft and should be consulted for counter-arguments and any severity challenge.

## Proof of Concept

Merge-normalized status: `executed`.

PoC script present: `poc.sh`.

Supporting evidence is present under `evidence/`.

1. Serve `http://evil.example/poc.html` with:
   ```html
   <img src="http://evil.localhost:11434/api/me">
   ```
   The browser resolves `evil.localhost` to 127.0.0.1 automatically. Ollama accepts the Host header `evil.localhost:11434` because it ends in `.localhost`. A simple-request GET reaches the daemon.
2. For JSON POST: ship the same page as a Chrome extension or VSCode extension (origins `chrome-extension://...` or `vscode-webview://...` — see p8-062 for CORS membership) and POST `/api/experimental/web_search` with `{"query":"victim's bill","model":"gpt-5"}`.

Remediation: replace suffix match with explicit allowlist `["localhost","127.0.0.1","[::1]"]` only. Require `OLLAMA_ORIGINS` opt-in for any `.internal`/`.local`/`.localhost` subdomain. Document the drive-by vector.

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Real-env reproduction succeeded: Host headers `evil.localhost:11434`, `attacker.local:11434`, `attacker.internal:11434` each returned 200 from a live `/` and `/api/tags` against 127.0.0.1 while the control `evil.example:11434` returned 403, and a `vscode-webview://` preflight to `/api/pull` passed.
Severity-Final: HIGH
PoC-Status: executed

## Impact

- Cross-origin reads against the daemon for any endpoint reachable via CORS "simple request" (GET, POST with `text/plain` / `application/x-www-form-urlencoded` / `multipart/form-data`).
- For JSON-POST endpoints, CORS preflight ordinarily blocks drive-by — but:
  - `app://*`, `file://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*` origins are explicitly allowed (`envconfig/config.go:100-106`); any extension/desktop app with those origins gets the suffix bypass + preflight pass combination, unlocking `/api/pull`, `/api/experimental/web_search`, and `/api/me`.
- DNS-rebinding against the loopback bind is trivial via `.localhost` auto-resolution without any rebinding infrastructure.

_Synthesized during merge normalization from `archon/findings/H5-allowedhost-suffix-squat-localhost-local-internal/draft.md`._
