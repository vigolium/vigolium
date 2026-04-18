Phase: 10
Sequence: 001
Slug: cross-origin-forced-signout
Verdict: VALID
Rationale: A cross-origin attacker from a file:// or vscode-webview:// context can trigger POST /api/signout, which calls the victim's ollama.com Disconnect endpoint signed with the victim's private key, forcibly deauthenticating the victim from ollama.com with no interaction required beyond opening a file.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: archon/findings-draft/p4-f07-cors-file-origin.md
Origin-Pattern: AP-001

## Summary

`POST /api/signout` is registered on the gin router at `server/routes.go:1690` and thus subject to the same CORS policy that allows `file://*`, `vscode-webview://*`, and `app://*` origins. `SignoutHandler` calls `auth.GetPublicKey()` to retrieve the victim's ed25519 private key from `~/.ollama/id_ed25519`, signs a deletion request, and forwards it to `https://ollama.com/api/user/keys/<encodedKey>` to revoke the victim's registered public key. The victim is silently signed out. This requires no special user action beyond having Ollama running and opening a malicious local HTML file or VS Code extension webview.

## Location

- `server/routes.go:1690` -- POST /api/signout (no auth, CORS allows file://*)
- `server/routes.go:2004-2034` -- SignoutHandler: reads private key, signs, calls ollama.com
- `auth/auth.go:21-40` -- GetPublicKey reads ~/.ollama/id_ed25519
- `api/client.go:468-470` -- Disconnect calls DELETE /api/user/keys/:encodedKey on ollama.com
- `envconfig/config.go:100-106` -- AllowedOrigins includes file://* and vscode-webview://*

## Attacker Control

- Full control over when signout fires (any cross-origin request to POST /api/signout)
- No parameters required; the private key and public key are resolved server-side
- DELETE /api/user/keys/:encodedKey is also exposed at `server/routes.go:1692` and also allows cross-origin forced signout via the deprecated route

## Trust Boundary Crossed

Local file or VS Code extension origin (untrusted) to ollama.com authentication state (trusted). The attacker revokes the victim's ollama.com authentication credential without the victim's knowledge or consent.

## Impact

- Victim is silently signed out of ollama.com while Ollama is running
- Cloud inference features and model access requiring authentication become unavailable
- Denial-of-service attack against authenticated cloud usage
- Repeated triggering can prevent the victim from staying authenticated (persistent DoS)
- The deprecated DELETE /api/user/keys/:encodedKey route (line 1692) provides an alternative path with the same effect

## Evidence

1. `server/routes.go:1690`: `r.POST("/api/signout", s.SignoutHandler)` — gin route, no auth middleware
2. `server/routes.go:2004-2034`: SignoutHandler calls `auth.GetPublicKey()`, base64-encodes it, calls `client.Disconnect(c, encKey)` targeting `https://ollama.com`
3. `auth/auth.go:21-40`: `GetPublicKey` reads `~/.ollama/id_ed25519` directly from filesystem
4. `envconfig/config.go:100-106`: `file://*` is hardcoded in `AllowedOrigins()` with no mechanism for operators to remove it
5. `server/routes.go:1664`: single CORS config applied to all routes — no route-group separation

## Reproduction Steps

1. Start Ollama and ensure the user is signed in to ollama.com (`ollama signin`)
2. Create a local HTML file:
   ```html
   <script>
   fetch('http://localhost:11434/api/signout', {method: 'POST'})
     .then(r => console.log('Signed out, status:', r.status));
   </script>
   ```
3. Open the HTML file locally in a browser (file:///tmp/evil.html)
4. Observe the CORS preflight passes and the POST succeeds
5. Verify the victim is signed out: `ollama whoami` returns unauthorized
