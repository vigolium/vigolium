## Summary

`WhoamiHandler` (`server/routes.go:1981-2010`) returns a JSON response containing a `signin_url` field built from `signinURL()` (`server/routes.go:183-192`):

```go
func signinURL() string {
    h, _ := os.Hostname()
    pubKey := auth.GetPublicKey()
    encKey := base64.RawURLEncoding.EncodeToString([]byte(pubKey))
    return fmt.Sprintf(signinURLStr, url.PathEscape(h), encKey)
}
```

where `signinURLStr = "https://ollama.com/connect?name=%s&key=%s"`. The hostname and the ed25519 public key are both embedded in the URL. When unauthenticated (no sign-in yet — the common path for most Ollama users), `WhoamiHandler` responds `401` with `{"error":"unauthorized", "signin_url": <URL including pubkey>}`. `cloud_proxy.go:350-357 writeCloudUnauthorized` emits the same.

No auth is required to hit `/api/me`. The only guard is `allowedHostsMiddleware` (see p8-060 / p8-061 for bypass primitives). The CORS config at `envconfig/config.go:100-106` explicitly includes `app://*`, `file://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*` as allowed origins — so desktop Electron apps, Tauri-wrapped UIs, and VSCode extensions pass preflight automatically.

## Details

`WhoamiHandler` (`server/routes.go:1981-2010`) returns a JSON response containing a `signin_url` field built from `signinURL()` (`server/routes.go:183-192`):

```go
func signinURL() string {
    h, _ := os.Hostname()
    pubKey := auth.GetPublicKey()
    encKey := base64.RawURLEncoding.EncodeToString([]byte(pubKey))
    return fmt.Sprintf(signinURLStr, url.PathEscape(h), encKey)
}
```

where `signinURLStr = "https://ollama.com/connect?name=%s&key=%s"`. The hostname and the ed25519 public key are both embedded in the URL. When unauthenticated (no sign-in yet — the common path for most Ollama users), `WhoamiHandler` responds `401` with `{"error":"unauthorized", "signin_url": <URL including pubkey>}`. `cloud_proxy.go:350-357 writeCloudUnauthorized` emits the same.

No auth is required to hit `/api/me`. The only guard is `allowedHostsMiddleware` (see p8-060 / p8-061 for bypass primitives). The CORS config at `envconfig/config.go:100-106` explicitly includes `app://*`, `file://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*` as allowed origins — so desktop Electron apps, Tauri-wrapped UIs, and VSCode extensions pass preflight automatically.

### Location

- `server/routes.go:59` — `signinURLStr = "https://ollama.com/connect?name=%s&key=%s"`
- `server/routes.go:183-192` — `signinURL()` derives hostname + pubkey
- `server/routes.go:1696` — `r.POST("/api/me", s.WhoamiHandler)`
- `server/routes.go:1981-2010` — `WhoamiHandler` emits pubkey on no-user
- `server/cloud_proxy.go:350-357` — `writeCloudUnauthorized` — same disclosure on every cloud-proxy 401

### Attacker Control

Any network-reachable HTTP client or any in-AllowOrigins extension.

### Trust Boundary Crossed

B10 (network) → local identity (cryptographic fingerprint of the user).

### Evidence

Tracer confirmed emission at `WhoamiHandler` line 1981-2010 and `writeCloudUnauthorized` line 350-357. CORS allowlist membership confirmed from `envconfig/config.go:100-106`.

## Root Cause

Validated rationale: `POST /api/me` (`server/routes.go:1696`) returns the victim's ed25519 public key and hostname in `signin_url` when unauthenticated (the common case), with no auth beyond `allowedHostsMiddleware`; `cloud_proxy.go:350-357 writeCloudUnauthorized` emits the same disclosure from every failed cloud-proxy attempt; the CORS list includes `app://*`, `file://*`, `tauri://*`, `vscode-webview://*`, `vscode-file://*` explicitly, so Electron apps, VSCode extensions, and Tauri launchers can read it cross-origin. Advocate did not write a standalone brief for this; synthesizer treats it as a medium-severity disclosure/fingerprinting primitive distinct from the identity theft chain.

Primary cited code reference: `server/routes.go:59`.

Merge extraction sink line: - `server/routes.go:59` — `signinURLStr = "https://ollama.com/connect?name=%s&key=%s"`

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. `curl -X POST http://<ollama>:11434/api/me -H 'Host: anything' -d '{}'` — response contains `signin_url` with ed25519 public key (base64url-encoded) and hostname.
2. From a VSCode extension: `fetch('http://localhost:11434/api/me', {method:'POST'})`.

Remediation:
- Do not emit the pub key in unauthenticated `/api/me` responses. Split the endpoint: return `{"authenticated": false}` when not signed in; only include the sign-in URL if the caller explicitly opts in (e.g., a `?signin_url=1` query parameter and a cookie flag).
- If the sign-in URL IS required, use an opaque server-side sign-in token instead of the raw public key.
- Gate `/api/me` behind the same optional auth as the rest of the daemon (`OLLAMA_AUTH=1`).

## Impact

- **Cross-origin device fingerprint**: hostname + stable ed25519 public key uniquely identifies the user/device; combines with browser fingerprinting for persistent tracking.
- **Sign-in target identification**: when combined with a phishing step, the attacker knows which account to phish (the key identifies the ollama.com user).
- **Cryptographic exposure**: leaking the public key is not itself a compromise, but it reduces the attacker's work when combined with any future signing-key-related vulnerability (p8-070 for permission check).
- Feeds CHAIN-A: step 1 of the identity-theft chain is "know which victim you're talking to".

_Synthesized during merge normalization from `archon/findings/M31-whoami-public-key-disclosure/draft.md`._
