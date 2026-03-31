Phase: 8
Sequence: 004
Slug: nginx-harbor-secret-header-passthrough
Verdict: VALID
Rationale: Missing Nginx header stripping is a confirmed defense-in-depth failure, but the strong 128-bit cryptographic secret is a practical blocking precondition, warranting MEDIUM.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md

## Summary

Harbor's Nginx reverse proxy does not strip the `Authorization` header from external requests. The Harbor-Secret authentication mechanism (priority 1 in the auth chain) extracts shared secrets from the `Authorization: Harbor-Secret <value>` header. If an external attacker obtains the shared secret (via environment variable leak, configuration exposure, or future CVE), they can send requests with the secret header from the external network to gain full internal service trust context, bypassing all other authentication.

## Location

- `make/photon/prepare/templates/nginx/nginx.http.conf.jinja` -- all location blocks lack `proxy_set_header Authorization ""`
- `make/photon/prepare/templates/nginx/nginx.https.conf.jinja` -- same gap
- `src/common/secret/request.go:29-37` -- `FromRequest` extracts Harbor-Secret from Authorization header
- `src/server/middleware/security/secret.go:29-37` -- secret.Generate is priority 1 in auth chain

## Attacker Control

The attacker controls the HTTP `Authorization` header value. Exploitation is conditional on knowing the shared secret value (32 hex chars from crypto/rand, 128 bits entropy).

## Trust Boundary Crossed

External network -> Internal service trust context (conditional on secret knowledge). The secret auth mechanism is designed for internal inter-service communication only.

## Impact

- Full internal service trust context (equivalent to JobService privileges)
- Bypasses all other authentication mechanisms (secret is priority 1 in auth chain)
- Any future secret leak immediately enables external exploitation with no Nginx-level barrier
- Defense-in-depth failure: the secret value is the sole protection layer

## Evidence

```
# Nginx config -- no Authorization header stripping
location /api/ {
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $x_forwarded_proto;
    # MISSING: proxy_set_header Authorization "";
}
```

```go
// src/common/secret/request.go:25-37
const HeaderPrefix = "Harbor-Secret "
func FromRequest(req *http.Request) string {
    auth := req.Header.Get("Authorization")
    if after, ok := strings.CutPrefix(auth, HeaderPrefix); ok {
        return after
    }
    return ""
}
```

## Reproduction Steps

1. Examine Nginx config templates -- confirm no `proxy_set_header Authorization ""` in any location block
2. If secret is known: send `curl -H "Authorization: Harbor-Secret <secret_value>" https://harbor.example.com/api/v2.0/users`
3. Observe full system-level access without any user credentials
4. Recommended fix: Add `proxy_set_header Authorization ""` to all external-facing Nginx location blocks, or use a separate header name for internal secret auth
