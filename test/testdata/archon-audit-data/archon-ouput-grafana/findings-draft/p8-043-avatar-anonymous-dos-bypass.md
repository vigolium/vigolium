Phase: 8
Sequence: 043
Slug: avatar-anonymous-dos-bypass
Verdict: VALID
Rationale: Avatar endpoint uses reqSignedIn instead of reqSignedInNoAnonymous, enabling unauthenticated DoS via outbound HTTP exhaustion when anonymous auth is enabled; one non-default precondition and DoS-only impact calibrate to MEDIUM.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

The avatar endpoint at `GET /avatar/:hash` (api.go:605) uses `reqSignedIn` middleware instead of `reqSignedInNoAnonymous`. When Grafana's anonymous authentication is enabled (`[auth.anonymous] enabled=true`), `reqSignedIn` does NOT block unauthenticated users because `requireLogin = !AllowAnonymous || forceLogin || ReqNoAnonynmous` evaluates to false. An unauthenticated attacker can send many concurrent requests with unique 32-character hex hashes, each triggering up to 2 outbound HTTPS requests to secure.gravatar.com. The LRU cache (2000 entries) is insufficient against the 16^32 possible hash space, enabling sustained outbound HTTP exhaustion and goroutine pressure against the Grafana instance.

## Location

- **Primary**: `pkg/api/api.go:605` -- `r.Get("/avatar/:hash", reqSignedIn, hs.AvatarCacheServer.Handler)` uses `reqSignedIn` instead of `reqSignedInNoAnonymous`
- **Auth logic**: `pkg/middleware/auth.go:216` -- `requireLogin = !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous` -- false when `AllowAnonymous=true`
- **Avatar handler**: `pkg/api/avatar/avatar.go:104` -- `fetchAndCache()` triggers outbound HTTP
- **Related**: `api.go:599` (/render/*) and `api.go:602` (/api/gnet/*) also use `reqSignedIn`

## Attacker Control

- **Input**: `:hash` URL path parameter (32 hex characters, validated by MD5 regex)
- **Hash space**: 16^32 possible unique hashes far exceed 2000-entry LRU cache
- **Minimum privilege**: Unauthenticated (when anonymous auth enabled)

## Trust Boundary Crossed

Internet (unauthenticated) -> Grafana server -> outbound HTTPS to secure.gravatar.com. The authentication gate is bypassed via the reqSignedIn/anonymous auth interaction, allowing unauthenticated users to trigger server-side outbound requests.

## Impact

- **Denial of Service**: Outbound HTTP connection exhaustion, goroutine pressure, memory pressure from concurrent requests
- **Amplification**: Each unique hash triggers up to 2 outbound HTTPS requests (Gravatar URL + fallback URL)
- **No rate limiting**: No application-level rate limit on the avatar endpoint
- **Service degradation**: Exhaustion of outbound connection pool affects all Grafana outbound communication (datasource queries, alerting, etc.)
- **No data compromise**: This is a DoS vector only

## Evidence

1. `api.go:605`: `r.Get("/avatar/:hash", reqSignedIn, hs.AvatarCacheServer.Handler)` -- uses reqSignedIn
2. `auth.go:216`: `requireLogin = !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous` -- false when AllowAnonymous=true
3. `avatar.go:104`: `fetchAndCache()` -> `performGet()` triggers 2 outbound HTTPS per cache miss
4. `avatar.go`: LRU cache with 2000 entries -- insufficient for 16^32 hash space
5. `avatar.go`: `validMD5` regex limits to 32 hex chars but does not reduce exploitability

## Reproduction Steps

1. Enable anonymous auth in grafana.ini: `[auth.anonymous] enabled = true`
2. Restart Grafana
3. Without any authentication, send many concurrent requests with unique hashes:
   ```bash
   for i in $(seq 1 1000); do
     hash=$(printf '%032x' $RANDOM$RANDOM$RANDOM$RANDOM)
     curl -s "http://localhost:3000/avatar/${hash}" &
   done
   ```
4. Monitor Grafana's outbound connections: `ss -tnp | grep 3000 | wc -l`
5. Expected: Each unique hash triggers 2 outbound HTTPS connections to secure.gravatar.com
6. Sustained flooding with unique hashes exhausts the server's outbound connection pool

Note: The `[auth.anonymous] enabled=true` configuration is disabled by default. Fix: change `reqSignedIn` to `reqSignedInNoAnonymous` at api.go:605.
