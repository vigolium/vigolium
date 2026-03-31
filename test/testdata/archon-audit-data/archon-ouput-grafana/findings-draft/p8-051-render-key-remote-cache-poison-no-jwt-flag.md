Phase: 10
Sequence: 051
Slug: render-key-remote-cache-poison-no-jwt-flag
Verdict: VALID
Rationale: When renderAuthJWT=false (the default), render key authentication falls through to remote cache lookup via getRenderUserFromCache(); if the remote cache backend (Redis or Memcached) is accessible without authentication — a common misconfiguration — an attacker can write arbitrary RenderUser data under the render-<key> prefix with Admin OrgRole and use any chosen string as a renderKey cookie, granting full render identity access without any feature flag or signing key.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-041-renderer-jwt-forgery-admin-takeover.md
Origin-Pattern: AP-041

## Summary

The `GetRenderUser` function in `pkg/services/rendering/auth.go` follows two mutually exclusive paths:
1. **JWT path** (when `FlagRenderAuthJWT` is enabled AND key starts with "eyJ"): validates JWT signature with `RendererAuthToken`
2. **Cache path** (default, when flag is disabled OR key doesn't look like JWT): looks up key in remote cache under prefix `render-<key>`

The cache path (`getRenderUserFromCache`) reads a gob-encoded `RenderUser` struct from the cache key `render-<renderKey>` without any signature, HMAC, or integrity check. The cache value is trusted completely — whatever `OrgRole` is stored in the cache becomes the authenticated identity's role.

When Grafana is configured to use Redis or Memcached as the `[remote_cache]` backend (operators commonly use Redis for HA deployments), and that cache is accessible without authentication (Redis's default configuration requires no password), an attacker with network access to the cache can:
1. Write a gob-encoded `RenderUser{OrgID: 1, UserID: 0, OrgRole: "Admin"}` to key `render-attacker-chosen-value`
2. Send `Cookie: renderKey=attacker-chosen-value` to any Grafana API endpoint
3. The `Render` authn client (priority 10) intercepts the request, calls `GetRenderUser`, finds the poisoned cache entry, and authenticates as Admin

This is a structural variant of the original finding: the root cause is the same (render authentication with a trivially controllable secret or no integrity protection), but the attack vector does not require the `renderAuthJWT` feature flag.

## Location

- **Primary**: `pkg/services/rendering/auth.go:70-87` — `getRenderUserFromCache` trusts gob-decoded `RenderUser` from remote cache without integrity check
- **Primary**: `pkg/services/rendering/auth.go:34-54` — `GetRenderUser` routes to cache path when `FlagRenderAuthJWT` is false (default) or key doesn't start with "eyJ"
- **Secondary**: `pkg/services/authn/clients/render.go:36-67` — `Authenticate()` constructs Admin identity from cache-returned `RenderUser.OrgRole` without additional validation
- **Secondary**: `conf/defaults.ini:231-236` — `[remote_cache] type = database` (default is DB, but Redis/Memcached are common production choices)

## Attacker Control

- **Input**: `Cookie: renderKey=<attacker-chosen-string>` on any HTTP request to Grafana
- **Cache write**: Gob-encoded `RenderUser{OrgID: 1, UserID: 0, OrgRole: "Admin"}` written to Redis/Memcached key `render-<chosen-string>`
- **Prerequisite**: Network access to the Redis/Memcached instance (unauthenticated, or with known credentials)
- **No feature flag required**: Attack works against default `renderAuthJWT=false` configuration

The gob encoding of `RenderUser` is deterministic and can be computed offline:
```go
// Encode target:
buf := bytes.NewBuffer(nil)
gob.NewEncoder(buf).Encode(&RenderUser{OrgID: 1, UserID: 0, OrgRole: "Admin"})
// Result: write buf.Bytes() to Redis key "render-mykey"
```

## Trust Boundary Crossed

Remote cache (TB: internal infrastructure) → Grafana HTTP API authentication (TB1: Internet → Grafana API). The remote cache is treated as a trusted store for authentication credentials without any signing or integrity protection. An attacker who can write to the cache crosses into Grafana's authentication domain.

## Impact

- Full render-service Admin identity without any feature flag or signing key knowledge
- In HA deployments with shared Redis, all Grafana nodes in the cluster are simultaneously vulnerable
- Persistence: TTL is `render_key_lifetime` (default 5 minutes), but the attacker can continuously re-write the cache entry
- No brute force required: attacker chooses the exact key value
- No Grafana credentials, no signing key, no feature flag: only network access to the cache

## Evidence

1. `auth.go:41-47`: Flag check: `if looksLikeJWT(key) && rs.features.IsEnabled(ctx, featuremgmt.FlagRenderAuthJWT)` — both conditions must be true for JWT path; default is cache path
2. `auth.go:70-87`: `getRenderUserFromCache` calls `gob.NewDecoder(buf).Decode(&ru)` — no signature validation, no HMAC check
3. `auth.go:89-101`: `setRenderKey` stores `gob.Encode(RenderUser{...})` — same format, confirming the wire format is reproducible
4. `render.go:43-57`: `Authenticate()` creates Admin identity when `OrgRole == "Admin"` with `SyncPermissions: true`
5. `conf/defaults.ini:237`: Redis config format documented — many production deployments use Redis; Redis default is no-auth on 127.0.0.1 but commonly exposed internally

## Reproduction Steps

1. Configure Grafana with Redis as remote cache: `[remote_cache] type = redis`; configure `addr=<redis-host>:6379` without password
2. Compute gob-encoded RenderUser bytes for Admin role (can be done offline)
3. Write poisoned cache entry to Redis:
   ```
   SET "grafana:render-myattackerkey" <gob-encoded-bytes> EX 300
   ```
   (Note: Grafana may prefix the key depending on configuration; verify with `KEYS render-*`)
4. Send request with poisoned cookie:
   ```
   curl -H "Cookie: renderKey=myattackerkey" http://localhost:3000/api/admin/settings
   ```
5. Expected: Admin API response (render identity granted Admin access)

Note: The `renderAuthJWT` feature flag does NOT need to be enabled. This attack path is active whenever a non-database remote cache backend is used.
