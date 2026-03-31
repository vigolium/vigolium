# Bypass Analysis: PATCH-T2-01 -- CVE-2026-21720 -- Unauthenticated Avatar Cache DoS

**Cluster ID:** AVATAR-DOS-01
**Patch Commit:** `86c2e52464f`
**Severity:** HIGH (7.5)

## Patch Summary

The patch addresses an unauthenticated Denial-of-Service vulnerability in the Gravatar avatar proxy endpoint (`/avatar/:hash`). Three mitigations were applied:

1. **Authentication gate**: Added `reqSignedIn` middleware to the `/avatar/:hash` route in `pkg/api/api.go` (line 605).
2. **Removed goroutine queue**: The old `Thunder` goroutine pool (queue size 10) that serialized outbound avatar fetches is bypassed -- the `update()` method now calls `avatarFetch()` directly via a dead-code `if true` branch, making the `Thunder` queue unreachable.
3. **Request context propagation**: `performGet()` now uses `http.NewRequestWithContext(ctx, ...)`, meaning outbound Gravatar fetches are tied to the incoming HTTP request's context. If the client disconnects or the server cancels the request, the outbound fetch is also cancelled.
4. **Bounded cache**: Replaced `go-cache` (unbounded) with `hashicorp/golang-lru/v2/expirable` LRU cache capped at 2000 entries with 1-hour TTL, preventing memory exhaustion from unique hash flooding.

## Bypass Verdict: **bypassable** (conditional)

The fix is bypassable when Grafana's anonymous authentication is enabled (`[auth.anonymous] enabled = true`).

## Evidence

### Finding 1: Anonymous Auth Bypass of `reqSignedIn` (CONFIRMED)

The route uses `reqSignedIn` which is defined as:

```go
// pkg/middleware/middleware.go:19
ReqSignedIn = Auth(&AuthOptions{ReqSignedIn: true})
```

The `Auth()` middleware in `pkg/middleware/auth.go:202-227` computes:

```go
requireLogin := !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous
if !c.IsSignedIn && options.ReqSignedIn && requireLogin {
    notAuthorized(c)
    return
}
```

When `[auth.anonymous]` is enabled in `grafana.ini`, the context handler sets:

```go
// pkg/services/contexthandler/contexthandler.go:147
reqContext.AllowAnonymous = reqContext.IsAnonymous
```

This means `c.AllowAnonymous = true`, so `requireLogin = false`, and the `reqSignedIn` check is effectively a no-op. The avatar endpoint becomes accessible to unauthenticated users, just as it was before the patch.

The correct fix would use `reqSignedInNoAnonymous` (which sets `ReqNoAnonynmous: true`), ensuring the check cannot be bypassed by anonymous sessions:

```go
// pkg/middleware/middleware.go:20
ReqSignedInNoAnonymous = Auth(&AuthOptions{ReqSignedIn: true, ReqNoAnonynmous: true})
```

**Impact**: Any Grafana instance with `[auth.anonymous] enabled = true` remains fully vulnerable to the original DoS attack. Anonymous auth is commonly enabled for public dashboards.

### Finding 2: No Response Body Size Limit (LOW)

The `getGravatarHandler` function reads the full response body from Gravatar without a size cap:

```go
// pkg/api/avatar/avatar.go:306-310
if resp.ContentLength > 0 {
    data = make([]byte, resp.ContentLength)
    _, err = io.ReadFull(resp.Body, data)
} else {
    data, err = io.ReadAll(resp.Body)
}
```

If the Gravatar server (or a man-in-the-middle) returns a very large `Content-Length`, Grafana will allocate that much memory. This is a secondary concern since the upstream is `secure.gravatar.com`, but it means a SSRF or DNS rebinding scenario could cause memory allocation issues. The `http.Client` timeout of 2 seconds provides partial mitigation.

### Finding 3: Dead Code -- Thunder Queue Still Present

The `Thunder` goroutine pool code (lines 212-266) remains in the file but is unreachable due to the `if true` guard on line 75. This is dead code that should be removed. It has no security impact but indicates the patch was conservative/incremental.

### Finding 4: Only One Avatar Route Exists (CONFIRMED SOUND)

There is only a single route registration for avatar serving: `r.Get("/avatar/:hash", ...)` in `pkg/api/api.go:605`. No alternative routes or API endpoints serve avatar images directly. The `AvatarCacheServer` is only consumed by this handler and by `GetAvatarForHash()` calls within user DTO construction (which do not serve images over HTTP).

### Finding 5: LRU Cache Bounds Are Sound

The LRU cache is bounded to 2000 entries with 1-hour TTL (`lru.NewLRU[string, *Avatar](2000, nil, time.Hour)`). This effectively caps memory usage from cached avatars. Even with bypass via anonymous auth, an attacker can only cause outbound requests to Gravatar (SSRF amplification), not unbounded memory growth.

### Finding 6: Cache Logic Change -- No Longer Re-fetches Expired Entries

The old code re-fetched avatars when `avatar.Expired()` returned true (after 10 minutes). The new code only fetches when the entry is not in the LRU cache at all (the LRU handles expiration internally at 1 hour). This means cache misses happen less frequently, reducing the amplification factor from the original attack. However, the 2000-entry cap means an attacker with access (via anonymous bypass) can still force 2000 unique outbound fetches.

## Summary of Bypass Conditions

| Condition | Bypass? | Notes |
|-----------|---------|-------|
| `[auth.anonymous] enabled = false` (default) | No | `reqSignedIn` blocks unauthenticated requests |
| `[auth.anonymous] enabled = true` | **Yes** | `AllowAnonymous` causes `reqSignedIn` to be skipped |
| Authenticated low-privilege user | Partial | Rate is bounded by LRU cap (2000) and 2s client timeout |

## Recommendation

Replace `reqSignedIn` with `reqSignedInNoAnonymous` on the avatar route to close the anonymous auth bypass:

```go
r.Get("/avatar/:hash", requestmeta.SetSLOGroup(requestmeta.SLOGroupHighSlow), reqSignedInNoAnonymous, hs.AvatarCacheServer.Handler)
```

Additionally, add an `io.LimitReader` wrapper around the Gravatar response body to cap memory allocation per avatar fetch.
