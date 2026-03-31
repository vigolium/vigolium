Phase: 9
Sequence: 080
Slug: user-signed-in-cache-no-delete-invalidation
Verdict: VALID
Rationale: SignedInUser is cached with a 5-second TTL at userimpl/legacy_user.go:376 but the Delete() function at line 208-219 makes no call to cacheService.Delete(), leaving deleted users' identity (including org roles and permissions) readable from cache for up to 5 seconds per pod, crossing the authentication revocation boundary.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-044-datasource-cache-no-delete-invalidation.md
Origin-Pattern: AP-044

## Summary

`pkg/services/user/userimpl/legacy_user.go` caches the `SignedInUser` result with a 5-second TTL when `GetSignedInUser` is called (line 376), but the `Delete()` function (lines 208-219) does not invalidate the cache entry. After an administrator deletes a user account, any in-flight or immediately subsequent request that authenticates as that user (via an active session cookie or API key) will still resolve the deleted user's `SignedInUser` object from the local in-process cache. The cached object includes org ID, org role, and team memberships — meaning authorization decisions made against it also reflect stale state.

This is the same structural anti-pattern as AP-044 (confirmed in p7-044 for datasources). The impact is more severe than the datasource case because the auth gate (TB2) is directly affected: a deleted user can continue to authenticate and be treated as a valid org member for up to 5 seconds per Grafana pod.

In HA deployments with N pods, the effective window is 5 seconds on each pod independently; the user's requests can cycle across pods to extend the access window.

## Location

- **Cache TTL and Set:** `pkg/services/user/userimpl/legacy_user.go:374-376`
  ```go
  cacheKey := newSignedInUserCacheKey(result.OrgID, result.UserID)
  s.cacheService.Set(cacheKey, *result, time.Second*5)
  ```
- **Delete path (no cache invalidation):** `pkg/services/user/userimpl/legacy_user.go:208-219`
  ```go
  func (s *LegacyService) Delete(ctx context.Context, cmd *user.DeleteUserCommand) error {
      _, err := s.store.GetByID(ctx, cmd.UserID)
      if err != nil { return err }
      return s.store.Delete(ctx, cmd.UserID)
      // MISSING: s.cacheService.Delete(newSignedInUserCacheKey(cmd.OrgID, cmd.UserID))
  }
  ```
- **Cache key construction:** `pkg/services/user/userimpl/legacy_user.go:382-384`
  ```go
  func newSignedInUserCacheKey(orgID, userID int64) string {
      return fmt.Sprintf("signed-in-user-%d-%d", userID, orgID)
  }
  ```
- **Cache read path:** `pkg/services/user/userimpl/legacy_user.go:355-366` — cache hit returns `*user.SignedInUser` directly, bypassing DB

## Attacker Control

A user whose account is being deleted by an administrator. The user must have a valid session token or API key at deletion time. The attacker sends authenticated requests immediately after deletion.

## Trust Boundary Crossed

TB2 (Authentication Gate) — a deleted identity continues to pass the authentication resolution step (`GetSignedInUser` returns the cached object without a database liveness check). Also TB3 (Authorization Gate) — the cached `SignedInUser` includes `OrgRole` and `Teams`, so RBAC decisions made against this stale identity grant the deleted user continued access to org resources.

## Impact

Deleted users retain authenticated access for up to 5 seconds per Grafana pod after account deletion. In a security-sensitive scenario (e.g., revoking access for a terminated employee or a compromised account), the administrator's delete action does not take effect immediately. The user can continue to read dashboards, query datasources, or perform any action their cached role allows during the TTL window. HA deployments amplify this: with N pods, requests rotated across pods extend the effective window.

The impact is bounded by the 5-second TTL and requires an active session/key. However, the authentication bypass is complete within that window — no partial mitigation exists.

## Evidence

1. `legacy_user.go:374-376`: `s.cacheService.Set(cacheKey, *result, time.Second*5)` — 5-second TTL set on read
2. `legacy_user.go:208-219`: `Delete()` calls only `s.store.Delete(ctx, cmd.UserID)` — no cache invalidation
3. `legacy_user.go:361-365`: Cache read path returns stale `SignedInUser` without any DB liveness check
4. `legacy_user.go:382-384`: `newSignedInUserCacheKey` — key is deterministic (orgID + userID), not session-scoped
5. No grep match for `cacheService.Delete` in `pkg/services/user/` package
6. Contrast with `pkg/services/pluginsintegration/plugincontext/plugincontext.go:155-157`: plugin settings cache correctly calls `cacheService.Delete()` in `InvalidateSettingsCache` — confirming the correct pattern exists in the codebase

## Reproduction Steps

1. Create a standard Grafana user in an organization
2. Authenticate as that user and obtain a session cookie or API key
3. Make an authenticated API call to warm the SignedInUser cache (e.g., `GET /api/user`)
4. As an administrator, delete the user account via `DELETE /api/admin/users/:id`
5. Within 5 seconds of step 4, make another authenticated API call using the credentials from step 2
6. Observe the request succeeds (200 OK) despite the account being deleted
7. After 5 seconds from step 4, observe the request fails (401 Unauthorized — cache expired, DB lookup fails)
