Phase: 7
Sequence: 044
Slug: datasource-cache-no-delete-invalidation
Verdict: VALID
Rationale: Confirmed 5-second stale credential window with no cache invalidation on delete at datasource.go:560-572. The datasource cache uses a 5-second TTL but has no delete-triggered invalidation, meaning deleted datasource credentials continue to be used for proxy requests during the TTL window. HA deployments amplify with per-pod independent caches.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

The datasource cache service at `pkg/services/datasources/service/cache.go` caches datasource objects with a 5-second TTL (`DefaultCacheTTL = 5 * time.Second`). When a datasource is deleted via `DeleteDataSource()` at `datasource.go:560-572`, there is NO call to `CacheService.Delete()` to invalidate the cached entry. The cached datasource object (including its backend URL and credentials) remains available for up to 5 seconds.

During this window, any query routed through the datasource proxy will use the cached (now-deleted) datasource's credentials to authenticate with the backend datasource. This means that after an admin deletes a datasource to revoke backend access, the credentials continue to be used for up to 5 seconds per Grafana pod.

In HA deployments with N pods, each pod has an independent process-local cache. The `DataSourceDeleted` event published at store.go:217-224 is for Grafana Live notifications, not for cache invalidation across pods.

This is part of the CVE-2026-21725 pattern.

## Location

- **Cache TTL:** `pkg/services/datasources/service/cache.go:17` -- `DefaultCacheTTL = 5 * time.Second`
- **Cache population:** `pkg/services/datasources/service/cache.go:113` -- `dc.CacheService.Set(uidCacheKey, ds, dc.cacheTTL)`
- **Delete without invalidation:** `pkg/services/datasources/service/datasource.go:560-572` -- `DeleteDataSource()` has no CacheService.Delete()
- **Stale cache read:** `pkg/services/datasources/service/cache.go:93-101` -- `GetDatasourceByUID()` returns cached entry
- **Live event (not cache):** `pkg/services/datasources/service/store.go:217-224` -- `PublishAfterCommit` is for Live notifications

## Attacker Control

Authenticated user with `datasources.ActionQuery` RBAC permission. After a datasource is deleted by an admin, the attacker continues to issue queries against the cached datasource UID during the 5-second TTL window.

## Trust Boundary Crossed

TB4 (Datasource Proxy) -- credentials for a deleted datasource continue to be injected into outbound proxy requests, crossing the credential injection boundary after the admin intended to revoke access.

## Impact

Transient access continuation: backend datasource credentials remain usable for up to 5 seconds per pod after deletion. In security-sensitive scenarios (e.g., revoking compromised credentials by deleting the datasource), this 5-second window allows continued access to the backend system.

In HA deployments with N pods, the effective window is up to 5s * N in the worst case (if the attacker rotates requests across pods).

## Evidence

1. `cache.go:17`: `DefaultCacheTTL = 5 * time.Second`
2. `cache.go:113-114`: `dc.CacheService.Set(uidCacheKey, ds, dc.cacheTTL); dc.CacheService.Set(idKey(ds.ID), ds, dc.cacheTTL)` -- cached on read
3. `datasource.go:560-572`: DeleteDataSource runs in transaction but has no cache invalidation
4. No grep match for `CacheService.Delete` in any datasource delete code path
5. `store.go:217-224`: DataSourceDeleted event is for Live, not cache

## Reproduction Steps

1. Create a datasource pointing to a backend service
2. Issue a query to cache the datasource (triggers cache.go:113)
3. Delete the datasource via `DELETE /api/datasources/uid/:uid`
4. Within 5 seconds, issue another query to the same datasource UID
5. Observe the query succeeds (uses cached credentials) despite the datasource being deleted from the database
6. After 5 seconds, observe the query fails (cache expired)
