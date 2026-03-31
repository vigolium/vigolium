# PATCH-T3-03: CVE-2024-1313 — Snapshot Deletion Auth Bypass

**Cluster ID:** snapshot-auth-k8s-migration
**Advisory:** CVE-2024-1313 (MEDIUM 6.5)
**Component:** `pkg/api/dashboard_snapshot.go`, K8s API at `pkg/registry/apis/dashboard/snapshot/`

## Patch Summary

The original CVE-2024-1313 fix added an **org membership check** to `DeleteDashboardSnapshot` in the legacy REST API (`pkg/api/dashboard_snapshot.go:218`):

```go
if queryResult.OrgID != c.OrgID {
    return response.Error(http.StatusUnauthorized, "OrgID mismatch", nil)
}
```

Previously, possessing the snapshot view key was sufficient to delete it cross-org. The fix ensures the caller belongs to the same organization as the snapshot owner.

Two recent commits added permissions to the new K8s API path:
- `5c89af649b2` — Adds `NewSnapshotAuthorizer` with RBAC verb-to-action mapping
- `c196ecd521b` — Adds dashboard existence validation on create

## Bypass Verdict: **bypassable**

### Finding 1: K8s API delete-by-deleteKey route lacks org membership check (HIGH)

**Path:** `pkg/registry/apis/dashboard/snapshot/routes.go:257-283`

The K8s API custom route `snapshots/delete/{deleteKey}` performs only an RBAC permission check (`ActionSnapshotsDelete`) but does **not** verify that the caller's org matches the snapshot's org. It calls `dashboardsnapshots.DeleteWithKey()` directly which also has no org check — it fetches the snapshot by delete key and deletes it regardless of org.

Compare:
- **Legacy API** (`pkg/api/dashboard_snapshot.go:218`): checks `queryResult.OrgID != c.OrgID`
- **K8s API** (`routes.go:266-275`): checks RBAC permission only, no org check

Any authenticated user with `snapshots:delete` permission who knows or guesses a deleteKey can delete snapshots belonging to other organizations via the K8s API route.

**Mitigation factor:** The deleteKey is a 32-character cryptographically random string (`crypto/rand`, 62-char alphabet = ~190 bits entropy), so brute-forcing is infeasible. However, deleteKey may be leaked through logs, URLs, or API responses.

### Finding 2: K8s API standard DELETE (by name) relies solely on namespace scoping

**Path:** `pkg/registry/apis/dashboard/snapshot/snapshot_legacy_store.go:60-83`

The `SnapshotLegacyStore.Delete()` method fetches the snapshot by its key (name) and deletes it without any explicit org check. The protection comes from K8s namespace scoping — the request context carries a namespace derived from the caller's org, and the K8s API server enforces that objects are accessed within their namespace.

This is **sound** as long as the K8s API server properly enforces namespace isolation. The `NamespaceScoped()` method returns `true` (line 43-44), and K8s API machinery enforces namespace boundaries. The `SnapshotAuthorizer` (line 52 in `authorizer.go`) checks `ActionSnapshotsDelete` permission for delete verbs.

**Verdict for this path:** Sound (namespace-scoped K8s isolation provides the equivalent of org check).

### Finding 3: Legacy delete-by-deleteKey has no org check either

**Path:** `pkg/api/dashboard_snapshot.go:164-186`

`DeleteDashboardSnapshotByDeleteKey` also lacks an org membership check. It calls `dashboardsnapshots.DeleteWithKey()` which fetches by delete key and deletes without org validation. This was the same pattern as the original CVE but via a different entry point (GET `/api/snapshots-delete/:deleteKey`).

However, this is by design — the deleteKey is a bearer secret returned only to the snapshot creator. The security model for this path relies entirely on the secrecy of the deleteKey rather than org membership. The `SnapshotPublicMode` middleware allows unauthenticated access to this endpoint when public mode is enabled, which is intentional.

### Finding 4: SnapshotPublicMode bypasses all auth for delete-by-deleteKey

**Path:** `pkg/middleware/auth.go:255-268`

When `SnapshotPublicMode` is `true`, the `SnapshotPublicModeOrDelete` middleware allows unauthenticated access to the delete-by-deleteKey endpoint. This is by design but worth noting — in public mode, anyone with a deleteKey can delete a snapshot without authentication.

The K8s API route `snapshots/delete/{deleteKey}` does NOT respect `SnapshotPublicMode` — it always requires authentication and RBAC. This is a behavioral inconsistency between the two API surfaces.

## Key Generation Analysis

Snapshot keys use `util.GetRandomString(32)` which uses `crypto/rand` with a 62-character alphabet. This produces approximately 190 bits of entropy, making brute-force infeasible.

## Summary of Bypass Vectors

| Vector | Status | Notes |
|--------|--------|-------|
| K8s delete-by-deleteKey missing org check | **Bypassable** | No org validation, only RBAC check |
| K8s standard DELETE (by name) | Sound | Namespace scoping provides org isolation |
| Legacy DELETE /api/snapshots/:key | Sound | Has explicit org check (CVE-2024-1313 fix) |
| Legacy GET /api/snapshots-delete/:deleteKey | By design | Relies on deleteKey secrecy, no org check |
| Key brute-force | Not feasible | 190-bit entropy from crypto/rand |
| SnapshotPublicMode | By design | Allows unauth delete-by-deleteKey in public mode |
| Config-gated: KubernetesSnapshots feature flag | Conditional | K8s path only active when flag enabled |

## Evidence

1. **K8s delete route** at `pkg/registry/apis/dashboard/snapshot/routes.go:257-283` — RBAC only, no org check
2. **Legacy delete** at `pkg/api/dashboard_snapshot.go:197-258` — has org check at line 218
3. **DeleteWithKey helper** at `pkg/services/dashboardsnapshots/service.go:223-240` — no org check, trusts caller
4. **Authorizer** at `pkg/registry/apis/dashboard/snapshot/authorizer.go:14-63` — RBAC only, no object-level org check
