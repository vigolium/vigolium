Phase: 8
Sequence: 002
Slug: k8s-snapshot-cross-org-delete
Verdict: VALID
Rationale: The K8s API snapshot delete paths (both delete-by-deleteKey at routes.go:275 and standard DELETE at snapshot_legacy_store.go:60-83) lack the org isolation check (queryResult.OrgID != c.OrgID) that was added to the legacy REST API as part of the CVE-2024-1313 fix. The database query at database.go:89-108 fetches snapshots by key/deleteKey without org filtering. The Advocate correctly identified high-entropy key requirement and experimental feature flag as mitigating factors that justify MEDIUM rather than HIGH severity.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-1-p8/debate.md

## Summary

The CVE-2024-1313 fix added an org isolation check (`queryResult.OrgID != c.OrgID`) to the legacy REST API snapshot deletion handler at `dashboard_snapshot.go:218`. This check was NOT ported to the K8s API paths:

1. **Delete-by-deleteKey** (`routes.go:275`): The K8s snapshot routes handler calls `dashboardsnapshots.DeleteWithKey(ctx, key, service)` without any org check after fetching the snapshot.

2. **Standard DELETE** (`snapshot_legacy_store.go:60-83`): The `SnapshotLegacyStore.Delete()` calls `GetDashboardSnapshot` with only `Key: name` (no org filter), then proceeds to delete.

3. **GET** (`snapshot_legacy_store.go:121-135`): The `Get()` function also lacks org filtering, enabling cross-org metadata read (though the `storageWrapper` strips sensitive fields).

The underlying database query at `database.go:89-108` uses xorm `sess.Get(&snapshot)` with only the Key or DeleteKey field set, generating a `WHERE key=?` or `WHERE delete_key=?` clause with NO `org_id` filter.

## Location

- **Delete-by-deleteKey**: `pkg/registry/apis/dashboard/snapshot/routes.go:260-283` -- K8s custom route handler
- **Standard DELETE**: `pkg/registry/apis/dashboard/snapshot/snapshot_legacy_store.go:60-83` -- `Delete()` method
- **Standard GET**: `pkg/registry/apis/dashboard/snapshot/snapshot_legacy_store.go:121-135` -- `Get()` method
- **Database query**: `pkg/services/dashboardsnapshots/database/database.go:89-108` -- `GetDashboardSnapshot()` with no org filter
- **Legacy REST API (correctly patched)**: `pkg/api/dashboard_snapshot.go:218` -- `queryResult.OrgID != c.OrgID`
- **K8s API registration**: `pkg/registry/apis/dashboard/register.go:787-808` -- unconditional registration

## Attacker Control

The attacker controls the snapshot key (resource name) or deleteKey in the K8s API request URL. The snapshot key is a high-entropy value (190 bits for deleteKey). Potential discovery vectors:
- Snapshot list API (org-scoped, so cross-org list is blocked)
- Log files recording snapshot operations
- Shared snapshot URLs containing the key
- The K8s deletekey subresource (`GET .../snapshots/{name}/deletekey`) which itself lacks org filtering

## Trust Boundary Crossed

TB-9 (K8s API aggregation) and TB-11 (Org isolation). The K8s namespace is mapped to org ID for API routing, but the `SnapshotLegacyStore` does not enforce org filtering at the database level. A user in one org can operate on snapshots belonging to a different org.

## Impact

- **Cross-org snapshot deletion**: User in Org-B can delete snapshots owned by Org-A (DoS, data loss)
- **Cross-org metadata read**: User in Org-B can read snapshot metadata (name, timestamps, external flag) from Org-A
- **DeleteKey exposure**: The deletekey subresource can expose deleteKeys cross-org, enabling delete-by-deleteKey attacks
- **CVE regression**: The CVE-2024-1313 fix is incomplete -- the K8s API path was not covered

## Evidence

1. `snapshot_legacy_store.go:61-63`: `GetDashboardSnapshot(ctx, &GetDashboardSnapshotQuery{Key: name})` -- no org filter
2. `database.go:92`: `snapshot := DashboardSnapshot{Key: query.Key, DeleteKey: query.DeleteKey}` -- xorm generates WHERE without org_id
3. `dashboard_snapshot.go:218`: `if queryResult.OrgID != c.OrgID` -- legacy REST API HAS this check (K8s path does NOT)
4. `register.go:787-808`: K8s storage registered unconditionally (not behind feature flag)
5. `routes.go:275`: `dashboardsnapshots.DeleteWithKey(ctx, key, service)` -- no org check before or after

## Reproduction Steps

1. Set up multi-org Grafana with at least 2 organizations
2. In Org-A, create a snapshot and record the snapshot key from the K8s API response
3. In Org-B, authenticate as a user with `ActionSnapshotsDelete` permission
4. Call `DELETE /apis/dashboard.grafana.app/v0alpha1/namespaces/org-B/snapshots/{org-a-snapshot-key}` using the K8s API
5. Expected: 404 or 403 (snapshot belongs to different org)
6. Actual: 200 OK -- snapshot from Org-A is deleted

Note: The `kubernetesSnapshots` feature flag (experimental, disabled by default) only controls REST-to-K8s routing, NOT K8s API availability. The K8s endpoint is accessible regardless.
