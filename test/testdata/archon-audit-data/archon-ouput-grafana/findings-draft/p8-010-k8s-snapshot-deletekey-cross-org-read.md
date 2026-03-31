Phase: 10
Sequence: 010
Slug: k8s-snapshot-deletekey-cross-org-read
Verdict: VALID
Rationale: The K8s snapshot `deletekey` subresource fetches the snapshot from the unwrapped store by key with no org filter, then returns the plaintext deleteKey to the requester — enabling a user in one org to retrieve the deleteKey of a snapshot owned by a different org and subsequently delete it.
Severity-Original: HIGH
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-002-k8s-snapshot-cross-org-delete.md
Origin-Pattern: AP-045

## Summary

The K8s snapshot `deletekey` subresource (`GET /apis/dashboard.grafana.app/v0alpha1/namespaces/{namespace}/snapshots/{name}/deletekey`) fetches the snapshot via `SnapshotLegacyStore.Get()` without any org_id filter at the database level. This allows a user in Org-B to retrieve the `deleteKey` field of a snapshot belonging to Org-A. Armed with the deleteKey, the attacker can then invoke the snapshot delete-by-deleteKey route (`DELETE .../snapshots/delete/{deleteKey}`) which p8-002 confirmed also lacks org isolation — completing a two-step cross-org snapshot deletion chain.

The `deletekey` subresource is distinct from the basic metadata read described in p8-002: it returns the **plaintext deleteKey** (a high-entropy 190-bit secret) that is normally stripped from standard GET/LIST responses by the `storageWrapper`. This is the most sensitive field associated with a snapshot, and its exposure provides a direct path to authenticated deletion.

## Location

- **Vulnerable handler**: `pkg/registry/apis/dashboard/snapshot/sub_deletekey.go:55-82` — `deleteKeyREST.Connect()` calls `r.getter.Get(ctx, name, &metav1.GetOptions{})` with no org check
- **Storage wiring**: `pkg/registry/apis/dashboard/register.go:808` — `NewDeleteKeyREST(snapshotDualWrite)` passes the unwrapped dual-write store (not the `storageWrapper`)
- **Unguarded store layer**: `pkg/registry/apis/dashboard/snapshot/snapshot_legacy_store.go:121-135` — `Get()` issues `GetDashboardSnapshot(ctx, &GetDashboardSnapshotQuery{Key: name})` with no OrgID field
- **Database query**: `pkg/services/dashboardsnapshots/database/database.go:92` — xorm `sess.Get(&snapshot)` with `DashboardSnapshot{Key: query.Key}` generates `WHERE key=?` with no `org_id` predicate
- **Legacy REST API (correctly patched for DELETE)**: `pkg/api/dashboard_snapshot.go:218` — `if queryResult.OrgID != c.OrgID` guard absent in K8s path

## Attacker Control

The attacker controls the snapshot `name` (resource name / key) in the K8s API URL path. The snapshot key is a high-entropy value (190 bits), but it is derivable from:
- Snapshot share URLs containing the key (shared cross-org or leaked via logs)
- The K8s snapshot list endpoint within the attacker's own org (returns own-org snapshots only), which does not help directly but may be combined with brute-force given key length
- Other K8s sub-resources that confirm key existence (e.g., `GET .../snapshots/{name}` returns metadata including `created`, `expires`, `name` fields)

Once the deleteKey is retrieved, the attacker can call `DELETE .../snapshots/delete/{deleteKey}` (the route at `routes.go:275`) confirmed vulnerable in p8-002.

## Trust Boundary Crossed

TB-9 (K8s API aggregation) and TB-11 (Org isolation). The K8s namespace in the URL is mapped to the requester's org for routing, but `SnapshotLegacyStore.Get()` does not use this org information to filter the database query. A user with `ActionSnapshotsDelete` RBAC permission in any org can read the deleteKey of any snapshot in any other org.

## Impact

- **DeleteKey exfiltration**: User in Org-B retrieves the plaintext deleteKey of a snapshot owned by Org-A
- **Chained cross-org deletion**: Using the exfiltrated deleteKey, the attacker can call the `delete/{deleteKey}` route to delete Org-A's snapshot (DoS, data loss)
- **Bypass of deleteKey confidentiality**: The `storageWrapper` deliberately strips deleteKey from standard GET/LIST responses to protect this field; the `deletekey` subresource on the unwrapped store bypasses this protection for cross-org keys
- **Severity escalation over p8-002 GET**: p8-002's GET variant only exposes metadata (name, timestamps, external flag). This variant exposes the deleteKey which is a capability token enabling deletion — materially higher impact

## Evidence

1. `sub_deletekey.go:57`: `obj, err := r.getter.Get(ctx, name, &metav1.GetOptions{})` — getter is `snapshotDualWrite`, not `storageWrapper`
2. `register.go:808`: `storage[snapshots.StoragePath("deletekey")], err = snapshot.NewDeleteKeyREST(snapshotDualWrite)` — unwrapped store passed
3. `register.go:802`: `storage[snapshots.StoragePath()] = snapshot.NewStorageWrapper(snapshotDualWrite)` — only the base path gets the wrapper that strips deleteKey
4. `snapshot_legacy_store.go:122-124`: `query := dashboardsnapshots.GetDashboardSnapshotQuery{Key: name}` then `s.Service.GetDashboardSnapshot(ctx, &query)` — no OrgID field set
5. `database.go:92`: `snapshot := DashboardSnapshot{Key: query.Key, DeleteKey: query.DeleteKey}` + `sess.Get(&snapshot)` — generates `WHERE key=?` with no org_id constraint
6. `sub_deletekey.go:68-80`: After the unguarded Get, the handler returns `deleteKey` field directly to the HTTP response

## Reproduction Steps

1. Set up multi-org Grafana with at least 2 organizations (Org-A orgID=1, Org-B orgID=2)
2. In Org-A, create a snapshot. Record the snapshot key `snap-abc123` from the K8s API response
3. In Org-B, authenticate as a user with `ActionSnapshotsDelete` permission
4. Call `GET /apis/dashboard.grafana.app/v0alpha1/namespaces/org-2/snapshots/snap-abc123/deletekey`
5. Expected: 404 Not Found (snapshot not in org-2's namespace)
6. Actual: 200 OK with `{"deleteKey": "<org-a-delete-key>"}` in the response body
7. Use the returned deleteKey to call `DELETE /apis/dashboard.grafana.app/v0alpha1/namespaces/org-2/snapshots/delete/<org-a-delete-key>`
8. Org-A's snapshot is deleted
