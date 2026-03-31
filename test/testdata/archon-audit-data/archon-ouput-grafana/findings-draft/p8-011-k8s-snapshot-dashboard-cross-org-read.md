Phase: 10
Sequence: 011
Slug: k8s-snapshot-dashboard-cross-org-read
Verdict: VALID
Rationale: The K8s snapshot `dashboard` subresource fetches the snapshot from the unwrapped store by key with no org filter, then returns the full dashboard JSON payload to the requester — enabling a user in one org to read the complete dashboard data (potentially containing sensitive query parameters, data, credentials in annotations/links) from a snapshot owned by a different org.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-002-k8s-snapshot-cross-org-delete.md
Origin-Pattern: AP-045

## Summary

The K8s snapshot `dashboard` subresource (`GET /apis/dashboard.grafana.app/v0alpha1/namespaces/{namespace}/snapshots/{name}/dashboard`) fetches the snapshot via `SnapshotLegacyStore.Get()` without any org_id filter at the database level. After fetching, it returns `snap.Spec.Dashboard` — the full embedded dashboard JSON — to the requester.

The `dashboard` subresource is distinct from the basic metadata read described in p8-002: the standard GET/LIST path strips `Spec.Dashboard` via `storageWrapper.stripSensitiveFields()`. The `dashboard` subresource explicitly circumvents this stripping by using the unwrapped store and extracting `snap.Spec.Dashboard` directly. A user in Org-B can read the full dashboard JSON of a snapshot belonging to Org-A, including all panel data, annotations, template variables, links, and any embedded data that was captured at snapshot creation time.

## Location

- **Vulnerable handler**: `pkg/registry/apis/dashboard/snapshot/sub_dashboard.go:58-87` — `dashboardREST.Connect()` calls `r.getter.Get(ctx, name, &metav1.GetOptions{})` then returns `snap.Spec.Dashboard`
- **Storage wiring**: `pkg/registry/apis/dashboard/register.go:804` — `NewDashboardREST(snapshotDualWrite)` passes the unwrapped dual-write store
- **Namespace check present but ineffective**: `sub_dashboard.go:59` calls `request.NamespaceInfoFrom(ctx, true)` to get the requester's namespace, but uses `ns.Value` only to set `dash.Namespace` in the response — it does NOT gate the database fetch on this value
- **Unguarded store layer**: `pkg/registry/apis/dashboard/snapshot/snapshot_legacy_store.go:121-135` — `Get()` issues `GetDashboardSnapshot(ctx, &GetDashboardSnapshotQuery{Key: name})` with no OrgID field
- **Database query**: `pkg/services/dashboardsnapshots/database/database.go:92` — xorm `sess.Get(&snapshot)` with `DashboardSnapshot{Key: query.Key}` generates `WHERE key=?` with no `org_id` predicate
- **stripSensitiveFields bypassed**: `pkg/registry/apis/dashboard/snapshot/storage_without_create.go:76-78` — dashboard stripping only applied on the `storageWrapper` path, not the `snapshotDualWrite` path used by this subresource

## Attacker Control

The attacker controls the snapshot `name` (resource name / key) in the K8s API URL path. The snapshot key is derivable from:
- Snapshot share URLs (containing the key in the URL path, often shared publicly)
- Logs recording snapshot creation
- Enumeration of known key formats if short snapshots are used

## Trust Boundary Crossed

TB-9 (K8s API aggregation) and TB-11 (Org isolation). The namespace context only affects the response `Namespace` field, not the database query. A user with `ActionSnapshotsRead` RBAC permission in any org can read the full dashboard data of any snapshot in any org.

## Impact

- **Cross-org dashboard data read**: User in Org-B reads the full embedded dashboard JSON of a snapshot belonging to Org-A
- **Sensitive data in dashboard payload**: Snapshots embed dashboard data including panel queries, annotation data, template variable values, links with potentially sensitive query strings, and any data captured at snapshot creation
- **Bypass of field-level access control**: The `storageWrapper` deliberately strips `Spec.Dashboard` from standard GET/LIST responses to protect this payload; the `dashboard` subresource on the unwrapped store bypasses this for cross-org snapshots
- **Information disclosure at org boundary**: Orgs are the primary isolation boundary in Grafana multi-tenancy; dashboard data of one org is not expected to be readable by users of another org

## Evidence

1. `sub_dashboard.go:65`: `obj, err := r.getter.Get(ctx, name, &metav1.GetOptions{})` — getter is `snapshotDualWrite`, not `storageWrapper`
2. `register.go:804`: `storage[snapshots.StoragePath("dashboard")], err = snapshot.NewDashboardREST(snapshotDualWrite)` — unwrapped store passed
3. `sub_dashboard.go:59-63`: `ns, err := request.NamespaceInfoFrom(ctx, true)` — ns.OrgID extracted from requester's namespace but NOT used to filter the Get call on line 65
4. `sub_dashboard.go:75-86`: Handler returns `snap.Spec.Dashboard` directly in the response body — the full dashboard JSON payload
5. `storage_without_create.go:72-78`: `stripSensitiveFields()` sets `out.Spec.Dashboard = nil` — this guard only applies when requests go through `storageWrapper.Get()`, not through the subresource path
6. `snapshot_legacy_store.go:122-124`: `query := dashboardsnapshots.GetDashboardSnapshotQuery{Key: name}` — no OrgID field
7. `database.go:92`: `sess.Get(&snapshot)` with `DashboardSnapshot{Key: query.Key}` — `WHERE key=?` only, no `org_id` constraint

## Reproduction Steps

1. Set up multi-org Grafana with at least 2 organizations (Org-A orgID=1, Org-B orgID=2)
2. In Org-A, create a snapshot with a dashboard containing sensitive panel data. Record the snapshot key `snap-abc123`
3. In Org-B, authenticate as a user with `ActionSnapshotsRead` permission
4. Call `GET /apis/dashboard.grafana.app/v0alpha1/namespaces/org-2/snapshots/snap-abc123/dashboard`
5. Expected: 404 Not Found (snapshot not in org-2's namespace)
6. Actual: 200 OK with `{"spec": {"object": <full dashboard JSON of Org-A>}}` in the response
7. The full dashboard payload including panels, queries, template variables, and annotations is returned
