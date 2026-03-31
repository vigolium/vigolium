Phase: 9
Sequence: 078
Slug: datasource-delete-by-id-toctou-readonly
Verdict: VALID
Rationale: DeleteDataSourceById performs the ReadOnly check outside the database transaction at datasources.go:170, identical structural TOCTOU as the UID endpoint confirmed in p7-043; the shared store.go transaction path does not re-check ReadOnly and has no SELECT FOR UPDATE.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-043-datasource-toctou-readonly-bypass.md
Origin-Pattern: AP-043

## Summary

The integer-ID datasource deletion handler `DeleteDataSourceById` at `pkg/api/datasources.go:152-188` exhibits the same pre-transaction TOCTOU pattern as the UID-based handler confirmed in p7-043. The handler fetches the datasource via `getRawDataSourceById()` at line 162 (outside any transaction), checks `ds.ReadOnly` at line 170, and then calls `DeleteDataSource()` at line 176 which enters the database transaction at `store.go:190`. Inside the transaction, the datasource is re-fetched with a plain `SELECT` (no `FOR UPDATE`) and the `ReadOnly` flag is never rechecked before the `DELETE` is executed.

This is a structural clone of the UID-based variant. The integer-ID endpoint is deprecated but remains fully active and reachable.

## Location

- **ReadOnly check (outside txn):** `pkg/api/datasources.go:170` — `if ds.ReadOnly { return 403 }`
- **Pre-transaction fetch:** `pkg/api/datasources.go:162` — `hs.getRawDataSourceById(c.Req.Context(), id, c.GetOrgID())`
- **Transaction entry:** `pkg/services/datasources/service/datasource.go:561` — `s.db.InTransaction()`
- **In-transaction re-fetch (no FOR UPDATE):** `pkg/services/datasources/service/store.go:192-193` — `ss.getDataSource(ctx, dsQuery, sess)`
- **DELETE execution:** `pkg/services/datasources/service/store.go:201` — `DELETE FROM data_source WHERE org_id=? AND id=?`

## Attacker Control

Authenticated user with `datasources:delete` RBAC permission over the target datasource. The attacker must time a concurrent `UpdateDataSource` request to toggle `ReadOnly` between the pre-transaction check (line 162) and the in-transaction DELETE (store.go:201).

## Trust Boundary Crossed

TB10 (Database Boundary) — integrity violation. Deletion of a `ReadOnly=true` datasource bypasses the admin-enforced provisioning protection.

## Impact

Deletion of a ReadOnly-protected datasource via the legacy integer-ID API endpoint. Equivalent impact to p7-043. Provisioned datasources auto-recreate, but the race demonstrates a structural integrity gap and may cause brief service disruption or unexpected behavior in infrastructure-as-code deployments. In HA deployments the TOCTOU window is amplified by process-local caches.

## Evidence

1. `datasources.go:162`: `ds, err := hs.getRawDataSourceById(c.Req.Context(), id, c.GetOrgID())` — plain DB read outside transaction
2. `datasources.go:170`: `if ds.ReadOnly { return response.Error(http.StatusForbidden, ...) }` — guard check outside transaction
3. `datasource.go:561`: `s.db.InTransaction(ctx, func(ctx context.Context) error { ... s.SQLStore.DeleteDataSource(ctx, cmd) ... })` — transaction entered after guard
4. `store.go:192`: `dsQuery := &datasources.GetDataSourceQuery{...}; ds, errGettingDS := ss.getDataSource(ctx, dsQuery, sess)` — plain SELECT inside txn
5. `store.go:201`: `sess.Exec("DELETE FROM data_source WHERE org_id=? AND id=?", ds.OrgID, ds.ID)` — DELETE without ReadOnly re-check
6. No `FOR UPDATE` clause in any in-transaction re-fetch
7. Shared transaction code path with the UID endpoint (same `store.go:190-229`)

## Reproduction Steps

1. Create a datasource and mark it as ReadOnly
2. Note the integer datasource ID
3. In parallel: (a) send `DELETE /api/datasources/:id`, (b) send concurrent `PUT /api/datasources/:id` requests toggling `ReadOnly` between true and false
4. Time the DELETE to land in the window where the pre-transaction fetch sees `ReadOnly=false` but the datasource is currently `ReadOnly=true`
5. Verify the ReadOnly datasource was deleted despite the protection
6. Same race window characteristics as p7-043; the integer-ID route is the alternate attack vector
