Phase: 9
Sequence: 079
Slug: datasource-delete-by-name-toctou-readonly
Verdict: VALID
Rationale: DeleteDataSourceByName performs the ReadOnly check outside the database transaction at datasources.go:314, using GetDataSource (not getRawDataSourceByUID) but flowing through the same shared store.go DeleteDataSource transaction that never re-checks ReadOnly; structurally identical TOCTOU to p7-043.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-043-datasource-toctou-readonly-bypass.md
Origin-Pattern: AP-043

## Summary

The name-based datasource deletion handler `DeleteDataSourceByName` at `pkg/api/datasources.go:298-334` exhibits the same pre-transaction TOCTOU pattern as the UID-based handler confirmed in p7-043. The handler fetches the datasource via `DataSourcesService.GetDataSource()` at line 306 (outside any transaction), checks `dataSource.ReadOnly` at line 314, and then calls `DeleteDataSource()` at line 319 which enters the database transaction via `store.go:190`. Inside the transaction, the datasource is re-fetched with a plain SELECT (no `FOR UPDATE`) and the `ReadOnly` flag is not rechecked before the DELETE.

This endpoint is also deprecated but remains fully active. The attack is slightly different: the name-based lookup means the race window involves the name-to-datasource mapping being stable while the ReadOnly flag changes, but the fundamental TOCTOU is identical.

## Location

- **ReadOnly check (outside txn):** `pkg/api/datasources.go:314` — `if dataSource.ReadOnly { return 403 }`
- **Pre-transaction fetch:** `pkg/api/datasources.go:306` — `hs.DataSourcesService.GetDataSource(c.Req.Context(), getCmd)` where `getCmd` has `Name: name`
- **Transaction entry:** `pkg/services/datasources/service/datasource.go:561` — `s.db.InTransaction()`
- **In-transaction re-fetch (no FOR UPDATE):** `pkg/services/datasources/service/store.go:192-193` — `ss.getDataSource(ctx, dsQuery, sess)`
- **DELETE execution:** `pkg/services/datasources/service/store.go:201` — `DELETE FROM data_source WHERE org_id=? AND id=?`

## Attacker Control

Authenticated user with `datasources:delete` RBAC permission. Must know the datasource name. Race window: concurrent `UpdateDataSource` toggles `ReadOnly` between the handler's check (line 314) and the store's DELETE (store.go:201).

## Trust Boundary Crossed

TB10 (Database Boundary) — integrity violation. Deletion of a `ReadOnly=true` datasource bypasses the admin-enforced provisioning protection.

## Impact

Deletion of a ReadOnly-protected datasource via the legacy name-based API endpoint. Equivalent impact to p7-043 and p7-078. The name-based endpoint is commonly used in automation scripts targeting provisioned datasources by their configured name, making this variant of operational significance.

## Evidence

1. `datasources.go:306`: `dataSource, err := hs.DataSourcesService.GetDataSource(c.Req.Context(), getCmd)` — DB read outside transaction
2. `datasources.go:314`: `if dataSource.ReadOnly { return response.Error(http.StatusForbidden, ...) }` — guard outside transaction
3. `datasource.go:561`: Transaction entered after the guard via `DeleteDataSource`
4. `store.go:192`: `ss.getDataSource(ctx, dsQuery, sess)` — plain SELECT inside txn, no FOR UPDATE
5. `store.go:201`: DELETE executed without ReadOnly re-check
6. Same shared `store.go:190-229` code path as p7-043 and p7-078

## Reproduction Steps

1. Create a datasource named "my-ds" and mark it ReadOnly
2. In parallel: (a) send `DELETE /api/datasources/name/my-ds`, (b) concurrently send `PUT` requests toggling ReadOnly true/false
3. Time the DELETE to land when the pre-transaction check reads ReadOnly=false but the flag has been changed to true
4. Verify deletion occurred despite ReadOnly protection
