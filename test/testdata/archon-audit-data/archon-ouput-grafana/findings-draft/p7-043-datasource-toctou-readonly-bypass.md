Phase: 7
Sequence: 043
Slug: datasource-toctou-readonly-bypass
Verdict: VALID
Rationale: Structural TOCTOU confirmed -- ReadOnly is checked once outside the transaction at datasources.go:260 and never rechecked inside the transaction at store.go:190-229. The missing SELECT FOR UPDATE enables a concurrent race to delete a ReadOnly datasource. Narrow race window and RBAC requirement limit severity.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-3/debate.md

## Summary

The datasource deletion handler at `pkg/api/datasources.go:252-266` performs the ReadOnly protection check OUTSIDE the database transaction. The handler first fetches the datasource via `getRawDataSourceByUID()` (line 252), checks `if ds.ReadOnly` (line 260), and then calls `DeleteDataSource()` (line 266) which runs in a transaction at `store.go:190-229`.

Inside the transaction, `getDataSource()` at store.go:192-193 re-fetches the datasource using a plain SELECT (no `SELECT ... FOR UPDATE`), and the ReadOnly flag is NOT rechecked. A concurrent `UpdateDataSource` request that sets `ReadOnly=true` between the handler's check (step 2) and the transaction's DELETE (step 4) results in the deletion of a datasource that should be protected by the ReadOnly flag.

This is part of the CVE-2026-21725 pattern.

## Location

- **ReadOnly check (outside txn):** `pkg/api/datasources.go:260` -- `if ds.ReadOnly { return 403 }`
- **Pre-transaction fetch:** `pkg/api/datasources.go:252` -- `getRawDataSourceByUID()`
- **Transaction entry:** `pkg/services/datasources/service/datasource.go:561` -- `s.db.InTransaction()`
- **In-transaction re-fetch (no FOR UPDATE):** `pkg/services/datasources/service/store.go:192-193` -- `ss.getDataSource(ctx, dsQuery, sess)`
- **DELETE execution:** `pkg/services/datasources/service/store.go:201` -- `DELETE FROM data_source WHERE org_id=? AND id=?`

## Attacker Control

Authenticated user with `datasources.ActionDelete` RBAC permission. The attacker must time a concurrent API call to modify the ReadOnly flag during the narrow window between the handler's check and the transaction's DELETE.

## Trust Boundary Crossed

TB10 (Database Boundary) -- integrity violation. The ReadOnly flag is an admin-enforced protection that prevents accidental or unauthorized deletion of provisioned datasources. Bypassing it crosses the admin-defined integrity boundary.

## Impact

Deletion of a ReadOnly-protected datasource. The ReadOnly flag is typically set on provisioned datasources managed by infrastructure-as-code. The deletion is operationally recoverable (provisioned datasources auto-recreate), but the race condition represents a structural integrity gap.

In HA deployments, the TOCTOU window is amplified by process-local caching (stale ReadOnly values may be served from cache on other pods).

## Evidence

1. `datasources.go:252`: `ds, err := hs.getRawDataSourceByUID(c.Req.Context(), uid, c.GetOrgID())` -- fetch outside txn
2. `datasources.go:260`: `if ds.ReadOnly { return 403 }` -- check outside txn
3. `store.go:192`: `dsQuery := &datasources.GetDataSourceQuery{...}; ds, errGettingDS := ss.getDataSource(ctx, dsQuery, sess)` -- plain SELECT inside txn
4. `store.go:201`: `sess.Exec("DELETE FROM data_source WHERE org_id=? AND id=?", ds.OrgID, ds.ID)` -- DELETE without re-checking ReadOnly
5. No `FOR UPDATE` clause in the in-transaction re-fetch

## Reproduction Steps

1. Create a datasource and mark it as ReadOnly (via provisioning or API)
2. In parallel: (a) send DELETE /api/datasources/uid/:uid, (b) continuously send UPDATE requests toggling ReadOnly between true and false
3. Time the DELETE to hit the window where the pre-transaction check sees ReadOnly=false but the datasource has been updated to ReadOnly=true before the in-transaction DELETE
4. Verify the ReadOnly datasource was deleted despite the protection
