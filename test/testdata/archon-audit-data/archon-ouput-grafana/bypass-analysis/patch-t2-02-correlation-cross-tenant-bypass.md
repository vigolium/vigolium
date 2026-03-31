# Bypass Analysis: PATCH-T2-02 — CVE-2026-21727 — Cross-Tenant Legacy Correlation

**Cluster ID:** correlations-cross-tenant
**Advisory:** CVE-2026-21727
**Severity:** LOW (3.3)
**Commit:** `e702db6096e`
**Component:** `pkg/services/correlations/database.go`

## Patch Summary

The patch removes the legacy `org_id = 0` fallback from correlation SQL queries. Before the fix, correlations created prior to the org_id migration (#72498) had `org_id = 0` in the database and were accessible to any organization via the condition `(correlation.org_id = 0 OR dss.org_id = correlation.org_id)`. The fix replaces this with strict equality: `dss.org_id = correlation.org_id`.

Five functions were patched:
1. `getCorrelation` — read single correlation
2. `getCorrelationsBySourceUID` — read correlations by source
3. `getCorrelations` — list all correlations
4. `deleteCorrelationsBySourceUID` — bulk delete by source
5. `deleteCorrelationsByTargetUID` — bulk delete by target

## Bypass Verdict: **sound** (with caveats noted below)

The core cross-tenant vulnerability is addressed. The read paths that join against `data_source` now enforce strict `org_id` equality, and the bulk delete paths now filter by exact `org_id` match. Legacy `org_id = 0` rows are effectively orphaned and inaccessible through normal API paths.

## Detailed Analysis

### Hypothesis 1: Legacy `org_id = 0` rows still accessible via other API paths

**Result: Not exploitable post-patch.**

All three read functions (`getCorrelation`, `getCorrelationsBySourceUID`, `getCorrelations`) now require `dss.org_id = correlation.org_id` in the JOIN condition. Since no `data_source` row will have `org_id = 0`, any legacy `correlation` row with `org_id = 0` will fail the INNER JOIN and never be returned.

### Hypothesis 2: No migration/cleanup for legacy `org_id = 0` rows

**Result: Confirmed -- no migration exists.**

The migration file `pkg/services/sqlstore/migrations/correlations_mig.go` defines the v2 schema with `org_id` defaulting to `0` for existing rows (line 39: `Default: "0"`). There is no subsequent migration that updates or deletes rows where `org_id = 0`. These rows remain in the database as dead data. While not exploitable through the patched code paths, they represent data debris that could become relevant if future code paths query the `correlation` table directly without the data_source JOIN guard.

### Hypothesis 3: Other CRUD operations with residual cross-tenant patterns

**Result: Minor weaknesses identified, but not exploitable for cross-tenant access.**

#### `deleteCorrelation` (line 72-105)

The actual DELETE statement at line 93 is:
```go
deletedCount, err := session.Delete(&Correlation{UID: cmd.UID, SourceUID: cmd.SourceUID})
```
This struct-based delete omits `OrgID` (zero-value int64 is ignored by xorm). The resulting SQL is effectively `DELETE FROM correlation WHERE uid = ? AND source_uid = ?` without an `org_id` filter. However, the function has a guard at line 83:
```go
correlation, err := s.GetCorrelation(ctx, GetCorrelationQuery(cmd))
```
This calls the patched `getCorrelation` which enforces strict `org_id` matching. If the correlation belongs to a different org, `GetCorrelation` returns `ErrCorrelationNotFound` and the delete is never reached. **Not exploitable**, but the missing `org_id` in the DELETE is a defense-in-depth gap.

#### `updateCorrelation` (line 107-181)

The struct-based `Get` at line 124 uses:
```go
correlation := Correlation{UID: cmd.UID, SourceUID: cmd.SourceUID, OrgID: cmd.OrgId}
found, err := session.Omit("source_type", "target_type").Get(&correlation)
```
Since `OrgID` is set and is a primary key, xorm includes it in the WHERE clause. The subsequent UPDATE at line 159-163 uses `Where("uid = ? AND source_uid = ?")` without `org_id`, but only executes if the Get succeeded with the correct org. **Not exploitable**, but again a defense-in-depth gap.

### Hypothesis 4: `deleteCorrelation` callable cross-tenant for legacy rows

**Result: Not exploitable.**

As analyzed above, `deleteCorrelation` calls `GetCorrelation` first, which now enforces strict `org_id` matching. Legacy `org_id = 0` rows will fail the data_source JOIN in `GetCorrelation`, preventing deletion by any tenant.

### Hypothesis 5: `deleteCorrelationsByTargetUID` logic bug

**Result: Confirmed logic bug, not security-relevant to this CVE.**

At line 326, `deleteCorrelationsByTargetUID` uses:
```go
session.Where("source_uid = ? and org_id = ?", cmd.TargetUID, cmd.OrgId).Delete(&Correlation{})
```
This filters on the `source_uid` column using `cmd.TargetUID` as the value. The intended behavior should be filtering on `target_uid` column. This means when a datasource is deleted, correlations that *point to* it (as target) are not cleaned up, while correlations that originate *from* a datasource whose UID happens to match the target UID would be incorrectly deleted. This is a functional correctness bug (likely benign in practice since UIDs are unique across the system), but not a cross-tenant security issue since `org_id` is properly filtered.

### Hypothesis 6: `createOrUpdateCorrelation` (provisioning path)

**Result: Properly scoped.**

The `createOrUpdateCorrelation` function (line 332-365) is marked as internal for migration use. It sets `OrgID: cmd.OrgId` in the struct before the `Get`, and uses `session.ID(core.NewPK(correlation.UID, correlation.SourceUID, correlation.OrgID))` for the update, which includes the org_id. The `createCorrelation` path also uses `cmd.OrgId` in the datasource lookup. No cross-tenant risk.

## Evidence Summary

| Vector | Status |
|--------|--------|
| Read paths (get*) | Fixed -- strict org_id equality enforced via JOIN |
| deleteCorrelationsBySourceUID | Fixed -- strict org_id equality in WHERE |
| deleteCorrelationsByTargetUID | Fixed (org_id) -- but has wrong column name bug (source_uid vs target_uid) |
| deleteCorrelation (single) | Guard via GetCorrelation prevents cross-tenant; DELETE itself lacks org_id (defense gap) |
| updateCorrelation | Guard via struct Get prevents cross-tenant; UPDATE itself lacks org_id (defense gap) |
| Legacy org_id=0 data cleanup | Missing -- no migration to remove/fix orphaned rows |
| createOrUpdateCorrelation | Properly scoped by org_id |

## Recommendations

1. **Defense-in-depth**: Add `OrgID` to the `deleteCorrelation` DELETE struct (`&Correlation{UID: cmd.UID, SourceUID: cmd.SourceUID, OrgID: cmd.OrgId}`) and add `org_id` to the `updateCorrelation` WHERE clause.
2. **Data cleanup**: Add a migration to either delete or reassign `org_id = 0` correlation rows to prevent future regressions if new code paths are added that query the table without the data_source JOIN.
3. **Bug fix**: `deleteCorrelationsByTargetUID` should filter on `target_uid` column, not `source_uid`.
