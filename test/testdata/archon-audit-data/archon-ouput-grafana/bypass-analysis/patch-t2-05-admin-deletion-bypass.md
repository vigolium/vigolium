# Bypass Analysis: CVE-2025-3580 — Admin User Deletion Escalation

**Patch Commit:** `5963be6f317e6fa1f142f176ae6fa7ec98b09b4c`
**Severity:** MEDIUM (5.5)
**Component:** `pkg/services/org/orgimpl/store.go` — `RemoveOrgUser()`
**Cluster ID:** CVE-2025-3580

## Patch Summary

The patch addresses two issues in `RemoveOrgUser()`:

1. **Server admin deletion prevention (line 727):** Added `!usr.IsAdmin` guard to the `ShouldDeleteOrphanedUser` branch. Previously, when a user was removed from their last org with `ShouldDeleteOrphanedUser: true`, the entire user record was deleted regardless of whether the user was a Grafana server admin. Now, server admins are preserved even when orphaned.

2. **Org membership check (lines 672-679):** Added a pre-check verifying the target user actually belongs to the specified org before performing deletions. Previously, calling `RemoveOrgUser` for a user not in the org would still execute the `DELETE FROM org_user` and related statements (which would be no-ops) and then reach the orphan-deletion logic. This was dangerous because: a user belonging to Org A could be targeted via a `RemoveOrgUser` call specifying Org B; the org_user DELETE would be a no-op, the subsequent org membership query would return zero orgs for the specified org context, and the code would proceed to the `ShouldDeleteOrphanedUser` path -- deleting the full user even though they still had legitimate org memberships elsewhere.

## Bypass Hypotheses and Findings

### H1: Does the check verify server admin role at time of deletion (not cached)?

**Verdict: Sound.**

The `usr` variable is loaded fresh from the database within the same transactional session at line 666: `sess.ID(cmd.UserID).Where(ss.notServiceAccountFilter()).Get(&usr)`. The `usr.IsAdmin` field checked at line 727 reflects the current database state. There is no caching or stale data risk within the transaction boundary.

### H2: Race condition — demote server admin then delete?

**Verdict: Low risk but theoretically possible.**

The transaction uses `WithTransactionalDbSession` which provides database-level transaction isolation. A concurrent request to demote a server admin (setting `IsAdmin = false`) could in theory commit between the `Get(&usr)` at line 666 and the `IsAdmin` check at line 727, but only under READ COMMITTED isolation. SQLite (default Grafana backend) serializes writes, making this impractical. PostgreSQL and MySQL with default settings could theoretically allow it, but the window is narrow (within a single transaction's execution). The practical risk is low.

### H3: Batch removal endpoints?

**Verdict: No batch bypass found.**

There are only two API routes that invoke `RemoveOrgUser`:
- `DELETE /api/org/users/:userId` -> `RemoveOrgUserForCurrentOrg()` (sets `ShouldDeleteOrphanedUser: true`)
- `DELETE /api/orgs/:orgId/users/:userId` -> `RemoveOrgUser()` (does NOT set `ShouldDeleteOrphanedUser`)

There are no batch/bulk removal or import endpoints that call `RemoveOrgUser`. The `AdminDeleteUser` endpoint (`DELETE /admin/users/:id`) has its own dedicated path through `userService.Delete()` and `orgService.DeleteUserFromAll()`, which is a separate code path requiring `ActionUsersDelete` permission (server admin level).

### H4: Both endpoints covered?

**Verdict: Sound.**

The fix is in the store layer (`sqlStore.RemoveOrgUser`), which is the single implementation called by both API handlers through `orgService.RemoveOrgUser()`. Both endpoints are covered by the same fix.

The `org_sync.go` caller (OAuth org sync) also passes through the same code path but does NOT set `ShouldDeleteOrphanedUser`, so it never reaches the deletion branch.

### H5: Other callers of `removeOrgUser` / `deleteUserInTransaction`?

**Verdict: Sound.**

`deleteUserInTransaction` is called from exactly one place besides `RemoveOrgUser`: the `deleteUserInTransaction` helper is a private method only used within the `RemoveOrgUser` function at line 729. The `DeleteUserFromAll` method only removes org_user records (raw SQL DELETE) and does not call `deleteUserInTransaction`.

### Additional Finding: Silent success on non-member removal

The new org membership check (lines 672-679) returns `nil` (success) when the user is not a member of the specified org. This is a design choice that prevents the orphan-deletion attack vector, but it means the API returns HTTP 200 even when the user was never in the org. This is not a security issue but could mask operational errors. The previous behavior would also have returned success (the DELETEs would be no-ops), so this is consistent.

### Additional Finding: `RemoveOrgUser` (cross-org endpoint) does not set `ShouldDeleteOrphanedUser`

The `DELETE /api/orgs/:orgId/users/:userId` endpoint (line 496-499) does NOT set `ShouldDeleteOrphanedUser: true`, unlike the current-org endpoint. This means the server admin deletion path is only reachable through `RemoveOrgUserForCurrentOrg` (`DELETE /api/org/users/:userId`). The cross-org endpoint would never have triggered the vulnerable code path even pre-patch. The fix is still correctly applied at the store layer covering all possible future callers.

## Bypass Verdict

**Sound.**

The fix addresses the vulnerability at the correct layer (store) with two complementary guards:
1. Org membership validation prevents cross-org orphan-deletion attacks
2. `IsAdmin` check prevents server admin account deletion even through the legitimate orphan path

Both checks use fresh database state within a transaction. All callers funnel through the single patched code path. No batch or alternative endpoints bypass the fix.
