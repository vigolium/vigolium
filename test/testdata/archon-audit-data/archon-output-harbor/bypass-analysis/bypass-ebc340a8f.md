# Bypass Analysis: ebc340a8f (CVE-2022-31666)

**Advisory:** CVE-2022-31666  
**Commit:** ebc340a8f7bb0cab4a3a128a5310122b2e895b16  
**File:** `src/common/rbac/project/rbac_role.go`  
**Cluster ID:** RBAC-WEBHOOK-001  
**Bypass Verdict:** sound (for the stated fix scope), with a noted sibling gap  

---

## Patch Summary

The patch adds a single permission entry to the `maintainer` role in the project RBAC policy map:

```go
// Pre-patch: maintainer had only ActionList for ResourceNotificationPolicy
{Resource: rbac.ResourceNotificationPolicy, Action: rbac.ActionList},

// Post-patch: maintainer now has both ActionRead and ActionList
{Resource: rbac.ResourceNotificationPolicy, Action: rbac.ActionRead},   // NEW
{Resource: rbac.ResourceNotificationPolicy, Action: rbac.ActionList},
```

The `maintainer` role was missing `ActionRead` for `ResourceNotificationPolicy` (webhook policies). This meant a project maintainer could list webhook policies (`GET /projects/{name}/webhook/policies`) but could not:

- Read a specific policy (`GET /projects/{name}/webhook/policies/{id}`) - requires `ActionRead`
- List executions for a policy (`GET .../executions`) - requires `ActionRead`
- List tasks for an execution - requires `ActionRead`
- Retrieve task logs - requires `ActionRead`
- Access last trigger times (`GET .../webhook/lasttrigger`) - requires `ActionRead`
- Retrieve supported event types (`GET .../webhook/events`) - requires `ActionRead`

The fix is applied at the RBAC role policy table level, which is the single authoritative source consumed by `RequireProjectAccess` across all webhook handler methods.

---

## Vulnerability Reconstructed (Pre-Patch State)

**Class:** Missing permission / broken access control - RBAC misconfiguration  
**Impact:** A project maintainer received an HTTP 403 Forbidden when attempting to read individual webhook policy details, view execution history, inspect logs, or check last trigger times. The intent per Harbor's role design is that maintainers should have read-only access to webhook policies (write actions such as create/update/delete remain restricted to `projectAdmin`). The missing `ActionRead` entry caused UI breakage and a functional denial-of-service for the maintainer role against webhook read endpoints.

---

## Bypass Hypotheses Tested

### 1. Alternate Entry Points (Other Callers Not Covered by the Fix)

**Result: No bypass.**

All webhook policy API operations funnel through a single handler (`src/server/v2.0/handler/webhook.go`) and one supporting handler (`webhook_job.go`). Every handler method invokes `RequireProjectAccess` with an appropriate action before any data access. There is no alternate code path, internal stub, or gRPC back-channel that exposes webhook policy data without going through these checks.

The internal `/service/notifications/*` routes in `src/server/route.go` are job status callback endpoints (not user-facing webhook policy management endpoints) and carry no `ResourceNotificationPolicy` checks because they are not policy management operations.

### 2. Config-Gated or Default-State Gaps

**Result: No bypass.**

The `notification_enable` system configuration flag (`src/common/const.go:160`) controls whether the notification subsystem is active globally. Disabling it would suppress webhook deliveries but does not alter RBAC enforcement. The `RequireProjectAccess` call precedes any notification system interaction and is not gated on `notification_enable`.

### 3. Role Confusion: developer / guest Roles

**Result: No bypass; intended behavior confirmed.**

The `developer`, `guest`, and `limitedGuest` roles have zero `ResourceNotificationPolicy` entries in `rbac_role.go`. They cannot call any webhook policy endpoint. This is consistent with Harbor's documented design intent (only projectAdmin and maintainer interact with webhook policies). The patch does not inadvertently grant any permissions to lower roles.

### 4. Cross-Project Permission Leak

**Result: No bypass.**

All read endpoints that were gated by `ActionRead` verify project-to-policy ownership through `requirePolicyInProject`. This function fetches the policy by ID and checks that `policy.ProjectID == projectID` derived from the URL parameter. A maintainer from Project A cannot reach a policy belonging to Project B even with a valid `WebhookPolicyID` from Project B because:
- The `RequireProjectAccess` call enforces project membership before data access.
- The `requirePolicyInProject` guard enforces policy-to-project binding.

### 5. Permission Check Bypass via Direct API Access (Robot Accounts)

**Result: Unaffected by patch; robot accounts operate correctly.**

Robot accounts use an explicit per-robot policy list, evaluated via `rbac_project.NewBuilderForPolicies`, and are never evaluated against `rolePoliciesMap`. The `ScopeProject` table in `const.go` (lines 294-298) defines the maximum allowable permissions a robot account can be granted for `ResourceNotificationPolicy` (all five actions: read, create, update, delete, list). However, a robot account only receives these permissions if an administrator explicitly grants them at robot creation time. This mechanism is orthogonal to the role-based fix and operates correctly.

System administrators bypass all project RBAC via the `admin.Evaluator` (which unconditionally returns `true` for all non-scanner-pull actions). This is intentional and unchanged.

### 6. Batch / Bulk Operations Skipping Per-Item Checks

**Result: No bypass.**

`ListWebhookPoliciesOfProject` applies `ActionList` and scopes the database query to `projectID` via `query.Keywords["ProjectID"] = projectID`. There is no bulk endpoint that would return policies across projects. The `ListWebhookJobs` endpoint in `webhook_job.go` similarly enforces `ActionList` and calls `requirePolicyAccess` to validate project ownership before returning any job data.

### 7. Sibling Resource Gap: ResourcePreatPolicy

**Result: Potential gap (out of scope for this patch; flagged for separate audit).**

The `preheat-policy` resource (`ResourcePreatPolicy`) is present in `projectAdmin` with full CRUD, but does **not** appear in the `maintainer` role at all. By contrast, `ResourceNotificationPolicy` now has read access for maintainer. If the intent is that maintainers can read-but-not-write policy resources, preheat policies may have an analogous omission. This has not been exploited by this patch but warrants a separate review.

---

## Fix Completeness Assessment

The fix is single-line and narrowly targeted: it adds only `ActionRead` for `ResourceNotificationPolicy` in the `maintainer` block. This is the correct and complete fix for the stated issue because:

1. The entire RBAC table for all five roles lives in one file (`rbac_role.go`).
2. The `RequireProjectAccess` function is the sole enforcement point for all webhook handler methods.
3. No other role required adjustment (projectAdmin already had all five actions; developer/guest intentionally have none).
4. There are no shadow codepaths, middleware overrides, or handler-level bypasses.

The fix does not over-grant: maintainer still lacks `ActionCreate`, `ActionUpdate`, and `ActionDelete` for `ResourceNotificationPolicy`, keeping write operations restricted to `projectAdmin`.

---

## Evidence (Key Code Locations)

- Pre-patch maintainer entry: `git show ebc340a8f~1:src/common/rbac/project/rbac_role.go` line 165
- Post-patch maintainer entry: `/Users/tuan.v.tran/AuditSource/harbor/src/common/rbac/project/rbac_role.go` lines 165-166
- All handler enforcement calls: `/Users/tuan.v.tran/AuditSource/harbor/src/server/v2.0/handler/webhook.go` (every exported method, lines 103-403)
- Webhook job handler: `/Users/tuan.v.tran/AuditSource/harbor/src/server/v2.0/handler/webhook_job.go` line 48
- Admin evaluator (unconditional allow for sysadmin): `/Users/tuan.v.tran/AuditSource/harbor/src/pkg/permission/evaluator/admin/admin.go` line 34
- Robot security context (not role-table-based): `/Users/tuan.v.tran/AuditSource/harbor/src/common/security/robot/context.go` lines 90-124

---

## Summary

| Vector | Assessment |
|--------|-----------|
| Alternate entry points | None found; single handler layer with uniform `RequireProjectAccess` calls |
| Config-gated checks | `notification_enable` does not gate RBAC; no bypass |
| Default-state gaps | No gaps; all roles at default (no explicit config needed) |
| Compatibility / legacy path | No legacy v1 webhook policy API exists |
| Parser differentials | N/A; RBAC check precedes all parsing |
| Missing normalization | N/A; action/resource matching is exact enum comparison |
| Sibling resource gap | `ResourcePreatPolicy` absent from `maintainer` role - flagged for separate review |
| Cross-project leak | Prevented by `requirePolicyInProject` ownership check |
| Batch bypass | List endpoints scope to projectID in SQL query |
| Robot account bypass | Robots use explicit policy grants, unaffected by role table |

**Overall verdict: sound.** The patch correctly and completely addresses the stated permission gap for the `maintainer` role. No bypass vectors were identified for the fixed functionality.
