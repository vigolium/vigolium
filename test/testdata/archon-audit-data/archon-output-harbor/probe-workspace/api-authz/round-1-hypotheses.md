# Round 1 Hypotheses (Backward Reasoner — Pre-Mortem / Abductive)

Reasoning model: Pre-Mortem + Abductive
Component: api-authz
Source: backward-reasoner-01

---

## PH-01: GetRetentionMetadata Unauthenticated Access

**Hypothesis**: `GetRentenitionMetadata` at `src/server/v2.0/handler/retention.go:144` has no authentication or authorization check. Any unauthenticated HTTP client can call `GET /api/v2.0/retentions/metadatas` and receive the retention policy template structure including rule templates, scope selectors, and tag selectors.

**Attack input**: `GET /api/v2.0/retentions/metadatas` with no credentials

**Code path**:
- `retentionAPI.Prepare` → calls `RequireAuthenticated` [retention.go:136-142]
- `GetRentenitionMetadata` → returns immediately with no auth call [retention.go:144-146]

**Wait**: Prepare IS called before GetRentenitionMetadata. Re-evaluating: `Prepare` calls `RequireAuthenticated`, which means an anonymous request WILL be rejected at the Prepare step. The payload is returned only if authenticated.

**Revised hypothesis**: The auth check exists in Prepare. However, the only check is `RequireAuthenticated` — any valid session or robot token grants access to the retention metadata, regardless of project membership. This is low severity (static metadata exposure).

**Sanitizers on path**: `RequireAuthenticated` in Prepare — NOT bypassable for standard requests. Bypassable only if authentication middleware is bypassed.

**Security consequence**: Minimal. Static template metadata exposed to all authenticated users.

**Status**: PARTIALLY VALID — low severity information disclosure to authenticated users, not a meaningful bypass.

**Severity estimate**: LOW

---

## PH-02: Retention API Post-Load Auth Pattern — IDOR via Retention ID Manipulation

**Hypothesis**: The retention API uses a "load then check" pattern. `GetRetention` and other methods first load the retention policy by ID (untrusted integer from URL), then call `requireAccess(ctx, p, action)` which checks `p.Scope.Reference` (the project ID stored in the DB) against the security context. If the `GetRetention` call returns a policy, the attacker learns the policy exists. If the project's retention ID doesn't match, `requirePolicyAccess` returns 404 — creating an oracle.

**Attack input**: Authenticated low-priv user sends `GET /api/v2.0/retentions/{id}` with sequential integer IDs

**Code path**:
- `retentionAPI.GetRetention(ctx, params)` [retention.go:148]
- `r.retentionCtl.GetRetention(ctx, id)` — fetches from DB by raw ID [retention.go:150]
- `r.requireAccess(ctx, p, rbac.ActionRead)` — checks project membership [retention.go:154]

**Assessment**: If the retention policy belongs to another project, `requireAccess` will call `RequireProjectAccess` which returns 403 if the user lacks access. However, the error difference between "policy not found" (404) and "access denied" (403) may reveal whether a retention policy with that ID exists — creating an IDOR oracle for policy existence across projects.

**Sanitizers on path**: `requireAccess` calls `RequireProjectAccess`. Does NOT return uniform error codes — 403 vs 404 differ.

**Security consequence**: Retention policy existence oracle — authenticated user can determine which project IDs have retention policies by probing retention IDs.

**Severity estimate**: LOW (information disclosure only)

---

## PH-03: SearchUserGroups Authenticated-Only — Full User Group Enumeration

**Hypothesis**: `SearchUserGroups` at `src/server/v2.0/handler/usergroup.go:186` requires only `RequireAuthenticated`. Any authenticated user (including guest-level project members) can enumerate ALL user groups in the Harbor instance by calling `GET /api/v2.0/usergroups/search?groupname=%` with wildcard patterns.

**Attack input**: Authenticated user sends `GET /api/v2.0/usergroups/search?groupname=%` (URL-encoded `%25` or any partial name)

**Code path**:
- `SearchUserGroups` [usergroup.go:186]
- `RequireAuthenticated(ctx)` — only auth check [usergroup.go:187]
- `u.ctl.SearchByName(ctx, params.Groupname, int(*params.PageSize))` [usergroup.go:205]
- `dao.SearchByName(ctx, name, limitSize)` [usergroup/dao/dao.go:168]
- SQL: `select ... where group_name like ? order by length(group_name), group_name asc limit ?`
- `likePattern = "%" + name + "%"` — no LIKE escape applied

**Note on LIKE**: `likePattern` is passed as parameterized value `?` to `o.Raw(sql, likePattern, ...)`. This prevents SQL injection. However, `name` is not passed through `orm.Escape()`, so an attacker can supply `%` (match all) or `_` (single-char wildcard) to control LIKE matching breadth.

**Sanitizers on path**: Only `RequireAuthenticated`. No `RequireSystemAccess`. No LIKE wildcard escape on `name`.

**Security consequence**: Any authenticated Harbor user can enumerate all LDAP group names and HTTP group names. In enterprise environments, this leaks Active Directory/LDAP group structure, group naming conventions, and potentially sensitive group names.

**Severity estimate**: MEDIUM

---

## PH-04: securityhub ListVulnerabilities — SQL Fragment Construction After Auth

**Hypothesis**: `ListVulnerabilities` at `src/server/v2.0/handler/security.go:102` correctly requires `RequireSystemAccess`. After auth, it calls `s.BuildQuery(ctx, params.Q, nil, params.Page, params.PageSize)` which parses the `q=` parameter. The resulting query flows to `securityhub/dao/security.go:311` which calls `checkQFilter` then `applyVulFilter`.

`checkQFilter` validates that only keys in `filterMap` are used. This is a whitelist validation. However, `applyVulFilter` iterates ALL `filterMap` entries and calls their `FilterFunc` for each. For a valid key like `severity`, the user-supplied value flows as a parameterized `?` placeholder. For `cvss_score_v3` (rangeType), the user must supply a `*q.Range` — but `checkQFilter` only validates `query.Keywords[k].(*q.Range)` type assertion.

**Attack input**: System admin authenticates, sends `GET /api/v2.0/security/vuls?q=cvss_score_v3=[notarange~]`

**Code path**:
- `parseRange` [builder.go:129] — parses `[min~max]` format; if malformed, returns error → BuildQuery fails with BadRequest
- Correctly handled at parse layer

**Revised**: The `q=` parser in `lib/q/builder.go` validates range syntax before the query object is constructed. Malformed range returns 400. Values go to `?` placeholders. The column name (`col`) in `exactMatchFilter` is ALWAYS from the hardcoded `filterMap` map, never from user input.

**Assessment**: SQL injection via securityhub `q=` parameter is NOT achievable. The `checkQFilter` whitelist + parameterized values prevent it. The `fmt.Sprintf(" and %v = ?", col)` pattern is fragile by example but col is trusted.

**Status**: INVALIDATED for SQL injection. The protection is real.

**Severity estimate**: N/A

---

## PH-05: Label API — Global Scope IDOR via Scope Manipulation

**Hypothesis**: `CreateLabel` at `src/server/v2.0/handler/label.go:51` accepts a label scope from the request body. The `requireAccess` helper at line 192 routes to `RequireSystemAccess` for global scope and `RequireProjectAccess` for project scope. If an attacker can supply a scope that bypasses both checks...

**Code path**:
- `CreateLabel` copies request body to `label` struct [label.go:53]
- `label.Level = common.LabelLevelUser` — forced
- `label.Scope` — taken from user-supplied body
- `requireAccess` [label.go:192]: switch on scope
  - `LabelScopeGlobal` → RequireSystemAccess
  - `LabelScopeProject` → RequireProjectAccess
  - default → returns BadRequest ("unsupported label scope")

**Assessment**: The switch is exhaustive: any scope value that isn't `LabelScopeGlobal` or `LabelScopeProject` gets a BadRequest error. An attacker cannot bypass the auth check by supplying an unexpected scope. The protection is sound.

**Status**: INVALIDATED — scope validation is exhaustive.

---

## PH-06: Developer Role Has Full TagRetention CRUD — Privilege Overgrant

**Hypothesis**: The RBAC `rolePoliciesMap` in `src/common/rbac/project/rbac_role.go:24` grants `developer` role full CRUD + Operate on `ResourceTagRetention`. This means a Harbor developer-level user can create, update, delete, and trigger tag retention policies that would delete artifacts from the project.

**Code path**:
- Project developer sends `POST /api/v2.0/retentions` with retention policy scoped to their project
- `retentionAPI.CreateRetention` calls `requireAccess(ctx, p, rbac.ActionCreate)` [retention.go:169]
- `requireAccess` calls `RequireProjectAccess(ctx, p.Scope.Reference, rbac.ActionCreate, rbac.ResourceTagRetention)` [retention.go:413]
- Developer role has `{Resource: rbac.ResourceTagRetention, Action: rbac.ActionCreate}` at line 213
- Developer can CREATE a retention policy and trigger it via `TriggerRetentionExecution`
- This causes deletion of artifacts in the project

**Sanitizers on path**: None against the developer role having this permission. Developers are intentionally granted retention CRUD.

**Security consequence**: A malicious developer can delete all non-latest artifacts in a project by creating and triggering an aggressive retention policy (e.g., "retain only 0 artifacts" or "retain only pushed within 0 days"). This effectively constitutes a data destruction capability for project developers.

**Note**: This is a role design issue, not a code bug. Whether developer should have `ActionDelete` on `ResourceTagRetention` is a policy question. The code is working as designed.

**Severity estimate**: MEDIUM (role overgrant — developers can destroy project artifact history)

---

## PH-07: Robot Account Can Create Other Robot Accounts (NolimitProvider)

**Hypothesis**: `NolimitProvider.GetPermissions(ScopeProject)` at `src/common/rbac/const.go:144` includes:
```go
{Resource: ResourceRobot, Action: ActionCreate},
{Resource: ResourceRobot, Action: ActionRead},
{Resource: ResourceRobot, Action: ActionList},
{Resource: ResourceRobot, Action: ActionDelete},
```

This means a project-scoped robot account can create other robot accounts within the same project. If a robot account's credentials are leaked (e.g., in CI/CD logs), an attacker can use those credentials to create a new robot account with the same permissions — effectively a persistence mechanism after the original robot is rotated.

**Attack input**: Attacker obtains project robot credentials → uses robot token to call `POST /api/v2.0/robots` with project scope

**Code path**:
- `robotAPI.CreateRobot` — checks project access with `RequireProjectAccess` [robot.go]
- Robot security context: `secCtx.Can(ctx, ActionCreate, projectResource.Robot)`
- NolimitProvider grants this to robots
- New robot with identical permissions is created

**Sanitizers on path**: None — NolimitProvider explicitly grants robot creation to robot accounts.

**Security consequence**: Compromised robot accounts can create persistent backdoor robot accounts. Rotating the compromised robot does not revoke the newly created shadow robot.

**Severity estimate**: MEDIUM

---

## PH-08: GetScanDataExportExecutionList — Authentication Only, No Project Scope Check

**Hypothesis**: The scan data export execution list endpoint uses only `RequireAuthenticated`. If the list is not filtered by user ID at the handler level, any authenticated user can view all export executions.

**Code path** (needs verification):
- `scanDataExportAPI.GetScanDataExportExecution` [scanexport.go:108] — has `RequireAuthenticated` + per-project access check + username match
- The LIST endpoint (if it exists) may lack the project scope check

**Assessment**: `GetScanDataExportExecution` correctly validates ownership. Need to verify if a list/enumerate endpoint exists without the ownership check. Based on anatomy, `GetScanDataExportExecutionList` was noted as `RequireAuthenticated ONLY`. This needs verification.

**Status**: NEEDS-DEEPER — requires reading the full scanexport.go to find the list method.

**Severity estimate**: MEDIUM if confirmed (cross-user data access)
