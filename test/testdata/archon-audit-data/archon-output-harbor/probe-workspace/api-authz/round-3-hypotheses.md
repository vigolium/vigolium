# Round 3 Hypotheses (Causal Verifier — Counterfactual Analysis)

Reasoning model: Causal / Counterfactual
Component: api-authz
Source: causal-verifier-01

Inputs:
- Round 1 validated findings: PH-03, PH-06, PH-07, PH-08
- Round 2 validated findings: PH-09, PH-10, PH-13
- Cross-model seeds: CROSS-01, CROSS-02, CROSS-04, CROSS-05

---

## PH-17: ListLabels Global Scope — Confirmed Unauthenticated Read (Causal Verification of PH-13 / CROSS-04)

**Causal question**: Does removing the `RequireAuthenticated` call from `CreateLabel` but keeping it absent from `ListLabels` cause an exploitable gap?

**Counterfactual**: If `labelAPI` had a `Prepare` method that called `RequireAuthenticated`, unauthenticated `GET /api/v2.0/labels?scope=g` would be blocked.

**Code verification**:
- `labelAPI` has NO `Prepare` method defined [label.go — not present]
- The `BaseAPI.Prepare` is `func (*BaseAPI) Prepare(_ context.Context, _ string, _ any) middleware.Responder { return nil }` [base.go:49] — returns nil, meaning no auth
- `ListLabels` at label.go:91 enters without any auth check for global scope
- For project scope at line 112: `lAPI.RequireProjectAccess(ctx, pid, rbac.ActionList, rbac.ResourceLabel)` IS called
- For global scope: code path goes directly to `lAPI.labelMgr.Count(ctx, query)` at line 119 with no auth

**Status**: VALIDATED — unauthenticated global label listing is confirmed.

**Attack**: `GET /api/v2.0/labels?scope=g&page_size=100&page=1` with no auth headers returns all global labels.

**Target**: `src/server/v2.0/handler/label.go:91` — `ListLabels`

**Code path**:
- `GET /api/v2.0/labels?scope=g` → `ListLabels` [label.go:91]
- scope check [line 98-100]: passes for `g`
- NO `RequireAuthenticated` or `RequireProjectAccess` for global path
- `labelMgr.Count` and `labelMgr.List` return global labels [lines 119-131]

**Sanitizers on path**: NONE for global scope list.

**Security consequence**: Any HTTP client can enumerate all system-wide labels in Harbor without authentication. Severity depends on label content — labels may contain internal security classifications, vulnerability tags, compliance status, or organizational naming conventions.

**Severity estimate**: LOW-MEDIUM

---

## PH-18: SearchUserGroups — Confirmed Group Name Enumeration by Any Authenticated User (Causal Verification of PH-03)

**Causal question**: Does the absence of `RequireSystemAccess` in `SearchUserGroups` cause group enumeration beyond what is operationally necessary?

**Counterfactual**: If `SearchUserGroups` required `RequireSystemAccess`, only system admins could enumerate groups. The current design allows ANY authenticated user to enumerate group names.

**Code verification**:
- `SearchUserGroups` [usergroup.go:186]: only `RequireAuthenticated` [line 187]
- `u.ctl.SearchByName(ctx, params.Groupname, int(*params.PageSize))` [line 205] calls DAO
- DAO `SearchByName` at `usergroup/dao/dao.go:168`:
  - SQL: `select id, group_name, group_type, ldap_group_dn, ...`
  - `likePattern = "%" + name + "%"` — unescaped
  - Result returned includes `ldap_group_dn` field from DB
- Handler conversion `getUserGroupSearchItem` at line 157: only maps `GroupName`, `GroupType`, `ID` — DOES NOT expose `ldap_group_dn` to API response

**LIKE wildcard**: `orm.Escape` is NOT called on `name`. User can supply `%` to match all groups or `_` for wildcard character. Since `likePattern = "%" + name + "%"` with `name="%"`, the result is `%%` which is equivalent to `%` in SQL LIKE — matches everything.

**Status**: VALIDATED — any authenticated user can enumerate ALL group names. LDAP DNs are NOT exposed in the response, but group names ARE. With `groupname=%` the attacker gets all groups.

**Target**: `src/server/v2.0/handler/usergroup.go:186` — `SearchUserGroups`

**Attack**: `GET /api/v2.0/usergroups/search?groupname=%&page_size=100&page=1` with any valid session cookie → returns all group names + IDs.

**Sanitizers on path**: `RequireAuthenticated` only. LIKE wildcard not escaped. No rate limiting on this endpoint.

**Security consequence**: Any authenticated Harbor user can enumerate all user group names. In LDAP-backed installations this reveals AD group names (which may include sensitive organizational structure, role hierarchy, project codenames). Provides reconnaissance for LDAP group claim injection attacks.

**Severity estimate**: MEDIUM

---

## PH-19: Webhook SSRF — Cloud Metadata Access Confirmed Possible (Causal Verification of PH-10 / CROSS-02)

**Causal question**: Does the absence of IP range validation in `validateTargets` causally enable SSRF to cloud metadata endpoints?

**Counterfactual**: If `validateTargets` checked `url.Host` against private IP ranges (10.0.0.0/8, 169.254.169.254, 127.0.0.1), the SSRF would be blocked at storage time.

**Code verification**:
```go
// webhook.go:409-415
url, err := utils.ParseEndpoint(target.Address)
if err != nil {
    return false, errors.New(err).WithCode(errors.BadRequestCode)
}
// Prevent SSRF security issue #3755
target.Address = url.Scheme + "://" + url.Host + url.Path
```

`utils.ParseEndpoint` parses the URL. The comment references issue #3755 but the fix only strips query parameters and fragments. There is NO check for:
- `url.Host == "169.254.169.254"` (cloud metadata)
- IP range membership checks
- `url.Host == "localhost"` or `url.Host == "127.0.0.1"`

**Execution path**: Webhook is stored → event fires → Job Service processes → HTTP client makes GET request to the stored URL. The Job Service HTTP client (`commonhttp.GetHTTPTransport`) does not do DNS-based SSRF prevention either (no SSRF middleware).

**Status**: VALIDATED — project admins can register webhooks targeting any IP address or hostname. The metadata service at `169.254.169.254` is accessible from Harbor's job service container in AWS/GCP/Azure deployments unless network-level controls (IMDSv2 requirement, iptables rules) are in place.

**Target**: `src/server/v2.0/handler/webhook.go:405` — `validateTargets`

**Attack**: Project admin sends `POST /api/v2.0/projects/{id}/webhook/policies` with `targets[0].address = "http://169.254.169.254/latest/meta-data/"`. Any project event triggers the job service to GET that URL. The response is logged in webhook execution logs, accessible to the project admin.

**Sanitizers on path**: Only URL parsing + scheme/host/path reconstruction. No IP range filter.

**Security consequence**: In cloud-hosted Harbor deployments: cloud metadata credentials (IAM roles, service account tokens). In Kubernetes deployments: internal service IP access, potential cluster API server access. The webhook execution log stores the response, providing exfiltration channel.

**Severity estimate**: HIGH

---

## PH-20: Robot Account Creates Robot Account — Persistence Mechanism (Causal Verification of PH-07)

**Causal question**: Does the `NolimitProvider` granting `ResourceRobot:ActionCreate` to project robots cause a meaningful persistence gap?

**Counterfactual**: If robot accounts could NOT create other robot accounts, rotating a compromised robot would fully remediate the breach.

**Code verification**:
- `NolimitProvider.GetPermissions(ScopeProject)` [const.go:144-158]:
  ```go
  &types.Policy{Resource: ResourceRobot, Action: ActionCreate},
  ```
  This explicitly grants robot accounts the ability to create robots.
- `robotAPI.CreateRobot` uses `RequireProjectAccess or RequireSystemAccess` — robot token has the project scope permission above
- A robot account's JWT, when presented as auth, goes through the `Robot` security context provider
- `secCtx.Can(ctx, ActionCreate, robot_resource)` returns true for project robots via NolimitProvider

**Operational note**: The `GetPermissionProvider()` function at `const.go:99` always returns `NolimitProvider{}` with a TODO comment: "TODO will determine by the ui configuration". This means the behavior is hardcoded in production.

**Status**: VALIDATED — project robot accounts can create other robot accounts within the same project scope.

**Target**: `src/common/rbac/const.go:99` — `GetPermissionProvider` always returns `NolimitProvider`

**Attack**: Attacker obtains leaked project robot credentials → calls `POST /api/v2.0/robots` with project scope → creates shadow robot with identical permissions → original robot is rotated → attacker retains access via shadow robot.

**Sanitizers on path**: None. NolimitProvider explicitly enables this.

**Security consequence**: Compromised robot accounts establish persistent access that survives credential rotation. No parent-child robot tracking (robots don't record which identity created them in a way that enables mass revocation by parent).

**Severity estimate**: MEDIUM

---

## PH-21: Developer Role TagRetention CRUD — Artifact Deletion via Aggressive Retention (Causal Verification of PH-06)

**Causal question**: Can a developer-level user in a project actually destroy artifact history through the retention policy system?

**Counterfactual**: If `developer` role lacked `ResourceTagRetention:ActionCreate` and `ActionOperate`, a developer could not create or trigger retention policies.

**Code verification** (`rbac_role.go:213-218`):
```go
{Resource: rbac.ResourceTagRetention, Action: rbac.ActionCreate},
{Resource: rbac.ResourceTagRetention, Action: rbac.ActionRead},
{Resource: rbac.ResourceTagRetention, Action: rbac.ActionUpdate},
{Resource: rbac.ResourceTagRetention, Action: rbac.ActionDelete},
{Resource: rbac.ResourceTagRetention, Action: rbac.ActionList},
{Resource: rbac.ResourceTagRetention, Action: rbac.ActionOperate},
```

Developer has full CRUD + Operate. `TriggerRetentionExecution` at `retention.go:270` checks `rbac.ActionUpdate` — which developer has.

**Additional check on CreateRetention** [retention.go:161]:
- `if len(p.Rules) > 15` — max 15 rules, still allows destructive policies
- Scope must be project-level (`p.Scope.Level == policy.ScopeLevelProject`) — prevents cross-project damage
- `old, err := r.proMetaMgr.Get(ctx, p.Scope.Reference, "retention_id")` — checks if project already has a retention policy. If yes, returns error. If no, creates one.

**Critical finding**: A project can only have ONE retention policy (enforced at creation). If the project already has a retention policy (created by admin), a developer cannot CREATE a new one — they can only UPDATE the existing one. If the existing policy allows it, a developer can UPDATE it to be destructive and then TRIGGER it.

**Status**: VALIDATED with nuance — if a project has an existing retention policy, a developer can update it to be destructive. If no retention policy exists, a developer can create a destructive one.

**Severity estimate**: MEDIUM (developer can destroy artifact history in their project; by design but represents significant overgrant)

---

## PH-22: GetScanDataExportExecutionList — Username Filter Correctness (Causal Verification of PH-09)

**Causal question**: Does `secContext.GetUsername()` return a value that uniquely identifies the authenticated user, preventing cross-user export execution visibility?

**Code verification** (`scanexport.go:212-265`):
- `secContext.GetUsername()` — returns the username from the security context
- `se.scanDataExportCtl.ListExecutions(ctx, secContext.GetUsername())` — filters by username
- Result is then checked against current project access: `requireProjectsAccess(ctx, pids, ...)`

For robot accounts: `GetUsername()` on a robot security context typically returns the robot account name (e.g., `robot$project+name`). Robot usernames are non-empty and unique.

**Username collision scenario**: If two users have the same username (impossible in Harbor's local DB due to unique constraint, but potentially possible in LDAP if DN mapping creates duplicates), they would see each other's exports.

**Empty username scenario**: Anonymous users are blocked by `RequireAuthenticated`. This prevents the `ListExecutions(ctx, "")` path.

**Assessment**: The implementation correctly filters by username. The cross-user visibility risk is mitigated. However, the project access re-check at line 259 has an interesting property: if the user's project access changes AFTER the export job was created (e.g., they are removed from the project), the re-check will FAIL for all their jobs (the combined project IDs include the old project). This would prevent them from seeing ANY of their historical exports, even from projects they still have access to.

**Status**: INVALIDATED for cross-user access. IDENTIFIED a new issue: project membership changes retroactively block access to historical exports.

**Severity estimate**: LOW (usability issue, not security issue)
