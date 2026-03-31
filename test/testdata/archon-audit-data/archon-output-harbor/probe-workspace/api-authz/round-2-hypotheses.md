# Round 2 Hypotheses (Contradiction Reasoner — TRIZ / Game Theory)

Reasoning model: TRIZ (contradiction analysis) + Game Theory (adversarial assumptions)
Component: api-authz
Source: contradiction-reasoner-01

---

## PH-09: GetScanDataExportExecutionList — Stale Project Access Grants Data Visibility

**Hypothesis**: `GetScanDataExportExecutionList` at `src/server/v2.0/handler/scanexport.go:212` implements the following logic:

1. List executions filtered by `secContext.GetUsername()` [line 222]
2. Collect all project IDs from all executions
3. Call `requireProjectsAccess(ctx, pids, rbac.ActionRead, rbac.ResourceExportCVE)` [line 259]

The contradiction: the access check is performed on the UNION of all project IDs across all executions. If a user was removed from Project A but still has access to Project B, and they previously exported data that included both projects, the combined `pids` check will FAIL because they lack access to Project A.

However, the GAME-THEORY contradiction is the reverse: if the user is STILL a member of all listed projects, they see all their historical exports. There is no check that verifies the export execution's project IDs still map to the current project (after project deletion or recreation). A deleted project would have no members — but the project ID check fails gracefully.

**More critical TRIZ finding**: The list uses `secContext.GetUsername()` to filter. If an attacker can craft a context where `GetUsername()` returns an empty string or a different username, they could see other users' exports.

**Evidence needed**: Check what `GetUsername()` returns for anonymous context (should be ""). Check if `ListExecutions(ctx, "")` with empty username returns all executions.

**Attack input**: Unauthenticated request OR robot account with no username set

**Code path**:
- `GetScanDataExportExecutionList` [scanexport.go:212]
- `RequireAuthenticated(ctx)` — passes for any authenticated user
- `secContext.GetUsername()` — what does this return for robot accounts?
- `se.scanDataExportCtl.ListExecutions(ctx, username)` — filters by username

**Sanitizers on path**: `RequireAuthenticated` blocks anonymous. For authenticated users, username filtering applies.

**Security consequence**: If robot accounts have empty usernames, or if `ListExecutions("")` returns all records, any robot token holder can enumerate all scan export executions from all users.

**Severity estimate**: MEDIUM (needs deeper investigation)

---

## PH-10: Webhook URL SSRF — Private IP Ranges Not Filtered

**Hypothesis**: `validateTargets` at `src/server/v2.0/handler/webhook.go:405` reconstructs the URL as:
```go
target.Address = url.Scheme + "://" + url.Host + url.Path
```

The comment says "Prevent SSRF security issue #3755" but only strips query parameters and fragments. It does NOT check for:
- `169.254.169.254` (AWS/GCP/Azure cloud metadata endpoint)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 private ranges)
- `127.0.0.1` / `localhost` (loopback)
- IPv6 loopback (`::1`) and link-local addresses

**TRIZ contradiction**: The fix addresses one SSRF attack class (request smuggling via URL injection) but leaves the core SSRF class (accessing internal network via legitimate HTTP GET) fully open.

**Attack input**: Project admin sends `POST /api/v2.0/projects/{id}/webhook/policies` with `targets[0].address = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"`

**Code path**:
- `CreateWebhookPolicyOfProject` [webhook.go:140]
- `RequireProjectAccess(ctx, ..., rbac.ActionCreate, rbac.ResourceNotificationPolicy)` — project admin passes
- `validateTargets(policy)` [webhook.go:151] — only validates scheme, does NOT filter IPs
- Policy stored in DB with full SSRF URL
- Event triggers → Job Service picks up → WebhookJob.execute
- HTTP GET to `169.254.169.254` — returns AWS IAM credentials

**Sanitizers on path**: Only `utils.ParseEndpoint` + URL reconstruction. No IP range check.

**Security consequence**: Any project admin can use Harbor's webhook system to make the job service perform HTTP GET requests to any IP address including cloud metadata endpoints, internal Kubernetes service IPs, or other internal services. In cloud deployments this yields IAM credentials (AWS), VM identity tokens (GCP/Azure), or internal service enumeration.

**Severity estimate**: HIGH

---

## PH-11: ORM Sort Key Injection via OrderBy — Beego ORM Trust Analysis

**Hypothesis**: `setSorts` at `src/lib/orm/query.go:234` builds sort strings as:
```go
sorting = sort.Key                          // user-supplied after Sortable check
if sort.DESC { sorting = fmt.Sprintf("-%s", sorting) }
sortings = append(sortings, sorting)
```
Then calls `qs.OrderBy(sortings...)`.

Beego ORM's `OrderBy` does NOT quote field names with backticks or double-quotes; it passes them directly. The `Sortable` check only verifies the key exists in the parsed model's key map. The model metadata parsing uses Go struct field names or `orm:"column(name)"` annotations.

**TRIZ contradiction**: The field name check is a whitelist against model field names (which are Go identifiers). Go identifiers CANNOT contain SQL special characters. Therefore sort injection is impossible unless a model has a column annotation that introduces SQL characters.

**Attack test**: Can an attacker supply `sort=-id; DROP TABLE harbor_user--`? The `Sortable` check would reject `id; DROP TABLE harbor_user--` because it's not in the model's key map (the key is `id` not `id; DROP TABLE harbor_user--`).

**Assessment**: Protection is REAL. The Sortable whitelist effectively prevents sort injection for all standard models because Go field names are restricted to `[A-Za-z0-9_]` and model column names use valid SQL identifiers from the ORM annotations.

**Exception case**: Check if any model has a `FilterByXxx` method that could be registered as a filterable/sortable key with special characters. Not applicable as method names must be valid Go identifiers.

**Status**: INVALIDATED — sort injection protection is real via Sortable whitelist.

---

## PH-12: securityhub countExceedLimit — SQL Injection via Concatenated sqlStr

**Hypothesis**: `countExceedLimit` at `src/pkg/securityhub/dao/security.go:302` builds:
```go
queryExceed := fmt.Sprintf(`SELECT EXISTS (%s LIMIT 1 OFFSET 1000)`, sqlStr)
err = o.Raw(queryExceed, params).QueryRow(&exceed)
```

If `sqlStr` contains any unsanitized user content, this would be a SQL injection at the outer `SELECT EXISTS(...)` level. The `params` slice is correctly passed as placeholders. But if a filter function somehow injects literal SQL into `sqlStr` instead of `params`, the EXISTS wrapper would execute that SQL.

**Analysis of applyVulFilter**: All filter functions either:
- Add ` and col = ?` with value in params (exactMatchFilter)
- Add ` and col between ? and ?` with range values in params (rangeFilter)
- Add ` and a.id IN (SELECT ...)` where the subquery is built by `orm.CreateInClause` (tagFilter)

**tagFilter analysis** (`security.go:155`):
```go
inClause, err := orm.CreateInClause(ctx, `SELECT artifact_id FROM tag WHERE tag.name = ?`, val)
sqlStr = " and a.id " + inClause
```
`orm.CreateInClause` is called with a fixed SQL template and `val` (user-supplied tag name) as a parameter. The resulting `inClause` is a string of IDs fetched from the DB — it is the result of executing `SELECT artifact_id FROM tag WHERE tag.name = ?` with `val` as a parameterized value.

**Risk**: `orm.CreateInClause` executes a SELECT to get IDs, then embeds those integer IDs directly into the SQL. Since artifact IDs are integers, this is safe. But the function requires a DB connection to evaluate. More importantly: `inClause` string is APPENDED to `sqlStr` (not parameterized), meaning it goes into the EXISTS wrapper as literal SQL text.

**Critical**: If `orm.CreateInClause` returns an `inClause` that contains injection-capable content (e.g., if it doesn't properly stringify integer IDs), SQL injection in the EXISTS context is possible.

**Status**: NEEDS-DEEPER — need to read `orm.CreateInClause` implementation.

**Severity estimate**: HIGH if CreateInClause doesn't properly sanitize integer IDs

---

## PH-13: ListLabels Global Scope — No Authentication for Public Label List

**Hypothesis**: `ListLabels` at `src/server/v2.0/handler/label.go:91` does NOT call `RequireAuthenticated` at the start. It only calls `RequireProjectAccess` if scope is `LabelScopeProject`. For global scope labels, there is no auth check at all.

**Code path**:
- `ListLabels` [label.go:91]
- Checks scope from `params.Scope` [line 97-100]
- If scope == `LabelScopeProject`: requires project access [line 112]
- If scope == `LabelScopeGlobal`: NO auth check — proceeds to list labels

**Attack input**: `GET /api/v2.0/labels?scope=g` with no credentials

**Sanitizers on path**: NONE for global scope label listing.

**Security consequence**: Unauthenticated users can enumerate all global (system-level) labels in Harbor. Global labels include internal tagging used for image management, vulnerability status markers, and custom organizational labels. This is an information disclosure vulnerability.

**Severity estimate**: LOW-MEDIUM (label names may contain sensitive organizational information; allows unauthenticated enumeration of system configuration)

---

## PH-14: Project Search API — Unauthenticated Private Project Name Disclosure

**Hypothesis**: `Search` at `src/server/v2.0/handler/search.go:55` does NOT require authentication. It uses the security context to filter projects:
- System admins: see all projects
- Authenticated local users: see projects where they are members + public projects
- Others (anonymous/non-local auth): only see public projects [line 71-73]: `kw["public"] = true`

**TRIZ contradiction**: The code correctly filters to public-only for anonymous users. BUT the `filterRepositories` call at line 107 passes the filtered `projects` list AND searches repositories by fuzzy name match. Since `projects` already contains only accessible projects, the repository search is also scoped.

**Assessment**: The search endpoint is correctly implemented — anonymous users only see public projects and their repositories.

**Status**: INVALIDATED — search is correctly scoped by security context.

---

## PH-15: member/dao ListRoles — GroupIDs Integer Slice as IN Clause Parameter

**Hypothesis**: `ListRoles` at `src/pkg/member/dao/dao.go:237` builds:
```go
sql += fmt.Sprintf(`union select role from project_member where entity_type = 'g' and entity_id in ( %s ) and project_id = ? `, orm.ParamPlaceholderForIn(len(user.GroupIDs)))
params = append(params, user.GroupIDs)
```

`orm.ParamPlaceholderForIn(n)` returns `"?,?,?"` (n placeholders). `user.GroupIDs` is `[]int` from the user's session context, derived from OIDC/LDAP group claim parsing at login time.

**Game-theory scenario**: If an attacker can manipulate the OIDC `groups` claim to include a non-integer value that survives the OIDC parsing as an integer (e.g., a very large number, or -1), can they bypass RBAC role checks?

**Specific concern**: If `user.GroupIDs` contains an integer that corresponds to a group ID that has project admin role for a target project, the RBAC evaluation in `ListRoles` would return that admin role.

**Analysis**: This is working as designed — `ListRoles` returns roles based on group memberships. The OIDC/LDAP group claim parsing maps group names to Harbor internal group IDs. If an attacker can forge OIDC group claims to include a name that matches a high-privileged internal group, they gain that privilege.

**Separate issue**: The `params = append(params, user.GroupIDs)` passes a slice directly to beego ORM's Raw. Beego ORM should expand this into individual `?` bindings matching the `ParamPlaceholderForIn` count. If there's a mismatch between the count of placeholders and the actual params (e.g., if GroupIDs has 0 elements but the `if len > 0` check passes), SQL errors could occur.

**Status**: NEEDS-DEEPER for the OIDC group claim injection path; GroupIDs slice parameter is handled by ORM correctly.

---

## PH-16: Retention API — Scope.Reference IDOR via Arbitrary Retention ID Read

**Hypothesis** (game theory): In `GetRetention`, the retention policy is fetched by raw integer ID BEFORE the project membership check. The sequence is:

```go
p, err := r.retentionCtl.GetRetention(ctx, id)  // fetches from DB
err = r.requireAccess(ctx, p, rbac.ActionRead)   // checks membership
```

If `GetRetention` succeeds (policy exists in another project), `requireAccess` checks `p.Scope.Reference` (the project ID of that policy). If the attacker is NOT a member of that project, they receive a 403 error — not 404. The timing difference or error message difference between "no such retention policy" and "you don't have access" is a cross-project oracle.

**But deeper**: The real issue is whether `requireAccess` with a policy from a different project could return success. The check is:
```go
RequireProjectAccess(ctx, p.Scope.Reference, action, rbac.ResourceTagRetention)
```
If `p.Scope.Reference` is project B's ID, and the attacker is NOT a member of project B, this correctly returns 403. **However**, if the attacker IS a system admin, they can read any retention policy regardless of project.

**TRIZ gap**: A system admin who should only manage their own retention policies can read/modify ALL retention policies via the admin account. This is by design for system admins. But what about a project admin of project A trying to trigger execution of project B's retention policy?

**Code path for TriggerRetentionExecution**:
```go
p, err := r.retentionCtl.GetRetention(ctx, params.ID)  // fetches ANY policy
err = r.requireAccess(ctx, p, rbac.ActionUpdate)        // checks if caller can update
                                                         // p.Scope.Reference is the policy's project
```

If attacker is a project admin of project A and guesses the retention ID of project B's policy (integer enumeration), `requireAccess` checks `p.Scope.Reference` (= project B's ID) and returns 403. The attacker learns: "a retention policy exists at this ID and belongs to another project I cannot access."

**Severity estimate**: LOW (existence oracle only — no data disclosed, no state changed)
