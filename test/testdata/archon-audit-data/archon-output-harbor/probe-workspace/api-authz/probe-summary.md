# Deep Probe Summary: api-authz

Status: complete
Loops: 1
Total hypotheses: 22 (PH-01 through PH-22)
Validated: 6
Invalidated: 12
Needs-Deeper: 1 (OIDC group injection — separate component boundary)
Stop reason: All significant entry points covered; no fragile protections remain; uncovered areas are internal-only or cross component boundaries outside this probe's scope.

---

## Validated Hypotheses

### PH-10/19: Webhook SSRF — No Private IP Filter

- Reasoning-Model: Contradiction (TRIZ) + Causal Counterfactual
- Target: `src/server/v2.0/handler/webhook.go:405` — `validateTargets`
- Attack input: Project admin `POST /api/v2.0/projects/{id}/webhook/policies` with `targets[0].address = "http://169.254.169.254/latest/meta-data/"`
- Code path: `CreateWebhookPolicyOfProject` [webhook.go:140] → `validateTargets` [webhook.go:151] → `utils.ParseEndpoint` [utils.go:36-53] — only validates scheme is http/https, NO host IP check → URL stored in DB → Job Service executes HTTP GET on event trigger → response accessible via webhook task log API
- Sanitizers on path: `utils.ParseEndpoint` — only validates scheme. NOT bypassable — the protection simply doesn't exist for IP range validation.
- Supporting code: `utils.go:44-46`: only `scheme != "http" && scheme != "https"` check; no `url.Host` validation.
- Security consequence: Project admin can use Harbor job service as SSRF proxy to access cloud metadata service (`169.254.169.254`), internal Kubernetes service IPs, other containers on the same network. In AWS/GCP/Azure deployments: yields IAM credentials, service account tokens, VM identity tokens. Response is logged in webhook execution task logs, providing exfiltration channel.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

---

### PH-03/18: SearchUserGroups — Full Group Enumeration by Any Authenticated User

- Reasoning-Model: Pre-Mortem (backward) + Causal
- Target: `src/server/v2.0/handler/usergroup.go:186` — `SearchUserGroups`
- Attack input: Any authenticated user `GET /api/v2.0/usergroups/search?groupname=%&page_size=100`
- Code path: `SearchUserGroups` → `RequireAuthenticated(ctx)` (only auth check) → `ctl.SearchByName(ctx, params.Groupname, int(*params.PageSize))` → `dao.SearchByName` where `likePattern = "%" + name + "%"` (no `orm.Escape`), SQL: `WHERE group_name LIKE ?` → returns all groups when `name="%"`
- Sanitizers on path: `RequireAuthenticated` — blocks anonymous, allows any authenticated user. LIKE wildcard escape (`orm.Escape`) is present in `SearchMemberByName` but absent here.
- Security consequence: Any authenticated Harbor user can enumerate all LDAP/HTTP group names and their internal IDs. In enterprise LDAP deployments, this leaks Active Directory group structure, organizational hierarchy, privileged group names (enabling reconnaissance for LDAP group claim injection attacks). The response includes group `id` fields, allowing cross-reference with project member lists.
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

---

### PH-13/17: ListLabels Global Scope — Unauthenticated Enumeration

- Reasoning-Model: Contradiction (TRIZ) + Causal
- Target: `src/server/v2.0/handler/label.go:91` — `ListLabels`
- Attack input: Unauthenticated `GET /api/v2.0/labels?scope=g`
- Code path: `ListLabels` → scope validated as `g` [line 98-100] → no `RequireAuthenticated` or `RequireProjectAccess` for global scope → `labelMgr.Count` and `labelMgr.List` called directly — returns all global labels
- Sanitizers on path: NONE for global scope path. `labelAPI` has no `Prepare` override; `BaseAPI.Prepare` returns nil.
- Supporting code: `base.go:49-51`: `func (*BaseAPI) Prepare(...) { return nil }`. No `labelAPI.Prepare` exists.
- Security consequence: Unauthenticated HTTP clients can enumerate all system-wide Harbor labels. Labels may contain security classification tags, compliance status markers, vulnerability severity tags, or internal naming conventions. While not a direct exploit, it represents a missing authentication boundary and provides information useful for targeting.
- Severity estimate: LOW-MEDIUM
- Evidence file: round-1-evidence.md

---

### PH-07/20: Robot Account Creates Robot Account — Persistent Backdoor

- Reasoning-Model: Pre-Mortem (backward) + Causal
- Target: `src/common/rbac/const.go:99` — `GetPermissionProvider` (hardcoded `NolimitProvider`)
- Attack input: Attacker with leaked project robot credentials → `POST /api/v2.0/robots` with project scope
- Code path: Robot auth → `NolimitProvider.GetPermissions(ScopeProject)` returns `ResourceRobot:ActionCreate` [const.go:144] → `robotAPI.CreateRobot` with project RBAC check passes → new robot created with same scope
- Sanitizers on path: TODO comment at `const.go:99`: "TODO will determine by the ui configuration" — `BaseProvider` does not include `ResourceRobot` in project permissions and would prevent this. But `GetPermissionProvider` is hardcoded to `NolimitProvider`.
- Security consequence: A leaked robot account can create shadow robot accounts that survive credential rotation of the original. No parent-child tracking of robot creation. All project robot accounts are peers — no mass revocation by parent. PERSISTENT ACCESS after credential rotation.
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

---

### PH-06/21: Developer Role TagRetention CRUD — Artifact Destruction Capability

- Reasoning-Model: Pre-Mortem (backward) + Causal
- Target: `src/common/rbac/project/rbac_role.go:213-219` — developer role policy map
- Attack input: Developer-level project member creates and triggers aggressive retention policy
- Code path: Developer calls `POST /api/v2.0/retentions` → `requireAccess(ctx, p, rbac.ActionCreate)` → `RequireProjectAccess(ctx, p.Scope.Reference, ActionCreate, ResourceTagRetention)` → developer has this permission → retention policy created → `TriggerRetentionExecution` [retention.go:270] checks `ActionUpdate` → developer has this → execution triggers → all non-matching artifacts deleted
- Sanitizers on path: `len(p.Rules) > 15` limits rule count. `if old > 0` prevents duplicate policies (developer can UPDATE but not CREATE if policy exists from admin). For projects with no existing retention policy: full creation capability.
- Security consequence: Malicious developer (or compromised developer account) can destroy artifact history in their project by creating a retention policy with rules like "retain most recent 0 artifacts" and immediately triggering it. Data destruction capability with no undo.
- Severity estimate: MEDIUM (design issue — developers have more privilege than typical developer roles in other systems)
- Evidence file: round-1-evidence.md

---

### PH-02/16: Retention Policy Cross-Project Existence Oracle

- Reasoning-Model: Pre-Mortem (backward) + Game Theory
- Target: `src/server/v2.0/handler/retention.go:148` — `GetRetention` (fetch-before-auth pattern)
- Attack input: Authenticated user `GET /api/v2.0/retentions/{id}` with sequential IDs
- Code path: `GetRetention` → `retentionCtl.GetRetention(ctx, id)` (DB fetch) → if NOT found: error (maps to 404) → if FOUND: `requireAccess` → if access denied: `errors.ForbiddenError` (403) → response differs by existence
- Sanitizers on path: `requireAccess` correctly enforces project membership. The oracle is a side effect of the load-before-check pattern.
- Security consequence: Any authenticated user can determine which integer retention policy IDs exist across all Harbor projects via differential 403/404 responses. Leaks: total count of retention policies, ID distribution, whether specific projects have retention configured. Low direct impact but crosses project isolation boundary.
- Severity estimate: LOW
- Evidence file: round-1-evidence.md

---

## NEEDS-DEEPER

### PH-09: GetScanDataExportExecutionList — Project Removal Retroactively Blocks Historical Access

- Why unresolved: The `requireProjectsAccess` check at `scanexport.go:259` collects ALL project IDs across ALL of a user's exports and requires current access to ALL of them. If a user is removed from ANY one project they previously exported data from, they lose access to ALL their historical exports — including those from projects they still belong to.
- Not a security vulnerability per se, but a logic bug that could be exploited: an attacker who is removed from a project cannot export their previously gathered CVE data even though the data was legitimately obtained.
- Suggested follow-up: Phase 8 should verify this is an intentional design choice and whether the project access check should be per-execution rather than across all executions combined.

---

## Invalidated Protections Confirmed Sound

The following attack hypotheses were investigated and found to be protected by real, firm controls:

| Hypothesis | Protection | Location |
|---|---|---|
| securityhub SQL injection via `q=` | `checkQFilter` whitelist + `?` params + trusted filterMap columns | `security.go:359`, `security.go:126-153` |
| ORM sort key injection via `sort=` | `meta.Sortable()` whitelist against Go struct field names | `query.go:234-260`, `metadata.go:62-150` |
| `countExceedLimit` EXISTS injection | `CreateInClause` uses `strconv.FormatInt` (integer-only output) | `orm.go:240-260` |
| Search API private project disclosure | Security context filters to member+public projects for non-admins | `search.go:63-74` |
| Label scope IDOR via body manipulation | `requireAccess` switch is exhaustive; unknown scopes return BadRequest | `label.go:192-203` |
| ScanExport cross-user visibility | `ListExecutions` filtered by `secContext.GetUsername()` | `scanexport.go:222` |

---

## Coverage Summary

| Entry Point | backward-reasoner | contradiction-reasoner | causal-verifier |
|---|:---:|:---:|:---:|
| `q=` query param → securityhub SQL | PH-04 (INVALID) | PH-12 (INVALID) | CROSS-03 (confirmed) |
| `sort=` param → ORM OrderBy | None | PH-11 (INVALID) | Confirmed safe |
| Webhook target URL → SSRF | None | PH-10 (VALIDATED) | PH-19 (VALIDATED) |
| Retention API fetch-before-auth | PH-02 (VALIDATED) | PH-16 (VALIDATED) | CROSS-05 (confirmed) |
| Label ListLabels global scope | PH-05 (INVALID) | PH-13 (VALIDATED) | PH-17 (VALIDATED) |
| SearchUserGroups auth level | PH-03 (VALIDATED) | None | PH-18 (VALIDATED) |
| Robot creates robot | PH-07 (VALIDATED) | CROSS-02 (combined) | PH-20 (VALIDATED) |
| Developer TagRetention CRUD | PH-06 (VALIDATED) | None | PH-21 (VALIDATED) |
| NolimitProvider hardcoded | PH-07 | None | PH-20 |
| CreateInClause + EXISTS | CROSS-03 | PH-12 | Confirmed safe |
| ScanExport cross-user | PH-08 (NEEDS-DEEPER) | PH-09 | PH-22 (logic bug) |
| Member/ListRoles GroupIDs | None | PH-15 | Separate component |
| Search private project leak | None | PH-14 (INVALID) | Confirmed safe |
| artifactrash timestamp SQL | None | None | Internal-only (not user-controllable) |

---

## Risk Register (Final)

| ID | Finding | Severity | Component | File:Line |
|---|---|---|---|---|
| RISK-01 | Webhook SSRF — no private IP/metadata filter | HIGH | webhook handler | `webhook.go:405`, `utils.go:36` |
| RISK-02 | SearchUserGroups group name enumeration by any authenticated user | MEDIUM | usergroup handler + dao | `usergroup.go:186`, `usergroup/dao/dao.go:168` |
| RISK-03 | Robot account creates shadow robot accounts (NolimitProvider hardcoded) | MEDIUM | RBAC const | `const.go:99` |
| RISK-04 | Developer role can create/trigger destructive retention policies | MEDIUM | RBAC role map | `rbac_role.go:213-219` |
| RISK-05 | ListLabels global scope accessible without authentication | LOW-MEDIUM | label handler | `label.go:91` |
| RISK-06 | Retention policy existence oracle (403 vs 404 on cross-project access) | LOW | retention handler | `retention.go:148` |
