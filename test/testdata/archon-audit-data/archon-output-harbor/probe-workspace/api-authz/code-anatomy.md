# Code Anatomy: api-authz

## 1. Handler Auth Coverage Map

### src/server/v2.0/handler/

Each handler method's first auth decision is noted. "Prepare=nil" means no auth in Prepare() — each method must check independently.

| Handler File | Method | Auth Call | RBAC Resource | RBAC Action |
|---|---|---|---|---|
| artifact.go | ListArtifacts | RequireProjectAccess | ResourceArtifact | ActionList |
| artifact.go | GetArtifact | RequireProjectAccess | ResourceArtifact | ActionRead |
| artifact.go | DeleteArtifact | RequireProjectAccess | ResourceArtifact | ActionDelete |
| artifact.go | CopyArtifact | RequireProjectAccess | ResourceArtifact | ActionCreate |
| artifact.go | ListTags | RequireProjectAccess | ResourceTag | ActionList |
| artifact.go | CreateTag | RequireProjectAccess | ResourceTag | ActionCreate |
| artifact.go | DeleteTag | RequireProjectAccess | ResourceTag | ActionDelete |
| artifact.go | GetAddition | RequireProjectAccess | ResourceArtifactAddition | ActionRead |
| artifact.go | AddLabel | RequireProjectAccess | ResourceArtifactLabel | ActionCreate |
| artifact.go | RemoveLabel | RequireProjectAccess | ResourceArtifactLabel | ActionDelete |
| artifact.go | GetVulnerabilitiesAddition | RequireProjectAccess | ResourceArtifactAddition | ActionRead |
| artifact.go | GetBuildHistoryAddition | RequireProjectAccess | ResourceArtifactAddition | ActionRead |
| artifact.go | GetSBOMAddition | RequireProjectAccess | ResourceArtifactAddition | ActionRead |
| auditlog.go | ListAuditLogs | RequireSystemAccess | ResourceAuditLog | ActionList |
| auditlog.go | ListAuditLogsOfProject | RequireProjectAccess | ResourceLog | ActionList |
| config.go | GetConfigurations | RequireSystemAccess | ResourceConfiguration | ActionRead |
| config.go | UpdateConfigurations | RequireSystemAccess | ResourceConfiguration | ActionUpdate |
| config.go | GetInternalconfig | RequireSystemAccess | ResourceConfiguration | ActionRead |
| gc.go | CreateGCSchedule | RequireSystemAccess | ResourceGarbageCollection | ActionCreate |
| gc.go | UpdateGCSchedule | RequireSystemAccess | ResourceGarbageCollection | ActionUpdate |
| gc.go | GetGCSchedule | RequireSystemAccess | ResourceGarbageCollection | ActionRead |
| gc.go | GetGCHistory | RequireSystemAccess | ResourceGarbageCollection | ActionList |
| gc.go | GetGC | RequireSystemAccess | ResourceGarbageCollection | ActionRead |
| gc.go | StopGC | RequireSystemAccess | ResourceGarbageCollection | ActionStop |
| gc.go | GetGCLog | RequireSystemAccess | ResourceGarbageCollection | ActionRead |
| health.go | GetHealth | NONE | - | - |
| icon.go | GetIcon | NONE | - | - |
| immutable.go | CreateImmuRule | RequireProjectAccess | ResourceImmutableTag | ActionCreate |
| immutable.go | DeleteImmuRule | RequireProjectAccess | ResourceImmutableTag | ActionDelete |
| immutable.go | UpdateImmuRule | RequireProjectAccess | ResourceImmutableTag | ActionUpdate |
| immutable.go | ListImmuRules | RequireProjectAccess | ResourceImmutableTag | ActionList |
| jobservice.go | GetWorkerPools | RequireSystemAccess | ResourceJobServiceMonitor | ActionList |
| jobservice.go | GetWorkers | RequireSystemAccess | ResourceJobServiceMonitor | ActionList |
| jobservice.go | StopRunningJob | RequireSystemAccess | ResourceJobServiceMonitor | ActionStop |
| jobservice.go | ActionPendingJobs | RequireSystemAccess | ResourceJobServiceMonitor | ActionStop |
| jobservice.go | GetJobLog | RequireSystemAccess | ResourceJobServiceMonitor | ActionList |
| jobservice.go | ListScheduledTasks | RequireSystemAccess | ResourceJobServiceMonitor | ActionList |
| label.go | CreateLabel | RequireAuthenticated OR RequireProjectAccess (scope-dependent) | ResourceLabel | ActionCreate |
| label.go | ListLabels | RequireAuthenticated (for project-scope no explicit check) | ResourceLabel | ActionList |
| label.go | GetLabel | RequireAuthenticated | ResourceLabel | ActionRead |
| label.go | UpdateLabel | ownership check, not RBAC | ResourceLabel | ActionUpdate |
| label.go | DeleteLabel | ownership check, not RBAC | ResourceLabel | ActionDelete |
| ldap.go | PingLDAP | RequireSystemAccess | ResourceLdapUser | ActionCreate |
| ldap.go | SearchLdapUser | RequireSystemAccess | ResourceLdapUser | ActionList |
| ldap.go | ImportLdapUser | RequireSystemAccess | ResourceLdapUser | ActionCreate |
| ldap.go | SearchLdapGroup | RequireSystemAccess | ResourceUserGroup | ActionList |
| member.go | CreateProjectMember | RequireProjectAccess | ResourceMember | ActionCreate |
| member.go | ListProjectMembers | RequireProjectAccess | ResourceMember | ActionList |
| member.go | UpdateProjectMember | RequireProjectAccess | ResourceMember | ActionUpdate |
| member.go | GetProjectMember | RequireProjectAccess | ResourceMember | ActionRead |
| member.go | DeleteProjectMember | RequireProjectAccess | ResourceMember | ActionDelete |
| oidc.go | GetOIDCUserInfo | RequireAuthenticated | - | - |
| permissions.go | GetPermissions | NONE (public endpoint — returns RBAC policy list) | - | - |
| ping.go | GetPing | NONE | - | - |
| preheat.go | CreateInstance | RequireSystemAccess | ResourcePreatInstance | ActionCreate |
| preheat.go | DeleteInstance | RequireSystemAccess | ResourcePreatInstance | ActionDelete |
| preheat.go | GetInstance | RequireSystemAccess (or authenticated?) | ResourcePreatInstance | ActionRead |
| preheat.go | ListInstances | RequireSystemAccess | ResourcePreatInstance | ActionList |
| preheat.go | UpdateInstance | RequireSystemAccess | ResourcePreatInstance | ActionUpdate |
| preheat.go | CreatePolicy | RequireProjectAccess | ResourcePreatPolicy | ActionCreate |
| preheat.go | DeletePolicy | RequireProjectAccess | ResourcePreatPolicy | ActionDelete |
| preheat.go | GetPolicy | RequireProjectAccess | ResourcePreatPolicy | ActionRead |
| preheat.go | ListPolicies | RequireProjectAccess | ResourcePreatPolicy | ActionList |
| preheat.go | UpdatePolicy | RequireProjectAccess | ResourcePreatPolicy | ActionUpdate |
| preheat.go | ManualPreheat | RequireProjectAccess | ResourcePreatPolicy | ActionCreate |
| preheat.go | StopExecution | RequireProjectAccess | ResourcePreatPolicy | ActionCreate |
| preheat.go | ListExecutions | RequireProjectAccess | ResourcePreatPolicy | ActionRead |
| preheat.go | ListTasks | RequireProjectAccess | ResourcePreatPolicy | ActionRead |
| preheat.go | GetPreheatLog | RequireProjectAccess | ResourcePreatPolicy | ActionRead |
| project.go | CreateProject | RequireAuthenticated (no project yet exists) | - | - |
| project.go | DeleteProject | RequireProjectAccess | ResourceProject (self) | ActionDelete |
| project.go | GetProject | RequireProjectAccess OR public | ResourceProject (self) | ActionRead |
| project.go | ListProjects | RequireAuthenticated | ResourceProject | ActionList |
| project.go | UpdateProject | RequireProjectAccess | ResourceProject (self) | ActionUpdate |
| project.go | GetProjectDeletable | RequireProjectAccess | ResourceProject | ActionDelete |
| project.go | GetProjectSummary | RequireProjectAccess | ResourceProject | ActionRead |
| project.go | HeadProject | NONE (public) | - | - |
| project_metadata.go | AddProjectMetadatas | RequireProjectAccess | ResourceMetadata | ActionCreate |
| project_metadata.go | ListProjectMetadatas | RequireProjectAccess | ResourceMetadata | ActionList |
| project_metadata.go | GetProjectMetadata | RequireProjectAccess | ResourceMetadata | ActionRead |
| project_metadata.go | UpdateProjectMetadata | RequireProjectAccess | ResourceMetadata | ActionUpdate |
| project_metadata.go | DeleteProjectMetadata | RequireProjectAccess | ResourceMetadata | ActionDelete |
| purge.go | CreatePurgeSchedule | RequireSystemAccess | ResourcePurgeAuditLog | ActionCreate |
| purge.go | UpdatePurgeSchedule | RequireSystemAccess | ResourcePurgeAuditLog | ActionUpdate |
| purge.go | GetPurgeSchedule | RequireSystemAccess | ResourcePurgeAuditLog | ActionRead |
| purge.go | GetPurgeHistory | RequireSystemAccess | ResourcePurgeAuditLog | ActionList |
| purge.go | GetPurgeJob | RequireSystemAccess | ResourcePurgeAuditLog | ActionRead |
| purge.go | StopPurge | RequireSystemAccess | ResourcePurgeAuditLog | ActionStop |
| purge.go | GetPurgeJobLog | RequireSystemAccess | ResourcePurgeAuditLog | ActionRead |
| quota.go | ListQuotas | RequireSystemAccess | ResourceQuota | ActionList |
| quota.go | GetQuota | RequireSystemAccess | ResourceQuota | ActionRead |
| quota.go | UpdateQuota | RequireSystemAccess | ResourceQuota | ActionUpdate |
| registry.go | CreateRegistry | RequireSystemAccess | ResourceRegistry | ActionCreate |
| registry.go | DeleteRegistry | RequireSystemAccess | ResourceRegistry | ActionDelete |
| registry.go | GetRegistry | RequireSystemAccess | ResourceRegistry | ActionRead |
| registry.go | ListRegistries | RequireSystemAccess | ResourceRegistry | ActionList |
| registry.go | UpdateRegistry | RequireSystemAccess | ResourceRegistry | ActionUpdate |
| registry.go | GetRegistryInfo | RequireSystemAccess | ResourceRegistry | ActionRead |
| registry.go | PingRegistry | RequireSystemAccess | ResourceRegistry | ActionRead |
| registry.go | ListRegistryProviderInfos | RequireSystemAccess | ResourceRegistry | ActionList |
| registry.go | ListRegistryProviderTypes | RequireSystemAccess | ResourceRegistry | ActionList |
| replication.go | CreateReplicationPolicy | RequireSystemAccess | ResourceReplicationPolicy | ActionCreate |
| replication.go | DeleteReplicationPolicy | RequireSystemAccess | ResourceReplicationPolicy | ActionDelete |
| replication.go | GetReplicationPolicy | RequireSystemAccess | ResourceReplicationPolicy | ActionRead |
| replication.go | ListReplicationPolicies | RequireSystemAccess | ResourceReplicationPolicy | ActionList |
| replication.go | UpdateReplicationPolicy | RequireSystemAccess | ResourceReplicationPolicy | ActionUpdate |
| replication.go | StartReplication | RequireSystemAccess | ResourceReplication | ActionCreate |
| replication.go | StopReplication | RequireSystemAccess | ResourceReplication | ActionCreate |
| replication.go | GetReplicationExecution | RequireSystemAccess | ResourceReplication | ActionRead |
| replication.go | ListReplicationExecutions | RequireSystemAccess | ResourceReplication | ActionList |
| replication.go | ListReplicationTasks | RequireSystemAccess | ResourceReplication | ActionList |
| replication.go | GetReplicationLog | RequireSystemAccess | ResourceReplication | ActionRead |
| repository.go | ListAllRepositories | RequireSystemAccess | ResourceCatalog | ActionRead |
| repository.go | ListRepositories | RequireProjectAccess | ResourceRepository | ActionList |
| repository.go | GetRepository | RequireProjectAccess | ResourceRepository | ActionRead |
| repository.go | UpdateRepository | RequireProjectAccess | ResourceRepository | ActionUpdate |
| repository.go | DeleteRepository | RequireProjectAccess | ResourceRepository | ActionDelete |
| retention.go | Prepare | RequireAuthenticated ONLY — NO project-specific check | - | - |
| retention.go | GetRentenitionMetadata | NONE — no auth check at all | - | - |
| retention.go | GetRetention | requireAccess (RequireProjectAccess via helper) | ResourceTagRetention | ActionRead |
| retention.go | CreateRetention | requireAccess (RequireProjectAccess via helper) | ResourceTagRetention | ActionCreate |
| retention.go | UpdateRetention | requireAccess (RequireProjectAccess via helper) | ResourceTagRetention | ActionUpdate |
| retention.go | DeleteRetention | requireAccess (RequireProjectAccess via helper) | ResourceTagRetention | ActionDelete |
| retention.go | TriggerRetentionExecution | requireAccess | ResourceTagRetention | ActionUpdate |
| retention.go | OperateRetentionExecution | requireAccess | ResourceTagRetention | ActionUpdate |
| retention.go | ListRetentionExecutions | requireAccess | ResourceTagRetention | ActionList |
| retention.go | ListRetentionTasks | requireAccess | ResourceTagRetention | ActionList |
| retention.go | GetRetentionTaskLog | requireAccess | ResourceTagRetention | ActionRead |
| robot.go | CreateRobot | RequireProjectAccess or RequireSystemAccess | ResourceRobot | ActionCreate |
| robot.go | DeleteRobot | RequireProjectAccess or RequireSystemAccess | ResourceRobot | ActionDelete |
| robot.go | GetRobot | RequireProjectAccess or RequireSystemAccess | ResourceRobot | ActionRead |
| robot.go | ListRobot | RequireProjectAccess or RequireSystemAccess | ResourceRobot | ActionList |
| robot.go | UpdateRobot | RequireProjectAccess or RequireSystemAccess | ResourceRobot | ActionUpdate |
| robot.go | RefreshSec | RequireProjectAccess or RequireSystemAccess | ResourceRobot | ActionUpdate |
| scan.go | ScanArtifact | RequireProjectAccess | ResourceScan | ActionCreate |
| scan.go | GetReportLog | RequireProjectAccess | ResourceArtifactAddition | ActionRead |
| scan.go | StopScanArtifact | RequireProjectAccess | ResourceScan | ActionStop |
| scan_all.go | StopScanAll | requireAccess (RequireSystemAccess) | ResourceScanAll | ActionStop |
| scan_all.go | CreateScanAllSchedule | requireAccess (RequireSystemAccess) | ResourceScanAll | ActionCreate |
| scan_all.go | UpdateScanAllSchedule | requireAccess (RequireSystemAccess) | ResourceScanAll | ActionUpdate |
| scan_all.go | GetScanAllSchedule | requireAccess (RequireSystemAccess) | ResourceScanAll | ActionRead |
| scan_all.go | GetLatestScanAllMetrics | requireAccess (RequireSystemAccess) | ResourceScanAll | ActionRead |
| scan_all.go | GetScanAllMetrics | requireAccess (RequireSystemAccess) | ResourceScanAll | ActionRead |
| scanexport.go | ExportScanData | RequireProjectAccess (per project ID in criteria) | ResourceExportCVE | ActionCreate |
| scanexport.go | GetScanDataExportExecution | RequireAuthenticated + per-project check | ResourceExportCVE | ActionRead |
| scanexport.go | DownloadScanData | RequireAuthenticated + per-project check | ResourceExportCVE | ActionRead |
| scanexport.go | GetScanDataExportExecutionList | RequireAuthenticated ONLY | - | - |
| scanner.go | CreateScanner | RequireSystemAccess | ResourceScanner | ActionCreate |
| scanner.go | DeleteScanner | RequireSystemAccess | ResourceScanner | ActionDelete |
| scanner.go | GetScanner | RequireSystemAccess | ResourceScanner | ActionRead |
| scanner.go | ListScanners | RequireSystemAccess | ResourceScanner | ActionList |
| scanner.go | UpdateScanner | RequireSystemAccess | ResourceScanner | ActionUpdate |
| scanner.go | SetScannerAsDefault | RequireSystemAccess | ResourceScanner | ActionCreate |
| scanner.go | GetScannerMetadata | RequireSystemAccess | ResourceScanner | ActionRead |
| scanner.go | GetProjectScanner | RequireProjectAccess | ResourceScanner | ActionRead |
| scanner.go | SetProjectScanner | RequireProjectAccess | ResourceScanner | ActionCreate |
| schedule.go | ListSchedules | RequireSystemAccess | ResourceJobServiceMonitor | ActionList |
| schedule.go | GetSchedulePaused | RequireSystemAccess | ResourceJobServiceMonitor | ActionList |
| search.go | Search | NONE (public search) | - | - |
| security.go | GetSecuritySummary | RequireSystemAccess | ResourceSecurityHub | ActionRead |
| security.go | ListVulnerabilities | RequireSystemAccess | ResourceSecurityHub | ActionList |
| statistic.go | GetStatistic | RequireAuthenticated | - | - |
| sys_cve_allowlist.go | GetSystemCVEAllowlist | NONE (check inside body?) | - | - |
| sys_cve_allowlist.go | UpdateSystemCVEAllowlist | RequireSystemAccess | ResourceConfiguration | ActionUpdate |
| systeminfo.go | GetSystemInfo | NONE or partial check | - | - |
| user.go | ListUsers | RequireSystemAccess | ResourceUser | ActionList |
| user.go | CreateUser | RequireSystemAccess | ResourceUser | ActionCreate |
| user.go | GetUser | self or RequireSystemAccess | ResourceUser | ActionRead |
| user.go | UpdateUserProfile | self or RequireSystemAccess | ResourceUser | ActionUpdate |
| user.go | DeleteUser | RequireSystemAccess | ResourceUser | ActionDelete |
| user.go | GetCurrentUserInfo | RequireAuthenticated | - | - |
| user.go | SetUserSysAdmin | RequireSystemAccess | ResourceUser | ActionUpdate |
| user.go | UpdateUserPassword | self or system admin | - | - |
| user.go | GetCurrentUserPermissions | RequireAuthenticated | - | - |
| user.go | DeleteUserSysAdmin | RequireSystemAccess | ResourceUser | ActionUpdate |
| user.go | SearchUsers | RequireAuthenticated | - | - |
| usergroup.go | ListUserGroups | RequireSystemAccess | ResourceUserGroup | ActionList |
| usergroup.go | GetUserGroup | RequireSystemAccess | ResourceUserGroup | ActionRead |
| usergroup.go | CreateUserGroup | RequireSystemAccess | ResourceUserGroup | ActionCreate |
| usergroup.go | UpdateUserGroup | RequireSystemAccess | ResourceUserGroup | ActionUpdate |
| usergroup.go | DeleteUserGroup | RequireSystemAccess | ResourceUserGroup | ActionDelete |
| usergroup.go | SearchUserGroups | RequireAuthenticated (ONLY) | - | - |
| webhook.go | ListWebhookPoliciesOfProject | RequireProjectAccess | ResourceNotificationPolicy | ActionList |
| webhook.go | CreateWebhookPolicyOfProject | RequireProjectAccess | ResourceNotificationPolicy | ActionCreate |
| webhook.go | UpdateWebhookPolicyOfProject | RequireProjectAccess | ResourceNotificationPolicy | ActionUpdate |
| webhook.go | DeleteWebhookPolicyOfProject | RequireProjectAccess | ResourceNotificationPolicy | ActionDelete |
| webhook.go | GetWebhookPolicyOfProject | RequireProjectAccess | ResourceNotificationPolicy | ActionRead |
| webhook.go | ListExecutionsOfWebhookPolicy | RequireProjectAccess | ResourceNotificationPolicy | ActionRead |
| webhook.go | ListTasksOfWebhookExecution | RequireProjectAccess | ResourceNotificationPolicy | ActionRead |
| webhook.go | GetLogsOfWebhookTask | RequireProjectAccess | ResourceNotificationPolicy | ActionRead |
| webhook.go | LastTrigger | RequireProjectAccess | ResourceNotificationPolicy | ActionRead |
| webhook.go | GetSupportedEventTypes | RequireProjectAccess | ResourceNotificationPolicy | ActionRead |
| webhook_job.go | ListWebhookJobs | RequireSystemAccess (or per-project?) | ResourceNotificationPolicy | ActionList |

### Auth Gaps Identified

1. **`retention.go:144` — `GetRentenitionMetadata`**: No authentication required at all. Returns static retention policy template metadata. Public exposure of system internals.

2. **`retention.go:136` — `Prepare`**: Only `RequireAuthenticated`, not `RequireProjectAccess`. Actual project auth is deferred to per-method `requireAccess` helper. If any retention method called without requireAccess check, project boundary would be crossed.

3. **`scanexport.go` — `GetScanDataExportExecutionList`**: Only `RequireAuthenticated`. Lists ALL export executions visible to the user filtered by user ID. No project-level access check. Could expose export metadata for projects user no longer has access to (stale data).

4. **`permissions.go` — `GetPermissions`**: No auth check. Returns the full RBAC permissions map. Could assist privilege escalation planning by revealing what permissions each role has.

5. **`sys_cve_allowlist.go` — `GetSystemCVEAllowlist`**: Needs investigation. Returns CVE allowlist. If unauthenticated reads are allowed, attackers learn which CVEs are explicitly ignored.

6. **`usergroup.go` — `SearchUserGroups`**: Only `RequireAuthenticated`, not `RequireSystemAccess`. Any authenticated user can enumerate all user groups. This leaks LDAP group structure to non-admin users.

7. **`search.go` — `Search`**: No auth check. Searches repositories, projects, users. Public access could enumerate private project names if not filtered.

---

## 2. SQL Injection Data Flow

### Path: `q=` parameter → SQL execution

```
HTTP GET ?q=key=value
  → go-swagger binds to *string params.Q
  → handler.BuildQuery(ctx, params.Q, params.Sort, ...)   [base.go:164]
    → q.Build(qs, st, pn, ps)                             [builder.go:36]
      → parseKeywords(q)                                   [builder.go:50]
        → for each "key=value" in q:
          → keyword[key] = parsePattern(value)
          → parsePattern returns: string|*FuzzyMatchValue|*Range|*OrList|*AndList
      → return &Query{Keywords: keywords, Sorts: sorts, ...}
  → handler passes q.Query to service/controller
    → service passes to DAO
      → orm.QuerySetter(ctx, model, query)                 [query.go:75]
        → setFilters(ctx, qs, query, metadata)             [query.go:154]
          → for key, value in query.Keywords:
            → mk, filterable = meta.Filterable(fieldKey)  [metadata.go:46]
            → if mk.FilterFunc != nil:
              → qs = mk.FilterFunc(ctx, qs, key, value)   [query.go:196]
                                                            ^ CUSTOM FUNC — may use fmt.Sprintf
            → else: beego ORM parameterized Filter()      [query.go:200-229]
```

### Critical: securityhub DAO custom filter flow

```
ListVulnerabilities(ctx, registrationUUID, 0, query)    [security.go:311]
  → checkQFilter(query, filterMap)                       [security.go:359]
    → validates key ∈ filterMap AND type matches
    → rejects unknown keys → returns BadRequest
  → applyVulFilter(ctx, sqlStr, query, params)          [security.go:328]
    → for k, m in filterMap:
      → if m.FilterFunc == nil: m.FilterFunc = exactMatchFilter
      → s, p = m.FilterFunc(ctx, k, query)
        → exactMatchFilter:
          → col = key (or filterMap[key].ColumnName if set)
          → sqlStr += fmt.Sprintf(" and %v = ?", col)   [security.go:135]
          → params += val
        → rangeFilter:
          → sqlStr += fmt.Sprintf(" and %v between ? and ?", key) [security.go:148]
  → sqlStr + s appended to vulnerabilitySQL base
  → o.Raw(sqlStr, params).QueryRows(...)                [security.go:324]
```

**Assessment**: `col` in `exactMatchFilter` is ALWAYS derived from the hardcoded `filterMap` key or its `ColumnName`. User-supplied query values go to `?` placeholders. However `fmt.Sprintf(" and %v = ?", col)` format is used even though `col` is trusted — it is fragile by example.

**Critical risk in `rangeFilter`**: `fmt.Sprintf(" and %v between ? and ?", key)` — `key` is the parameter name from `filterMap` iteration (e.g., `"cvss_score_v3"`), which is hardcoded. The actual min/max values go to `?` placeholders. Safe as-is.

**Critical risk in `countExceedLimit`**: `fmt.Sprintf("SELECT EXISTS (%s LIMIT 1 OFFSET 1000)", sqlStr)` — `sqlStr` is the SQL string built from the iterative filter application. If any filter function appends unparameterized user content to `sqlStr`, this would be in an EXISTS subquery. Currently safe because values go to params, but the outer wrapping of the whole SQL is a risk pattern.

### artifactrash DAO — fmt.Sprintf in SQL (direct injection)

```
dao.Filter(ctx, cutOff time.Time)                       [dao.go:82]
  → sql = fmt.Sprintf(`...TO_TIMESTAMP('%f')`, float64(cutOff.UnixNano())/float64(time.Second))
  → ormer.Raw(sql).QueryRows(&deletedAfs)               [dao.go:91]

dao.Flush(ctx, cutOff time.Time)                        [dao.go:100]
  → sql = fmt.Sprintf(`DELETE FROM artifact_trash where creation_time <= TO_TIMESTAMP('%f')`, float64(cutOff.UnixNano())/float64(time.Second))
  → ormer.Raw(sql).Exec()                               [dao.go:107]
```

**Assessment**: `cutOff` is a `time.Time` value. It is produced internally by the GC scheduler (not directly from HTTP parameters). The float64 formatting (`%f`) produces digits-only output (e.g., `1711500000.000000`), so SQL injection is impossible in practice. But this is a dangerous anti-pattern.

### member DAO

```
GetProjectMember(ctx, queryMember, query)               [dao.go:63]
  → sql += " and a.entity_name = ? " if Entityname set
  → sql += " and a.entity_type = ? " if len(EntityType)==1
  → sql += " and a.entity_id = ? " if EntityID > 0
  → PaginationOnRawSQL(query, sql, queryParam)
  → o.Raw(sql, queryParam).QueryRows(...)               [dao.go:109]
```

**Assessment**: All user-supplied values go to `?` placeholders. Pagination is appended as `limit ? offset ?` with integer values. Safe.

```
ListRoles(ctx, user, projectID)                         [dao.go:237]
  → sql uses ParamPlaceholderForIn(len(user.GroupIDs))
  → GroupIDs are integers from session context
```

**Assessment**: `orm.ParamPlaceholderForIn` generates `?,?,?` placeholders. GroupIDs are integers (int64 type). Safe.

### usergroup DAO

```
SearchByName(ctx, name, limitSize)                      [dao.go:168]
  → likePattern = "%" + name + "%"
  → o.Raw(sql, likePattern, limitSize).QueryRows(...)
```

**Assessment**: `likePattern` is passed as a parameterized value to `Raw(sql, likePattern, ...)`. Safe (beego ORM will parameterize it). No LIKE special-char escaping unlike `SearchMemberByName` which uses `orm.Escape`.

**Risk**: `SearchByName` does NOT call `orm.Escape(name)` before building the LIKE pattern. The `%` and `_` wildcards in the user-supplied `name` are not escaped, allowing the user to perform arbitrary LIKE searches (all `%`, or use `_` for single-char matching). This is an information disclosure risk, not SQL injection.

---

## 3. ORM Sort Key Flow

```
setSorts(qs, query, metadata)                           [query.go:234]
  → for sort in query.Sorts:
    → if meta.Sortable(sort.Key):
      → sorting = sort.Key                              ← user-supplied string
      → if sort.DESC: sorting = fmt.Sprintf("-%s", sorting)
    → sortings = append(sortings, sorting)
  → if len(sortings) > 0:
    → qs = qs.OrderBy(sortings...)
```

The sort key is checked against `meta.Sortable()` which only returns true for known model fields. If a key passes this check, it is passed to beego ORM's `OrderBy(sortings...)`. Beego ORM internally handles `ORDER BY` construction; whether it quotes field names depends on the ORM implementation.

**Risk**: If an attacker supplies a key that matches a filterable field name containing SQL-significant characters (e.g., a model that has a field like `"status; DROP"`), the sort key would be passed unquoted to `OrderBy`. In practice, model field names are Go identifiers (no SQL characters), making this safe. But the guarantee relies on the model definition, not the ORM layer.

---

## 4. RBAC Model Analysis

### Role → Resource → Action Coverage

**Developer role has `ResourceTagRetention` CRUD + Operate** — This means a developer-level user can create, update, delete, and trigger retention policies. This is broad for a "developer" role and may exceed intended privilege.

**Resources in handler calls that are NOT in project rolePoliciesMap**:
- `ResourceExportCVE` with `ActionList` — in `NolimitProvider` for project robots, but NOT in `rolePoliciesMap`. Project admin can access via NolimitProvider but standard roles cannot list exports.

**`ResourceConfiguration` with `ActionUpdate`** — only in `projectAdmin` role. Correct scope.

**Missing from guest role that exists in developer/maintainer**:
- `ResourceTagRetention` — guest has NO access to retention policies, while developer has full CRUD. Significant gap if developer accounts are compromised.

**`limitedGuest` role** — Has no access to: tags (create/delete), artifacts (create/delete), members, labels, scans, retention, immutable tags, notification policies. This is intentionally restricted.

### System Role Policies

**`ResourceSecurityHub` (ActionRead, ActionList)** — system admin only. Correctly gated.

**Robot accounts (`NolimitProvider`)** — can access `ResourceRobot` CRUD at both system and project scope. This means a robot account can create other robot accounts — potential privilege escalation if a robot account is compromised.

---

## 5. Key Security-Relevant Code Observations

### Webhook URL Sanitization Gap (webhook.go:405)
```go
target.Address = url.Scheme + "://" + url.Host + url.Path
```
Only schema+host+path are retained. No check for:
- Private IP ranges (10.x, 172.16-31.x, 192.168.x)
- Loopback (127.0.0.1, localhost)
- Link-local (169.254.x.x — cloud metadata endpoint)
- IPv6 equivalents (::1, fc00::/7)

### Retention Prepare Weak Auth (retention.go:136-142)
```go
func (r *retentionAPI) Prepare(ctx context.Context, _ string, _ any) middleware.Responder {
    if err := r.RequireAuthenticated(ctx); err != nil {
        return r.SendError(ctx, err)
    }
    return nil
}
```
If a future method is added to retentionAPI without its own `requireAccess` call, any authenticated user can access it.

### securityhub exactMatchFilter SQL Pattern (security.go:126-139)
```go
func exactMatchFilter(_ context.Context, key string, query *q.Query) (sqlStr string, params []any) {
    col := key
    if len(filterMap[key].ColumnName) > 0 {
        col = filterMap[key].ColumnName
    }
    sqlStr = fmt.Sprintf(" and %v = ?", col)  // col is from trusted map
    params = append(params, val)
    return
}
```
The `col` variable comes from `filterMap`, not user input. But the pattern of using `fmt.Sprintf` to build SQL is a maintenance risk. Any developer who adds a new filter without understanding this could accidentally pass user input as `col`.

### SearchByName LIKE wildcard (usergroup/dao/dao.go:176)
```go
likePattern := "%" + name + "%"
_, err = o.Raw(sql, likePattern, limitSize).QueryRows(&usergroups)
```
`orm.Escape` is NOT called on `name`. User can supply `%` to match all groups or `_` for single-char matching. Not SQL injection, but allows broader-than-intended enumeration.
