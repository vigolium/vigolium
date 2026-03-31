# Attack Surface Map: api-authz

## Entry Points

- `src/server/v2.0/handler/base.go:164` — `BuildQuery` — accepts raw `q` string, `sort` string, `pageNumber`, `pageSize` from any API handler; passed directly to `q.Build`
- `src/lib/q/builder.go:36` — `Build` — parses raw `q=k=v,k=~v,k=[min~max],k={v1 v2 v3}` query string into Keywords map; keys are attacker-controlled strings
- `src/lib/orm/query.go:75` — `QuerySetter` — takes `q.Query.Keywords` (user-controlled keys and values) and applies them as ORM filters or custom `FilterFunc` callbacks
- `src/lib/orm/query.go:234` — `setSorts` — takes `q.Query.Sorts` (user-controlled sort keys) and calls `qs.OrderBy(sortings...)` with those strings if metadata.Sortable returns true
- `src/pkg/securityhub/dao/security.go:311` — `ListVulnerabilities` — accepts `q *q.Query` with attacker-supplied filter keywords; builds raw SQL by concatenation
- `src/pkg/securityhub/dao/security.go:270` — `CountVulnerabilities` — same; passes to `applyVulFilter` which appends SQL fragments
- `src/pkg/securityhub/dao/security.go:126` — `exactMatchFilter` — uses `fmt.Sprintf(" and %v = ?", col)` where `col` is a map key from `filterMap`
- `src/pkg/securityhub/dao/security.go:142` — `rangeFilter` — uses `fmt.Sprintf(" and %v between ? and ?", key)` where `key` is the literal string from filterMap iteration
- `src/pkg/securityhub/dao/security.go:302` — `countExceedLimit` — uses `fmt.Sprintf("SELECT EXISTS (%s LIMIT 1 OFFSET 1000)", sqlStr)` where `sqlStr` is the SQL built from user query
- `src/pkg/artifactrash/dao/dao.go:89` — `Filter` — uses `fmt.Sprintf(...TO_TIMESTAMP('%f')`, float64(cutOff.UnixNano())/...)` inserting float directly into SQL string
- `src/pkg/artifactrash/dao/dao.go:106` — `Flush` — same pattern with DELETE SQL
- `src/pkg/member/dao/dao.go:63` — `GetProjectMember` — uses raw SQL built with conditional appends; `entityName` used with parameterized `?` but `entityType` is a single-char field that's bounds-checked only by `len(queryMember.EntityType) == 1`
- `src/pkg/member/dao/dao.go:237` — `ListRoles` — uses `orm.ParamPlaceholderForIn(len(user.GroupIDs))` to build IN clause; `user.GroupIDs` comes from OIDC/LDAP group claims
- `src/pkg/usergroup/dao/dao.go:168` — `SearchByName` — uses `"%" + name + "%"` as LIKE pattern; `name` is user-provided group name search string (parameterized)
- `src/server/v2.0/handler/webhook.go:103` — `ListWebhookPoliciesOfProject` — project-scoped, requires `RequireProjectAccess`
- `src/server/v2.0/handler/webhook.go:140` — `CreateWebhookPolicyOfProject` — project-scoped, requires `RequireProjectAccess`; target URL validated by `validateTargets` but only scheme+host+path stripped; no private IP or SSRF filter
- `src/server/v2.0/handler/retention.go:136` — `Prepare` — uses `RequireAuthenticated` only (not `RequireProjectAccess`); project-level check delegated to `requireAccess` inside each method
- `src/server/v2.0/handler/retention.go:144` — `GetRentenitionMetadata` — NO auth check at all; returns static metadata
- `src/server/v2.0/handler/security.go:44` — `GetSecuritySummary` — uses `RequireSystemAccess`
- `src/server/v2.0/handler/security.go:102` — `ListVulnerabilities` — uses `RequireSystemAccess`; then calls `s.BuildQuery` passing `params.Q` directly

## Trust Boundary Crossings

- HTTP Client -> `q.Build` (`src/lib/q/builder.go:36`): attacker-controlled `q=` parameter becomes `Keywords` map with user-supplied keys and values. Keys are validated only against model metadata (filterable check), values are parsed but not SQL-escaped at this layer.
- `Keywords` map -> `setFilters` (`src/lib/orm/query.go:154`): if a `FilterFunc` is defined for a key, it is called with the raw value. The `FilterFunc` may build SQL using `fmt.Sprintf`. This is the TB-3 crossing (Core API -> Database).
- `q.Query` -> `applyVulFilter` (`src/pkg/securityhub/dao/security.go:328`): iterates over `filterMap`, calling each filter function that matches a keyword in the query. The resulting SQL fragment is directly concatenated to `vulnerabilitySQL`.
- `cutOff time.Time` -> `fmt.Sprintf` SQL (`src/pkg/artifactrash/dao/dao.go:89,106`): `cutOff` is produced by internal GC scheduler, not directly user-controlled, but the pattern demonstrates raw SQL construction without parameterization.
- `user.GroupIDs []int` -> `orm.ParamPlaceholderForIn` (`src/pkg/member/dao/dao.go:248`): GroupIDs sourced from OIDC/LDAP group claims at login; if group ID injection is possible, this IN clause is affected.
- Webhook target URL -> stored in DB -> Job Service HTTP client: user-controlled URL stored without SSRF validation beyond scheme+host+path normalization.

## Auth / AuthZ Decision Points

- `src/server/v2.0/handler/base.go:108` — `RequireProjectAccess` — checks `secCtx.Can(ctx, action, resource)` scoped to project. MUST be called by every project-scoped handler method.
- `src/server/v2.0/handler/base.go:127` — `RequireSystemAccess` — checks system-level RBAC. Used for admin-only endpoints.
- `src/server/v2.0/handler/base.go:143` — `RequireAuthenticated` — only checks `IsAuthenticated()`, no resource/action check. Weaker than `RequireProjectAccess`.
- `src/server/v2.0/handler/retention.go:136` — `retentionAPI.Prepare` — calls `RequireAuthenticated` ONLY; project access is checked per-method in `requireAccess` (post-load pattern).
- `src/server/v2.0/handler/preheat.go:68` — `preheatAPI.Prepare` — returns nil (NO auth check in Prepare). Each method must call auth explicitly.
- `src/common/rbac/project/rbac_role.go:24` — `rolePoliciesMap` — defines all project-role -> resource+action mappings. `developer` role has `ResourceTagRetention` CRUD + Operate (overly broad: should be read-only for developers in most use cases).
- `src/common/rbac/const.go:163` — `PoliciesMap[ScopeSystem]` — defines system-level resource/action policies for admin robots.
- `src/common/rbac/project/evaluator.go` — RBAC evaluation for project scope.
- `src/common/rbac/system/evaluator.go` — RBAC evaluation for system scope.

## Validation / Sanitization Functions

- `src/lib/q/builder.go:207` — `escapeValue` — strips leading `\` from values. NOT SQL escaping; only for the query parser's escape character.
- `src/lib/orm/query.go:201` — `Escape(f.Value)` — called on fuzzy match values before `Filter(key+"__icontains", ...)`. Uses beego ORM's Escape, which escapes `%` and `_` for LIKE patterns.
- `src/pkg/securityhub/dao/security.go:359` — `checkQFilter` — validates that each keyword in query exists in `filterMap` AND that the type matches (string/range/int). This is the primary guard against unknown filter keys. Rejects unknown keys with 400 error.
- `src/pkg/securityhub/dao/security.go:126` — `exactMatchFilter` — `col` is derived from `filterMap[key].ColumnName` or `key` itself. The keys in `filterMap` are hardcoded strings (`cve_id`, `severity`, `status`, `cvss_score_v3`, `project_id`, `repository_name`, `package`, `tag`, `digest`). The `col` variable in `fmt.Sprintf(" and %v = ?", col)` is therefore from a trusted map, NOT from user input.
- `src/server/v2.0/handler/webhook.go:405` — `validateTargets` — calls `utils.ParseEndpoint(target.Address)` and reconstructs URL as `scheme + "://" + host + path`. Does NOT check for private IP ranges (`192.168.x.x`, `10.x.x.x`, `169.254.169.254`).
- `src/pkg/member/dao/dao.go:228` — `orm.Escape(entityName)` — properly escapes LIKE special chars in `SearchMemberByName`.

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|---|---|---|:---:|---|
| Nginx | Core API | TLS terminated, IP forwarded | YES | Internal services bypass Nginx |
| Security Middleware | Handler | User identity established in `secCtx` | YES (all paths get a secCtx, even anonymous) | None — anonymous ctx is still set |
| Handler `Prepare` | Handler method | Auth checked in Prepare | NO | `preheatAPI.Prepare` returns nil; `retentionAPI.Prepare` only checks authenticated (not authorized) |
| Handler method | `RequireProjectAccess` | Each method calls auth check at entry | NO | `GetRentenitionMetadata` has no auth call; `retention.Prepare` is only `RequireAuthenticated` |
| `q.Build` | `lib/orm.QuerySetter` | `Keywords` keys are safe column names | NO | Custom `FilterFunc` receives the raw user-supplied value; key source depends on `filterMap`/model metadata |
| `orm.QuerySetter` | PostgreSQL (via beego ORM) | ORM parameterizes all values | NO | `FilterFunc` callbacks may use `fmt.Sprintf` to build SQL fragments (securityhub does this) |
| `q.Query` | `applyVulFilter` (securityhub) | Keys are validated by `checkQFilter` | YES for keys | `checkQFilter` validates key existence and type but NOT value content for `stringType`; value flows to `fmt.Sprintf` position `col` which uses the map key (trusted) but `val` goes to `?` placeholder (safe) |
| API Handler | DB (artifact_trash DAO) | cutOff is internal server time | YES (currently) | If cutOff could be influenced by user input, `fmt.Sprintf` in SQL becomes exploitable |
| API Handler | DB (member DAO) | EntityType is 1-char validated | YES | Single-char check passes `'g'` or `'u'`; no further validation but these are valid type values |
| Handler | DB (member ListRoles) | GroupIDs are trusted integers | PARTIAL | GroupIDs derive from OIDC/LDAP group attribute parsing at login; malformed group IDs could be non-integer if type assertion fails silently |
| System admin check | securityhub DAO | Caller is system admin | YES for `ListVulnerabilities` | `q` parameter content still flows through to SQL build after auth passes |

## Trust Chain Gaps

1. **Prepare-layer auth gap (preheat + retention)**: `preheatAPI.Prepare` returns nil (no auth), and `retentionAPI.Prepare` only calls `RequireAuthenticated`. Method-level authorization is the only line of defense. If any method in these APIs lacks its own `RequireProjectAccess` call, the request is processed without proper authorization.

2. **ORM FilterFunc SQL construction**: When `orm.QuerySetter` dispatches to a custom `FilterFunc`, the function receives user-supplied `value any` directly. If the function uses `fmt.Sprintf` to construct SQL with the value (rather than using parameterized `?`), SQL injection is possible. The securityhub DAO's `exactMatchFilter` uses `fmt.Sprintf(" and %v = ?", col)` but `col` is from the trusted map — however the pattern is fragile and easy to replicate incorrectly elsewhere.

3. **Sort key injection**: `setSorts` in `lib/orm/query.go:234` passes sort keys to `qs.OrderBy(sortings...)` after checking `meta.Sortable(sort.Key)`. The `sort.Key` is the user-supplied key string from the `sort` query parameter, passed to beego ORM's `OrderBy`. If beego ORM passes this string directly to SQL ORDER BY without full parameterization, injection may be possible.

4. **securityhub `rangeFilter` fmt.Sprintf with key**: `fmt.Sprintf(" and %v between ? and ?", key)` at line 148 uses `key` which is the key from `filterMap` iteration (trusted hardcoded string `cvss_score_v3`), but the pattern is identical to using user input and could be mistaken for safe by developers adding new filters.

5. **`GetRentenitionMetadata` no auth**: `retentionAPI.GetRentenitionMetadata` (line 144) has no authentication or authorization check; it returns a static payload but the pattern creates a precedent for unauthenticated access.

6. **Webhook SSRF gap**: `validateTargets` reconstructs the URL but does not check for private/loopback/link-local addresses. An authenticated project admin can register a webhook targeting `http://169.254.169.254/` or internal IPs.

7. **Sort parameter flows to `OrderBy` without field quoting**: Sort key is passed as a string to beego's `OrderBy`. If a malicious key like `id; DROP TABLE` passes `meta.Sortable`, it could produce unsafe SQL. The metadata.Sortable check restricts to known fields, but the exact escaping/quoting done by beego ORM on the sort key string deserves verification.
