# Review Chamber: chamber-2

Cluster: Authorization Bypass & RBAC
DFD Slices: DFD-1 (SQL Expression Pipeline), DFD-4 (Dashboard/Folder RBAC), DFD-8 (User/Org Management)
NNN Range: p8-020 to p8-039
Started: 2026-04-11T10:00:00Z
Status: CLOSED

## Pre-Seeded Hypotheses from Deep Probe

### H-00a: GracePeriodSeconds=0 Provisioned Dashboard Delete Bypass
- Source: Probe PH-01 (rbac-orgmgmt), SAST F-001 (CRITICAL)
- Target: `pkg/registry/apis/dashboard/register.go:334-337`

### H-00b: Standalone Mode Full Provisioning Bypass
- Source: Probe PH-02 (rbac-orgmgmt)
- Target: `pkg/registry/apis/dashboard/register.go:343-346`

### H-00c: Zanzana Reconciler 1-Hour Default Post-Revocation Window
- Source: Probe PH-04/PH-19 (rbac-orgmgmt)
- Target: `pkg/services/accesscontrol/dualwrite/reconciler.go:150`, `pkg/setting/settings_zanzana.go:418`

### H-00d: Invite Quota Bypass (Duplicate QuotaTargetSrv)
- Source: Probe PH-17 (rbac-orgmgmt)
- Target: `pkg/api/api.go:353`

### H-00e: UpdateTempUserStatus No Org_ID Constraint
- Source: Probe PH-18 (rbac-orgmgmt)
- Target: `pkg/services/temp_user/tempuserimpl/store.go:30`

### H-00f: RevokeInvite Cross-Org via GrafanaAdmin Override
- Source: Probe PH-10 (rbac-orgmgmt)
- Target: `pkg/api/org_invite.go:207`

### H-00g: WITH RECURSIVE Allowlist Gap (DoS)
- Source: Probe PH-11/PH-R3-01 (sql-expression)
- Target: `pkg/expr/sql/parser_allow.go:170`

## Round 1 -- Ideation

### [IDEATOR] Hypotheses -- 2026-04-11T10:05:00Z

**H-01: DeleteCollection Bypasses Provisioned Dashboard Check**
- Source: Probe PH-03
- Target: `pkg/registry/apis/dashboard/register.go:338-341`
- Hypothesis: DELETE to `/apis/dashboard.grafana.app/v1/namespaces/org-<id>/dashboards` (no UID) causes `a.GetName() == ""` -> `return nil`, bypassing provisioning check. Enables bulk deletion including provisioned dashboards.
- Attacker: Admin with collection-delete permission

**H-02: Datasource Query Routes Unscoped EvalPermission**
- Source: SAST F-007
- Target: `pkg/api/api.go:421-438`
- Hypothesis: Proxy/health/resources routes use `EvalPermission(datasources.ActionQuery)` without scope. Any user with query permission on any datasource can access any datasource.

**H-03: Snapshot Delete Route Unscoped EvalPermission**
- Source: SAST F-007
- Target: `pkg/api/api.go:608`
- Hypothesis: `DELETE /api/snapshots/:key` uses unscoped permission. Post-CVE-2024-1313 org check may be incomplete.

**H-04: Alerting SQL Expression Persists After Feature Flag Disable**
- Source: Probe PH-R3-03
- Target: `pkg/services/ngalert/eval/eval.go:80,876`
- Hypothesis: Cached pipeline ignores feature flag changes. Combined with H-00g, creates persistent scheduled DoS.

**H-05: Annotation Mass-Delete Unscoped Permission**
- Source: SAST F-007
- Target: `pkg/api/api.go:525`
- Hypothesis: `POST /api/annotations/mass-delete` uses unscoped permission. Handler may lack dashboard-level auth check.

**H-06: GetDashboardUIDs Info Leak via Unscoped Permission**
- Source: SAST F-007
- Target: `pkg/api/api.go:500`
- Hypothesis: Any user with read on one dashboard can convert arbitrary IDs to UIDs across their org.

**H-07: Org User Search Without Resource Scope**
- Source: SAST F-007
- Target: `pkg/api/api.go:345-346`
- Hypothesis: Unscoped `OrgUsersRead` allows listing all org users regardless of team/group scope.

## Round 2 -- Tracing

### [TRACER] Evidence Summary -- 2026-04-11T10:15:00Z

**H-00a**: REACHABLE. `register.go:335`: unconditional early return when `GracePeriodSeconds==0`. No sanitizer blocks the bypass. Any user with `dashboards:delete` can delete provisioned dashboards via K8s API.

**H-00b**: REACHABLE (conditional). `register.go:344`: `isStandalone` bypasses all validation. Only affects standalone/App Platform deployments. Code comment says "HACK."

**H-00c**: REACHABLE (conditional). `settings_zanzana.go:418`: 1h default reconciler interval. `acimpl/service.go`: 60s cache TTL. Total ~61-minute post-revocation window. Only when Zanzana feature flag enabled.

**H-00d**: REACHABLE. `api.go:353`: `quota(user.QuotaTargetSrv), quota(user.QuotaTargetSrv)` -- duplicate. Compare with correct pattern at line 236: `quota(user.QuotaTargetSrv), quota(org.QuotaTargetSrv)`. Org quota never checked.

**H-00e**: REACHABLE (defense-in-depth). `store.go:30`: `UPDATE temp_user SET status=? WHERE code=?` lacks org_id. Handler at `org_invite.go:207` has org check but SQL has none.

**H-00f**: REACHABLE. `org_invite.go:207`: `c.GetIsGrafanaAdmin()` allows cross-org revocation. By-design for super-admin.

**H-00g**: REACHABLE. `parser_allow.go:170`: `*sqlparser.With` allowed unconditionally. `Recursive` bool is not an AST node type -- invisible to walker. Bounded by 100k output cells + 10s timeout. Requires `FlagSqlExpressions`.

**H-01**: REACHABLE. `register.go:339`: `a.GetName() == ""` for DeleteCollection -> `return nil`. Requires collection-delete K8s permission (admin).

**H-02**: PARTIAL. Route unscoped but handler calls `GetDatasourceByUID(ctx, uid, c.SignedInUser, skipCache)` which enforces org-scope and per-datasource RBAC. Handler-level protection blocks exploitation.

**H-03**: PARTIAL. Route unscoped but handler at `dashboard_snapshot.go:218` checks `queryResult.OrgID != c.OrgID`. Also checks dashboard-level write permission. Snapshot keys are 30-char random strings. CVE-2024-1313 fix present.

**H-04**: REACHABLE. `eval.go:876`: `BuildPipeline()` called once. `eval.go:80`: cached pipeline reused without re-checking feature flag. Combined with H-00g, persistent scheduled DoS until rule deleted or scheduler restarted.

**H-05**: PARTIAL. Route unscoped but handler calls `canMassDeleteAnnotations` which checks dashboard-level `dashboards:write` permission.

**H-06**: PARTIAL. Route unscoped but service layer uses `requester.GetOrgID()` scoping. UIDs visible in URLs, not sensitive.

**H-07**: NOT EXPLOITABLE. By-design: org user listing scoped to caller's org via `c.GetOrgID()`.

## Round 3 -- Challenge

### [ADVOCATE] Defense Briefs -- 2026-04-11T10:25:00Z

**H-00a**: No blocking protection found. The GracePeriodSeconds=0 bypass is unconditional. Editor with delete permission can exploit. K8s API is registered and accessible in standard Grafana.

**H-00b**: Deployment mode limits scope to standalone only. Standard Grafana unaffected. Flag is operator-controlled, not attacker-controlled. MEDIUM scope limitation.

**H-00c**: Feature flag (non-default) + configurable interval limit scope. Legacy RBAC (default) is synchronous. Affects only Zanzana-enabled deployments.

**H-00d**: User quota still applies. Org quota gap enables unlimited temp_user records (DB bloat) but not direct privilege escalation. Resource exhaustion only.

**H-00e**: Handler-level check present and correct. SQL gap is structural fragility, not currently exploitable. Matches CVE-2024-10452 pattern.

**H-00f**: GrafanaAdmin cross-org is by-design for super-admin role. Not a vulnerability.

**H-00g**: Feature flag required (public preview). Output limits (100k cells) + timeout (10s) bound impact. Allowlist bypass is genuine but bounded.

**H-01**: Admin permission required. K8s DeleteCollection is standard API behavior. Protection bypass is real but requires elevated permissions.

**H-02**: Handler-level `GetDatasourceByUID` blocks exploitation. FALSE POSITIVE.

**H-03**: Multiple blocking protections: org check, dashboard permission, key entropy. FALSE POSITIVE.

**H-04**: Feature flag limits initial creation. Output limits bound per-evaluation. No mechanism forces cleanup on flag change.

**H-05**: Handler `canMassDeleteAnnotations` blocks exploitation. FALSE POSITIVE.

**H-06**: Org-scoped in service layer. UIDs not sensitive. LOW severity -> DROP.

**H-07**: By-design behavior. FALSE POSITIVE.

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-00a -- 2026-04-11T10:35:00Z

**Prosecution summary**: `register.go:335` unconditional early return on `GracePeriodSeconds==0` bypasses provisioned dashboard protection. Any user with `dashboards:delete` can craft a DELETE with `gracePeriodSeconds:0`. K8s API accessible in standard Grafana.

**Defense summary**: Requires `dashboards:delete` permission (Editor+). No blocking protection found.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Unconditional bypass of provisioned dashboard deletion protection via attacker-controlled HTTP body field; no blocking protection found; cross-privilege boundary crossing (Editor bypasses admin-controlled provisioning).

**Finding draft written to**: archon/findings-draft/p8-020-graceperiod-provisioning-bypass.md
**Registry updated**: AP-020 GracePeriodSeconds admission bypass

---

### [SYNTHESIZER] Verdict for H-00b -- 2026-04-11T10:35:00Z

**Prosecution summary**: `isStandalone==true` bypasses all provisioned dashboard validation. Code labeled "HACK."

**Defense summary**: Only affects standalone/App Platform deployments. Flag is operator-controlled. Standard Grafana unaffected.

**Pre-FP Gate**: failed on check-1: attacker control not verified (deployment mode is operator-set)

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Complete provisioning bypass in standalone deployments; severity limited by non-default deployment mode; real vulnerability in App Platform where provisioned dashboards should be immutable.

**Finding draft written to**: archon/findings-draft/p8-021-standalone-provisioning-bypass.md
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-00c -- 2026-04-11T10:35:00Z

**Prosecution summary**: 1-hour default reconciler + 60s cache = ~61-minute post-revocation access window in Zanzana-enabled deployments. Emergency revocation is ineffective.

**Defense summary**: Zanzana must be enabled (non-default). Interval configurable. Legacy RBAC (default) is synchronous.

**Pre-FP Gate**: all checks passed (conditional on feature flag)

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: 61-minute post-revocation access window undermines emergency revocation in Zanzana-enabled deployments; limited by non-default feature flag.

**Finding draft written to**: archon/findings-draft/p8-022-zanzana-reconciler-revocation-gap.md
**Registry updated**: AP-022 Async reconciler permission revocation delay

---

### [SYNTHESIZER] Verdict for H-00d -- 2026-04-11T10:35:00Z

**Prosecution summary**: `api.go:353` duplicates `quota(user.QuotaTargetSrv)` where second should be `quota(org.QuotaTargetSrv)`. Org quota never enforced on invite creation.

**Defense summary**: User quota still enforced. Impact is resource exhaustion (unlimited temp_user records), not privilege escalation.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Confirmed bug (duplicate quota check) enables unlimited invite creation bypassing org quota; resource exhaustion impact; matches invite-system vulnerability pattern (CVE-2024-10452).

**Finding draft written to**: archon/findings-draft/p8-023-invite-org-quota-bypass.md
**Registry updated**: AP-023 Duplicate quota check missing org quota

---

### [SYNTHESIZER] Verdict for H-00e -- 2026-04-11T10:35:00Z

**Prosecution summary**: SQL `UPDATE temp_user SET status=? WHERE code=?` lacks `AND org_id=?`. Handler-level org check is sole protection.

**Defense summary**: Handler check present and correct. SQL gap is structural fragility, not currently exploitable.

**Pre-FP Gate**: failed on check-1: attacker control not currently verified (handler blocks)

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Defense-in-depth gap matching CVE-2024-10452 structural pattern; handler protection is sole barrier; SQL omission creates fragility one code change from cross-org exploitation.

**Finding draft written to**: archon/findings-draft/p8-024-tempuser-sql-no-orgid.md
**Registry updated**: AP-024 SQL org_id defense-in-depth gap

---

### [SYNTHESIZER] Verdict for H-00f -- 2026-04-11T10:35:00Z

**Prosecution summary**: GrafanaAdmin can revoke invites from any org.

**Defense summary**: By-design for super-admin role. Not a vulnerability.

**Pre-FP Gate**: failed on check-4: requires admin/root position

**Verdict: FALSE POSITIVE**
**Severity: --**
**Rationale**: GrafanaAdmin cross-org invite revocation is by-design super-admin behavior.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-00g -- 2026-04-11T10:35:00Z

**Prosecution summary**: WITH RECURSIVE passes allowlist because `*sqlparser.With` allowed unconditionally and `Recursive` bool is invisible to AST walker. Enables sourceless DoS bounded by output/timeout limits.

**Defense summary**: Feature flag required. Output cell limit (100k) and timeout (10s) bound impact.

**Pre-FP Gate**: all checks passed (conditional on feature flag)

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Genuine allowlist bypass allowing recursive CTE; bounded by output/timeout limits and requires feature flag.

**Finding draft written to**: archon/findings-draft/p8-025-with-recursive-allowlist-bypass.md
**Registry updated**: AP-025 SQL allowlist node-type-only checking gap

---

### [SYNTHESIZER] Verdict for H-01 -- 2026-04-11T10:35:00Z

**Prosecution summary**: DeleteCollection has empty name -> `a.GetName()==""` -> `return nil` bypassing provisioning check. Bulk deletion of all dashboards including provisioned ones.

**Defense summary**: Requires admin-level collection-delete permission. Standard K8s API behavior.

**Pre-FP Gate**: failed on check-4: requires admin permission

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Provisioning protection bypass via bulk delete; requires admin permission limiting severity; compounds with H-00a as systemic provisioned-dashboard protection failure.

**Finding draft written to**: archon/findings-draft/p8-026-deletecollection-provisioning-bypass.md
**Registry updated**: no new pattern (same root cause as AP-020)

---

### [SYNTHESIZER] Verdict for H-02 -- 2026-04-11T10:35:00Z

**Prosecution summary**: Datasource routes use unscoped EvalPermission.

**Defense summary**: Handler `GetDatasourceByUID` enforces org-scope and per-datasource RBAC. Blocking protection found.

**Pre-FP Gate**: failed on check-2: framework protection found (handler-level authorization)

**Verdict: FALSE POSITIVE**
**Severity: --**
**Rationale**: Handler-level authorization blocks exploitation despite unscoped route-level permission.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-03 -- 2026-04-11T10:35:00Z

**Prosecution summary**: Snapshot delete uses unscoped permission.

**Defense summary**: Multiple blocking protections: org check (line 218), dashboard permission check (229-238), 30-char random key entropy. CVE-2024-1313 fix present.

**Pre-FP Gate**: failed on check-2: framework protection found (multiple layers)

**Verdict: FALSE POSITIVE**
**Severity: --**
**Rationale**: Multiple blocking protections prevent exploitation of unscoped route permission.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-04 -- 2026-04-11T10:35:00Z

**Prosecution summary**: Feature flag not re-checked in cached evaluators. Pipeline built once, reused indefinitely. Combined with H-00g, persistent scheduled DoS.

**Defense summary**: Feature flag limits initial creation. Per-evaluation output/timeout bounds apply.

**Pre-FP Gate**: all checks passed (conditional on feature flag)

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Feature flag disable does not stop existing SQL expression evaluations; persistent scheduled resource consumption bypasses admin control; bounded by per-evaluation limits.

**Finding draft written to**: archon/findings-draft/p8-027-alerting-featureflag-persistence.md
**Registry updated**: AP-027 Feature flag not re-checked in cached evaluators

---

### [SYNTHESIZER] Verdict for H-05 -- 2026-04-11T10:35:00Z

**Defense summary**: Handler `canMassDeleteAnnotations` performs dashboard-level authorization. Blocking protection found.

**Verdict: FALSE POSITIVE**
**Severity: --**
**Rationale**: Handler-level authorization blocks exploitation.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-06 -- 2026-04-11T10:35:00Z

**Verdict: DROP**
**Severity: --**
**Rationale**: Low severity. Org-scoped in service layer; UIDs not sensitive (visible in URLs).

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-07 -- 2026-04-11T10:35:00Z

**Verdict: FALSE POSITIVE**
**Severity: --**
**Rationale**: By-design behavior for org user management.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-00a | VALID | HIGH | p8-020-graceperiod-provisioning-bypass.md |
| H-00b | VALID | MEDIUM | p8-021-standalone-provisioning-bypass.md |
| H-00c | VALID | MEDIUM | p8-022-zanzana-reconciler-revocation-gap.md |
| H-00d | VALID | MEDIUM | p8-023-invite-org-quota-bypass.md |
| H-00e | VALID | MEDIUM | p8-024-tempuser-sql-no-orgid.md |
| H-00f | FALSE POSITIVE | -- | -- |
| H-00g | VALID | MEDIUM | p8-025-with-recursive-allowlist-bypass.md |
| H-01 | VALID | MEDIUM | p8-026-deletecollection-provisioning-bypass.md |
| H-02 | FALSE POSITIVE | -- | -- |
| H-03 | FALSE POSITIVE | -- | -- |
| H-04 | VALID | MEDIUM | p8-027-alerting-featureflag-persistence.md |
| H-05 | FALSE POSITIVE | -- | -- |
| H-06 | DROP | -- | -- |
| H-07 | FALSE POSITIVE | -- | -- |

Findings written: 8
Patterns added to registry: 4
Variant candidates: 0

Chamber closed: 2026-04-11T10:40:00Z
