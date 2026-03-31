# Bypass Analysis: CVE-2024-8118 — Alerting Permission Bypass

**Patch Commit:** `c2799b4901d` (#93940)
**Component:** `pkg/services/ngalert/api/authorization.go`
**Severity:** MEDIUM (CVSS 5.1)
**Cluster ID:** alerting-permission-model

## Patch Summary

The vulnerability was a permission action mismatch on the POST endpoint for external (Lotex) rule groups. The endpoint `POST /api/ruler/{DatasourceUID}/api/v1/rules/{Namespace}` was protected by `ActionAlertingInstancesExternalWrite` (`alert.instances.external:write`) instead of the correct `ActionAlertingRuleExternalWrite` (`alert.rules.external:write`).

**Pre-patch (vulnerable):**
```go
case http.MethodPost + "/api/ruler/{DatasourceUID}/api/v1/rules/{Namespace}":
    eval = ac.EvalPermission(ac.ActionAlertingInstancesExternalWrite, ...)
```

**Post-patch (fixed):**
```go
case http.MethodPost + "/api/ruler/{DatasourceUID}/api/v1/rules/{Namespace}":
    eval = ac.EvalPermission(ac.ActionAlertingRuleExternalWrite, ...)
```

This means a user with only `alert.instances.external:write` permission (the "Silences Writer" role, granted to Editors via `instancesWriterRole`) could create/update alert rule groups on external Alertmanager datasources without having `alert.rules.external:write`. The `instancesWriterRole` is intended only for managing silences, not alert rules.

## Bypass Verdict: **Sound**

The fix correctly addresses the vulnerability. The single-line change ensures the POST endpoint for external rule groups now requires the proper `alert.rules.external:write` permission, which is only included in the `rulesWriterRole` (and its parents `alertingWriterRole`/`alertingAdminRole`).

## Evidence and Analysis

### Hypothesis 1: Other endpoints with similar permission action mismatches

**Result: No additional mismatches found.**

Audited all Lotex (external datasource) ruler endpoints in `authorization.go`:

| Endpoint | Permission Used | Expected | Correct? |
|----------|----------------|----------|----------|
| `DELETE /api/ruler/{DatasourceUID}/.../rules/{Namespace}` | `ActionAlertingRuleExternalWrite` | Rule write | Yes |
| `DELETE /api/ruler/{DatasourceUID}/.../rules/{Namespace}/{Groupname}` | `ActionAlertingRuleExternalWrite` | Rule write | Yes |
| `GET /api/ruler/{DatasourceUID}/.../rules/{Namespace}` | `ActionAlertingRuleExternalRead` | Rule read | Yes |
| `GET /api/ruler/{DatasourceUID}/.../rules/{Namespace}/{Groupname}` | `ActionAlertingRuleExternalRead` | Rule read | Yes |
| `GET /api/ruler/{DatasourceUID}/.../rules` | `ActionAlertingRuleExternalRead` | Rule read | Yes |
| `POST /api/ruler/{DatasourceUID}/.../rules/{Namespace}` | `ActionAlertingRuleExternalWrite` | Rule write | Yes (FIXED) |

All external ruler endpoints now use the correct `RuleExternal*` actions. The external alertmanager instance/silence endpoints correctly use `InstancesExternal*` actions, and external notification endpoints correctly use `NotificationsExternal*` actions.

### Hypothesis 2: ExternalAlertRuleWrite abuse for internal operations

**Result: No cross-domain abuse possible.**

The permission model cleanly separates:
- `alert.rules:*` — Grafana internal alert rules (scoped to folders)
- `alert.rules.external:*` — External ruler rules (scoped to datasource UIDs)
- `alert.instances:*` — Grafana alert instances
- `alert.instances.external:*` — External alertmanager instances (scoped to datasource UIDs)

The Grafana ruler endpoints (lines 24-68) use `ActionAlertingRule{Read,Create,Update,Delete}` with folder scopes. The external ruler endpoints (lines 99-110) use `ActionAlertingRuleExternal{Read,Write}` with datasource scopes. These are distinct action constants and scope types, preventing cross-domain privilege escalation.

### Hypothesis 3: REST vs k8s API consistency

**Result: No k8s API paths exist in this authorization file.**

The `authorization.go` file handles only REST API paths. There is no k8s/apiserver alerting authorization in this file, and the `apps/alerting/` directory does not contain separate authorization logic. The k8s alerting roles are declared in the same `roles.go` file (receivers, templates, time-intervals, routes, inhibition-rules roles) but use Kubernetes RBAC rather than this `authorize()` function.

### Hypothesis 4: OR-chained permissions creating unintended access

**Result: Minor observation, not exploitable for this CVE.**

Several provisioning endpoints use `EvalAny()` with broad legacy permissions like `ActionAlertingProvisioningWrite` alongside newer fine-grained permissions. For example, `POST /api/v1/provisioning/alert-rules` accepts either `ActionAlertingProvisioningWrite` OR (`ActionAlertingRuleCreate` AND `ActionAlertingProvisioningSetStatus`). This is by design -- the legacy provisioning permissions are organization-scoped super-permissions. This does not relate to the CVE-2024-8118 fix.

### Hypothesis 5: Internal vs external Alertmanager differentiation

**Result: Correctly differentiated.**

The permission model has three separate domains for external resources:
- `alert.rules.external:{read,write}` for external ruler rules
- `alert.instances.external:{read,write}` for external alertmanager instances/silences
- `alert.notifications.external:{read,write}` for external alertmanager configuration

Each domain has dedicated read/write actions scoped to datasource UIDs. The role definitions in `roles.go` assign these to separate reader/writer roles:
- `rulesReaderRole`/`rulesWriterRole` handles `RuleExternalRead`/`RuleExternalWrite`
- `instancesReaderRole`/`instancesWriterRole` handles `InstancesExternalRead`/`InstancesExternalWrite`
- `externalNotificationsReaderRole`/`externalNotificationsWriterRole` handles `NotificationsExternalRead`/`NotificationsExternalWrite`

### Hypothesis 6: Recent commit #120552 provisioning API permission gaps

**Result: No new gaps introduced.**

Commit `9a1e887b69f` split previously grouped provisioning GET/write endpoints into individual cases to add resource-specific permissions. The changes are additive -- each endpoint now accepts its existing legacy permissions OR a new fine-grained permission (e.g., `ActionAlertingRoutesRead` for policies export, `ActionAlertingNotificationsTimeIntervalsRead` for mute-timings export). These new permissions are used with `EvalAny()`, meaning they serve as alternative authorization paths. The existing broad permissions (`ActionAlertingProvisioningRead`, `ActionAlertingNotificationsProvisioningRead`) remain as options, maintaining backward compatibility. No permissions were weakened.

## Summary

The fix is **sound**. The single-line change correctly replaces the wrong permission constant (`ActionAlertingInstancesExternalWrite`) with the intended one (`ActionAlertingRuleExternalWrite`) on the POST external ruler rule groups endpoint. No other endpoints in the authorization file exhibit similar mismatches. The permission model correctly separates internal/external and rule/instance/notification domains. No bypass vectors were identified.
