Phase: 8
Sequence: 020
Slug: graceperiod-provisioning-bypass
Verdict: VALID
Rationale: Unconditional bypass of provisioned dashboard deletion protection via attacker-controlled GracePeriodSeconds=0 in HTTP body; no blocking protection found; cross-privilege boundary crossing (Editor bypasses admin-controlled provisioning).
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-2/debate.md

## Summary

The `validateDelete` admission webhook in the Grafana Dashboard K8s API unconditionally skips all provisioned-dashboard protection when the `GracePeriodSeconds` field in the delete options is set to 0. This is a standard K8s delete-options field that any authenticated user with `dashboards:delete` permission can control. The bypass allows deletion of provisioned dashboards that are intended to be immutable configuration-as-code artifacts managed by administrators.

## Location

- **File**: `pkg/registry/apis/dashboard/register.go`
- **Lines**: 334-337
- **Function**: `validateDelete`
- **Code**:
```go
if deleteOptions.GracePeriodSeconds != nil && *deleteOptions.GracePeriodSeconds == 0 {
    return nil
}
```

## Attacker Control

The attacker controls the `GracePeriodSeconds` field in the HTTP DELETE request body. This is a standard Kubernetes `metav1.DeleteOptions` field. Setting it to 0 (equivalent to `kubectl delete --grace-period=0 --force`) triggers the unconditional early return.

Example request:
```
DELETE /apis/dashboard.grafana.app/v1/namespaces/org-1/dashboards/<provisioned-uid>
Content-Type: application/json

{"kind":"DeleteOptions","apiVersion":"v1","gracePeriodSeconds":0}
```

## Trust Boundary Crossed

Authenticated user with Editor role (holding `dashboards:delete` permission) -> Admin-controlled provisioning protection. Provisioned dashboards represent infrastructure-as-code artifacts that should only be manageable through the provisioning pipeline, not through user-facing API calls.

## Impact

- Deletion of provisioned dashboards that are expected to be immutable
- Disruption of monitoring infrastructure managed via configuration-as-code
- Re-provisioning gap until the provisioning cycle runs (could be minutes to hours depending on configuration)
- Potential loss of security-critical dashboard content (restricted datasource panels, compliance dashboards)

## Evidence

1. `register.go:335`: Unconditional early return `if deleteOptions.GracePeriodSeconds != nil && *deleteOptions.GracePeriodSeconds == 0 { return nil }`
2. `register.go:370-371`: Provisioned check (`mgr.Kind == utils.ManagerKindClassicFP`) is dead code after early return
3. SAST F-001 confirmed reachability via CodeQL slice `dashboard-provisioning-bypass`
4. Deep Probe PH-01 (rbac-orgmgmt) validated with full code trace
5. No sanitizer or secondary check exists between the GracePeriodSeconds evaluation and the return statement

## Reproduction Steps

1. Deploy Grafana with at least one provisioned dashboard
2. Authenticate as an Editor or Admin user
3. Send DELETE request to `/apis/dashboard.grafana.app/v1/namespaces/org-1/dashboards/<provisioned-dashboard-uid>` with body `{"kind":"DeleteOptions","apiVersion":"v1","gracePeriodSeconds":0}`
4. Verify the provisioned dashboard is deleted
5. Verify that the same request without `gracePeriodSeconds:0` returns an error about provisioned dashboards being protected
