Phase: 8
Sequence: 026
Slug: deletecollection-provisioning-bypass
Verdict: VALID
Rationale: K8s DeleteCollection request bypasses provisioned dashboard protection because admission webhook skips validation when resource name is empty; requires admin collection-delete permission.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-2/debate.md

## Summary

The `validateDelete` admission webhook skips all provisioned-dashboard protection for DeleteCollection requests (bulk delete). When a DELETE request targets the collection endpoint without specifying a resource name, `a.GetName()` returns an empty string, triggering an early return that bypasses the provisioning check. This allows bulk deletion of all dashboards in an org, including provisioned ones.

## Location

- **File**: `pkg/registry/apis/dashboard/register.go`
- **Lines**: 338-341
- **Code**:
```go
// Skip validation for DeleteCollection requests (DELETE .../dashboards)
if a.GetName() == "" {
    return nil
}
```

## Attacker Control

The attacker sends a DELETE request to the collection endpoint:
```
DELETE /apis/dashboard.grafana.app/v1/namespaces/org-1/dashboards
```
(no trailing UID -- targets the collection)

## Trust Boundary Crossed

Admin with collection-delete K8s permission -> provisioning protection. The protection exists to prevent deletion of dashboards managed by configuration-as-code.

## Impact

- Bulk deletion of ALL dashboards in an org including provisioned ones
- No individual provisioned-dashboard check occurs
- Compounds with p8-020 and p8-021 as part of systemic provisioned-dashboard protection failure
- Requires elevated (admin-level) K8s collection-delete permission, limiting exploitability

## Evidence

1. `register.go:339`: `if a.GetName() == "" { return nil }` with comment about DeleteCollection
2. Deep Probe PH-03 (rbac-orgmgmt) validated
3. Same function as p8-020 and p8-021 -- three separate bypass paths in one function

## Reproduction Steps

1. Deploy Grafana with provisioned dashboards
2. Authenticate as admin with K8s collection-delete permission
3. Send `DELETE /apis/dashboard.grafana.app/v1/namespaces/org-1/dashboards`
4. Verify all dashboards (including provisioned) are deleted
5. Verify the provisioning check at register.go:370 is never reached
