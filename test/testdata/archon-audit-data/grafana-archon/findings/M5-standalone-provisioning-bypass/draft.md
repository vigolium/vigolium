Phase: 8
Sequence: 021
Slug: standalone-provisioning-bypass
Verdict: VALID
Rationale: Complete provisioning protection bypass in standalone/App Platform deployments via isStandalone flag; code explicitly labeled "HACK"; real vulnerability where provisioned dashboards should be immutable.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-1-ambiguous
Debate: archon/chamber-workspace/chamber-2/debate.md

## Summary

In standalone/App Platform deployment mode, the `validateDelete` admission webhook unconditionally skips all provisioned-dashboard protection. The code comment explicitly labels this as a "HACK." Any user with `dashboards:delete` permission in a standalone deployment can delete provisioned dashboards.

## Location

- **File**: `pkg/registry/apis/dashboard/register.go`
- **Lines**: 343-346
- **Function**: `validateDelete`
- **Code**:
```go
// HACK: deletion validation currently doesn't work for the standalone case. So we currently skip it.
if b.isStandalone {
    return nil
}
```

## Attacker Control

The attacker does not control the `isStandalone` flag (operator-set at deployment). However, in standalone deployments, any user with delete permission automatically bypasses provisioning protection without any special request crafting.

## Trust Boundary Crossed

Authenticated user with Editor role -> Admin-controlled provisioning protection, but only in standalone/App Platform deployments.

## Impact

- Complete absence of provisioned dashboard protection in standalone deployments
- All impacts from p8-020 apply, but without requiring any special request crafting
- Affects App Platform deployments where Grafana runs as a standalone service

## Evidence

1. `register.go:344`: `if b.isStandalone { return nil }` with "HACK" comment
2. `register.go:234`: `RegisterStandaloneAPIService()` sets `isStandalone: true`
3. Deep Probe PH-02 (rbac-orgmgmt) validated

## Reproduction Steps

1. Deploy Grafana in standalone/App Platform mode
2. Provision dashboards via configuration-as-code
3. Authenticate as an Editor with delete permission
4. Send standard DELETE request to the provisioned dashboard
5. Verify dashboard is deleted without the provisioning protection error
