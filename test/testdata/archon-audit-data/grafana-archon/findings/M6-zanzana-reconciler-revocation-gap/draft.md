Phase: 8
Sequence: 022
Slug: zanzana-reconciler-revocation-gap
Verdict: VALID
Rationale: 61-minute post-revocation access window in Zanzana-enabled deployments due to 1-hour default reconciler interval plus 60-second cache TTL; undermines emergency access revocation.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-2/debate.md

## Summary

When Zanzana (OpenFGA-based authorization) is enabled, the permission reconciler runs on a 1-hour default interval. Combined with a 60-second RBAC cache TTL, revoked permissions remain effective for up to approximately 61 minutes after an administrator revokes access. This makes emergency access revocation ineffective in Zanzana-enabled deployments.

## Location

- **File**: `pkg/setting/settings_zanzana.go`
- **Line**: 418
- **Code**: `zr.Interval = reconcilerSec.Key("interval").MustDuration(1 * time.Hour)`
- **File**: `pkg/services/accesscontrol/dualwrite/reconciler.go`
- **Line**: 150 (ticker with configurable interval)
- **File**: `pkg/services/accesscontrol/acimpl/service.go`
- **Cache TTL**: `cacheTTL = 60 * time.Second`

## Attacker Control

The attacker exploits the temporal gap. After an admin revokes their permissions, the attacker continues making API calls that are authorized by the stale cached permissions and the un-reconciled Zanzana state.

## Trust Boundary Crossed

Revoked user -> continued access to resources. The admin's revocation action is semantically a security boundary change that does not take effect for up to 61 minutes.

## Impact

- Emergency access revocation is not effective for ~61 minutes
- A compromised account continues to have full access during the revocation window
- In incident response scenarios, this delay can allow data exfiltration or further lateral movement
- Configurable: operators who reduce the interval can mitigate, but the default is insecure

## Evidence

1. `settings_zanzana.go:418`: Default 1-hour reconciler interval
2. `reconciler.go:150`: Periodic ticker-based reconciliation
3. `acimpl/service.go`: 60-second cache TTL
4. Deep Probe PH-04/PH-19 (rbac-orgmgmt) validated with full trace

## Reproduction Steps

1. Enable Zanzana feature flag in Grafana configuration
2. Grant a user permission to access a dashboard
3. Verify the user can access the dashboard
4. Revoke the user's permission via the RBAC API
5. Within 61 minutes, verify the user can still access the dashboard
6. After the reconciler runs (up to 1 hour) and cache expires (60s), verify access is denied
