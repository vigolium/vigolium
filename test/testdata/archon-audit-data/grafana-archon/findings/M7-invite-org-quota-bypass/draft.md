Phase: 8
Sequence: 023
Slug: invite-org-quota-bypass
Verdict: VALID
Rationale: Confirmed duplicate quota(user.QuotaTargetSrv) on invite creation route where second should be quota(org.QuotaTargetSrv); org-level quota never checked; enables unlimited invite creation.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-2/debate.md

## Summary

The invite creation route at `POST /api/org/invites` has a duplicate `quota(user.QuotaTargetSrv)` middleware check where the second should be `quota(org.QuotaTargetSrv)`. This means the org-level user quota is never enforced on invite creation, allowing an org admin to create unlimited invitations beyond the configured org user limit.

## Location

- **File**: `pkg/api/api.go`
- **Line**: 353
- **Code**:
```go
orgRoute.Post("/invites", authorize(ac.EvalPermission(ac.ActionOrgUsersAdd)), quota(user.QuotaTargetSrv), quota(user.QuotaTargetSrv), routing.Wrap(hs.AddOrgInvite))
```
- **Correct pattern** (line 236):
```go
quota(user.QuotaTargetSrv), quota(org.QuotaTargetSrv)
```

## Attacker Control

An org admin controls the invite creation payload. They can repeatedly call `POST /api/org/invites` to create unlimited `temp_user` records.

## Trust Boundary Crossed

Org admin -> org-level resource quota enforcement. The quota system is a security control designed to limit resource consumption per organization.

## Impact

- Unlimited `temp_user` database records (resource exhaustion / DB bloat)
- If invite acceptance does not re-validate org quota, the org user count limit is also bypassed
- Database performance degradation from unbounded temp_user table growth
- Potential spam if invites trigger email notifications

## Evidence

1. `api.go:353`: `quota(user.QuotaTargetSrv), quota(user.QuotaTargetSrv)` -- duplicate user quota, missing org quota
2. `api.go:236`: Correct pattern with `quota(user.QuotaTargetSrv), quota(org.QuotaTargetSrv)`
3. `org_invite.go:117`: `CreateTempUser` has no quota validation at store layer
4. Deep Probe PH-17 (rbac-orgmgmt) validated

## Reproduction Steps

1. Configure org-level user quota (e.g., max 10 users per org)
2. Fill the org to its user limit
3. As org admin, call `POST /api/org/invites` repeatedly
4. Verify invites are created without org quota enforcement
5. Compare with user signup route which correctly checks org quota
