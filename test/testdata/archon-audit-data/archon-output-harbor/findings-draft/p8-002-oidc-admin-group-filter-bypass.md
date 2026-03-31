Phase: 8
Sequence: 002
Slug: oidc-admin-group-filter-bypass
Verdict: VALID
Rationale: The GroupFilter regex is applied to DB group population but NOT to the admin role check, allowing a compromised OIDC provider to inject admin group membership bypassing the configured filter.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-01/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: filterGroup is provably only called in populateGroupsDB (helper.go:455), never before the admin group check at helper.go:396 which operates on raw unfiltered OIDC groups claims.
Severity-Final: MEDIUM
PoC-Status: theoretical

## Summary

Harbor's OIDC integration checks admin group membership against raw, unfiltered groups from the OIDC provider's claims. The `GroupFilter` regex, intended to restrict which groups are recognized, is only applied in `populateGroupsDB` for database group population -- not before the admin group check at `helper.go:396`. A compromised or malicious OIDC provider can grant system admin to any user by including the configured `AdminGroup` value in the groups claim, bypassing any GroupFilter restrictions.

## Location

- `src/pkg/oidc/helper.go:394-399` -- admin group check on unfiltered groups
- `src/pkg/oidc/helper.go:455` -- `filterGroup` only called in `populateGroupsDB`
- `src/pkg/oidc/helper.go:458-467` -- `filterGroup` function definition

## Attacker Control

The attacker controls the OIDC provider's groups claim. This requires either: (a) a compromised OIDC provider that is already configured in Harbor, or (b) a malicious OIDC provider configured by a deceptive admin. The AdminGroup value must be known (it is a Harbor configuration setting).

## Trust Boundary Crossed

OIDC provider -> Harbor admin role assignment. The GroupFilter was designed as a trust boundary control to limit which groups the OIDC provider can influence, but it fails for the most critical check (admin role).

## Impact

- System admin privileges granted to any OIDC-authenticated user
- Admin role refreshed on every OIDC CLI request via `InjectGroupsToUser`
- Affects all users authenticating through the compromised OIDC provider
- GroupFilter provides false sense of security to operators

## Evidence

```go
// src/pkg/oidc/helper.go:394-399
res.Groups, res.hasGroupClaim = groupsFromClaims(c, setting.GroupsClaim)
// ^^^ raw unfiltered groups
if len(setting.AdminGroup) > 0 {
    if slices.Contains(res.Groups, setting.AdminGroup) {
        // ^^^ admin check on UNFILTERED groups
        res.AdminGroupMember = true
    }
}

// src/pkg/oidc/helper.go:454-455 (filterGroup only used here)
func populateGroupsDB(groupNames []string) ([]int, error) {
    // ...
    return usergroup.Mgr.Populate(..., model.UserGroupsFromName(filterGroup(groupNames, cfg.GroupFilter), ...))
}
```

## Reproduction Steps

1. Configure Harbor with OIDC auth mode, set AdminGroup to "harbor-admins", set GroupFilter to "^allowed-.*"
2. At the OIDC provider, add "harbor-admins" to a test user's groups claim
3. Note: "harbor-admins" does not match GroupFilter regex "^allowed-.*"
4. Authenticate as the test user via OIDC CLI
5. Observe that the user is granted system admin despite GroupFilter not matching "harbor-admins"
