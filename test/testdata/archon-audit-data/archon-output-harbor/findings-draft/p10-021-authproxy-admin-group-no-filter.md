Phase: 10
Sequence: 021
Slug: authproxy-admin-group-no-filter
Verdict: VALID
Rationale: The HTTP AuthProxy path assigns Harbor admin via raw groups from the k8s token review without any group filter, identical in structure to the confirmed OIDC GroupFilter bypass (p8-002) where the filter is applied to DB population but not to the admin role check.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-002-oidc-admin-group-filter-bypass.md
Origin-Pattern: AP-002

## Summary

Harbor's HTTP AuthProxy integration assigns system admin privileges based on raw group membership from the k8s TokenReview response without any group filter. The `UserFromReviewStatus` function at `http.go:122-133` checks if any of the user's raw groups from `status.User.Groups` matches any configured `AdminGroups` value. Unlike the OIDC path which has a `GroupFilter` regex (albeit misapplied per p8-002), the authproxy path has no group filter concept at all. A compromised k8s token review endpoint or a misconfigured cluster can grant any user Harbor system admin by including the `admin_groups` string in the TokenReview groups claim. The authproxy `AdminGroups` and `AdminUsernames` configuration values are stored as plain `StringType` (not filtered or validated), and all groups from the TokenReview are directly populated into the Harbor DB and used for admin role assignment in a single operation.

## Location

- `src/pkg/authproxy/http.go:99-136` -- `UserFromReviewStatus` applies `adminGroups` check against raw `status.User.Groups` with no filter
- `src/pkg/authproxy/http.go:114-116` -- all groups from token review are populated to DB without filtering
- `src/server/middleware/security/auth_proxy.go:84` -- caller passes raw `httpAuthProxyConf.AdminGroups` from config

## Attacker Control

The attacker controls the k8s TokenReview response groups field. This requires either: (a) a compromised k8s API server or token review endpoint, (b) a misconfigured `HTTPAuthProxyTokenReviewEndpoint` pointing at an attacker-controlled server (facilitated by the StringType URL validation gap in p8-027), or (c) a rogue k8s cluster configured as Harbor's auth proxy. The `AdminGroups` value is a Harbor configuration string, discoverable from Harbor configuration API.

## Trust Boundary Crossed

HTTP AuthProxy token review response -> Harbor admin role assignment. The token review endpoint is an external system and its groups claim is trusted without any filter constraint, providing no operator control over which groups can influence the admin role.

## Impact

- System admin privileges granted to any authproxy-authenticated user whose groups claim includes the configured `AdminGroups` value
- Unlike OIDC which has a partial filter (albeit broken for admin), authproxy has zero group filtering
- All groups from the token review are also inserted into Harbor's `user_group` table (line 116), expanding the attack surface to project-level RBAC via group membership
- Admin role is assigned on every authenticated request via `user.AdminRoleInAuth = u2.AdminRoleInAuth` in `auth_proxy.go:90`

## Evidence

```go
// src/pkg/authproxy/http.go:114-133
if len(status.User.Groups) > 0 {
    userGroups := model.UserGroupsFromName(status.User.Groups, common.HTTPGroupType)
    groupIDList, err := usergroup.Mgr.Populate(orm.Context(), userGroups)  // ALL groups inserted, no filter
    // ...
    if len(adminGroups) > 0 && !user.AdminRoleInAuth {
        agm := make(map[string]struct{})
        for _, ag := range adminGroups {
            agm[ag] = struct{}{}
        }
        for _, ug := range status.User.Groups {  // raw groups, no filter
            if _, ok := agm[ug]; ok {
                user.AdminRoleInAuth = true  // admin granted from unfiltered claim
                break
            }
        }
    }
}

// Compare: OIDC path has GroupFilter (misapplied per p8-002), AuthProxy has NO filter at all
```

## Reproduction Steps

1. Configure Harbor with HTTP AuthProxy mode, set `admin_groups` to "harbor-admins"
2. Configure a malicious token review endpoint that returns `status.User.Groups = ["harbor-admins"]`
3. Send a Docker login request to Harbor with a token that the malicious endpoint validates
4. Observe Harbor grants system admin role via `AdminRoleInAuth = true`
5. Verify the user can perform admin operations
6. Recommended fix: Add a `GroupFilter` equivalent to the authproxy configuration and apply it before admin group membership check, analogous to OIDC's `GroupFilter` (and fix its application order per p8-002)
