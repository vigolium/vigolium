Phase: 8
Sequence: 040
Slug: usergroup-enum-like
Verdict: VALID
Rationale: Confirmed missing authorization check allows any authenticated user to enumerate all system group names including LDAP DNs via unescaped LIKE wildcard, crossing the project isolation trust boundary with no blocking protection beyond basic authentication.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-03/debate.md

## Summary

The `SearchUserGroups` API endpoint (`GET /api/v2.0/usergroups/search`) only requires basic authentication (`RequireAuthenticated`) with no RBAC authorization check. Any authenticated user -- regardless of role or project membership -- can enumerate all LDAP, HTTP, and OIDC group names, IDs, types, and LDAP DNs system-wide by supplying a wildcard groupname parameter. The DAO layer's `SearchByName` function constructs a LIKE pattern using string concatenation (`"%" + name + "%"`) without calling `orm.Escape`, allowing the `%` wildcard character to match all groups.

## Location

- **Handler**: `src/server/v2.0/handler/usergroup.go:186-209` -- `SearchUserGroups`
- **DAO**: `src/pkg/usergroup/dao/dao.go:168-182` -- `SearchByName`
- **Missing escape pattern**: Compare with `src/pkg/member/dao/dao.go` which properly uses `orm.Escape`

## Attacker Control

- **Input**: `groupname` query parameter in `GET /api/v2.0/usergroups/search?groupname=%`
- **Control level**: Full -- attacker supplies the LIKE pattern
- **Auth requirement**: Any valid authentication (basic auth, session, token, robot account)

## Trust Boundary Crossed

- **TB-3 boundary**: Authenticated user -> system-wide group data (no project scoping)
- **Expected boundary**: Group enumeration should require system admin or at minimum project-scoped access
- **Actual boundary**: Any authenticated user has unrestricted access

## Impact

- Full enumeration of all LDAP/HTTP/OIDC group names and internal IDs
- In enterprise LDAP deployments: leaks Active Directory group structure, organizational hierarchy, privileged group names
- LDAP DNs are returned, revealing directory tree structure
- Group IDs enable cross-referencing with project member lists
- Enables reconnaissance for LDAP group claim injection attacks (see OIDC admin group injection finding)

## Evidence

```go
// src/server/v2.0/handler/usergroup.go:186-209
func (u *userGroupAPI) SearchUserGroups(ctx context.Context, params operation.SearchUserGroupsParams) middleware.Responder {
    if err := u.RequireAuthenticated(ctx); err != nil {  // ONLY auth check -- no RBAC
        return u.SendError(ctx, err)
    }
    // ... builds query ...
    ug, err := u.ctl.SearchByName(ctx, params.Groupname, int(*params.PageSize))
    // ...
}

// src/pkg/usergroup/dao/dao.go:168-182
func (d *dao) SearchByName(ctx context.Context, name string, limitSize int) ([]*model.UserGroup, error) {
    // ...
    sql := "select id, group_name, group_type, ldap_group_dn, ... where group_name like ? ..."
    likePattern := "%" + name + "%"  // NO orm.Escape -- wildcard injection
    _, err = o.Raw(sql, likePattern, limitSize).QueryRows(&usergroups)
    // ...
}
```

## Reproduction Steps

1. Authenticate as any Harbor user (including low-privilege guest accounts)
2. Send: `GET /api/v2.0/usergroups/search?groupname=%25&page_size=100`
   - Note: `%25` is URL-encoded `%` which becomes the LIKE wildcard `%`
3. Response returns all groups system-wide with names, IDs, types, and LDAP DNs
4. Iterate with `page` parameter to enumerate all groups if count exceeds page_size
