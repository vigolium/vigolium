Phase: 10
Sequence: 080
Slug: searchusers-enum-like
Verdict: VALID
Rationale: SearchUsers API uses RequireAuthenticated only (no RBAC) and the DAO constructs a LIKE pattern with unescaped wildcards, allowing any authenticated user to enumerate all usernames system-wide -- structurally identical to the confirmed p8-040 usergroup enumeration pattern.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-040-usergroup-enum-like.md
Origin-Pattern: AP-040

## Summary

The `SearchUsers` API endpoint (`GET /api/v2.0/users/search`) checks only `RequireAuthenticated` with no RBAC scoping. The DAO's `SearchByName` function at `src/pkg/user/dao/dao.go:136` constructs a LIKE pattern via `"%" + name + "%"` without calling `orm.Escape`, identical to the confirmed usergroup enumeration bug (p8-040). Any authenticated user can enumerate all Harbor usernames, email addresses, and user IDs system-wide by supplying a single `%` character as the `username` query parameter.

## Location

- **Handler**: `src/server/v2.0/handler/user.go:265-288` -- `SearchUsers`, only `RequireAuthenticated` check
- **Manager**: `src/pkg/user/manager.go:250-251` -- delegates to DAO
- **DAO**: `src/pkg/user/dao/dao.go:128-147` -- `SearchByName`, `likePattern := "%" + name + "%"` (no `orm.Escape`)

## Attacker Control

- **Input**: `username` query parameter in `GET /api/v2.0/users/search?username=%`
- **Control level**: Full -- attacker supplies the LIKE pattern character
- **Auth requirement**: Any valid authentication (basic auth, session, token, robot account)

## Trust Boundary Crossed

Any authenticated user (including guests and robot accounts scoped to a single project) gains access to the complete Harbor user directory -- names, emails, and user IDs -- with no project or role scoping. This crosses the project isolation boundary (TB-3).

## Impact

- Full enumeration of all Harbor usernames and email addresses
- Internal user IDs are returned, enabling correlation with member lists and audit logs
- In enterprise deployments, leaks the organizational directory structure
- Facilitates targeted account takeover or social engineering attacks
- Combined with p8-040 (group enumeration): attacker can map users to LDAP/OIDC groups

## Evidence

```go
// src/server/v2.0/handler/user.go:265-288
func (u *usersAPI) SearchUsers(ctx context.Context, params operation.SearchUsersParams) middleware.Responder {
    if err := u.RequireAuthenticated(ctx); err != nil {  // ONLY auth check -- no RBAC
        return u.SendError(ctx, err)
    }
    // ...
    l, err := u.ctl.SearchByName(ctx, params.Username, int(*params.PageSize))
    // ...
}

// src/pkg/user/dao/dao.go:128-147
func (d *dao) SearchByName(ctx context.Context, name string, limitSize int) ([]*commonmodels.User, error) {
    // ...
    sql := "select * from harbor_user where username like ? and deleted = false order by length(username), username asc limit ?"
    likePattern := "%" + name + "%"  // NO orm.Escape -- wildcard injection
    _, err = o.Raw(sql, likePattern, limitSize).QueryRows(&users)
    // ...
}
```

## Reproduction Steps

1. Authenticate as any Harbor user (including a guest or robot with minimal permissions)
2. Send: `GET /api/v2.0/users/search?username=%25&page_size=100`
   - Note: `%25` is URL-encoded `%` which becomes the LIKE wildcard `%`
3. Response returns all non-deleted users system-wide with username, email, and user_id fields
4. Iterate with `page` parameter to enumerate all users if count exceeds page_size
