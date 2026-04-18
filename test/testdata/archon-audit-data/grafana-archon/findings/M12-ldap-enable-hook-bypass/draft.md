Phase: 8
Sequence: 042
Slug: ldap-enable-hook-bypass
Verdict: VALID
Rationale: EnableUserHook unconditionally re-enables admin-disabled LDAP users on login attempt with no mechanism to distinguish admin-imposed disable from sync-imposed disable, undermining incident response access revocation.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-3/debate.md

## Summary

The `EnableUserHook` at `pkg/services/authn/authnimpl/sync/user_sync.go:421-441` unconditionally sets `is_disabled=false` for any LDAP-managed user attempting to log in, regardless of whether the account was disabled by a Grafana administrator. The database schema has only a single `is_disabled bool` column with no distinction between admin-imposed and LDAP-sync-imposed disable. The DB write executes at hook priority 20 before other validation hooks, and persists even if the login ultimately fails.

## Location

- `pkg/services/authn/authnimpl/sync/user_sync.go:421-441` — `EnableUserHook()` function
- `pkg/services/authn/authnimpl/registration.go` — hook priority 20 registration

## Attacker Control

Any LDAP-managed user whose Grafana account was disabled by an administrator can trigger the re-enable by attempting an LDAP login. The user only needs valid LDAP directory credentials (which may not have been revoked if the admin only disabled the Grafana account).

## Trust Boundary Crossed

Admin-disabled user state -> enabled user state. The trust boundary is the admin's access control decision (disable user) which is silently overridden by the LDAP sync mechanism.

## Impact

- Undermines admin's ability to immediately revoke access during incident response
- Admin must coordinate with LDAP directory administrators to truly disable access
- Account re-enable persists in the database even if the login attempt fails for other reasons
- Attacker regains full access to dashboards, datasources, and other resources associated with their Grafana account

## Evidence

```go
// pkg/services/authn/authnimpl/sync/user_sync.go:421-441
func (s *UserSync) EnableUserHook(ctx context.Context, id *authn.Identity, _ *authn.Request) error {
    // ...
    if !id.ClientParams.EnableUser {
        return nil
    }
    // No check for admin-imposed disable
    userID, err := id.GetInternalID()
    // ...
    isDisabled := false
    return s.userService.Update(ctx, &user.UpdateUserCommand{UserID: userID, IsDisabled: &isDisabled})
}
```

## Reproduction Steps

1. Configure Grafana with LDAP authentication
2. Create or sync an LDAP user in Grafana
3. As Grafana admin, disable the user account via `PUT /api/admin/users/<id>/disable`
4. As the disabled user, attempt LDAP login
5. Observe: the `is_disabled` flag is set to `false` in the database at hook priority 20
6. Verify: the user account is re-enabled regardless of whether the login attempt succeeds or fails
