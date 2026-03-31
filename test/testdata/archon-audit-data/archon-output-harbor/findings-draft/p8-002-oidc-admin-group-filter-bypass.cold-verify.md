# Cold Verification: p8-002-oidc-admin-group-filter-bypass

## Verdict

```
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: filterGroup is provably only called in populateGroupsDB (helper.go:455), never before the admin group check at helper.go:396 which operates on raw unfiltered OIDC groups claims.
Severity-Final: MEDIUM
PoC-Status: theoretical
```

## Sub-claim Validation

| Sub-claim | Result | Evidence |
|-----------|--------|----------|
| A: Attacker controls OIDC groups claim | VALID | Requires compromised OIDC provider -- recognized threat model for GroupFilter |
| B: Admin check uses unfiltered groups | VALID | helper.go:394-396 -- groupsFromClaims() output fed directly to slices.Contains() |
| C: filterGroup only in populateGroupsDB | VALID | grep confirms single call site at helper.go:455 |
| D: AdminGroupMember grants sysadmin | VALID | helper.go:496 -> context.go:78 -- AdminRoleInAuth enables IsSysAdmin() |

## Code Path Trace (Independent)

1. `helper.go:394` -- `groupsFromClaims(c, setting.GroupsClaim)` returns raw groups
2. `helper.go:396` -- `slices.Contains(res.Groups, setting.AdminGroup)` on raw groups
3. `helper.go:397` -- `res.AdminGroupMember = true`
4. `helper.go:496` -- `user.AdminRoleInAuth = info.AdminGroupMember`
5. `context.go:78` -- `IsSysAdmin()` returns true via `AdminRoleInAuth`

No validation, sanitization, or filtering exists between steps 1 and 2.

## Protection Search Result

No protection blocks the attack. The `filterGroup` function (helper.go:459-476) is only invoked inside `populateGroupsDB` (helper.go:455) for database group population. It is never applied before the admin check.

## Reproduction

Blocked by infrastructure requirements (needs OIDC provider + Harbor instance). The code analysis is definitive -- the gap is structural and unambiguous.

## Severity Rationale

Downgraded from HIGH to MEDIUM due to:
- Significant precondition: requires compromised OIDC provider
- Requires both AdminGroup and GroupFilter to be configured
- Theoretical only (no live reproduction)

The impact (full sysadmin) is severe, but the precondition prevents escalation beyond MEDIUM.
