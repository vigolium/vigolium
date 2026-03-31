Phase: 8
Sequence: 041
Slug: robot-shadow-nolimit
Verdict: VALID
Rationale: Hardcoded NolimitProvider grants robot accounts the ability to create shadow robots that survive credential rotation, undermining the credential lifecycle trust boundary. The explicit TODO comment confirms this was an incomplete implementation.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-03/debate.md

## Summary

The `GetPermissionProvider()` function in `src/common/rbac/const.go:99-101` is hardcoded to return `NolimitProvider` instead of the intended `BaseProvider`. The `NolimitProvider` grants `ResourceRobot:ActionCreate` at project scope, meaning any robot account with project-level permissions can create new peer robot accounts. These shadow robots survive credential rotation of the original robot, creating a persistent backdoor. The `BaseProvider` intentionally omits `ResourceRobot:ActionCreate`, confirming this is an overpermission.

## Location

- **Permission provider**: `src/common/rbac/const.go:99-101` -- `GetPermissionProvider()` returns `&NolimitProvider{}`
- **NolimitProvider permissions**: `src/common/rbac/const.go:144-158` -- includes `ResourceRobot:ActionCreate` at project scope
- **BaseProvider comparison**: `src/common/rbac/const.go:108-111` -- `BaseProvider.GetPermissions` uses `PoliciesMap` which omits robot creation
- **TODO comment**: Line 100: `// TODO will determine by the ui configuration`

## Attacker Control

- **Input**: Leaked robot account credentials (commonly stored in CI/CD pipelines, build systems, automation)
- **Control level**: Full -- attacker can create new robot accounts with equivalent permissions
- **Auth requirement**: Valid robot account credentials for the target project

## Trust Boundary Crossed

- **Credential rotation boundary**: New robot accounts are peers, not children. Rotating the original robot's credentials does not affect shadow robots.
- **Expected boundary**: Credential rotation should revoke all access from a compromised robot
- **Actual boundary**: Shadow robots persist indefinitely after rotation

## Impact

- Persistent access after credential compromise detection and rotation
- No parent-child tracking of robot creation -- no mass revocation by parent
- All project robot accounts are peers with equivalent permissions
- Shadow robots can themselves create more shadow robots (recursive persistence)
- Undermines incident response procedures that rely on credential rotation

## Evidence

```go
// src/common/rbac/const.go:98-101
// GetPermissionProvider gives the robot permission provider
func GetPermissionProvider() RobotPermissionProvider {
    // TODO will determine by the ui configuration
    return &NolimitProvider{}  // SHOULD be BaseProvider
}

// src/common/rbac/const.go:144-158 -- NolimitProvider at project scope
if s == ScopeProject {
    return append(n.BaseProvider.GetPermissions(ScopeProject),
        &types.Policy{Resource: ResourceRobot, Action: ActionCreate},  // overpermission
        &types.Policy{Resource: ResourceRobot, Action: ActionRead},
        &types.Policy{Resource: ResourceRobot, Action: ActionList},
        &types.Policy{Resource: ResourceRobot, Action: ActionDelete},
        // ... also grants Member CRUD ...
    )
}
```

## Reproduction Steps

1. Obtain valid robot account credentials for a project (e.g., from CI/CD configuration)
2. Authenticate as the robot: `curl -u 'robot$name:secret' ...`
3. Create a new robot account:
   ```
   POST /api/v2.0/robots
   {
     "name": "shadow-bot",
     "level": "project",
     "permissions": [{"namespace": "project-name", "access": [...]}]
   }
   ```
4. Rotate the original robot's credentials
5. Verify the shadow robot still has access: `curl -u 'robot$shadow-bot:new-secret' ...`
