Phase: 8
Sequence: 042
Slug: developer-retention-destroy
Verdict: VALID
Rationale: Developer role has destructive artifact deletion capability via TagRetention that exceeds the principle of least privilege, allowing data destruction without project admin approval. While a design choice, the risk to data integrity in multi-tenant environments is significant.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-03/debate.md

## Summary

The Harbor developer project role has full CRUD plus Operate permissions on `ResourceTagRetention`, identical to the projectAdmin and maintainer roles. This allows a developer (or compromised developer account) to create a retention policy with aggressive rules (e.g., "retain most recent 0 artifacts"), trigger its execution, and permanently delete all non-matching artifacts in the project. There is no undo mechanism. The guest role does NOT have these permissions, confirming the developer role is elevated beyond expected privilege.

## Location

- **Developer role policy**: `src/common/rbac/project/rbac_role.go:213-218` -- TagRetention CRUD + Operate
- **ProjectAdmin comparison**: `src/common/rbac/project/rbac_role.go:59-64` -- identical permissions
- **Guest role**: `src/common/rbac/project/rbac_role.go:248+` -- NO TagRetention permissions
- **Retention handler**: `src/server/v2.0/handler/retention.go` -- RBAC enforcement uses these permissions

## Attacker Control

- **Input**: Retention policy rules (number of artifacts to retain, tag patterns, execution trigger)
- **Control level**: Full CRUD + ability to trigger immediate execution
- **Auth requirement**: Developer role in a project

## Trust Boundary Crossed

- **Privilege boundary**: Developer role crosses into administrative data lifecycle management
- **Expected boundary**: Developers should create/push artifacts but not control retention policy that can delete them
- **Actual boundary**: Developer has full artifact destruction capability

## Impact

- Permanent deletion of all artifacts in a project (irreversible)
- Data integrity violation in multi-tenant environments
- Compromised developer account can cause project-wide supply chain disruption
- No approval workflow for destructive retention operations
- Same permissions as project admin for this resource type

## Evidence

```go
// src/common/rbac/project/rbac_role.go:195-218 (developer role)
"developer": {
    // ...
    {Resource: rbac.ResourceTagRetention, Action: rbac.ActionCreate},
    {Resource: rbac.ResourceTagRetention, Action: rbac.ActionRead},
    {Resource: rbac.ResourceTagRetention, Action: rbac.ActionUpdate},
    {Resource: rbac.ResourceTagRetention, Action: rbac.ActionDelete},
    {Resource: rbac.ResourceTagRetention, Action: rbac.ActionList},
    {Resource: rbac.ResourceTagRetention, Action: rbac.ActionOperate},  // trigger execution
    // ...
}
```

## Reproduction Steps

1. Authenticate as a developer-level project member
2. Verify no existing retention policy: `GET /api/v2.0/retentions?scope=project&project_id=<pid>`
3. Create a destructive retention policy:
   ```
   POST /api/v2.0/retentions
   {
     "rules": [{"template": "latestPushedK", "params": {"latestPushedK": 0}, "tag_selectors": [{"kind": "doublestar", "decoration": "matches", "pattern": "**"}]}],
     "scope": {"level": "project", "ref": <project_id>}
   }
   ```
4. Trigger execution: `POST /api/v2.0/retentions/<id>/executions`
5. All artifacts in the project are deleted by the retention execution
