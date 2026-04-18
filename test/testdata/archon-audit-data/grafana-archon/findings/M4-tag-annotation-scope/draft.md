Phase: 8
Sequence: 007
Slug: tag-annotation-scope
Verdict: VALID
Rationale: Org-wide annotation scope exposed to unauthenticated public dashboard viewers. Design assumption violation -- tag annotations were designed for authenticated context but are now accessible without auth.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-1/debate.md

## Summary

Tag-based annotations configured on public dashboards execute with org-wide scope, returning annotation events from ALL dashboards in the organization that use matching tags. When a public dashboard has annotations enabled with `Target.Type == "tags"`, the annotation query sets `DashboardID = 0` and `DashboardUID = ""`, causing the annotation repository to search across all org dashboards. This exposes potentially sensitive operational annotations (incident notes, deployment markers, on-call comments) from private dashboards to unauthenticated public dashboard viewers.

## Location

- **Scope removal**: `pkg/services/publicdashboards/service/query.go:61-65` -- `DashboardID = 0`, `DashboardUID = ""`
- **Annotation query**: `pkg/services/publicdashboards/service/query.go:68` -- `AnnotationsRepo.Find(svcCtx, annoQuery)` with service identity

## Attacker Control

No special attacker input required. The unauthenticated visitor simply accesses the public dashboard annotations endpoint. The tag configuration is controlled by the dashboard editor.

## Trust Boundary Crossed

Unauthenticated internet user -> org-wide annotation data from private dashboards. Annotations may contain text entered by authenticated users across all dashboards in the organization.

## Impact

- **Cross-dashboard data disclosure**: Annotations from ALL org dashboards matching the configured tags are returned, not just from the public dashboard
- **Sensitive data leakage**: Annotation text may contain incident response notes, deployment information, internal communications, or other operational data
- **No scoping control**: Dashboard editors configuring tag annotations on public dashboards cannot restrict the scope to only their dashboard

## Evidence

```go
// pkg/services/publicdashboards/service/query.go:61-65
if anno.Target.Type == "tags" {
    annoQuery.DashboardID = 0   // removes dashboard scope
    annoQuery.DashboardUID = "" // removes dashboard scope
    annoQuery.Tags = anno.Target.Tags
}
// Line 68: queries with service identity (org-level access)
annotationItems, err := pd.AnnotationsRepo.Find(svcCtx, annoQuery)
```

## Reproduction Steps

1. Create multiple dashboards in an org with annotations tagged "production"
2. Add sensitive text to annotations on private dashboards (e.g., "Incident: DB credentials rotated due to leak")
3. Create a public dashboard with annotations enabled and a tag-type annotation filter for "production"
4. As an unauthenticated user, access the public dashboard annotations endpoint
5. Observe annotations from ALL org dashboards with the "production" tag, including private dashboards
