Phase: 8
Sequence: 024
Slug: tempuser-sql-no-orgid
Verdict: VALID
Rationale: SQL UPDATE temp_user lacks org_id constraint; handler-level org check is sole barrier; structural fragility matching CVE-2024-10452 pattern; one code change from cross-org exploitation.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-1-ambiguous
Debate: archon/chamber-workspace/chamber-2/debate.md

## Summary

The `UpdateTempUserStatus` SQL query updates temp_user records by invite code without an org_id constraint. The handler-level org check at `org_invite.go:207` is the sole protection against cross-org invite manipulation. This structural pattern matches CVE-2024-10452 (invite IDOR) where a similar single-barrier defense was exploited.

## Location

- **File**: `pkg/services/temp_user/tempuserimpl/store.go`
- **Line**: 30
- **Code**: `UPDATE temp_user SET status=? WHERE code=?` (missing `AND org_id=?`)
- **Handler check**: `pkg/api/org_invite.go:207` -- `canRevoke := c.GetOrgID() == queryResult.OrgID || c.GetIsGrafanaAdmin()`

## Attacker Control

Not currently exploitable -- handler check blocks cross-org access. However, any future code path calling `UpdateTempUserStatus` without the handler-level org validation would enable cross-org invite manipulation.

## Trust Boundary Crossed

Potential cross-org boundary: org A -> org B invite status modification (currently blocked by handler check).

## Impact

- Defense-in-depth gap: SQL provides no safety net if handler check is bypassed
- Historical precedent: CVE-2024-10452 exploited identical structural pattern
- Risk of regression: any new route or internal call that uses `UpdateTempUserStatus` without org validation creates a cross-org IDOR

## Evidence

1. `store.go:30`: `UPDATE temp_user SET status=? WHERE code=?` -- no org_id filter
2. `org_invite.go:207`: Handler check is sole protection
3. CVE-2024-10452: Same structural pattern was exploited (MEDIUM, CVSS 4.3)
4. Deep Probe PH-18 (rbac-orgmgmt) validated

## Reproduction Steps

1. Review `UpdateTempUserStatus` SQL to confirm absence of org_id constraint
2. Verify handler-level check at org_invite.go:207 blocks cross-org access
3. To validate the structural risk: create a test that calls `UpdateTempUserStatus` directly with a code from a different org and verify the status is updated (no SQL-level protection)
4. Recommended fix: add `AND org_id=?` to the SQL WHERE clause and pass org_id through the command struct
