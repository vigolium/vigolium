Phase: 10
Sequence: 082
Slug: developer-scan-export-nolimit
Verdict: VALID
Rationale: The developer role has ResourceExportCVE ActionCreate with no per-user or per-project limit on concurrent scan export jobs, and the ScanDataExport job has MaxCurrency=1 only at the global type level -- a developer can spam the export API to exhaust the shared job worker pool, structurally identical to the p8-028 webhook queue exhaustion pattern.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-028-webhook-queue-exhaustion.md
Origin-Pattern: AP-028

## Summary

The `developer` project role includes `{Resource: rbac.ResourceExportCVE, Action: rbac.ActionCreate}`. The `ExportScanData` handler at `src/server/v2.0/handler/scanexport.go:65` has no rate limiting or per-user/per-project job count check -- it unconditionally creates a new `ScanDataExport` job on every request. While `ScanDataExport.MaxCurrency()` returns 1 (one active job per Redis instance), this limit applies globally across the entire system, not per user. A developer-role user can submit many export requests for different project/criteria combinations simultaneously. Each consumes a shared job worker slot, starving other critical jobs (replication, GC, scanning). Additionally, `ShouldRetry()` returns `true` with `MaxFails=1`, meaning failed export jobs are retried, compounding queue pressure.

## Location

- **Handler**: `src/server/v2.0/handler/scanexport.go:65-106` -- `ExportScanData`, no job count or rate limit check
- **Role policy**: `src/common/rbac/project/rbac_role.go:243-245` -- developer has `ResourceExportCVE ActionCreate`
- **Job limits**: `src/jobservice/job/impl/scandataexport/scan_data_export.go:51-70` -- `MaxFails=1`, `MaxCurrency=1` (global, not per-user), `ShouldRetry=true`

## Attacker Control

- **Input**: HTTP requests to `POST /api/v2.0/export/cve` with varying criteria (project IDs, CVE IDs, tags, labels)
- **Control level**: Developer can submit unlimited export jobs with distinct criteria combinations
- **Auth requirement**: Developer role in any project

## Trust Boundary Crossed

A developer role in a single project can generate sustained job queue pressure system-wide, affecting replication, GC, and scanning jobs for all projects across all tenants.

## Impact

- Job worker pool pressure: each pending export job occupies a slot
- Cross-tenant starvation: replication, GC, and scan jobs delayed or timed out for all projects
- No per-user rate limit prevents a single compromised developer from submitting hundreds of export jobs
- Recovery requires manual job cancellation or worker restart

## Evidence

```go
// src/server/v2.0/handler/scanexport.go:65-106
func (se *scanDataExportAPI) ExportScanData(ctx context.Context, params operation.ExportScanDataParams) middleware.Responder {
    // ... validates params ...
    for _, pid := range params.Criteria.Projects {
        if err := se.RequireProjectAccess(ctx, pid, rbac.ActionCreate, rbac.ResourceExportCVE); err != nil {
            return se.SendError(ctx, err)
        }
    }
    // NO job count check, NO rate limit
    jobID, err := se.scanDataExportCtl.Start(userContext, ...)
    // ...
}

// src/common/rbac/project/rbac_role.go:243-245 (developer role)
{Resource: rbac.ResourceExportCVE, Action: rbac.ActionCreate},
{Resource: rbac.ResourceExportCVE, Action: rbac.ActionRead},
{Resource: rbac.ResourceExportCVE, Action: rbac.ActionList},

// src/jobservice/job/impl/scandataexport/scan_data_export.go:51-70
func (sde *ScanDataExport) MaxFails() uint  { return 1 }
func (sde *ScanDataExport) MaxCurrency() uint { return 1 }  // global, not per-user
func (sde *ScanDataExport) ShouldRetry() bool { return true }
```

## Reproduction Steps

1. Authenticate as a developer in any project
2. Rapidly submit multiple scan export jobs with distinct criteria:
   ```
   POST /api/v2.0/export/cve
   {"criteria": {"projects": [<pid>], "cveIds": "CVE-2024-XXXX", ...}}
   ```
3. Repeat with different project IDs or CVE filter combinations (each is a distinct job instance)
4. Observe job service queue filling with export jobs
5. Monitor replication and scanning jobs from other projects being delayed
