# Bypass Analysis: PATCH-T3-04 (CVE-2024-1442) and PATCH-T3-05 (CVE-2024-9476)

## Cluster ID: T3-GROUP-02

---

## PATCH-T3-04: CVE-2024-1442 — Datasource Wildcard UID Privilege Escalation

### Patch Summary

The vulnerability allowed a user with datasource creation privileges to create a datasource with a UID of `*`, which in the Grafana RBAC system matches the wildcard scope `datasources:uid:*`. This effectively grants the creator permissions over ALL datasources. The fix enforces UID validation via `util.ValidateUID()` in the SQL store layer during both `AddDataSource` (create) and `UpdateDataSource` (update) operations.

**Validation mechanism:** `util.ValidateUID()` calls `IsValidShortUID()` which checks against the regex `^[a-zA-Z0-9\-\_]*$`. The `*` character is NOT in this character set, so it is correctly rejected. Empty UIDs and UIDs exceeding `MaxUIDLength` are also rejected.

### Bypass Verdict: **sound**

### Evidence and Analysis

**H1: Does validation reject ALL wildcard-like values or only literal `*`?**

The regex `^[a-zA-Z0-9\-\_]*$` is a strict allowlist. It rejects ANY character not in `[a-zA-Z0-9_-]`. This means:
- Literal `*` -- REJECTED
- URL-encoded `%2A` -- REJECTED (contains `%`)
- Unicode variants -- REJECTED (only ASCII alphanumeric accepted)
- Other glob patterns (`?`, `[`, etc.) -- REJECTED

This is a strong fix because it uses an allowlist rather than a denylist for specific dangerous values. No encoding or normalization bypass is possible against a character-class allowlist.

**H2: Is UID validation applied at both REST API and k8s API datasource endpoints?**

The validation is applied at the SQL store layer (`pkg/services/datasources/service/store.go` lines 296-298 for create, lines 367-369 for update), which is called by the service layer `AddDataSource`/`UpdateDataSource`. Both the legacy REST API and the provisioning system use these service methods:

- REST API -> `Service.AddDataSource()` -> `SqlStore.AddDataSource()` -> `ValidateUID()` (covered)
- Provisioning -> `DatasourceProvisioner.provisionDataSources()` -> `dsService.AddDataSource()` -> same path (covered)
- k8s API path (`pkg/api/datasources_k8s.go`) is currently READ-ONLY (GET only), gated behind `FlagDatasourcesRerouteLegacyCRUDAPIs`. Writes still go through the legacy path. No bypass here.

**H3: Are there other special UID values that could provide elevated access?**

Empty string UIDs are handled: when `cmd.UID == ""` in AddDataSource (store.go line 290), a UID is auto-generated rather than validated. The code path is: `if cmd.UID == "" { generateNewDatasourceUid() } else if ValidateUID() fails { return error }`. This is correct.

For UpdateDataSource (store.go line 366): `if len(cmd.UID) > 0 { ValidateUID() }`. If UID is empty on update, it is skipped -- but the service layer (datasource.go line 595) always sets `cmd.UID = dataSource.UID` from the existing record before reaching the store, so an empty UID on update would use the existing valid UID.

**H4: Does the fix apply to update operations?**

Yes. `UpdateDataSource` in store.go (line 367) validates the UID if it is non-empty. And the service layer always populates it from the existing record. Covered.

**H5: k8s admission layer validation?**

The k8s datasource API is read-only in the current codebase. Write operations are not yet routed through k8s. When/if they are, k8s naming rules (`[a-z0-9]([-a-z0-9]*[a-z0-9])?`) are even more restrictive than the current `ValidateUID` regex, so no bypass would exist in the k8s path.

### Residual Observations

- The `validUIDPattern` allows uppercase characters (`A-Z`), while k8s naming conventions are lowercase-only. This is not a security issue but could cause compatibility problems during migration to k8s-native storage.
- The test at `datasource_test.go:901` shows a datasource with `Name: "*"` (not UID). Datasource NAMES can still contain `*`. The CVE was specifically about UIDs matching RBAC scope wildcards (`datasources:uid:*`), and datasource names are not used directly in scope evaluation (names are resolved to UIDs via `NewNameScopeResolver`). A datasource named `*` gets UID `2` in the test, which is a valid alphanumeric UID.

---

## PATCH-T3-05: CVE-2024-9476 — Cloud Migration Cross-Org Access

### Patch Summary

The vulnerability allowed a user in one organization to access Cloud Migration resources (sessions, snapshots) belonging to another organization. The fix scoped all Cloud Migration API endpoints and store queries to use `c.OrgID` from the authenticated request context, and the store layer enforces `org_id=?` in SQL WHERE clauses.

### Bypass Verdict: **bypassable** (residual gap in `CancelSnapshot`)

### Evidence and Analysis

**H1: Are there residual Cloud Migration API endpoints that still lack org-scoping?**

Reviewing all endpoints in `pkg/services/cloudmigration/api/api.go`:

| Endpoint | Method | OrgID Scoping |
|----------|--------|---------------|
| `GetToken` | GET | No orgID needed (global token) |
| `CreateToken` | POST | No orgID needed (global token) |
| `DeleteToken` | DELETE | No orgID needed (global token) |
| `GetSessionList` | GET | `c.OrgID` passed -- SCOPED |
| `GetSession` | GET | `c.OrgID` passed -- SCOPED |
| `CreateSession` | POST | `c.OrgID` passed -- SCOPED |
| `DeleteSession` | DELETE | `c.OrgID` passed -- SCOPED |
| `CreateSnapshot` | POST | `signedInUser.GetOrgID()` used in service -- SCOPED |
| `GetSnapshot` | GET | `c.OrgID` in query -- SCOPED |
| `GetSnapshotList` | GET | `c.OrgID` in query -- SCOPED |
| `UploadSnapshot` | POST | `c.OrgID` passed -- SCOPED |
| **`CancelSnapshot`** | **POST** | **NO orgID passed -- NOT SCOPED** |
| `GetResourceDependencies` | GET | Static data, no scoping needed |

**FINDING: `CancelSnapshot` does NOT pass `c.OrgID` to the service layer.** The API handler (api.go line 633) calls `cma.cloudMigrationService.CancelSnapshot(ctx, sessUid, snapshotUid)` with only sessionUid and snapshotUid -- no orgID. The service interface definition (cloudmigration.go line 33) confirms the signature: `CancelSnapshot(ctx context.Context, sessionUid string, snapshotUid string) error`.

The `CancelSnapshot` service implementation (cloudmigration.go line 796) directly calls `s.cancelFunc()` and `s.updateSnapshotWithRetries()` without any org-scoped session lookup. The `UpdateSnapshot` store method (xorm_store.go line 228) uses: `UPDATE cloud_migration_snapshot SET status=? WHERE session_uid=? AND uid=?` -- no org_id in the WHERE clause.

This means a user in Org A can cancel an in-progress snapshot belonging to Org B, provided they know the session UID and snapshot UID. The practical impact is limited because:
1. All endpoints require `cloudmigration.MigrationAssistantAccess` RBAC permissions
2. The cancel operation only cancels the currently running goroutine (there is a single `cancelFunc` per service instance)
3. Session/snapshot UIDs are not easily guessable (generated via `util.GenerateShortUID()`)

However, this is still a cross-org authorization bypass in the cancel path.

**H2: Is the fix applied to both export and import phases?**

- Export (CreateSnapshot): Uses `signedInUser.GetOrgID()` for session lookup -- SCOPED
- Upload (UploadSnapshot): Uses `c.OrgID` for session and snapshot lookup -- SCOPED
- Import (GetSnapshot status sync): Uses orgID from query -- SCOPED
- Cancel: NOT SCOPED (see above)

**H3: SSRF chain with presigned URL exfiltration?**

The `UploadSnapshot` path properly scopes the session and snapshot lookup by orgID before requesting presigned URLs from GMS. The presigned URL is generated server-side by GMS, so a cross-org user cannot obtain URLs for another org's snapshots (the session lookup would fail due to org_id mismatch). No viable SSRF chain through this path.

**H4: GMS API calls scoped to user's org?**

GMS calls use the session's auth token, which is encrypted and stored per-session. Since sessions are org-scoped, the GMS calls inherit the correct org context. Properly scoped.

**H5: Snapshot decryption path org check?**

`GetSnapshotByUID` (xorm_store.go line 364) first validates the session exists for the given orgID via `GetMigrationSessionByUID(ctx, orgID, sessionUid)` which uses `WHERE org_id=? AND uid=?`. Then it fetches the snapshot by session_uid. This is properly scoped. The encryption key retrieval uses `secretskv.AllOrganizations` for the namespace, but this is acceptable because the snapshot UID is globally unique and access is gated by the prior session org check.

### Summary of Findings

| ID | Finding | Severity | Vector |
|----|---------|----------|--------|
| T3-04 | Datasource UID wildcard validation | Sound | Allowlist regex blocks all non-alphanumeric characters |
| T3-05-A | Cloud Migration org-scoping (most endpoints) | Sound | OrgID enforced in SQL WHERE clauses |
| T3-05-B | CancelSnapshot missing orgID check | Bypassable (Low) | No org-scoped session lookup; can cancel cross-org snapshot operations |

### Files Examined

- `/Users/tuan.v.tran/AuditSource/grafana/pkg/util/shortid_generator.go` -- ValidateUID, IsValidShortUID, regex pattern
- `/Users/tuan.v.tran/AuditSource/grafana/pkg/services/datasources/service/store.go` -- AddDataSource, UpdateDataSource with ValidateUID calls
- `/Users/tuan.v.tran/AuditSource/grafana/pkg/services/datasources/service/datasource.go` -- Service.AddDataSource, Service.UpdateDataSource
- `/Users/tuan.v.tran/AuditSource/grafana/pkg/services/datasources/accesscontrol.go` -- ScopePrefix, ScopeAll definitions
- `/Users/tuan.v.tran/AuditSource/grafana/pkg/api/datasources_k8s.go` -- k8s datasource handler (read-only)
- `/Users/tuan.v.tran/AuditSource/grafana/pkg/services/cloudmigration/api/api.go` -- All Cloud Migration API endpoints
- `/Users/tuan.v.tran/AuditSource/grafana/pkg/services/cloudmigration/cloudmigration.go` -- Service interface (CancelSnapshot signature lacks orgID)
- `/Users/tuan.v.tran/AuditSource/grafana/pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go` -- Service implementation
- `/Users/tuan.v.tran/AuditSource/grafana/pkg/services/cloudmigration/cloudmigrationimpl/xorm_store.go` -- Store layer with org-scoped queries
- `/Users/tuan.v.tran/AuditSource/grafana/pkg/services/provisioning/datasources/datasources.go` -- Provisioning path (uses same service layer)
