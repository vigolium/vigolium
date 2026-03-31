# Variant Analysis for p7-043 (datasource-toctou-readonly-bypass / AP-043)

**Origin finding:** security/findings-draft/p7-043-datasource-toctou-readonly-bypass.md
**Pattern:** AP-043 — TOCTOU Pre-Transaction Check
**Search date:** 2026-03-20
**Variant analyst:** Phase 9 agent

---

## Search Strategy Applied

### 1. Registry-Driven Grep (AP-043 detection signature)
Searched for `ReadOnly` flag checks followed by delete operations across all service objects.

### 2. AST-Level Structural Search
Searched for the flow shape: (fetch object outside transaction) -> (check ReadOnly/isProvisioned flag) -> (delete inside transaction without re-check).

### 3. Service Object Survey
Examined: alert rules (ngalert), dashboards, users, and all three datasource delete handlers (by ID, by UID, by Name).

### 4. Phase 7 Addendum Targets
Chamber 3 addendum notes that `ReadOnly` is checked outside transaction at `datasources.go:260`. The UID path is confirmed in p7-043. Examined sibling handlers.

---

## Candidate Evaluation

### Candidate A: `DeleteDataSourceById` — TOCTOU on ReadOnly (by Integer ID)

**File:** `pkg/api/datasources.go:152-188`
**Pattern:**
```
ds, err := hs.getRawDataSourceById(c.Req.Context(), id, c.GetOrgID())  // line 162 — outside txn
...
if ds.ReadOnly {                                                         // line 170 — check outside txn
    return response.Error(403, ...)
}
cmd := &datasources.DeleteDataSourceCommand{ID: id, ...}
hs.DataSourcesService.DeleteDataSource(c.Req.Context(), cmd)            // line 176 — enters txn
// store.go:190: re-fetches without FOR UPDATE, no ReadOnly re-check
```
**Root cause match:** Identical structural TOCTOU as the UID endpoint. The integer-ID delete handler `DeleteDataSourceById` has the same fetch-check-delete split with no re-entrancy protection inside the transaction. `store.go:190-229` is the same underlying transaction code path and does not re-check `ReadOnly`.
**Attacker control:** Authenticated user with `datasources:delete` permission. Race window between line 162 and the store's DELETE.
**Trust boundary:** TB10 (Database Boundary) — same integrity violation as AP-043.
**Blocking protection:** None beyond the pre-transaction ReadOnly check.
**Severity:** MEDIUM (same as AP-043; integer-ID endpoint is deprecated but still active)
**Verdict:** CONFIRMED — variant p7-078

### Candidate B: `DeleteDataSourceByName` — TOCTOU on ReadOnly (by Name)

**File:** `pkg/api/datasources.go:298-334`
**Pattern:**
```
dataSource, err := hs.DataSourcesService.GetDataSource(c.Req.Context(), getCmd)  // line 306 — outside txn
...
if dataSource.ReadOnly {                                                            // line 314 — check outside txn
    return response.Error(403, ...)
}
cmd := &datasources.DeleteDataSourceCommand{Name: name, ...}
hs.DataSourcesService.DeleteDataSource(c.Req.Context(), cmd)                      // line 319 — enters txn
// same store.go code path, no ReadOnly re-check inside txn
```
**Root cause match:** Structurally identical TOCTOU. The name-based delete endpoint has the same check/transaction split. Note that `GetDataSource` (not `getRawDataSourceByUID`) is used here, but it goes through the same SQL layer and has no transaction context.
**Attacker control:** Same as Candidate A.
**Trust boundary:** TB10.
**Blocking protection:** None.
**Severity:** MEDIUM
**Verdict:** CONFIRMED — variant p7-079

### Candidate C: Dashboard Provisioning Check in `SaveDashboard`

**File:** `pkg/api/dashboard.go:475-493`
**Pattern:** `GetProvisionedDashboardDataByDashboardID` called outside transaction before `SaveDashboard`. However, this is a save/update path, not a delete path, and the provisioning check result is passed as `allowUiUpdate` flag into the service — it is not a delete integrity check.
**Assessment:** Different operation type (save, not delete). The `validateProvisionedDashboard` parameter is passed through to the K8s layer, making this a different architecture. Not structurally equivalent to the TOCTOU delete pattern.
**Verdict:** REJECTED (different operation, different architecture)

### Candidate D: Alert Rule Provisioned Check (`ngalert`)

**File:** `pkg/services/ngalert/api/api_ruler.go:169`
**Pattern:** Comment references provisioned check but not a pre-transaction flag check pattern. No ReadOnly-equivalent flag used before an unprotected transaction delete.
**Assessment:** Alert rule deletion uses a different concurrency model. No direct structural match.
**Verdict:** REJECTED (no structural match)

---

## Confirmed Variants

| ID | File | Line | Description | Severity |
|----|------|------|-------------|----------|
| p7-078 | pkg/api/datasources.go | 152-188 | DeleteDataSourceById TOCTOU on ReadOnly | MEDIUM |
| p7-079 | pkg/api/datasources.go | 298-334 | DeleteDataSourceByName TOCTOU on ReadOnly | MEDIUM |

**Variants found: 2**
