Phase: 10
Sequence: p8-005
Slug: rbac-middleware-variant-search-exhaustive
Verdict: FALSE_POSITIVE
Rationale: Exhaustive search across all ac.Middleware usages, req* middleware functions, pkg/middleware/ files, and pkg/api/api.go route registrations found no additional instances of the AP-042 pattern (RBAC handler constructed but result discarded without calling with (c)); all other usages correctly pass the returned handler as route middleware.
Severity-Original: N/A
PoC-Status: not-applicable
Origin-Finding: security/findings-draft/p8-001-snapshot-rbac-middleware-never-invoked.md
Origin-Pattern: AP-042

## Summary

Variant hunt for AP-042 (Go middleware construction without invocation / dead RBAC check). The root pattern is `ac.Middleware(ac2)(ac.EvalPermission(...))` called as a standalone statement inside a handler closure, where the returned `web.Handler` is never assigned or called with `(c)`. A full-coverage search was conducted using four strategies: registry-driven grep, flow-shape search, Phase 8 Addendum surface review, and chamber workspace review. No new exploitable instances were found.

## Search Strategies Executed

### 1. Registry-Driven Grep (AP-042 detection_signature)

Pattern: `grep -rn 'ac.Middleware.*)(ac.Eval' pkg/middleware/ | grep -v '(c)'`

Results: Only `pkg/middleware/auth.go:249` and `pkg/middleware/auth.go:266` matched. Both are already documented in p8-001.

### 2. Full ac.Middleware Enumeration

All 18 usages of `ac.Middleware(` in non-test Go files:

- `pkg/middleware/auth.go:249` -- BUG (p8-001)
- `pkg/middleware/auth.go:266` -- BUG (p8-001)
- `pkg/infra/usagestats/service/api.go:15` -- correct: assigned to `authorize`, used as route middleware
- `pkg/api/api.go:73` -- correct: assigned to `authorize`, used as route middleware
- `pkg/services/publicdashboards/api/api.go:78` -- correct: assigned to `auth`, used as route middleware
- `pkg/services/anonymous/anonimpl/api/api.go:51` -- correct: assigned to `auth`, used as route middleware
- `pkg/services/ssosettings/api/api.go:64` -- correct: assigned to `auth`, used as route middleware
- `pkg/services/accesscontrol/api/api.go:42` -- correct: assigned to `authorize`, used as route middleware
- `pkg/services/resourcepermissions/api.go:74` -- correct: assigned to `auth`, used as route middleware
- `pkg/services/ldap/api/service.go:63` -- correct: assigned to `authorize`, used as route middleware
- `pkg/services/cloudmigration/api/api.go:49` -- correct: assigned to `authorize`, used as route middleware
- `pkg/services/serviceaccounts/api/api.go:58` -- correct: assigned to `auth`, used as route middleware
- `pkg/services/team/teamapi/api.go:67` -- correct: assigned to `authorize`, used as route middleware
- `pkg/services/libraryelements/api.go:39` -- correct: assigned to `authorize`, used as route middleware
- `pkg/services/supportbundles/supportbundlesimpl/api.go:21` -- correct: assigned to `authorize`, used as route middleware
- `pkg/services/dashboardimport/api/api.go:42` -- correct: assigned to `authorize`, used as route middleware
- `pkg/services/ngalert/api/authorization.go:17` -- correct: assigned to `authorize`, returned as route middleware handler
- `pkg/services/correlations/api.go:18` -- correct: assigned to `authorize`, used as route middleware

### 3. req* Middleware Variable Search

All `req*` variables in `pkg/api/api.go` are plain `web.Handler` values or closures (not curried RBAC factories). Each is passed as a route middleware argument. No inline handler construction or discarding found.

### 4. pkg/middleware/ Full Review

All non-test Go files in `pkg/middleware/` reviewed. No file other than `auth.go` constructs an RBAC closure and discards the result. Other middleware functions (`ProvisioningAuth`, `CanAdminPlugins`, `RoleAppPluginAuth`, `NoAuth`, `Auth`, `RoleAuth`) all directly call their security checks within the handler closure.

### 5. Phase 8 Addendum / KB Review

The KB does not document a Phase 8 Addendum section. Chamber workspace variant-candidate directories were absent. No pre-identified candidates exist for AP-042 beyond the two original instances.

### 6. Flow Shape Search

Searched for `Middleware\([^)]+\)\([^)]+\)\s*$` (handler construction as standalone statement) across all `pkg/` Go files. Only match was `authorize_in_org_test.go:188` (a test fixture assigning to `middleware` variable — not a real vulnerability).

## Location

N/A (no new vulnerable locations found)

## Attacker Control

N/A

## Trust Boundary Crossed

N/A

## Impact

N/A -- search exhausted, no new instances found beyond p8-001 scope

## Evidence

1. `pkg/middleware/auth.go:249,266` -- Only locations with the bug (already in p8-001)
2. All 16 other `ac.Middleware(` usages correctly assign to a variable and pass as route middleware
3. No standalone `ac.Middleware(...)(...)\n` statements exist outside auth.go lines 249/266

## Reproduction Steps

Run: `grep -rn 'ac\.Middleware\|accesscontrol\.Middleware' pkg/ --include="*.go" | grep -v "_test\.go"`

Review each result: all except auth.go:249 and auth.go:266 follow the correct `authorize := ac.Middleware(...); ...route.Get(..., authorize(eval), ...)` pattern.
