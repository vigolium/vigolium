# Round 1 Hypotheses: Snapshot Auth Bypass, Avatar Anonymous Bypass, Alerting Secrets

## Focus: K8s snapshot missing org check, REST snapshot unauthenticated GET, avatar anonymous bypass, reqSignedIn misuse patterns

---

### PH-01: K8s Snapshot Delete-by-DeleteKey Cross-Org Deletion
**Hypothesis**: The K8s API endpoint for deleting snapshots via deleteKey (routes.go:257-283) performs RBAC check for `ActionSnapshotsDelete` but does NOT verify that the snapshot belongs to the requesting user's org. The `DeleteWithKey()` function at `service.go:223` fetches by deleteKey without org filter and deletes across orgs.
**Input path**: `DELETE .../snapshots/delete/:deleteKey` -> `routes.go:272` -> `DeleteWithKey()` -> `service.go:223`
**Assumption broken**: Code assumes RBAC is sufficient isolation, but RBAC is org-scoped while deleteKey is global.
**Test**: Trace `DeleteWithKey` to confirm no org filter in SQL query. Compare with REST API `DeleteDashboardSnapshot` at dashboard_snapshot.go:218 which HAS org check.

### PH-02: REST Snapshot GET Has No Auth Middleware
**Hypothesis**: `GET /api/snapshots/:key` at api.go:611 has NO auth middleware whatsoever. The snapshot key is the only authentication. If snapshot keys are enumerable or leaked, any unauthenticated user can access snapshot data.
**Input path**: `GET /api/snapshots/:key` -> `dashboard_snapshot.go:112` -> `GetDashboardSnapshot()`
**Assumption broken**: Security relies entirely on key secrecy (bearer-token pattern) with no additional auth check.
**Test**: Verify api.go:611 -- confirm no middleware before `routing.Wrap(hs.GetDashboardSnapshot)`. Check if keys have sufficient entropy.

### PH-03: Avatar Anonymous Bypass for DoS
**Hypothesis**: The avatar endpoint at api.go:605 uses `reqSignedIn` instead of `reqSignedInNoAnonymous`. When anonymous auth is enabled, unauthenticated users can make requests to `/avatar/:hash` which triggers outbound HTTP requests to Gravatar. With unique hashes, an attacker can exhaust the LRU cache (2000 entries) and goroutines.
**Input path**: `GET /avatar/:hash` -> `avatar.go:104` -> `getAvatarForHashContext()` -> outbound HTTP
**Assumption broken**: Endpoint assumes only authenticated users access it; anonymous auth bypasses this.
**Test**: Confirm reqSignedIn vs reqSignedInNoAnonymous at api.go:605. Verify avatar.go makes outbound HTTP on cache miss.

### PH-04: Other reqSignedIn Routes Vulnerable to Anonymous Bypass
**Hypothesis**: There are ~39 routes using `reqSignedIn` vs ~7 using `reqSignedInNoAnonymous`. Some of these reqSignedIn routes expose sensitive functionality that should not be accessible to anonymous users.
**Input path**: Multiple routes in `pkg/api/api.go`
**Assumption broken**: `reqSignedIn` is assumed to require real authentication but anonymous auth bypasses it.
**Test**: Enumerate all `reqSignedIn` routes and identify those that expose sensitive data or actions (e.g., `/render/*`, `/api/gnet/*`, dashboard routes).

### PH-05: K8s Snapshot Create Leaks DeleteKey in Response
**Hypothesis**: When creating a snapshot via the K8s API (routes.go:224-232), the response includes the `DeleteKey` in plaintext. If this response is logged, cached, or intercepted, the deleteKey can be used for cross-org deletion via PH-01.
**Input path**: `POST .../snapshots/create` -> `routes.go:224-232` -> response body contains `DeleteKey`
**Test**: Verify response structure at routes.go:225-231. Check if deleteKey is also in REST API create response.

### PH-06: SnapshotPublicMode Allows Unauthenticated Deletion
**Hypothesis**: When `SnapshotPublicMode` is enabled, the `SnapshotPublicModeOrDelete` middleware (auth.go:255-268) allows unauthenticated users to call `DeleteDashboardSnapshotByDeleteKey`. Combined with the deleteKey being in the URL path, this enables unauthenticated snapshot deletion.
**Input path**: `GET /api/snapshots-delete/:deleteKey` -> `SnapshotPublicModeOrDelete` -> `DeleteDashboardSnapshotByDeleteKey`
**Assumption broken**: SnapshotPublicMode is intended for read access but also enables delete.
**Test**: Verify SnapshotPublicModeOrDelete at auth.go:255-268 -- confirms unauthenticated access when public mode on.

### PH-07: Alerting Contact Point Secret Leakage via Error Messages
**Hypothesis**: When testing a contact point (test-receiver), error messages from failed webhook/API calls may include secret values (API keys, URLs) in the error response returned to the user.
**Input path**: Contact point test endpoint -> webhook call fails -> error message includes secret
**Test**: Find test-receiver handler and trace error handling path.

### PH-08: Avatar SSRF via Hash-Controlled URL
**Hypothesis**: The avatar handler constructs URLs to Gravatar using the user-supplied hash: `baseUrl + hash + "?"`. While the hash is validated as 32-char hex (avatar.go:107), the constructed URL always goes to Gravatar. However, the hash is attacker-controlled and could be used for cache poisoning attacks or to enumerate valid Gravatar accounts.
**Input path**: `GET /avatar/:hash` -> `avatar.go:74` -> `baseUrl + a.hash + "?"` -> outbound HTTP
**Test**: Verify hash validation is sufficient. Check if baseUrl is hardcoded or configurable.
