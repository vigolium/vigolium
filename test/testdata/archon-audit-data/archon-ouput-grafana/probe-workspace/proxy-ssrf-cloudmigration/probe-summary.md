# Deep Probe Summary: Datasource Proxy, Cloud Migration, and SSRF

**Status**: complete
**Rounds**: 2
**Total hypotheses generated**: 17
**Validated**: 13
**NEEDS-DEEPER**: 2
**Invalidated**: 2
**Stop reason**: High-yield findings across both major attack surfaces (cloud migration and datasource proxy). Key vulnerability classes thoroughly covered. Diminishing returns expected from additional rounds.

## Attack Surface Map Reference
`security/probe-workspace/proxy-ssrf-cloudmigration/attack-surface-map.md`

---

## Validated Hypotheses

### PH-01: CancelSnapshot cross-org state corruption via unscoped SQL UPDATE
- **Input path**: `pkg/services/cloudmigration/api/api.go:633` -- `CancelSnapshot(ctx, sessUid, snapshotUid)` -- no orgID passed
- **Assumption broken**: Code assumes `(session_uid, snapshot_uid)` pair uniquely scopes to the requesting org. No org_id in SQL WHERE clause.
- **Attack input**: Admin in Org B POSTs to `/api/cloudmigration/migration/{sessUid}/snapshot/{snapshotUid}/cancel` using UIDs belonging to Org A
- **Code path**: `api.go:633` -> `cloudmigration.go:819 updateSnapshotWithRetries` -> `xorm_store.go:228 UPDATE cloud_migration_snapshot SET status=? WHERE session_uid=? AND uid=?` (no org_id)
- **Sanitizers on path**: `util.ValidateUID` (format only); RBAC `MigrationAssistantAccess` (default: GrafanaAdmin only)
- **Security consequence**: Cross-org snapshot status corruption. Migration disruption for any org on a shared instance.
- **Severity estimate**: MEDIUM (default access restricted to GrafanaAdmin; HIGH on instances with delegated migration permissions)
- **Evidence file**: `round-1-evidence.md`

### PH-02: CancelSnapshot cancels the GLOBAL cancelFunc -- cross-org goroutine termination
- **Input path**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:812` -- `s.cancelFunc()` -- global service-level pointer
- **Assumption broken**: Code assumes cancel only affects the targeted snapshot. In reality, `s.cancelFunc` is a single pointer shared across all orgs and concurrent operations.
- **Attack input**: Any call to CancelSnapshot endpoint (even with arbitrary valid UIDs) cancels whatever async operation (CreateSnapshot, UploadSnapshot, or GMS status polling) is currently running for ANY org.
- **Code path**: `api.go:633` -> `cloudmigration.go:812 s.cancelFunc()` (called WITHOUT lock) -> cancels context of whoever set `s.cancelFunc` last (any org)
- **Sanitizers on path**: `recover()` for nil panic; RBAC MigrationAssistantAccess
- **Security consequence**: Instance-wide DoS against cloud migration operations. No UID guessing needed -- any CancelSnapshot call aborts the currently running operation.
- **Severity estimate**: MEDIUM (default GrafanaAdmin access; HIGH with delegated permissions)
- **Evidence file**: `round-1-evidence.md`

### PH-04: CreateToken leaks secret and can invalidate existing migration sessions
- **Input path**: `pkg/services/cloudmigration/api/api.go:128` -- `CreateToken` -- no orgID; returns raw secret token
- **Assumption broken**: Token operations are instance-scoped. Any authorized user can create a new token, which deletes the existing access policy and revokes all active migration sessions.
- **Attack input**: Admin in Org B calls `POST /api/cloudmigration/token` -- existing token is destroyed, new secret returned to attacker
- **Code path**: `api.go:128` -> `cloudmigration.go:266-277 DeleteAccessPolicy` -> `cloudmigration.go:319-333 CreateToken` -> base64-encoded secret returned in response
- **Sanitizers on path**: RBAC MigrationAssistantAccess (default GrafanaAdmin)
- **Security consequence**: Token rotation DoS + secret exposure on multi-org instances with shared migration infrastructure
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-1-evidence.md`

### PH-05: SSRF via unvalidated presigned URL from GMS response
- **Input path**: `pkg/services/cloudmigration/gmsclient/gms_client.go:228-234` -- `CreatePresignedUploadUrl` returns unvalidated URL from GMS
- **Assumption broken**: Code trusts GMS-returned presigned URL without scheme, host, or IP validation
- **Attack input**: Compromised or MITM'd GMS returns `http://169.254.169.254/latest/meta-data/` as presigned URL
- **Code path**: `gms_client.go:234 result.UploadUrl` -> `cloudmigration.go:739` -> `snapshot_mgmt.go:756 PresignedURLUpload` -> `s3.go:32 url.Parse (no validation)` -> `s3.go:82-88 http.NewRequestWithContext + httpClient.Do` -> HTTP POST to attacker-controlled endpoint
- **Sanitizers on path**: None. `url.Parse` is syntactic only. Go net/http blocks `file://` but allows any HTTP/HTTPS target including internal IPs.
- **Security consequence**: Server-Side Request Forgery. Grafana makes multipart POST to arbitrary internal/external HTTP targets.
- **Severity estimate**: HIGH (requires GMS compromise or MITM; see PH-07 for HTTP mode lowering the bar)
- **Evidence file**: `round-1-evidence.md`

### PH-06: SSRF + credential exfiltration -- all datasource credentials in snapshot payload
- **Input path**: `pkg/services/cloudmigration/cloudmigrationimpl/snapshot_mgmt.go:305` -- `DecryptJsonData` decrypts ALL datasource SecureJsonData
- **Assumption broken**: Code decrypts all credentials (passwords, API keys, OAuth secrets) and embeds them in snapshot payloads, trusting that the upload destination is always GMS-controlled S3.
- **Attack input**: Compromised GMS supplies attacker public key (PH-07) + attacker upload URL (PH-05)
- **Code path**: `snapshot_mgmt.go:305 DecryptJsonData` -> plaintext credentials in `AddDataSourceCommand.SecureJsonData` -> encrypted with GMSPublicKey (attacker-controlled if GMS compromised) -> `s3.go:88 httpClient.Do` to attacker URL
- **Sanitizers on path**: Encryption with GMSPublicKey (but key is attacker-supplied in compromise scenario)
- **Security consequence**: Complete exfiltration of all datasource credentials (database passwords, API keys, OAuth secrets) for the entire org. Equivalent to full secrets store dump.
- **Severity estimate**: HIGH (conditional on GMS compromise; CRITICAL if combined with HTTP-mode GMS communication)
- **Evidence file**: `round-1-evidence.md`

### PH-08: Data race on cancelFunc -- read/write without proper synchronization
- **Input path**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:812` -- `s.cancelFunc()` without lock
- **Assumption broken**: `s.cancelFunc` is read and invoked at line 812 without holding `cancelMutex`, while goroutines write it under the lock. This is a Go memory model violation detectable by `-race`.
- **Attack input**: Concurrent CancelSnapshot calls or CancelSnapshot during goroutine startup/teardown
- **Code path**: `cloudmigration.go:812 s.cancelFunc()` (no lock, read) concurrent with `cloudmigration.go:529 s.cancelFunc = nil` (under lock, write)
- **Sanitizers on path**: `recover()` catches nil panics but does not prevent the data race itself
- **Security consequence**: Non-deterministic behavior; snapshot may become stuck in non-cancelable state. Data race can cause undefined behavior on some architectures.
- **Severity estimate**: LOW (primarily availability impact)
- **Evidence file**: `round-1-evidence.md`

### PH-09: cancelFunc not bound to snapshot UID -- cross-operation state corruption
- **Input path**: `pkg/services/cloudmigration/cloudmigrationimpl/cloudmigration.go:539,768,668` -- three different operations all write to same `s.cancelFunc`
- **Assumption broken**: `s.cancelFunc` is a bare function pointer with no association to a specific snapshot UID. CancelSnapshot cancels whatever operation last set `s.cancelFunc`, but updates the DB status of the snapshot from the HTTP request params.
- **Attack input**: User triggers CreateSnapshot (goroutine A sets cancelFunc), then UploadSnapshot (goroutine B overwrites cancelFunc). CancelSnapshot for snapshot-A calls cancelFunc-B. Snapshot-A marked canceled in DB but goroutine-A still running. Goroutine-B context canceled but snapshot-B status unchanged.
- **Code path**: `cloudmigration.go:539` (set) -> `cloudmigration.go:768` (overwrite) -> `cloudmigration.go:812` (call wrong one) -> `cloudmigration.go:819-824` (update wrong snapshot status)
- **Sanitizers on path**: `buildSnapshotMutex` prevents concurrent uploads; atomic flag prevents concurrent GMS polling. These reduce but do not eliminate the race window.
- **Security consequence**: Inconsistency between DB state and actual goroutine state. A snapshot appears "canceled" while still running, or a running operation's context is silently killed.
- **Severity estimate**: LOW (availability/data integrity)
- **Evidence file**: `round-1-evidence.md`

### PH-10: UpdateSnapshot SQL has no org_id -- systemic missing-org pattern
- **Input path**: `pkg/services/cloudmigration/cloudmigrationimpl/xorm_store.go:228-229,238-241` -- two UPDATE statements with no org_id
- **Assumption broken**: SQL UPDATE uses only `(session_uid, uid)` as key. Both status and public_key updates lack org scoping.
- **Attack input**: Same as PH-01 but extends to public_key corruption (line 238-241)
- **Code path**: All callers of `updateSnapshotWithRetries` (lines 517, 552, 631, 716, 747, 780, 819) pass only UID and SessionID -- never orgID
- **Sanitizers on path**: UID randomness; RBAC access control
- **Security consequence**: Root cause of PH-01. Any snapshot status or public key can be corrupted cross-org. Public key substitution could theoretically enable re-encryption with attacker key.
- **Severity estimate**: MEDIUM
- **Evidence file**: `round-1-evidence.md`

### PH-11: Path differential between CleanRelativePath and PathUnescape in datasource proxy
- **Input path**: `pkg/services/datasourceproxy/datasourceproxy.go:146` -- `extractProxyPath(c.Req.URL.EscapedPath())`
- **Assumption broken**: Route ACL matching (via `CleanRelativePath` on percent-encoded path) and forwarding (via `PathUnescape`) operate on different path representations. `CleanRelativePath` treats `%2F` as literal characters; `PathUnescape` decodes them to `/`.
- **Attack input**: `GET /api/datasources/proxy/uid/myds/api%2f..%2fadmin/dangerous-endpoint`
- **Code path**: `datasourceproxy.go:146 EscapedPath()` -> `ds_proxy.go:305 CleanRelativePath("api%2f..%2fadmin/dangerous-endpoint")` = `"api%2f..%2fadmin/dangerous-endpoint"` -> `ds_proxy.go:322 HasPrefix("api%2f..%2fadmin/dangerous-endpoint", "api")` = true (route matches) -> `ds_proxy.go:209 JoinURLFragments` -> `ds_proxy.go:212 PathUnescape` -> `api/../admin/dangerous-endpoint` -> forwarded as `/admin/dangerous-endpoint`
- **Sanitizers on path**: Router-level path normalization may reject `%2F` before reaching handler (needs empirical verification)
- **Security consequence**: Route ACL bypass -- attacker can access restricted datasource backend endpoints by encoding path traversal sequences
- **Severity estimate**: MEDIUM (conditional on router behavior with %2F)
- **Evidence file**: `round-2-evidence.md`

### PH-12: OSS DataSourceRequestValidator is a complete no-op
- **Input path**: `pkg/services/validations/oss.go:11` -- `Validate() error { return nil }`
- **Assumption broken**: The request validator in OSS builds performs zero validation. Enterprise has real validation, but OSS users get none.
- **Attack input**: Any datasource proxy request -- all pass validation unconditionally
- **Code path**: `datasourceproxy.go:111 p.DataSourceRequestValidator.Validate(ds.URL, ds.JsonData, c.Req)` -> `oss.go:11 return nil`
- **Sanitizers on path**: None in OSS
- **Security consequence**: Zero request-level validation on datasource proxy in OSS. Combined with PH-16 (empty whitelist), there is no SSRF protection at the application layer.
- **Severity estimate**: MEDIUM (systemic gap enabling SSRF via admin-created datasources)
- **Evidence file**: `round-2-evidence.md`

### PH-13: X-DS-Authorization header credential override
- **Input path**: `pkg/api/pluginproxy/ds_proxy.go:230-234` -- reads X-DS-Authorization from incoming request
- **Assumption broken**: Any authenticated user can replace the outbound Authorization header on a datasource proxy request by supplying `X-DS-Authorization` in the inbound request. This overwrites stored BasicAuth credentials.
- **Attack input**: `GET /api/datasources/proxy/uid/myds/api/v1/query` with header `X-DS-Authorization: Bearer attacker-token`
- **Code path**: `ds_proxy.go:220-228 BasicAuth set` -> `ds_proxy.go:230 dsAuth = req.Header.Get("X-DS-Authorization")` -> `ds_proxy.go:233 req.Header.Set("Authorization", dsAuth)` -- overwrites BasicAuth
- **Sanitizers on path**: OAuth passthrough (if enabled) overwrites again, reducing impact in that config
- **Security consequence**: Credential oracle against datasource backends. Attacker can test whether a specific credential authenticates to a backend by observing response differences. Can also inject arbitrary auth for datasources with multi-tenant backends.
- **Severity estimate**: LOW-MEDIUM (by-design feature with security implications)
- **Evidence file**: `round-2-evidence.md`

### PH-14: Datasource URL auto-prepend of http:// enables scheme-less SSRF
- **Input path**: `pkg/api/datasource/validation.go:78-83` -- auto-prepends `http://` to scheme-less URLs
- **Assumption broken**: URL validation auto-normalizes scheme-less inputs to `http://`. No IP/hostname blocklist applied.
- **Attack input**: Admin creates datasource with URL=`169.254.169.254` (no scheme)
- **Code path**: `validation.go:78 !reURL.MatchString("169.254.169.254")` = true -> `validation.go:82 "http://169.254.169.254"` -> `url.Parse` succeeds -> returned as valid target URL
- **Sanitizers on path**: None. No IP validation in the chain.
- **Security consequence**: Facilitates SSRF by silently normalizing internal IP addresses to valid HTTP URLs
- **Severity estimate**: LOW (admin-level action required; no IP blocklist is the root cause from PH-12/PH-16)
- **Evidence file**: `round-2-evidence.md`

### PH-16: DataProxyWhiteList defaults to empty -- zero SSRF protection
- **Input path**: `pkg/api/pluginproxy/ds_proxy.go:402-411` -- `checkWhiteList` skips check when whitelist is empty
- **Assumption broken**: Default Grafana OSS installations have an empty `data_source_proxy_whitelist` (`conf/defaults.ini:399`). The whitelist check is completely bypassed.
- **Attack input**: Any datasource proxy request to any target URL
- **Code path**: `ds_proxy.go:403 len(proxy.cfg.DataProxyWhiteList) > 0` = false -> returns true -> no SSRF check
- **Sanitizers on path**: None at application layer. Network-level controls (firewall, IMDSv2) are external to Grafana.
- **Security consequence**: Default OSS installations have zero application-layer SSRF protection. Any admin-created datasource pointing to internal IPs is accessible by all datasource users (Viewer+).
- **Severity estimate**: MEDIUM (systemic default insecure configuration)
- **Evidence file**: `round-2-evidence.md`

---

## NEEDS-DEEPER (unresolved, for Phase 8 chambers)

### PH-03: DeleteToken deletes tokens without org scoping
- **Why unresolved**: The token deletion hits an external GCOM API (`authapi.DeleteToken`). Whether GCOM enforces that the caller's credentials can only delete tokens belonging to their stack requires reading the external GCOM API implementation (not available in this codebase).
- **Suggested follow-up**: Verify GCOM API authorization model. Test whether a Grafana instance can delete tokens belonging to a different stack.

### PH-07: Attacker-supplied GMSPublicKey enables credential decryption
- **Why unresolved**: Need to verify (1) that the `grafana-cloud-migration-snapshot` library actually uses `GMSPublicKey` for encryption, and (2) the TLS client configuration in GMS HTTP client. Key finding from code review: `gms_client.go:314` allows `http://` prefix override on `GMSDomain`, which would bypass TLS entirely. Also need to verify the `IsDeveloperMode` interaction (line 154: developer mode uses in-memory client, skipping GMS entirely, but does NOT restrict `GMSDomain` configuration).
- **Suggested follow-up**: Clone `github.com/grafana/grafana-cloud-migration-snapshot` and verify encryption implementation. Test whether `GMSDomain=http://attacker.com` is rejected or accepted in production mode. Check if `GMSDomain` can be set via environment variable or API.

---

## KB Domain Research Used

### SSRF via Cloud Migration Presigned URL (H4 from prior audit)
- Applied to: PH-05, PH-06 -- Confirmed still present. The presigned URL from GMS is passed to `objectstorage/s3.go:PresignedURLUpload` with zero URL validation. Only `url.Parse` (syntactic) is applied.
- Additionally discovered: `gms_client.go:314` accepts `http://` prefix override, making MITM trivial when configured with HTTP scheme.

### Cross-Org Cloud Migration (CVE-2024-9476)
- Applied to: PH-01, PH-02, PH-09, PH-10 -- Extended the known CancelSnapshot cross-org pattern. Found that `UpdateSnapshot` SQL systemically lacks org_id (both `status` and `public_key` updates). Also discovered that `s.cancelFunc` is a global singleton enabling cross-org DoS without any UID guessing.

### Datasource Proxy Path Differential (CVE-2025-3454, M7)
- Applied to: PH-11 -- Identified specific differential between `CleanRelativePath` (operates on percent-encoded strings) and `PathUnescape` (decodes to path separators). The root cause is that route matching and forwarding use incompatible path representations.

### OSS SSRF Defaults (M7, AS-09)
- Applied to: PH-12, PH-14, PH-16 -- Confirmed that OSS Grafana has zero application-layer SSRF protection: validator is no-op, URL validation has no IP blocklist, and whitelist defaults to empty.
