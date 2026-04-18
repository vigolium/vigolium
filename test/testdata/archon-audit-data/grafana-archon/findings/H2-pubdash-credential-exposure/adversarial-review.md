# Adversarial Review: pubdash-credential-exposure

## Step 1 -- Restate and Decompose

**Restated vulnerability**: When a Grafana instance exposes a public dashboard that uses a datasource configured with "direct" (browser-side) access mode and BasicAuth or InfluxDB credentials, those decrypted credentials are included in the JSON response sent to unauthenticated users. The filtering introduced for CVE-2026-27877 limits which datasources appear in the response, but does not suppress the credential fields for datasources that pass the filter.

**Sub-claims**:

- **Sub-claim A**: An attacker with only a public dashboard access token can trigger code that calls `getFSDataSources`, which populates credential fields. **SUPPORTED** -- The `/bootdata/:accessToken` endpoint is registered with `reqNoAuth` and calls `setIndexViewData` -> `getFrontendSettings` -> `getFSDataSources`. The `SetPublicDashboardAccessToken` middleware sets `PublicDashboardAccessToken` on the context.

- **Sub-claim B**: The `getFSDataSources` function decrypts and includes credentials for direct-mode datasources without checking `IsPublicDashboardView()`. **SUPPORTED** -- Lines 541-577 of `pkg/api/frontendsettings.go` contain the credential extraction block for `DS_ACCESS_DIRECT`. The only `IsPublicDashboardView()` check is at line 476, which controls WHICH datasources appear (filtering by dashboard usage) but does NOT gate the credential extraction block.

- **Sub-claim C**: Decrypted credentials are serialized and returned to the caller in JSON. **SUPPORTED** -- `DataSourceDTO` (pkg/plugins/models.go:282-312) has `BasicAuth string json:"basicAuth,omitempty"`, `Password string json:"password,omitempty"`, and `Username string json:"username,omitempty"`. The DTO is included in `FrontendSettingsDTO.Datasources` which is returned as JSON.

## Step 2 -- Independent Code Path Trace

**Entry point**: `GET /bootdata/:accessToken` (pkg/api/api.go:207-214)

1. Route registered with `reqNoAuth` middleware -- no authentication required
2. `SetPublicDashboardAccessToken` middleware sets `c.PublicDashboardAccessToken = accessToken`
3. `SetPublicDashboardOrgIdOnContext` sets `c.OrgID` from the public dashboard's org
4. Handler: `hs.GetBootdata(c)` (pkg/api/frontendsettings.go:37)
5. Calls `hs.setIndexViewData(c)` (pkg/api/index.go:51)
6. Calls `hs.getFrontendSettings(c)` (pkg/api/frontendsettings.go:127)
7. Calls `hs.getFSDataSources(c, availablePlugins)` (pkg/api/frontendsettings.go:145)
8. At line 476: `c.IsPublicDashboardView()` returns true (token is set)
9. Enters public dashboard branch: `publicDashFilterUsedDataSources` filters datasources to only those used by the dashboard
10. For each surviving datasource, lines 541-577 execute WITHOUT any public-dashboard guard:
    - If `ds.Access == DS_ACCESS_DIRECT && ds.BasicAuth`: decrypts and sets `dsDTO.BasicAuth` (base64 user:password)
    - If `ds.Access == DS_ACCESS_DIRECT && ds.Type == DS_INFLUXDB`: decrypts and sets `dsDTO.Password` (plaintext)
11. DTO is serialized to JSON in `IndexViewData.Settings.Datasources`

**Validation/sanitization on path**: NONE for credential fields in the public dashboard context.

**Framework protections**: None applicable -- this is direct Go struct serialization, no ORM or template escaping involved.

**Note on finding's stated endpoint**: The finding states `GET /api/frontend/settings` as the endpoint. This route (pkg/api/api.go:471) does NOT have the `SetPublicDashboardAccessToken` middleware, so `PublicDashboardAccessToken` would not be set unless carried by some other means. The actual exploitable endpoint is `GET /bootdata/:accessToken` which explicitly sets the token. The vulnerability exists in the shared `getFSDataSources` function either way.

## Step 3 -- Protection Surface Search

| Layer | Control | Blocks Attack? |
|-------|---------|---------------|
| Language | Go type system | No -- string fields populated with decrypted values |
| Framework | No ORM/template escaping for this JSON endpoint | No |
| Middleware | `reqNoAuth` on bootdata endpoint -- explicitly allows unauthenticated access | No |
| Application | `publicDashFilterUsedDataSources` at line 476-483 | **Partially** -- limits WHICH datasources appear but does NOT suppress credential fields |
| Application | No `IsPublicDashboardView()` guard on lines 541-577 | No -- credential extraction runs unconditionally |
| RBAC | RBAC is explicitly skipped for public dashboard views (line 477 comment) | No |
| Documentation | No SECURITY.md mention of this as accepted risk | N/A |

**No blocking protection found.**

## Step 4 -- Real-Environment Reproduction

**PoC-Status: theoretical**

Real environment reproduction was not attempted due to the complexity of building and configuring a full Grafana instance with a direct-mode datasource and public dashboard in a cold verification context. However, the code path is unambiguous:

- The test at `frontendsettings_test.go:803` confirms that `publicDashFilterUsedDataSources` returns datasources used by the dashboard
- The test does NOT test direct-mode datasources or credential stripping -- all test datasources use default (proxy) access mode
- No code between the filter and the credential extraction block checks `IsPublicDashboardView()`

The vulnerability is deterministic from code analysis: if a filtered datasource has `Access == "direct"` and `BasicAuth == true`, the decrypted password WILL be included in the response.

## Step 5 -- Prosecution and Defense Briefs

### Prosecution Brief

The vulnerability is a genuine credential disclosure to unauthenticated users. Evidence:

1. **Unauthenticated access**: `GET /bootdata/:accessToken` is registered with `reqNoAuth` (pkg/api/api.go:208). Any user with the access token (which is visible in the public dashboard URL) can call this endpoint.

2. **No credential suppression**: `getFSDataSources` (pkg/api/frontendsettings.go:464-629) has exactly ONE `IsPublicDashboardView()` check at line 476, used solely to filter which datasources appear. The credential extraction block at lines 541-577 runs unconditionally for all datasources that pass the filter.

3. **Plaintext credentials in response**: `DataSourceDTO.Password` (pkg/plugins/models.go:305) is serialized as `json:"password,omitempty"` and populated with `hs.DataSourcesService.DecryptedPassword()` output at line 575. `DataSourceDTO.BasicAuth` (line 297) contains the full base64 `Basic user:password` header.

4. **Real configuration**: Direct-mode datasources with BasicAuth are a legitimate Grafana configuration, especially for InfluxDB v1.x. The Grafana UI allows creating such datasources.

5. **Preconditions are minimal**: (a) A datasource with `access: direct` and credentials configured, (b) a dashboard using that datasource with public sharing enabled. Both are standard operational configurations.

### Defense Brief

1. **Direct access mode is deprecated in practice**: Most modern Grafana deployments use proxy mode (`DS_ACCESS_PROXY`), which does not trigger the credential extraction block. The likelihood of encountering a direct-mode datasource with a public dashboard is reduced but not zero.

2. **Access token required**: The attacker needs the public dashboard access token. While this is present in the URL and not secret by design, it does limit the attack surface to known public dashboards.

3. **Finding's stated endpoint may be inaccurate**: The finding claims `GET /api/frontend/settings` is the vector, but this endpoint does not set `PublicDashboardAccessToken` automatically. The actual vector is `/bootdata/:accessToken`. However, the underlying vulnerability in `getFSDataSources` is real regardless of endpoint.

4. **InfluxDB v0.8 is extremely rare**: The `DS_INFLUXDB_08` type (lines 557-566) is essentially obsolete. However, `DS_INFLUXDB` (current InfluxDB, lines 568-577) and BasicAuth (lines 542-551) are still viable.

## Step 6 -- Severity Challenge

Starting at MEDIUM:

- **Upgrade signal**: Remotely triggerable by any unauthenticated user with a public dashboard URL -- YES
- **Upgrade signal**: Meaningful trust boundary crossing (unauthenticated -> decrypted backend credentials) -- YES
- **Upgrade signal**: No significant preconditions beyond a public dashboard with direct-mode datasource -- MODERATE (direct mode is less common but valid)
- **Downgrade signal**: Requires direct-mode datasource configuration (not the default) -- MODERATE downgrade signal
- **Downgrade signal**: Theoretical only (no live reproduction) -- MODERATE downgrade signal

Challenged severity: **HIGH** -- The trust boundary crossing (unauthenticated internet user to decrypted backend database credentials) is severe enough to warrant HIGH despite the precondition of direct-mode configuration. This matches the original severity.

## Step 7 -- Verdict

```
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Code path from unauthenticated /bootdata/:accessToken endpoint through getFSDataSources deterministically includes decrypted BasicAuth and InfluxDB passwords in JSON response for direct-mode datasources, with no IsPublicDashboardView() guard on the credential extraction block (lines 541-577 of frontendsettings.go).
Severity-Final: HIGH
PoC-Status: theoretical
```

**Note**: The finding's stated endpoint (`GET /api/frontend/settings`) is likely not the primary attack vector. The confirmed vector is `GET /bootdata/:accessToken` which is registered with `reqNoAuth` and explicitly sets the public dashboard access token on the context. The vulnerability in `getFSDataSources` is real and confirmed via code analysis.
