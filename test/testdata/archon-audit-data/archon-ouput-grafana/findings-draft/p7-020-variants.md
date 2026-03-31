# Variant Analysis: p7-020-xds-auth-credential-injection (AP-020)

Phase: 9
Origin-Finding: security/findings-draft/p7-020-xds-auth-credential-injection.md
Origin-Pattern: AP-020 (Header-Forwarding Credential Override Without Origin Validation)
Analysis-Date: 2026-03-20
Analyst: Phase 9 Variant Hunter

## Search Strategies Applied

### 1. Registry-Driven Grep Search

Pattern searched: `X-DS-Authorization` across entire codebase (Go + TypeScript).

Results:
- `pkg/api/pluginproxy/ds_proxy.go:230-234` — confirmed original location (AP-020 instance)
- `public/app/core/services/backend_srv.ts:305` — frontend protocol origin (reads `Authorization`, writes `X-DS-Authorization`), not a server-side issue

No other locations promote `X-DS-Authorization` to `Authorization`.

### 2. AST-Level Structural Search: Other Header-Forwarding Patterns

Searched for `Header.Get → Header.Set` patterns involving auth-semantic headers in proxy directors.

Locations examined:
- `pkg/api/pluginproxy/pluginproxy.go` (PluginProxy director)
- `pkg/services/ngalert/api/util.go` (AlertingProxy.withReq)
- `pkg/services/datasourceproxy/datasourceproxy.go` (DataSourceProxyService)
- `pkg/util/proxyutil/reverse_proxy.go` (wrapDirector)

### 3. Flow Shape Search (source → transform → sink)

Traced: attacker HTTP request header → proxy director function → outbound backend Authorization header

Examined proxy paths:
- `/api/datasources/proxy/uid/:uid/*` and `/api/datasources/proxy/:id/*`
- `/api/plugin-proxy/:pluginId/*`
- `/api/alertmanager/:DatasourceUID/...` (ngalert LotexAM)
- `/api/ruler/:DatasourceUID/...` (ngalert LotexRuler)
- `/api/public/dashboards/:accessToken/panels/:panelId/query`

### 4. Phase 7 Addendum Targets

KB Phase 7 Addendum (Chamber 2) references:
- "X-DS-Authorization not in the wrapDirector strip list" — this is the p7-020 finding itself
- No additional surfaces mentioned for this specific pattern

### 5. Chamber Variant Candidates

No `variant-candidates/` subdirectories found in chamber-workspace (chamber-1, chamber-2, chamber-3 each contain only `debate.md`).

---

## Candidate Analysis

### Candidate A: PluginProxy Path (`/api/plugin-proxy/:pluginId/*`)

**File**: `pkg/api/pluginproxy/pluginproxy.go:147-198`
**Route**: `ANY /api/plugin-proxy/:pluginId/*` (requires `plugins:app:access` RBAC)

**Analysis**:
The PluginProxy director does NOT contain the `X-DS-Authorization → Authorization` transformation present in `ds_proxy.go`. The `wrapDirector` wrapper (`pkg/util/proxyutil/reverse_proxy.go:70-82`) strips `Authorization` (via `AuthHTTPHeaderListFromContext`) but does NOT strip `X-DS-Authorization`. Therefore:

- An attacker sending `X-DS-Authorization: Bearer evil` to `/api/plugin-proxy/:pluginId/*` will have that header forwarded verbatim to the backend as `X-DS-Authorization`.
- The backend plugin would need to specially interpret `X-DS-Authorization` for this to be exploitable.
- No existing Grafana built-in plugin has been found to promote `X-DS-Authorization` to `Authorization` on the backend side.
- The credential injection mechanism (unauthorized Authorization header replacement) of AP-020 is **absent** here.

**Verdict**: NOT a variant. Different behavior (no transformation to Authorization). At most a header information disclosure to plugin backends, which is a weaker, separate concern.

### Candidate B: Alertmanager/Loki/Prometheus Alerting Proxy

**Files**:
- `pkg/services/ngalert/api/util.go:128-198` (AlertingProxy.withReq)
- `pkg/services/ngalert/api/lotex_am.go` (LotexAM.withAMReq)
- `pkg/services/ngalert/api/lotex_ruler.go` (LotexRuler handlers)
- `pkg/services/ngalert/api/lotex_prom.go` (LotexProm handlers)

**Routes**: `/api/alertmanager/:DatasourceUID/*`, `/api/ruler/:DatasourceUID/*`, `/api/v1/rules/:DatasourceUID/*`

**Analysis**:
The `AlertingProxy.withReq` function (util.go:137) creates a fresh `http.NewRequest(method, u.String(), body)`. Only the `headers` parameter map entries are added to this fresh request (util.go:141-143). The original user request's headers — including any `X-DS-Authorization` sent by the attacker — are NOT copied to the new request. The `createProxyContext` at util.go:104-121 sets `cpy.Req = request` (the fresh request). This fresh request then flows through `ProxyDatasourceRequestWithUID/ID`, which calls the same `ds_proxy.go` director.

Since the fresh request contains no `X-DS-Authorization`, the director's check at `ds_proxy.go:231` (`if len(dsAuth) > 0`) evaluates to false. Credential injection does not occur.

**Verdict**: NOT a variant. The fresh-request construction in `AlertingProxy.withReq` acts as an accidental protection against AP-020 on the alerting proxy surface. The attacker cannot inject `X-DS-Authorization` via the alerting endpoint.

### Candidate C: Public Dashboard Query Path

**File**: `pkg/services/publicdashboards/api/query.go:54-76`
**Route**: `POST /api/public/dashboards/:accessToken/panels/:panelId/query` (unauthenticated)

**Analysis**:
`QueryPublicDashboard` calls `pd.PublicDashboardService.GetQueryDataResponse`, which at `service/query.go:149` calls `pd.QueryDataService.QueryData(svcCtx, svcIdent, ...)`. This path uses the plugin SDK's backend gRPC/in-process data query mechanism, NOT the HTTP datasource proxy. The `svcIdent` is a service identity created via `identity.WithServiceIdentity` using `dashboard.OrgID` (line 148). No HTTP headers from the client request are forwarded to the backend datasource. The datasource credentials are handled by the plugin SDK's authentication layer, not by `ds_proxy.go`'s director.

**Verdict**: NOT a variant. The public dashboard query path uses a different transport (plugin SDK backend) that is architecturally separate from the HTTP proxy. AP-020's header injection mechanism does not apply.

### Candidate D: `X-Grafana-Org-Id` and Other `X-Grafana-*` Headers

**Frontend origin**: `public/app/core/services/backend_srv.ts:297` sets `X-Grafana-Org-Id`.

**Analysis**:
Searched for any server-side code that reads `X-Grafana-Org-Id` and uses it as an authorization-sensitive value in proxy director functions. The header is read in the org context resolution layer (`pkg/middleware/org.go`) but is stripped from outbound proxy requests by `PrepareProxyRequest` (which strips `Origin`, `Referer`) — however, `X-Grafana-Org-Id` is not in the `PrepareProxyRequest` strip list.

However, the AP-020 pattern specifically requires: (1) header read from incoming request, (2) header promoted to `Authorization` on outbound request. `X-Grafana-Org-Id` is used for org routing, not credential injection. This is a different trust boundary than the credential management boundary crossed by AP-020.

**Verdict**: NOT a variant. Different header semantics; does not cross the credential management trust boundary.

---

## Summary of Confirmed Variants

**No confirmed variants found** in the assigned NNN range (p7-069 to p7-071).

The AP-020 pattern (X-DS-Authorization → Authorization promotion in a proxy director) has a single confirmed instance in the codebase: `pkg/api/pluginproxy/ds_proxy.go:230-234`. The other candidate surfaces either:

1. Use a different proxy mechanism that does not perform the header transformation (PluginProxy)
2. Use a fresh-request construction that prevents attacker headers from reaching the director (AlertingProxy)
3. Use a non-HTTP transport that bypasses the proxy director entirely (public dashboard SDK path)

The wrapDirector's AuthHTTPHeaderList (which strips `Authorization` and other auth headers) does NOT include `X-DS-Authorization`, confirming that the original finding's root cause is structural. However, the structural isolation of other proxy paths prevents the pattern from propagating to those surfaces.

---

## Attack Pattern Registry Update

No new instances to append to AP-020's `confirmed_instances`. The registry entry for AP-020 remains:

```json
{
  "file": "pkg/api/pluginproxy/ds_proxy.go",
  "line": "230-234",
  "finding": "p7-020"
}
```

---

## Notes for Future Searches

- If a new proxy surface is added that uses `httputil.ReverseProxy` with a director that does not explicitly delete `X-DS-Authorization` before processing auth headers, it would inherit the AP-020 pattern.
- The `wrapDirector` strip list (via `AuthHTTPHeaderListFromContext`) should be audited to include `X-DS-Authorization` as a countermeasure — this would fix p7-020 at the framework level and prevent future recurrences.
- The PluginProxy's `X-DS-Authorization` passthrough (forwarded verbatim to backend plugins) is a lower-severity informational issue: plugin backends receive this header and could misinterpret it, but no known built-in plugin does so.
