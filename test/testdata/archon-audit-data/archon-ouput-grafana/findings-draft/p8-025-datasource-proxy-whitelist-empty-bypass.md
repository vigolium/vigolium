---
id: p8-025
title: Datasource Proxy Empty Whitelist Default Disables SSRF Protection
severity: MEDIUM
status: VALID
verdict: VALID
cluster: Authentication & Authorization
---

Phase: 10
Sequence: 025
Slug: datasource-proxy-whitelist-empty-bypass
Verdict: VALID
Rationale: The datasource proxy whitelist check at pkg/api/pluginproxy/ds_proxy.go:402-411 uses `len(proxy.cfg.DataProxyWhiteList) > 0` as its gate, so when the list is empty (the default at conf/defaults.ini:398-399), ALL datasource URLs pass validation unconditionally. This is the same "empty allowlist = allow all" root cause as the auth proxy finding (p8-004), applied to SSRF protection.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p8-004-auth-proxy-empty-whitelist-bypass.md
Origin-Pattern: AP-047

## Summary

The `checkWhiteList()` function in the datasource proxy (`pkg/api/pluginproxy/ds_proxy.go:402-411`) implements IP/hostname whitelisting to restrict which hosts Grafana may proxy datasource requests to. The guard condition is `len(proxy.cfg.DataProxyWhiteList) > 0`. When `DataProxyWhiteList` is empty — the default, because `data_source_proxy_whitelist` at `conf/defaults.ini:399` is blank — the condition is `false`, the body of the `if` is skipped entirely, and `checkWhiteList()` returns `true` for every datasource URL.

The intended purpose of `data_source_proxy_whitelist` is to prevent Server-Side Request Forgery (SSRF): an admin user who can create or edit datasources could set the datasource URL to an internal host (e.g., `http://169.254.169.254/` for cloud metadata, or `http://internal-db:5432/`) and use the Grafana proxy to tunnel requests through Grafana to that target. The whitelist is the only control preventing this. Because the whitelist is opt-in (default empty), SSRF protection is OFF by default.

## Location

- `pkg/api/pluginproxy/ds_proxy.go:402-411` — `checkWhiteList()`: the outer guard `len(proxy.cfg.DataProxyWhiteList) > 0` makes the entire check a no-op when the list is empty
- `pkg/api/pluginproxy/ds_proxy.go:280-283` — `validateRequest()`: calls `checkWhiteList()` as the sole URL restriction gate
- `pkg/setting/setting.go:1867-1872` — `DataProxyWhiteList` is initialized as an empty map when the config string is blank
- `conf/defaults.ini:398-399` — `data_source_proxy_whitelist =` (empty by default)

## Attacker Control

The attacker must be an authenticated admin user (or otherwise have datasource write permission via RBAC). With datasource admin access, the attacker can:

1. Create or modify a datasource and set its URL to an internal network target.
2. Issue a datasource proxy request via `GET /api/datasources/proxy/uid/:uid/<path>` or `GET /api/datasources/proxy/:id/<path>`.
3. Because `checkWhiteList()` always returns `true` on a default installation, Grafana forwards the request to the internal target.

The attacker controls the full target URL (datasource URL + proxy path) passed to Grafana's outbound HTTP client.

## Trust Boundary Crossed

TB-5 (Datasource Proxy): The whitelist is the guard at the boundary between authenticated Grafana users and arbitrary outbound network connections. With the whitelist empty, the boundary is removed — any host reachable from the Grafana server is a valid proxy target.

TB-6 (External Datasources): With no whitelist, Grafana becomes a general HTTP proxy to any internal network resource, crossing the boundary between the data plane and internal infrastructure.

## Impact

- **SSRF to internal infrastructure**: Grafana can proxy HTTP requests to any internal host — cloud metadata services (`169.254.169.254`), internal databases, Kubernetes API servers, admin UIs not exposed to the internet.
- **Cloud credential theft**: On AWS/GCP/Azure, querying the instance metadata endpoint via SSRF yields IAM credentials with the instance's role.
- **Internal network scanning**: By iterating over proxy paths, an attacker can enumerate internal services and ports.
- **Credential-carrying proxy requests**: Grafana injects datasource credentials into outbound requests; targeting an attacker-controlled server leaks those credentials.

Note: This requires admin-level access to datasource configuration, which significantly reduces exploitability compared to the auth proxy bypass (p8-004). However, in multi-tenant Grafana deployments or where datasource admin is granted to semi-trusted users (e.g., org admins), this is a meaningful internal privilege escalation path.

## Evidence

1. `ds_proxy.go:402-411`:
   ```go
   func (proxy *DataSourceProxy) checkWhiteList() bool {
       if proxy.targetUrl.Host != "" && len(proxy.cfg.DataProxyWhiteList) > 0 {
           if _, exists := proxy.cfg.DataProxyWhiteList[proxy.targetUrl.Host]; !exists {
               proxy.ctx.JsonApiErr(403, "Data proxy hostname and ip are not included in whitelist", nil)
               return false
           }
       }
       return true  // ALWAYS reached when DataProxyWhiteList is empty (the default)
   }
   ```

2. `setting.go:1866-1872`:
   ```go
   // read data source proxy whitelist
   cfg.DataProxyWhiteList = make(map[string]bool)
   securityStr := valueAsString(security, "data_source_proxy_whitelist", "")
   for _, hostAndIP := range util.SplitString(securityStr) {
       cfg.DataProxyWhiteList[hostAndIP] = true
   }
   // When securityStr is empty, DataProxyWhiteList remains empty -- checkWhiteList() will not enforce
   ```

3. `defaults.ini:398-399`:
   ```ini
   # data source proxy whitelist (ip_or_domain:port separated by spaces)
   data_source_proxy_whitelist =
   ```

4. The structural pattern is identical to `proxy.go:200-203` (p8-004):
   - Both check `len(<list>) == 0` / `len(<list>) > 0` as an early return
   - Both return `true` (allow) when the list is empty
   - Both default to an empty list in `conf/defaults.ini`

## Reproduction Steps

1. Start Grafana with default configuration (no `data_source_proxy_whitelist` setting).
2. As an org admin, create a new datasource of type "SimpleJSON" (or any HTTP-based type) with URL: `http://169.254.169.254/`
3. Issue a datasource proxy request: `curl -u admin:admin 'http://localhost:3000/api/datasources/proxy/uid/<uid>/latest/meta-data/'`
4. Expected (with whitelist configured): 403 Forbidden — host not in whitelist.
5. Actual: Request is forwarded to `169.254.169.254` — the AWS instance metadata endpoint.
6. To verify protection works: set `data_source_proxy_whitelist = prometheus-host:9090` in config and repeat — Grafana now returns 403 for the metadata endpoint.

## Defense Brief

- `data_source_proxy_whitelist` is documented as optional. Most Grafana deployments trust their admin users to configure legitimate datasource URLs, and network-level controls (VPC routing, IAM instance profiles, firewalls) are expected to prevent SSRF.
- The whitelist requires knowledge of all legitimate datasource hosts at deployment time, which is operationally difficult in dynamic environments.
- Counter-argument: SSRF via the datasource proxy is a well-known attack class (CVE-2020-13379, CVE-2020-11110). Default-off protection leaves the majority of deployments unprotected.
