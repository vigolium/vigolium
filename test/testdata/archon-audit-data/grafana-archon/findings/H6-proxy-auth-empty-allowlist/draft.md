Phase: 8
Sequence: 040
Slug: proxy-auth-empty-allowlist
Verdict: VALID
Rationale: Confirmed insecure-by-default IP allowlist behavior within the auth proxy feature — when enabled, empty whitelist (default) allows any IP to impersonate any user via the proxy header.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-3/debate.md

## Summary

When Grafana's auth proxy feature is enabled (`[auth.proxy] enabled = true`), the IP allowlist (`whitelist`) defaults to an empty string. The `isAllowedIP()` function at `pkg/services/authn/clients/proxy.go:200-202` returns `true` when the parsed allowlist is empty (`len(c.acceptedIPs) == 0`), meaning any IP address is accepted. This allows any network-accessible client to authenticate as any Grafana user by setting the configured proxy header (default: `X-WEBAUTH-USER`).

## Location

- `pkg/services/authn/clients/proxy.go:200-202` — `isAllowedIP()` function
- `pkg/services/authn/clients/proxy.go:220-224` — `parseAcceptList()` returns nil for empty string
- `pkg/services/authn/clients/proxy.go:76-113` — `Authenticate()` flow
- `conf/defaults.ini:973,978` — `enabled = false`, `whitelist =`

## Attacker Control

Full control over the username via the HTTP proxy header (default: `X-WEBAUTH-USER`). The attacker can impersonate any Grafana user including `admin` by setting this header from any IP address.

## Trust Boundary Crossed

Unauthenticated external network -> fully authenticated Grafana user session. The auth proxy is designed to trust a reverse proxy to set the header, but with an empty allowlist, this trust is extended to all IP addresses.

## Impact

Complete authentication bypass. Any user, including Grafana server administrator, can be impersonated. This enables:
- Full administrative access to Grafana
- Access to all dashboards, datasources, and their stored credentials
- Modification of alerting rules and notification channels
- Creation of new admin accounts for persistence

## Evidence

```go
// pkg/services/authn/clients/proxy.go:200-202
func (c *Proxy) isAllowedIP(r *authn.Request) bool {
    if len(c.acceptedIPs) == 0 {
        return true  // Empty allowlist = accept all IPs
    }
    // ... IP check logic ...
}

// pkg/services/authn/clients/proxy.go:220-224
func parseAcceptList(s string) ([]*net.IPNet, error) {
    if len(strings.TrimSpace(s)) == 0 {
        return nil, nil  // Empty string -> nil slice -> len 0
    }
    // ...
}
```

```ini
# conf/defaults.ini:973,978
[auth.proxy]
enabled = false
# ...
whitelist =
```

## Reproduction Steps

1. Enable auth proxy in Grafana configuration: `[auth.proxy] enabled = true`
2. Leave `whitelist` at default (empty)
3. Send HTTP request from any IP: `curl -H "X-WEBAUTH-USER: admin" http://grafana:3000/api/org`
4. Observe: request is authenticated as the `admin` user with full privileges
5. Confirm `isAllowedIP()` returns true because `len(c.acceptedIPs) == 0`
