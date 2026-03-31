---
id: p8-004
title: Auth Proxy Empty Whitelist Default Enables Complete Authentication Bypass
severity: HIGH
status: VALID
verdict: VALID
cluster: Authentication & Authorization
---

Phase: 8
Sequence: 004
Slug: auth-proxy-empty-whitelist-bypass
Verdict: VALID
Rationale: When auth proxy is enabled without configuring the IP whitelist (which defaults to empty), isAllowedIP() at proxy.go:200-203 returns true for ALL source IPs. Any network client can send the X-WEBAUTH-USER header and authenticate as any user including GrafanaAdmin. The Advocate correctly identified that auth proxy is disabled by default, but the empty whitelist default creates a dangerous security trap for operators enabling the feature.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-1-p8/debate.md

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Unit test proves isAllowedIP returns true for all IPs when whitelist is empty (the default), and Authenticate succeeds with attacker-controlled username from arbitrary IPs; no compensating control exists in middleware or application code.
Severity-Final: HIGH
PoC-Status: executed

## Summary

The auth proxy client at `pkg/services/authn/clients/proxy.go` has an `isAllowedIP` function (line 200-217) that returns `true` when the `acceptedIPs` list is empty. The default configuration at `conf/defaults.ini:968` sets `whitelist = ` (empty string), and `parseAcceptList` (line 220-233) returns `nil` for empty input. This means when an operator enables auth proxy (`[auth.proxy] enabled = true`) without explicitly configuring the whitelist, ALL source IPs are accepted.

Combined with the `getProxyHeader` function (line 250-258) which reads the auth header (`X-WEBAUTH-USER` by default) directly from the HTTP request without any additional validation (no HMAC, no shared secret, no origin verification), any network client that can reach the Grafana instance can impersonate any user by simply setting the header.

## Location

- `pkg/services/authn/clients/proxy.go:200-203` -- `isAllowedIP` returns `true` when `len(c.acceptedIPs) == 0`
- `pkg/services/authn/clients/proxy.go:220-233` -- `parseAcceptList` returns `nil, nil` for empty whitelist string
- `pkg/services/authn/clients/proxy.go:76-113` -- `Authenticate` method: calls `isAllowedIP` then reads header value as username
- `pkg/services/authn/clients/proxy.go:250-258` -- `getProxyHeader` reads header with no additional validation
- `conf/defaults.ini:962-970` -- Default configuration: `enabled = false`, `whitelist = ` (empty)

## Attacker Control

The attacker has full control over the `X-WEBAUTH-USER` HTTP header value, which is directly used as the authenticated username. No additional credentials, tokens, or verification is required. The header value maps directly to a user identity via the `AuthenticateProxy` flow.

With `auto_sign_up = true` (default), the attacker can even specify non-existent usernames, which will be auto-provisioned as new users.

## Trust Boundary Crossed

TB-2 (Auth Gate). The authentication boundary is completely bypassed -- any network client that can send an HTTP request to Grafana with the configured header name can authenticate as any user, including the Grafana server admin.

## Impact

- **Complete authentication bypass**: No credentials required, single HTTP header grants full access
- **Admin impersonation**: Attacker can authenticate as `admin` or any Grafana server admin
- **Data source credential theft**: Admin access enables reading stored data source credentials
- **Configuration manipulation**: Admin access enables modifying alerting rules, dashboards, and server settings
- **User creation**: With `auto_sign_up = true` (default), attacker can create arbitrary user accounts
- **Lateral movement**: Data source credentials may provide access to databases, cloud APIs, and monitoring infrastructure

## Evidence

1. `proxy.go:200-203`:
   ```go
   func (c *Proxy) isAllowedIP(r *authn.Request) bool {
       if len(c.acceptedIPs) == 0 {
           return true  // ALL IPs accepted when whitelist is empty
       }
       // ... IP filtering ...
   }
   ```

2. `proxy.go:220-223`:
   ```go
   func parseAcceptList(s string) ([]*net.IPNet, error) {
       if len(strings.TrimSpace(s)) == 0 {
           return nil, nil  // empty whitelist -> nil list -> isAllowedIP returns true
       }
   }
   ```

3. `defaults.ini:962-968`:
   ```ini
   [auth.proxy]
   enabled = false
   header_name = X-WEBAUTH-USER
   whitelist =
   ```

4. `proxy.go:83`:
   ```go
   username := getProxyHeader(r, c.cfg.AuthProxy.HeaderName, c.cfg.AuthProxy.HeadersEncoded)
   ```
   No HMAC, no shared secret, no origin validation -- raw header value is trusted.

## Reproduction Steps

1. Configure Grafana with `[auth.proxy] enabled = true` (all other auth.proxy settings at default)
2. From any network client, send: `curl -H "X-WEBAUTH-USER: admin" http://grafana:3000/api/org`
3. Expected (secure): 401 Unauthorized (no IP whitelist configured, should deny all)
4. Actual: 200 OK with admin user's organization info -- full authentication bypass

To verify IP filtering works when whitelist IS configured:
5. Set `whitelist = 192.168.1.0/24` in configuration
6. Repeat the curl from a non-whitelisted IP
7. Expected and actual: 401 Unauthorized (IP not in whitelist)

## Defense Brief

- **Auth proxy is disabled by default** (`enabled = false`). The vulnerability requires explicit operator action to enable the feature.
- **Intended deployment model**: Auth proxy is designed for use behind a reverse proxy (nginx, Apache, HAProxy) that sets the X-WEBAUTH-USER header from a trusted identity source and strips the header from incoming external requests.
- **Documentation**: Grafana documentation recommends configuring the whitelist when using auth proxy.
- **Counter-argument**: The default empty whitelist creates a "pit of failure" -- operators who enable auth proxy with minimal configuration get zero IP-based protection. The secure default should be deny-all when no whitelist is configured.

## Severity Justification

HIGH severity because:
- Complete authentication bypass when auth proxy is enabled without whitelist
- Any network client can impersonate any user including Grafana Server Admin
- No credentials needed -- single HTTP header is sufficient
- auto_sign_up = true (default) enables arbitrary user account creation
- Impact: full admin access, credential theft from data sources, data exfiltration

Not CRITICAL because:
- Auth proxy is disabled by default (requires explicit operator opt-in)
- The feature is intended for network-isolated deployments behind a trusted reverse proxy
- Standard deployment architecture would have the proxy stripping untrusted headers
- However, the empty whitelist default significantly reduces the configuration barrier to a vulnerable state
