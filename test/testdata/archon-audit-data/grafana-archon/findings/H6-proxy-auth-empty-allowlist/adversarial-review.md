# Adversarial Review: proxy-auth-empty-allowlist

## Step 1 -- Restate and Decompose

**Restated claim**: When Grafana's auth proxy feature is explicitly enabled by an administrator and the IP whitelist is left at its default empty value, the `isAllowedIP()` function permits requests from any source IP. This allows any client that can reach Grafana's HTTP port to set the `X-WEBAUTH-USER` header and authenticate as any Grafana user, including admin.

**Sub-claims**:
- **Sub-claim A**: Attacker controls the `X-WEBAUTH-USER` HTTP header value. **VALID** -- any HTTP client can set arbitrary headers.
- **Sub-claim B**: When auth proxy is enabled with an empty whitelist, `isAllowedIP()` returns `true` for any source IP. **VALID** -- confirmed at `proxy.go:200-202`.
- **Sub-claim C**: The `Authenticate()` method uses the header value to authenticate as the specified user without further IP-based verification. **VALID** -- confirmed at `proxy.go:76-113`.

All sub-claims are coherent and verifiable.

## Step 2 -- Independent Code Path Trace

1. **Entry point**: `Proxy.Test()` at line 148 checks if the proxy header is present in the request. If present, the authn framework calls `Proxy.Authenticate()`.
2. **`Authenticate()` at line 76**: First calls `c.isAllowedIP(r)` (line 79).
3. **`isAllowedIP()` at line 200**: Checks `len(c.acceptedIPs) == 0`. If true, returns `true` immediately.
4. **`acceptedIPs` population**: Set during `ProvideProxy()` at line 50 via `parseAcceptList(cfg.AuthProxy.Whitelist)`.
5. **`parseAcceptList()` at line 220**: If the input string (after trim) has length 0, returns `nil, nil`.
6. **Default config**: `conf/defaults.ini:978` sets `whitelist =` (empty string).
7. **Back in `Authenticate()`**: After IP check passes, extracts username from header at line 83, then calls `proxyClient.AuthenticateProxy()` at line 105 to create/lookup the user.

**Validation/sanitization on path**: Only `isAllowedIP()` -- which is bypassed when acceptedIPs is empty. No other middleware strips or validates the proxy header.

**Discrepancies from finding**: None. The code path matches the finding's description exactly.

## Step 3 -- Protection Surface Search

| Layer | Protection Found | Blocks Attack? |
|-------|-----------------|---------------|
| Application config | `enabled = false` by default (defaults.ini:973) | YES -- requires explicit opt-in |
| Application code | `isAllowedIP()` with empty allowlist returns true | NO -- this IS the vulnerability |
| Network | Typical deployment behind reverse proxy | NOT CODE-ENFORCED -- depends on deployment |
| Documentation | Auth proxy docs mention whitelist "can be used to prevent spoofing" | PARTIAL -- acknowledged but no strong warning |
| Framework | No middleware strips proxy headers | NO protection |

**Key finding**: The primary protection is that the feature is disabled by default. When enabled, there is no code-level protection against arbitrary IP access with an empty whitelist.

## Step 4 -- Real-Environment Reproduction

**PoC-Status: theoretical**

Reproduction requires:
1. A running Grafana instance
2. Modified configuration with `[auth.proxy] enabled = true`
3. Empty whitelist (default)

The code path is deterministic and trivially verifiable from static analysis:
- `parseAcceptList("")` returns `nil, nil` (line 221-222)
- `len(nil) == 0` is `true` in Go
- Therefore `isAllowedIP()` returns `true` for any request

A full Grafana instance was not provisioned due to environment constraints (compile time, configuration changes needed). However, the behavior is a simple conditional with no runtime ambiguity.

## Step 5 -- Prosecution Brief

The code at `pkg/services/authn/clients/proxy.go:200-202` explicitly returns `true` when the accepted IP list is empty. The `parseAcceptList` function at lines 220-223 returns `nil` for an empty whitelist string. The default configuration sets `whitelist =` (empty). When an administrator enables auth proxy without configuring a whitelist, the `Authenticate()` method at line 76 will:
1. Accept requests from any IP (line 79, `isAllowedIP()` returns true)
2. Extract the username from the `X-WEBAUTH-USER` header (line 83)
3. Authenticate as that user (line 105)

No middleware strips or validates the proxy header. The documentation does not strongly warn about this behavior. An attacker with network access to Grafana's port can trivially impersonate any user including admin.

## Step 5 -- Defense Brief

This finding requires non-default configuration. Auth proxy is disabled by default (`enabled = false`). An administrator must explicitly opt in. The "empty whitelist = accept all" behavior is an intentional design pattern common across proxy authentication implementations (Apache mod_auth, Nginx auth_request, etc.). The feature is designed for deployment behind a trusted reverse proxy where network topology provides the security boundary. The documentation at `docs/sources/setup-grafana/configure-access/configure-authentication/auth-proxy/index.md` explicitly mentions the whitelist's purpose. Administrators who enable auth proxy are expected to understand proxy authentication and configure appropriate network-level or application-level access controls. This is a known-risk design decision, not a bug.

## Step 6 -- Severity Challenge

Starting at MEDIUM:
- **Upgrade signals**: Remotely triggerable when enabled; complete auth bypass; crosses unauthenticated-to-admin trust boundary.
- **Downgrade signals**: Requires non-default configuration (admin must explicitly enable auth proxy); intentional design pattern; feature designed for behind-reverse-proxy deployment; theoretical PoC only.

The downgrade signals are decisive. The feature requires explicit opt-in. The behavior is intentional. The typical deployment model (behind reverse proxy) provides network-level protection.

**Challenged severity: MEDIUM** (downgraded from HIGH)

## Step 7 -- Verdict

The code behavior is exactly as described in the finding. The `isAllowedIP()` function does return `true` when the allowlist is empty, and the default configuration has an empty allowlist. When auth proxy is enabled, this does allow any IP to authenticate as any user via the proxy header.

However, this requires:
1. Explicit administrator action to enable a non-default feature
2. The administrator to expose Grafana directly to untrusted networks while using proxy auth
3. The administrator to not configure the whitelist

The prosecution survives the defense on the narrow technical claim. Reproduction is blocked by environment constraints but the code path is deterministic and trivially verifiable.

```
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Code at proxy.go:200-202 unambiguously returns true for empty acceptedIPs list, and default config sets whitelist to empty, but requires non-default auth.proxy.enabled=true.
Severity-Final: MEDIUM
PoC-Status: theoretical
```
