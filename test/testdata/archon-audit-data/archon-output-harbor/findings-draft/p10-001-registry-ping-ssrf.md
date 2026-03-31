Phase: 10
Sequence: 001
Slug: registry-ping-ssrf
Verdict: VALID
Rationale: PingRegistry accepts a system-admin-supplied URL, validates it with ValidateHTTPURL (scheme-only, no IP filtering), then calls IsHealthy which makes an outbound HTTP request to the user-controlled host, enabling SSRF to cloud metadata, loopback, and RFC1918 addresses.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-029-scanner-ssrf.md
Origin-Pattern: AP-022

## Summary

The `PingRegistry` handler at `POST /api/v2.0/registries/ping` accepts a user-supplied registry URL, passes it through `ValidateHTTPURL` (scheme-only validation, no IP filtering), then invokes `IsHealthy` which creates a registry adapter and calls `HealthCheck()` — ultimately making one or more outbound HTTP requests to the attacker-controlled URL. The error response differentiates between connection refused, timeout, and parse error, providing an internal-network port scanning oracle. The same flow applies to `CreateRegistry` and `UpdateRegistry` which also call `c.validate()` → `IsHealthy`.

Unlike `PingScanner` (p8-029), the registry ping can authenticate to the target endpoint using user-supplied credentials (`access_key`, `access_secret`), amplifying the impact to authenticated internal SSRF.

## Location

- `src/server/v2.0/handler/registry.go:225-292` — `PingRegistry` accepts URL, calls `ValidateHTTPURL` then `IsHealthy`
- `src/server/v2.0/handler/registry.go:46-77` — `CreateRegistry` calls `r.ctl.Create` which validates then probes
- `src/controller/registry/controller.go:88-110` — `validate()` calls `ValidateHTTPURL` (scheme-only) then `IsHealthy`
- `src/controller/registry/controller.go:172-182` — `IsHealthy` creates adapter and calls `HealthCheck()`
- `src/pkg/reg/adapter/native/adapter.go:118-131` — `HealthCheck` calls `Ping()` making HTTP GET to registry URL
- `src/lib/endpoint.go:27-45` — `ValidateHTTPURL` validates scheme only, no IP filtering

## Attacker Control

- System admin controls registry URL via `POST /api/v2.0/registries/ping` with body `{"url": "http://169.254.169.254/", "type": "harbor"}`
- URL passes `ValidateHTTPURL` (http/https scheme accepted, no IP filtering)
- Credentials `access_key`/`access_secret` passed as BasicAuth to the target — enables authenticated internal SSRF
- `insecure: true` bypasses TLS certificate verification

## Trust Boundary Crossed

- TB-8: Core API container to any HTTP-reachable host on the internal network
- System admin privilege escalates to internal network HTTP reconnaissance with credential injection

## Impact

- Internal service discovery via error-based oracle (connection refused vs. timeout)
- Cloud metadata credential theft (`http://169.254.169.254/latest/meta-data/`)
- Authenticated SSRF: user-supplied credentials forwarded as BasicAuth to internal endpoints
- TLS bypass via `insecure: true` enables targeting self-signed internal HTTPS services

## Evidence

- `registry.go:243`: `lib.ValidateHTTPURL(*params.Registry.URL)` — scheme-only validation
- `controller.go:95`: `lib.ValidateHTTPURL(registry.URL)` — same scheme-only check in validate()
- `controller.go:101`: `c.IsHealthy(ctx, registry)` — makes outbound HTTP request
- `endpoint_test.go:32-33`: `http://127.0.0.1` and `http://169.254.169.254` pass ValidateHTTPURL
- Pattern matches AP-022: ValidateHTTPURL as sole URL validation before HTTP request

## Reproduction Steps

1. Authenticate as system administrator
2. Send: `POST /api/v2.0/registries/ping` with body:
   `{"url": "http://169.254.169.254/latest/meta-data/", "type": "harbor", "insecure": true}`
3. Observe error response: timeout (host unreachable), connection refused (port closed), or registry error (port open)
4. Iterate across internal IPs/ports to map internal network
5. For authenticated SSRF: include `credential_type`, `access_key`, `access_secret` in body
