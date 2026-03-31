Phase: 10
Sequence: 062
Slug: scanner-credential-api-exposure
Verdict: VALID
Rationale: The GET /api/v2.0/scanners/{id} endpoint returns the full ScannerRegistration model including the plaintext access_credential field (Basic auth password, Bearer token, or API key) with no redaction, exposing scanner adapter credentials to any system administrator.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p8-032-uaa-secret-not-redacted.md
Origin-Pattern: AP-032

## Summary

The `scanner_registration.access_credential` field stores the scanner adapter's authentication credential (Basic auth password, Bearer token, or X-ScannerAdapter-API-Key) in the database. The `ToSwagger` conversion in `src/server/v2.0/handler/model/scanner.go:44` includes `AccessCredential: s.AccessCredential` directly in the API response without redaction. Any system administrator calling `GET /api/v2.0/scanners/{id}` or `GET /api/v2.0/scanners` (list) receives the credential in plaintext. This is structurally identical to p8-032 (UAAClientSecret not redacted): a credential field is never annotated as requiring redaction, so it passes through to the API response.

## Location

- `src/server/v2.0/handler/model/scanner.go:44` -- `AccessCredential: s.AccessCredential` included verbatim in ToSwagger output
- `src/server/v2.0/handler/scanner.go:108` -- `GetScanner` returns `model.NewScannerRegistration(r).ToSwagger(ctx)` with no scrubbing
- `src/pkg/scan/dao/scanner/model.go:51` -- `AccessCredential` field with `json:"access_credential,omitempty"` tag

## Attacker Control

- Any system administrator calls `GET /api/v2.0/scanners/{id}` or `GET /api/v2.0/scanners`
- No special authentication beyond system admin role required
- Scanner registrations are often created with real credentials for production Trivy/Clair instances

## Trust Boundary Crossed

- Scanner adapter credential (external system secret) exposed to any system admin reading the configuration API

## Impact

- Plaintext exposure of scanner adapter credentials (API keys, Basic auth passwords, Bearer tokens) to any system admin
- Can be used to directly access the vulnerability scanner adapter, bypassing Harbor's RBAC
- If scanner is shared across multiple Harbor instances or used externally, credential compromise affects all uses
- Structurally identical root cause to p8-032: no redaction mechanism applied to this credential type

## Evidence

- `scanner.go:44`: `AccessCredential: s.AccessCredential` - no masking
- Contrast: scan job logging in `job.go:428` explicitly sets `AccessCredential: "[HIDDEN]"` before logging, showing the developer was aware credentials are sensitive - but the API response path is not protected
- `scanner.go:94-108`: `GetScanner` calls `ToSwagger` on raw registration with no pre-processing

## Reproduction Steps

1. Authenticate as system administrator
2. Create a scanner with credentials: `POST /api/v2.0/scanners` with `{"auth": "Basic", "access_credential": "username:password", "url": "http://trivy-adapter:8080", "name": "test-scanner"}`
3. Retrieve the scanner: `GET /api/v2.0/scanners/{uuid}`
4. Observe `access_credential` field in response contains plaintext `username:password`
5. Contrast: confirm that `oidc_client_secret` is redacted in `GET /api/v2.0/configurations`
