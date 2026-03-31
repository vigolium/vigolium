Phase: 8
Sequence: 029
Slug: scanner-ssrf
Verdict: VALID
Rationale: PingScanner endpoint accepts arbitrary URLs via ValidateHTTPURL (scheme-only check), making outbound HTTP GET to {url}/api/v1/metadata; fixed path suffix limits exploitation to error-based oracle but enables internal service discovery.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md

## Summary

The `PingScanner` endpoint at `POST /api/v2.0/scanners/ping` accepts a user-supplied URL that passes through `ValidateHTTPURL` (scheme-only validation) and triggers an outbound HTTP GET to `{url}/api/v1/metadata`. While the fixed path suffix limits the attacker's control over the request path, the error-based oracle (connection refused vs. timeout vs. parse error) enables internal service discovery. The same pattern applies to `CreateScanner` and `UpdateScanner` endpoints.

## Location

- `src/server/v2.0/handler/scanner.go:169-190` -- `PingScanner` handler
- `src/pkg/scan/dao/scanner/model.go:100-127` -- `Registration.Validate()` calls ValidateHTTPURL
- `src/controller/scanner/base_controller.go:306-333` -- `Ping()` calls `getScannerAdapterMetadata`
- `src/pkg/scan/rest/v1/client.go:110-129` -- `GetMetadata()` makes HTTP GET

## Attacker Control

- System admin controls scanner URL via POST /api/v2.0/scanners/ping
- URL passes ValidateHTTPURL (scheme-only, no IP filtering)
- Fixed path suffix `/api/v1/metadata` appended -- limits to error-based oracle

## Trust Boundary Crossed

- Core API to internal network via scanner client HTTP request

## Impact

- Internal service discovery via error-based oracle
- Port/service status mapping across internal network
- Limited by fixed path suffix -- cannot read arbitrary content

## Evidence

- Tracer confirmed end-to-end code path
- endpoint.go:27-45: ValidateHTTPURL scheme-only, no IP filtering
- endpoint_test.go:32-33: `http://127.0.0.1` and `http://169.254.169.254` pass validation

## Reproduction Steps

1. Authenticate as system administrator
2. Send: `POST /api/v2.0/scanners/ping` with body `{"url": "http://169.254.169.254/latest/meta-data/"}`
3. Observe error response: timeout (host unreachable), connection refused (port closed), or parse error (port open but not scanner)
4. Iterate across internal IPs to discover services
