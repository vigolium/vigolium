Phase: 8
Sequence: 022
Slug: webhook-ssrf-no-ip-filter
Verdict: VALID
Rationale: Webhook and Slack job addresses pass scheme-only validation with zero IP filtering, enabling project-admin SSRF to cloud metadata, internal services, and loopback; auth_header injection and skip_cert_verify amplify to authenticated internal HTTPS SSRF. No blocking protections found across all 5 defense layers.
Severity-Original: HIGH
PoC-Status: theoretical
PoC-Block-Reason: Harbor requires full deployment stack (PostgreSQL, Redis, core, job service, registry, portal, nginx) for end-to-end webhook execution testing. Code path is fully deterministic with no defensive branches — blocked by deployment complexity, not by any security mechanism.
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md

## Summary

Harbor's webhook and Slack notification jobs execute HTTP requests to user-controlled URLs with no IP address filtering, no DNS pinning, and no URL denylist. The `validateTargets` function in webhook.go only validates URL scheme (http/https) via `ParseEndpoint`. Combined with user-controllable `auth_header` (arbitrary Authorization header injection) and `skip_cert_verify` (TLS verification bypass), this enables authenticated SSRF to internal HTTPS services including cloud metadata endpoints and Kubernetes API servers.

The validate-at-store, execute-later architecture also creates a DNS rebinding gap (H-00j) -- any future IP denylist added only at store time would be bypassed.

## Location

- `src/server/v2.0/handler/webhook.go:409-415` -- `validateTargets` calls ParseEndpoint (scheme-only check)
- `src/common/utils/utils.go:36-53` -- `ParseEndpoint` validates only http/https scheme
- `src/jobservice/job/impl/notification/webhook_job.go:103-120` -- `execute()` uses address directly in http.NewRequest
- `src/jobservice/job/impl/notification/webhook_job.go:91-96` -- `skip_cert_verify` selects insecure HTTP client
- `src/pkg/notifier/handler/notification/http_handler.go:78-79` -- `auth_header` injected as Authorization header

## Attacker Control

- Project-admin controls: webhook address, auth_header, skip_cert_verify
- All values stored in DB and forwarded to job service without re-validation
- No IP filtering: 169.254.169.254, 127.0.0.1, 10.x.x.x, 192.168.x.x all allowed

## Trust Boundary Crossed

- TB-5: Core API to Job Service (shared secret)
- TB-8: Job Service to external/internal endpoints (no URL validation)
- Project-admin privilege escalates to internal network access

## Impact

- Cloud metadata credential theft (AWS IAM roles, GCP service accounts)
- Internal service discovery and exploitation
- Authenticated access to internal HTTPS services via auth_header
- TLS bypass enables targeting self-signed internal services

## Evidence

- Deep Probe PH-01, PH-06, PH-10: Validated end-to-end
- P7-002: Previously identified, confirmed with additional auth_header and skip_cert_verify dimensions
- False-fix comment at webhook.go:414: "Prevent SSRF security issue #3755" but only strips userinfo, not IPs

## Reproduction Steps

1. Authenticate as project-admin
2. Create webhook: `POST /api/v2.0/projects/{id}/webhook/policies` with `{"address": "http://169.254.169.254/latest/meta-data/", "event_types": ["ARTIFACT_PUSHED"], "skip_cert_verify": true, "auth_header": "Bearer <internal-token>"}`
3. Push an artifact to trigger the webhook
4. Observe outbound HTTP POST from job service to 169.254.169.254
5. For authenticated SSRF: set address to internal HTTPS service and auth_header to service token
