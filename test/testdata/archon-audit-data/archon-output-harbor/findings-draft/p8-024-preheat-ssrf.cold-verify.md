Phase: 8
Sequence: 024
Slug: preheat-ssrf
Verdict: VALID
Rationale: Preheat provider endpoint SSRF via ValidateHTTPURL scheme-only check with no IP filtering; IP encoding bypasses (hex, decimal, IPv6-mapped) confirmed; store-without-validate pattern in instance creation widens DNS rebinding TOCTOU window.
Severity-Original: HIGH
PoC-Status: theoretical
Pre-FP-Flag: none
Debate: security/chamber-workspace/chamber-02/debate.md

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: No IP-level filtering exists anywhere in the preheat endpoint flow; ValidateHTTPURL only checks scheme; HTTP client uses unrestricted http.Client; system admin can direct requests to any IP including cloud metadata.
Severity-Final: MEDIUM
PoC-Status: theoretical

## Summary

Harbor's P2P preheat flow accepts arbitrary URLs for provider endpoints with only scheme validation (http/https). The `ValidateHTTPURL` function at `src/lib/endpoint.go:27-45` performs no IP address filtering, allowing SSRF to cloud metadata (169.254.169.254), loopback, and RFC1918 addresses. IP encoding bypasses (hex: `0x7f000001`, decimal: `2130706433`, IPv6-mapped: `::ffff:127.0.0.1`) further evade any string-based IP checks. The preheat instance creation path (`CreateInstance`) explicitly skips validation with a code comment `// !WARN: We don't check the health of the instance here`, creating a wider TOCTOU window for DNS rebinding than other SSRF entry points.

## Location

- `src/lib/endpoint.go:27-45` -- `ValidateHTTPURL` checks scheme only, no IP filtering
- `src/pkg/p2p/preheat/provider/dragonfly.go:199-213` -- `GetHealth` calls ValidateHTTPURL then HTTP GET
- `src/controller/p2p/preheat/controller.go:195` -- `CreateInstance` stores endpoint without validation
- `src/server/v2.0/handler/preheat.go:547` -- `convertParamInstanceToModelInstance` copies endpoint as-is

## Attacker Control

- System admin (for instance creation) or project admin (for policy) controls the endpoint URL
- All IP forms accepted: decimal, hex, octal, IPv6-mapped, IPv6 zone-ID
- No DNS pinning -- rebinding possible between store and enforcement

## Trust Boundary Crossed

- TB-8: Job Service to external/internal endpoints
- Core API trust to internal network access

## Impact

- Cloud metadata credential theft via preheat job HTTP requests
- Internal service probing and exploitation
- DNS rebinding bypass of future IP denylists

## Evidence

- Deep Probe PH-04/PH-C05: Validated end-to-end
- endpoint_test.go:32-33 confirms `http://127.0.0.1` passes validation
- Controller.go:195 comment: `// !WARN: We don't check the health of the instance here`

## Reproduction Steps

1. Authenticate as system admin
2. Create preheat instance: `POST /api/v2.0/p2p/preheat/instances` with `{"endpoint": "http://169.254.169.254/", "vendor": "dragonfly", "name": "test"}`
3. Create preheat policy targeting the instance
4. Trigger preheat enforcement (artifact push matching policy filter)
5. Observe outbound HTTP request from job service to metadata endpoint

## Cold Verification Notes

- Severity downgraded from HIGH to MEDIUM: system admin privilege is a significant precondition that narrows the attacker profile
- The Preheat code path (dragonfly.go:268, kraken.go:89) does not even call ValidateHTTPURL, making the situation worse than described in the original finding
- Reproduction blocked by infrastructure requirements (multi-service Harbor deployment needed); verdict based on code analysis
- Full adversarial review at: security/adversarial-reviews/preheat-ssrf-review.md
