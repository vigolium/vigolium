## CROSS-01: Admin webhook SSRF to internal services

Source-A: PH-03 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-01 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Both target `Webhook.notify` using admin-configured destination URLs that flow directly into `requests.post` without SSRF guard. Same file/function and trust boundary (admin config → outbound HTTP).
Combined hypothesis: Admin can configure webhook destinations to internal/metadata endpoints, leading to SSRF-triggered internal actions (e.g., Docker API, metadata read) when alerts fire.
Test direction for causal-verifier: Check whether any URL validation/allowlist or private-address blocking exists in destination schema or notify path; confirm redirects are not filtered.

## CROSS-02: Event webhook payload forwarding to internal endpoints

Source-A: PH-01 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-03 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Both rely on `tasks/general.py:record_event` forwarding attacker-supplied event JSON to env-configured webhook URLs. Same trust boundary (user-controlled event data → internal webhook URL).
Combined hypothesis: Authenticated users can inject arbitrary event payloads that are forwarded to internal endpoints configured in `EVENT_REPORTING_WEBHOOKS`, enabling internal action triggers (e.g., Docker API or internal service control).
Test direction for causal-verifier: Verify `/api/events` authentication/authorization, confirm event payload is forwarded verbatim, and assess whether hooks are commonly set to internal endpoints.

## CROSS-03: Manual alert evaluation bypasses notification gating

Source-A: PH-04 from backward-reasoner (round-1-hypotheses.md)
Source-B: PH-02 from contradiction-reasoner (round-2-hypotheses.md)
Connection: Both point to `AlertEvaluateResource.post` calling `notify_subscriptions` even when `should_notify` is false, enabling repeated outbound requests. Same function and trust boundary (manual eval → outbound webhooks).
Combined hypothesis: Alert owners can spam webhook destinations or amplify SSRF by repeatedly invoking manual evaluation despite rearm throttling.
Test direction for causal-verifier: Confirm control flow for `should_notify` vs `notify_subscriptions` and whether rate limiting/rearm is enforced elsewhere.
