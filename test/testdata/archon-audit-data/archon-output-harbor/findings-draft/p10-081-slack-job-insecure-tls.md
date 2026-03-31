Phase: 10
Sequence: 081
Slug: slack-job-insecure-tls
Verdict: VALID
Rationale: SlackJob.init reads skip_cert_verify from user-controlled job parameters and switches to InsecureSkipVerify=true, identical to the confirmed WebhookJob pattern (p7-005), enabling MitM attacks on Slack webhook deliveries.
Severity-Original: MEDIUM
PoC-Status: pending
Origin-Finding: security/findings-draft/p7-005-webhook-insecure-tls.md
Origin-Pattern: AP-028

## Summary

`SlackJob.init()` at `src/jobservice/job/impl/notification/slack_job.go:114-119` reads `skip_cert_verify` from the job parameter map and switches the HTTP client to `httpHelper.clients[insecure]` (`InsecureSkipVerify: true`) when the flag is set. This is the identical code pattern as the confirmed `WebhookJob` finding (p7-005). A project-admin can create a Slack notification policy with `skip_cert_verify: true`, causing Slack webhook deliveries to bypass TLS certificate verification and become vulnerable to MitM interception.

## Location

- **SlackJob init**: `src/jobservice/job/impl/notification/slack_job.go:114-119` -- insecure branch enabled by user parameter
- **Handler origin**: Slack policy created via `POST /api/v2.0/projects/{id}/webhook/policies` with type `slack`
- **Parameter flow**: `SkipCertVerify` field in `src/pkg/notification/policy/model/model.go:97` → persisted to DB → deserialized into job params at `src/pkg/notifier/handler/notification/slack_handler.go:124`

## Attacker Control

- **Input**: `skip_cert_verify: true` in Slack notification policy creation
- **Control level**: Project-admin or above can set this flag
- **Auth requirement**: Project-admin role

## Trust Boundary Crossed

Job Service to external Slack/webhook endpoints (TB-8). When `skip_cert_verify=true` is set, a network-adjacent attacker can present any TLS certificate and intercept or modify the Slack notification payload in transit.

## Impact

- MitM interception of Slack webhook payloads (may contain artifact names, digests, event metadata)
- Same impact as p7-005 but affecting the Slack notification transport path
- No logging or auditing when insecure transport is used
- Persists indefinitely until the policy is updated

## Evidence

```go
// src/jobservice/job/impl/notification/slack_job.go:108-121
func (sj *SlackJob) init(ctx job.Context, params map[string]any) error {
    sj.logger = ctx.GetLogger()

    // default use secure transport
    sj.client = httpHelper.clients[secure]
    if v, ok := params["skip_cert_verify"]; ok {
        if skipCertVerify, ok := v.(bool); ok && skipCertVerify {
            // if skip cert verify is true, it means not verify remote cert, use insecure client
            sj.client = httpHelper.clients[insecure]  // InsecureSkipVerify: true
        }
    }
    return nil
}

// src/pkg/notifier/handler/notification/slack_handler.go:124
"skip_cert_verify": event.Target.SkipCertVerify,  // user-controlled field flows into job params
```

## Reproduction Steps

1. Authenticate as project-admin
2. Create a Slack notification policy:
   ```
   POST /api/v2.0/projects/{id}/webhook/policies
   {
     "name": "slack-alert",
     "event_types": ["ARTIFACT_PUSHED"],
     "targets": [{"type": "slack", "address": "https://hooks.slack.com/...", "skip_cert_verify": true}]
   }
   ```
3. Push an artifact to trigger the Slack notification
4. A network-adjacent attacker can MitM the HTTPS connection to the Slack endpoint
5. Webhook payload is intercepted with no TLS error because certificate validation is disabled
