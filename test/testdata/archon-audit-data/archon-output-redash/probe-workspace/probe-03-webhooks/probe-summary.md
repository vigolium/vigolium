# Deep Probe Summary: Webhooks and destinations

Status: complete
Loops: 2
Total hypotheses: 40
Validated: 22
Needs-Deeper: 0
Stop reason: covered all entry points

## Validated Hypotheses

### PH-02: Non-admin uses destination subscription to trigger internal SSRF
- Reasoning-Model: Pre-Mortem
- Target: `redash/handlers/alerts.py:116` — `AlertSubscriptionListResource.post`
- Attack input: `POST /api/alerts/<id>/subscriptions` with `destination_id` pointing to an internal webhook
- Code path: `AlertSubscriptionListResource.post` → `AlertSubscription.notify` → `NotificationDestination.notify` → `Webhook.notify`
- Sanitizers on path: none
- Security consequence: non-admins can trigger internal HTTP requests if an admin-configured destination targets internal services
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-03: Admin-configured webhook SSRF to internal endpoints
- Reasoning-Model: Pre-Mortem
- Target: `redash/destinations/webhook.py:29` — `Webhook.notify`
- Attack input: create webhook destination with internal URL, then trigger alert evaluation
- Code path: `DestinationListResource.post` → `NotificationDestination.notify` → `Webhook.notify`
- Sanitizers on path: none
- Security consequence: SSRF to internal/metadata endpoints via webhook destinations
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-04: Manual alert evaluation bypasses rearm gating
- Reasoning-Model: Pre-Mortem + Causal
- Target: `redash/handlers/alerts.py:51` — `AlertEvaluateResource.post`
- Attack input: repeated `POST /api/alerts/<id>/evaluate`
- Code path: `AlertEvaluateResource.post` → `notify_subscriptions` → destination `notify`
- Sanitizers on path: `should_notify` (bypassable; does not gate notifications)
- Security consequence: outbound notification spam/DoS, SSRF amplification
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md / round-1-evidence-loop2.md

### PH-05: Event ingestion causes DB/worker exhaustion
- Reasoning-Model: Pre-Mortem
- Target: `redash/handlers/events.py:60` — `EventsResource.post`
- Attack input: `POST /api/events` with large event arrays/fields
- Code path: `EventsResource.post` → `record_event_task.delay` → `tasks/general.py:record_event`
- Sanitizers on path: none
- Security consequence: queue saturation and storage growth, degrading alert delivery
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-01 (Round 2): Destination URL SSRF via schema-only validation
- Reasoning-Model: TRIZ
- Target: `redash/handlers/destinations.py:102-113` — `DestinationListResource.post`
- Attack input: create destination with internal URL; trigger notifications
- Code path: `DestinationListResource.post` → `Webhook.notify`
- Sanitizers on path: schema-only validation (no URL allowlist)
- Security consequence: SSRF to internal services
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-03 (Round 2): Event webhook forwarding to env-configured URLs
- Reasoning-Model: TRIZ
- Target: `redash/tasks/general.py:19-26` — `record_event`
- Attack input: `POST /api/events` with crafted event payload
- Code path: `EventsResource.post` → `record_event` → `requests.post(hook, json={schema,data})`
- Sanitizers on path: none (envelope only)
- Security consequence: attacker-controlled payloads forwarded to internal hooks if configured
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-12: Event webhook envelope still exploitable
- Reasoning-Model: Pre-Mortem
- Target: `redash/tasks/general.py:15-27` — `record_event`
- Attack input: crafted event payloads to `/api/events` and internal hook configured
- Code path: `EventsResource.post` → `record_event` → `requests.post` envelope
- Sanitizers on path: none
- Security consequence: internal JSON endpoints can be targeted even with envelope wrapper
- Severity estimate: HIGH
- Evidence file: round-1-evidence-loop2.md

### PH-01 (Loop2 Round-2): Alert update rebinds to unauthorized query
- Reasoning-Model: TRIZ + Causal
- Target: `redash/handlers/alerts.py:30-37` — `AlertResource.post`
- Attack input: `POST /api/alerts/<id>` with `query_id` of unauthorized query
- Code path: `AlertResource.post` → `update_model` (no query access check)
- Sanitizers on path: none
- Security consequence: unauthorized data exposure via alert notifications
- Severity estimate: HIGH
- Evidence file: round-1-evidence-loop2.md

### PH-02 (Loop2 Round-2): Alert deletion lacks event forwarding
- Reasoning-Model: TRIZ + Causal
- Target: `redash/handlers/alerts.py:43-47` — `AlertResource.delete`
- Attack input: `DELETE /api/alerts/<id>` by owner/admin
- Code path: delete without `record_event`
- Sanitizers on path: none
- Security consequence: stealthy removal of monitoring with reduced audit trail
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-03 (Loop2 Round-2): Subscriber list exposes PII to alert viewers
- Reasoning-Model: TRIZ + Causal
- Target: `redash/handlers/alerts.py:143-148` — `AlertSubscriptionListResource.get`
- Attack input: `GET /api/alerts/<id>/subscriptions` by view-only user
- Code path: `AlertSubscription.to_dict` → `User.to_dict` (email/groups)
- Sanitizers on path: none
- Security consequence: PII leakage enabling targeted phishing
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-04 (Loop2 Round-2): Subscription deletion ignores alert_id context
- Reasoning-Model: Game-Theory
- Target: `redash/handlers/alerts.py:152-156` — `AlertSubscriptionResource.delete`
- Attack input: delete subscription by ID without alert context validation
- Code path: `AlertSubscription.query.get_or_404` → `require_admin_or_owner` → delete
- Sanitizers on path: partial (owner check only)
- Security consequence: users can delete their subscriptions without alert context checks; enables stealth opt-out
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-05 (Loop2 Round-2): Event webhook amplification via record_event
- Reasoning-Model: TRIZ + Game-Theory
- Target: `redash/handlers/base.py:41-61` — `record_event`
- Attack input: repeated calls to event-recording endpoints
- Code path: `record_event_task.delay` → `tasks/general.py:record_event` → webhook posts
- Sanitizers on path: none
- Security consequence: outbound webhook amplification/DoS against configured hooks
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-06 (Loop2 Round-2): Event webhook envelope to internal JSON endpoints
- Reasoning-Model: TRIZ + Game-Theory
- Target: `redash/tasks/general.py:15-27` — `record_event`
- Attack input: crafted events, internal hook configured
- Code path: `EventsResource.post` → `record_event` → `requests.post` envelope
- Sanitizers on path: none
- Security consequence: SSRF-style access to internal JSON endpoints
- Severity estimate: HIGH
- Evidence file: round-1-evidence-loop2.md

### PH-07 (Loop2 Round-2): Destination type enumeration is unaudited
- Reasoning-Model: TRIZ
- Target: `redash/handlers/destinations.py:15-18` — `DestinationTypeListResource.get`
- Attack input: `GET /api/destinations/types` by admin
- Code path: returns list without `record_event`
- Sanitizers on path: none
- Security consequence: silent reconnaissance of available destinations
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-08 (Loop2 Round-2): Event listing exposes metadata without access logging
- Reasoning-Model: TRIZ + Causal
- Target: `redash/handlers/events.py:65-69` — `EventsResource.get`
- Attack input: paginate event logs as admin
- Code path: `serialize_event` includes user agent/location; no `record_event`
- Sanitizers on path: none
- Security consequence: stealthy metadata harvesting
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-13 (Loop2 Round-3): Rearm check not causally gating notifications
- Reasoning-Model: Causal
- Target: `redash/handlers/alerts.py:51-62` — `AlertEvaluateResource.post`
- Attack input: repeated manual evaluations
- Code path: `notify_subscriptions` called regardless of `should_notify`
- Sanitizers on path: `should_notify` (ineffective)
- Security consequence: notification spam/DoS, SSRF amplification
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-14 (Loop2 Round-3): Subscription list discloses subscriber PII
- Reasoning-Model: Causal
- Target: `redash/handlers/alerts.py:143-148` — `AlertSubscriptionListResource.get`
- Attack input: view-only user lists subscriptions
- Code path: `AlertSubscription.to_dict` → `User.to_dict` (email/groups)
- Sanitizers on path: none
- Security consequence: PII leakage
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-15 (Loop2 Round-3): Alert update can rebind to unauthorized queries
- Reasoning-Model: Causal
- Target: `redash/handlers/alerts.py:30-37` — `AlertResource.post`
- Attack input: update alert with unauthorized `query_id`
- Code path: `update_model` sets new `query_id` without access check
- Sanitizers on path: none
- Security consequence: unauthorized data exposure via notifications
- Severity estimate: HIGH
- Evidence file: round-1-evidence-loop2.md

### PH-18 (Loop2 Round-3): Alert deletion unaudited by event webhooks
- Reasoning-Model: Causal
- Target: `redash/handlers/alerts.py:43-47` — `AlertResource.delete`
- Attack input: delete alert
- Code path: delete without `record_event`
- Sanitizers on path: none
- Security consequence: stealthy removal of detection rules
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-19 (Loop2 Round-3): Destination schema validation not protective against SSRF
- Reasoning-Model: Causal
- Target: `redash/handlers/destinations.py:102-113` — `DestinationListResource.post`
- Attack input: create destination with internal URL
- Code path: schema validation only → `Webhook.notify`
- Sanitizers on path: schema-only validation (insufficient)
- Security consequence: SSRF to internal endpoints
- Severity estimate: HIGH
- Evidence file: round-1-evidence-loop2.md

### PH-21 (Loop2 Round-3): Base URL used in notification links without validation
- Reasoning-Model: Causal
- Target: `redash/destinations/hangoutschat.py:70` — `HangoutsChat.notify`
- Attack input: misconfigured org base URL
- Code path: `utils.base_url` → link embedding
- Sanitizers on path: none
- Security consequence: phishing links in notifications
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

### PH-23 (Loop2 Round-3): Event log access is unrecorded
- Reasoning-Model: Causal
- Target: `redash/handlers/events.py:65-69` — `EventsResource.get`
- Attack input: admin lists events
- Code path: `serialize_event` without `record_event`
- Sanitizers on path: none
- Security consequence: stealthy metadata harvesting
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence-loop2.md

## NEEDS-DEEPER

None.

## Coverage Summary
| Entry Point | backward-reasoner | contradiction-reasoner | causal-verifier |
|------------|:-:|:-:|:-:|
| DestinationTypeListResource.get | PH-01 (loop2) | PH-07 (loop2) | PH-07 (loop2) |
| DestinationResource.get | PH-02 (loop2) | PH-05 (loop2) | PH-17 (loop2, invalidated) |
| DestinationResource.delete | PH-03 (loop2) | PH-05 (loop2) | PH-18 (loop2) |
| AlertResource.get | PH-04 (loop2) | PH-05 (loop2) | — |
| AlertResource.post | PH-05 (loop2) | PH-01 (loop2) | PH-15 (loop2) |
| AlertResource.delete | PH-06 (loop2) | PH-02 (loop2) | PH-18 (loop2) |
| AlertMuteResource.post/delete | PH-07 (loop2) | PH-05 (loop2) | — |
| AlertSubscriptionListResource.get | PH-08 (loop2) | PH-03 (loop2) | PH-14 (loop2) |
| AlertSubscriptionResource.delete | PH-09 (loop2) | PH-04 (loop2) | — |
| AlertListResource.get | PH-10 (loop2) | PH-05 (loop2) | — |
| EventsResource.get | PH-11 (loop2) | PH-08 (loop2) | PH-23 (loop2) |
| EventsResource.post | PH-12 (loop2) | PH-06 (loop2) | PH-16 (loop2, invalidated) |
