# Round 2 Hypotheses — Webhooks and Destinations

## PH-01: Alert update rebinds to unauthorized query

- **Reasoning-Model**: TRIZ
- **Target**: `redash/handlers/alerts.py:30-37` — `AlertResource.post`
- **Attacker starting position**: authenticated user who owns the alert but lacks access to target query
- **Attack input / strategy**: `POST /api/alerts/<alert_id>` with JSON `{"query_id": <unauthorized_query_id>, "options": {...}}`, then trigger `/api/alerts/<alert_id>/evaluate` or wait for scheduled evaluation to observe notification state changes.
- **Tension / Game**: Convenience of partial alert edits vs. completeness of access control when switching query bindings.
- **What was sacrificed / Information accumulated**: Re-validation of `query_id` access on update; attacker accumulates alert state/notifications about a query they should not access.
- **Security consequence**: Potential leakage of query state/metadata or alert-triggered notifications for a query outside the attacker’s permissions.
- **Severity estimate**: HIGH
- **Read needed**: `redash/handlers/alerts.py:30-37`
- **Deepening direction**: Check whether update path revalidates query access or enforces org-level ownership elsewhere; confirm alert notification contents for data exposure.

---

## PH-02: Alert deletion lacks audit event forwarding

- **Reasoning-Model**: TRIZ
- **Target**: `redash/handlers/alerts.py:43-47` — `AlertResource.delete`
- **Attacker starting position**: authenticated user who owns the alert
- **Attack input / strategy**: `DELETE /api/alerts/<alert_id>` to remove the alert after suspicious activity; repeat for multiple alerts to minimize audit trail in event webhook reporting.
- **Tension / Game**: Performance/simplicity in delete path vs. auditability of destructive actions.
- **What was sacrificed / Information accumulated**: Event recording is omitted, so external event webhooks never see the deletion.
- **Security consequence**: Stealthy cleanup of alerts without external audit visibility; weakens forensic timeline.
- **Severity estimate**: MEDIUM
- **Read needed**: `redash/handlers/alerts.py:43-47`
- **Deepening direction**: Verify whether any other logging (DB triggers, audit table) records alert deletes; check for API-level monitoring elsewhere.

---

## PH-03: Subscriber list exposure to view-only users

- **Reasoning-Model**: TRIZ
- **Target**: `redash/handlers/alerts.py:143-148` — `AlertSubscriptionListResource.get`
- **Attacker starting position**: authenticated user with view-only access to an alert
- **Attack input / strategy**: `GET /api/alerts/<alert_id>/subscriptions` and harvest `user` fields returned by `AlertSubscription.to_dict()`.
- **Tension / Game**: Collaboration convenience vs. privacy of subscriber identities and potential PII.
- **What was sacrificed / Information accumulated**: Subscriber user details are returned for any viewer of the alert; attacker collects user identity data.
- **Security consequence**: Enumeration of alert subscribers for phishing, social engineering, or user targeting.
- **Severity estimate**: MEDIUM
- **Read needed**: `redash/handlers/alerts.py:143-148`, `redash/models/__init__.py:1465-1470`
- **Deepening direction**: Inspect `User.to_dict()` to see whether email or sensitive identifiers are exposed.

---

## PH-04: Subscription deletion ignores alert_id context

- **Reasoning-Model**: Game-Theory
- **Target**: `redash/handlers/alerts.py:151-156` — `AlertSubscriptionResource.delete`
- **Attacker starting position**: authenticated user (not necessarily with access to the alert in the URL)
- **Attack input / strategy**: Iterate `DELETE /api/alerts/<any>/subscriptions/<subscriber_id>` for sequential IDs; when owned by attacker, deletion succeeds even if the alert is not accessible via the path.
- **Tension / Game**: Simpler lookup by subscription ID vs. binding delete to the alert context.
- **What was sacrificed / Information accumulated**: Authorization tied only to subscription owner; attacker learns which subscription IDs belong to them by response differences.
- **Security consequence**: Ability to unsubscribe from alerts without alert visibility checks; facilitates stealthy opt-out from monitoring.
- **Severity estimate**: MEDIUM
- **Read needed**: `redash/handlers/alerts.py:151-156`
- **Deepening direction**: Confirm response codes for non-owned subscriptions and whether IDs are guessable/monotonic.

---

## PH-05: Event webhook amplification via record_event

- **Reasoning-Model**: TRIZ + Game-Theory
- **Target**: `redash/handlers/base.py:41-61` — `BaseResource.record_event` / `record_event`; `redash/tasks/general.py:19-27` — `record_event`
- **Attacker starting position**: authenticated user with access to endpoints that call `record_event` (e.g., alert view/mute/list, destination view/delete)
- **Attack input / strategy**: Loop high-rate calls to event-recording endpoints (e.g., `GET /api/alerts/<id>`, `POST /api/alerts/<id>/mute`, `GET /api/destinations/<id>`) to generate a burst of event webhook POSTs to each `EVENT_REPORTING_WEBHOOKS` URL.
- **Tension / Game**: Observability/audit trails vs. resilience against abuse of logging side effects.
- **What was sacrificed / Information accumulated**: No rate-limit or throttling on event recording; attacker can amplify request count into outbound webhook traffic and observe which requests consistently succeed/fail via timing and system load.
- **Security consequence**: Potential DoS of internal webhook targets or abuse as SSRF traffic source if hooks target internal endpoints.
- **Severity estimate**: MEDIUM
- **Read needed**: `redash/handlers/base.py:41-61`, `redash/tasks/general.py:19-27`
- **Deepening direction**: Verify any global rate limiting on record_event or queue worker, and whether webhook URLs include internal/private endpoints.

---

## PH-06: Event webhook envelope still reaches internal JSON endpoints

- **Reasoning-Model**: TRIZ + Game-Theory
- **Target**: `redash/tasks/general.py:19-27` — `record_event` (webhook envelope)
- **Attacker starting position**: authenticated user who can influence event payloads (via EventsResource.post) and trigger event forwarding
- **Attack input / strategy**: Send crafted event list to `POST /api/events` where each event contains attacker-controlled fields; then trigger forwarding to `EVENT_REPORTING_WEBHOOKS` that point to internal services accepting generic JSON, even if Docker API rejects the envelope.
- **Tension / Game**: Standardized webhook schema vs. compatibility with diverse webhook endpoints; attacker adapts by targeting endpoints that ignore unknown fields or parse nested `data`.
- **What was sacrificed / Information accumulated**: Endpoint validation/allowlist is absent; attacker learns which internal endpoints accept the envelope by observing side effects and response timing.
- **Security consequence**: SSRF-style access to internal JSON endpoints or unintended actions where the envelope is tolerated.
- **Severity estimate**: HIGH
- **Read needed**: `redash/tasks/general.py:19-27`, `redash/handlers/events.py:60-63`
- **Deepening direction**: Identify internal endpoints that accept arbitrary JSON (metrics/logging/CI hooks) and whether they can act on nested `data` fields.

---

## PH-07: Silent enumeration of destination types

- **Reasoning-Model**: TRIZ
- **Target**: `redash/handlers/destinations.py:15-18` — `DestinationTypeListResource.get`
- **Attacker starting position**: authenticated admin (or compromised admin session)
- **Attack input / strategy**: `GET /api/destination_types` to list all registered destinations, then choose the weakest-validation destination for SSRF-style webhook targets.
- **Tension / Game**: Admin convenience for UI configuration vs. visibility/auditability of destination capability discovery.
- **What was sacrificed / Information accumulated**: No event record or additional guard on the enumeration path; attacker learns which destination families (e.g., webhook types) are enabled.
- **Security consequence**: Increases attacker efficiency in selecting the most permissive outbound channel.
- **Severity estimate**: MEDIUM
- **Read needed**: `redash/handlers/destinations.py:15-18`
- **Deepening direction**: Check if any destination types have especially permissive schemas (e.g., raw JSON templates or custom headers).

---

## PH-08: Events listing exposes user metadata without access logging

- **Reasoning-Model**: TRIZ
- **Target**: `redash/handlers/events.py:65-69` — `EventsResource.get`
- **Attacker starting position**: authenticated admin
- **Attack input / strategy**: Paginate through `GET /api/events?page=N&page_size=250` to extract user-agent/IP and object details at scale.
- **Tension / Game**: Admin observability vs. privacy and audit of who accessed event logs.
- **What was sacrificed / Information accumulated**: No record_event call on event log access; attacker can quietly harvest org activity metadata.
- **Security consequence**: Privacy exposure (user agents, IPs, activity timeline) with limited traceability of access.
- **Severity estimate**: MEDIUM
- **Read needed**: `redash/handlers/events.py:65-69`
- **Deepening direction**: Confirm serialized event fields and whether sensitive values (API key names, user agents, IPs) are included.

---

## Coverage Check

| Entry Point | TRIZ tension found? | Game Theory mechanism found? |
|------------|:-:|:-:|
| DestinationTypeListResource.get | PH-07 / YES — enumeration vs audit | NO — no repeated-interaction mechanism beyond enumeration |
| DestinationResource.get | PH-05 / YES — audit vs abuse of event hooks | PH-05 / YES — amplification through repeated GETs |
| DestinationResource.delete | PH-05 / YES — audit vs abuse of event hooks | PH-05 / YES — amplification through repeated DELETEs |
| AlertResource.get | PH-05 / YES — audit vs abuse of event hooks | PH-05 / YES — amplification through repeated GETs |
| AlertResource.post | PH-01 / YES — partial update vs access revalidation | PH-05 / YES — amplification through repeated POSTs |
| AlertResource.delete | PH-02 / YES — delete simplicity vs audit trail | NO — single-shot delete; no repeated-interaction advantage noted |
| AlertMuteResource.post | PH-05 / YES — audit vs abuse of event hooks | PH-05 / YES — toggle loop amplification |
| AlertMuteResource.delete | PH-05 / YES — audit vs abuse of event hooks | PH-05 / YES — toggle loop amplification |
| AlertSubscriptionListResource.get | PH-03 / YES — collaboration vs privacy | NO — one-shot disclosure; no learning loop required |
| AlertSubscriptionResource.delete | PH-04 / YES — convenience vs contextual auth | PH-04 / YES — ID-guessing with response feedback |
| AlertListResource.get | PH-05 / YES — audit vs abuse of event hooks | PH-05 / YES — repeated list polling |
| EventsResource.get | PH-08 / YES — admin observability vs privacy/audit | NO — listing is informative but not adaptive probing |

| Trust Chain Gap | TRIZ hypothesis generated? |
|----------------|:-:|
| Destination URLs are validated only by schema type/required fields; no protocol/domain allowlist and no SSRF guard on outbound requests. | PH-05 / YES — event hook amplification highlights lack of outbound restrictions (adjacent trust gap) |
| Event reporting webhooks use environment-configured URLs, bypassing destination validation entirely. | PH-06 / YES — envelope-compatible internal endpoints + no validation |
| All destinations use raw `requests.post` (no private-address blocking), so internal/metadata endpoints remain reachable if configured. | PH-06 / YES — internal endpoint targeting via webhook envelope |

| Interactive Mechanism | Game Theory hypothesis generated? |
|----------------------|:-:|
| Event recording to `EVENT_REPORTING_WEBHOOKS` | PH-05 / YES — amplification via repeated record_event-triggering calls |
| Alert subscription deletion by ID | PH-04 / YES — response feedback on guessed IDs |
| Events pagination | NO — no adaptive advantage beyond bulk enumeration |
