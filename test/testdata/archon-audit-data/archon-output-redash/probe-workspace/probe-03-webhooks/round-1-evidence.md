# Evidence — Webhooks and Destinations

## [HARVESTER] PH-01: Event webhook used as internal Docker control plane

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/events.py:60-63` — `EventsResource.post` loops `events_list` and calls `self.record_event(event)` for each entry.
2. `redash/handlers/base.py:41-61` — `BaseResource.record_event` → `record_event` adds `user_id`/`org_id`, `user_agent`, `ip`, `timestamp`, then enqueues `record_event_task.delay(options)`.
3. `redash/tasks/general.py:15-27` — `record_event` persists the event and sends `requests.post(hook, json={"schema":..., "data": event.to_dict()})` to each hook.
4. `redash/models/__init__.py:1333-1351` — `Event.record` stores required fields and moves remaining attacker fields into `additional_properties`.

**Sanitizers on path**:
- `redash/tasks/general.py:22-26` — payload is wrapped in `{"schema":..., "data": event.to_dict()}` and sent via `requests.post(..., json=data)` — **Blocks**: prevents the event JSON from being sent as the raw top-level body required by the Docker API container spec in the hypothesis.

**Verdict rationale**: The event webhook payload is not forwarded verbatim; it is wrapped in a schema envelope and transformed via `Event.record`/`event.to_dict()`. The Docker API in the hypothesis expects a top-level container spec, so the request body does not match and the “create container” claim is blocked by the payload transformation.

**Fragility Score** (INVALIDATED only): Fragile
- **Reason**: A single code-level transformation (schema wrapper) prevents this specific payload shape; there is no explicit SSRF guard or payload validator, and any change to the envelope could re-enable the path.

---

## [HARVESTER] PH-02: Non-admin uses destination subscription to trigger internal SSRF

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:115-129` — `AlertSubscriptionListResource.post` requires `require_access(alert, view_only)` and accepts arbitrary `destination_id` in the same org, creating an `AlertSubscription`.
2. `redash/handlers/alerts.py:50-62` — `AlertEvaluateResource.post` (owner/admin) calls `notify_subscriptions(alert, new_state, {})` unconditionally.
3. `redash/tasks/alerts.py:11-16` — `notify_subscriptions` iterates `alert.subscriptions` and calls `subscription.notify(...)`.
4. `redash/models/__init__.py:1477-1486` — `AlertSubscription.notify` delegates to `NotificationDestination.notify` when a destination is present.
5. `redash/models/__init__.py:1437-1440` — `NotificationDestination.notify` resolves the destination and calls `destination.notify(..., self.options)`.
6. `redash/destinations/webhook.py:29-48` — `Webhook.notify` performs `requests.post(options.get("url"), ...)` with no URL filtering.

**Sanitizers on path**:
- None observed.

**Verdict rationale**: Any user with view access to an alert can subscribe it to an existing destination by ID, and the notify pipeline posts directly to the destination URL without SSRF guards. If an admin-created destination points to an internal URL, a non-admin can cause requests to that internal endpoint through alert evaluation.

---

## [HARVESTER] PH-03: Admin-configured webhook used to prune internal containers

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/destinations.py:102-125` — `DestinationListResource.post` (admin) creates destinations using schema validation only.
2. `redash/destinations/webhook.py:13-23` — webhook schema requires only a string `url` (no allowlist or private-range block).
3. `redash/tasks/alerts.py:11-16` → `redash/models/__init__.py:1477-1486` → `redash/models/__init__.py:1437-1440` — notification pipeline resolves destination and calls `notify`.
4. `redash/destinations/webhook.py:29-48` — `Webhook.notify` issues `requests.post(options.get("url"), ...)` directly.

**Sanitizers on path**:
- None observed.

**Verdict rationale**: Admins can configure webhook destinations with arbitrary URLs, and the notify pipeline posts directly to those URLs without SSRF checks. This makes internal endpoints reachable; whether the Docker prune endpoint accepts the exact payload is endpoint-specific, but the outbound request is unblocked.

---

## [HARVESTER] PH-04: Alert evaluation floods webhooks despite should-notify gate

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:50-62` — `AlertEvaluateResource.post` evaluates the alert and calls `notify_subscriptions(alert, new_state, {})` regardless of `should_notify`.
2. `redash/tasks/alerts.py:20-25` — `should_notify` computes rearm gating, but its result only controls state updates.
3. `redash/tasks/alerts.py:11-16` — `notify_subscriptions` calls `subscription.notify(...)` for each subscription.
4. `redash/destinations/webhook.py:29-48` — `Webhook.notify` issues `requests.post(...)` for each notification.

**Sanitizers on path**:
- None observed.

**Verdict rationale**: Manual evaluation always calls `notify_subscriptions`, even when `should_notify` is false. This enables repeated outbound notifications and potential request flooding by alert owners/admins.

---

## [HARVESTER] PH-05: Event ingestion used for database and worker exhaustion

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/events.py:60-63` — `EventsResource.post` reads `request.get_json(force=True)` and iterates `events_list` without size checks.
2. `redash/handlers/base.py:41-61` — `record_event` enqueues a background job for each event via `record_event_task.delay(options)`.
3. `redash/tasks/general.py:15-27` — `record_event` inserts an `Event` row and forwards each event to configured webhooks.
4. `redash/models/__init__.py:1333-1351` — `Event.record` stores required fields and keeps remaining payload in `additional_properties`.

**Sanitizers on path**:
- None observed.

**Verdict rationale**: The handler accepts a JSON list of arbitrary length and enqueues one job per event without rate/size limits. Large lists with large fields can drive DB growth and job queue saturation.

---

## [HARVESTER] PH-01 (Round 2): Destination URL SSRF via schema-only validation

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/destinations.py:102-125` — destination creation uses `ConfigurationContainer` with schema only.
2. `redash/destinations/webhook.py:13-23` — webhook schema requires only a `url` string.
3. `redash/models/__init__.py:1437-1440` — `NotificationDestination.notify` invokes destination notify with stored options.
4. `redash/destinations/webhook.py:29-48` — `Webhook.notify` posts directly to `options.get("url")`.

**Sanitizers on path**:
- None observed.

**Verdict rationale**: URL validation is schema-only; no allowlist or private-range filtering exists before `requests.post`, so internal/metadata URLs are reachable if configured.

---

## [HARVESTER] PH-02 (Round 2): Manual alert evaluation bypasses rearm gating, enabling repeated SSRF spam

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:50-62` — `AlertEvaluateResource.post` always calls `notify_subscriptions`.
2. `redash/tasks/alerts.py:20-25` — `should_notify` only affects state updates; it does not block notifications in manual evaluate.
3. `redash/tasks/alerts.py:11-16` → `redash/destinations/webhook.py:29-48` — subscriptions result in outbound `requests.post` calls.

**Sanitizers on path**:
- None observed.

**Verdict rationale**: The manual evaluation path does not gate notifications on `should_notify`, allowing repeated evaluations to generate bursts of outbound requests.

---

## [HARVESTER] PH-03 (Round 2): Event reporting webhooks allow attacker-controlled payloads to env-configured internal endpoints

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/events.py:60-63` — authenticated users can submit events; each event is forwarded to `record_event`.
2. `redash/handlers/base.py:50-61` — `record_event` enriches event data and enqueues a job.
3. `redash/tasks/general.py:19-26` — for each `EVENT_REPORTING_WEBHOOKS` URL, performs `requests.post(hook, json={"schema":..., "data": event.to_dict()})`.
4. `redash/models/__init__.py:1333-1351` — attacker-supplied fields become `additional_properties` inside `event.to_dict()`.

**Sanitizers on path**:
- None observed (only a schema envelope is added).

**Verdict rationale**: Event data from the user is forwarded to every configured event webhook, and the only transformation is an envelope wrapper. If a hook points to an internal endpoint expecting JSON, attacker-controlled fields reach that endpoint via server-origin requests.

---

## [HARVESTER] PH-01 (Round 3): Webhook destination SSRF depends on external egress controls

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/destinations.py:102-125` — admin can create destinations with arbitrary URL values.
2. `redash/destinations/webhook.py:13-23` — schema requires only a string `url`.
3. `redash/destinations/webhook.py:29-48` — `requests.post(options.get("url"), ...)` with no in-code URL restrictions.

**Sanitizers on path**:
- None observed.

**Verdict rationale**: In-code validation does not restrict internal URLs; only external network controls could prevent access. Without egress filtering, SSRF to internal/metadata endpoints is reachable.

---

## [HARVESTER] PH-02 (Round 3): Event webhook forwarding enables internal action triggers

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/events.py:60-63` — events submitted by authenticated users are forwarded for recording.
2. `redash/handlers/base.py:50-61` — `record_event` enriches and enqueues.
3. `redash/tasks/general.py:19-26` — `requests.post` to each `EVENT_REPORTING_WEBHOOKS` URL with `json={"schema":..., "data": event.to_dict()}`.
4. `redash/models/__init__.py:1333-1351` — attacker fields are preserved in `additional_properties`.

**Sanitizers on path**:
- None observed (payload is wrapped, not validated).

**Verdict rationale**: The event pipeline forwards attacker-controlled event fields to environment-configured webhooks with no URL or payload validation, enabling internal action triggers if hooks are internal.

---

## [HARVESTER] PH-03 (Round 3): Manual alert evaluation bypasses rearm throttling

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:50-62` — `AlertEvaluateResource.post` calls `notify_subscriptions` unconditionally after evaluate.
2. `redash/tasks/alerts.py:20-25` — `should_notify` only affects state updates, not the manual notify call.
3. `redash/tasks/alerts.py:11-16` — subscriptions are notified and downstream `Webhook.notify` posts requests.

**Sanitizers on path**:
- None observed.

**Verdict rationale**: Rearm throttling does not block notifications in manual evaluation, allowing repeated trigger of outbound webhook calls.

---
