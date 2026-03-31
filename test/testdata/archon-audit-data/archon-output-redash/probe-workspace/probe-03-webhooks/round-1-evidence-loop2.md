# Evidence — webhooks

## [HARVESTER] PH-01 (Round-1): Non-admin enumeration of destination types enables targeted webhook abuse

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/destinations.py:15-18` — `DestinationTypeListResource.get` is guarded by `@require_admin` and returns destination type list.

**Sanitizers on path**:
- `redash/handlers/destinations.py:16` — `require_admin` — Blocks: non-admin requests are denied.

**Verdict rationale**: The handler is admin-only; a non-admin cannot access the list of destination types.

**Fragility Score**: Fragile
- **Reason**: Single code-level admin check with no defense-in-depth.

---

## [HARVESTER] PH-02 (Round-1): Unauthorized read of destination configuration leaks webhook URLs

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/destinations.py:21-33` — `DestinationResource.get` is guarded by `@require_admin`, loads destination, returns `destination.to_dict(all=True)`.

**Sanitizers on path**:
- `redash/handlers/destinations.py:22` — `require_admin` — Blocks: non-admin requests are denied.

**Verdict rationale**: Destination detail is admin-only; non-admins cannot read destination configuration.

**Fragility Score**: Fragile
- **Reason**: Single admin gate; no additional access control layers on this endpoint.

---

## [HARVESTER] PH-03 (Round-1): Unauthorized destination deletion causes alerting blackout

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/destinations.py:63-77` — `DestinationResource.delete` is guarded by `@require_admin` and deletes destination.

**Sanitizers on path**:
- `redash/handlers/destinations.py:63` — `require_admin` — Blocks: non-admin requests are denied.

**Verdict rationale**: Only admins can delete destinations, preventing non-admin deletion.

**Fragility Score**: Fragile
- **Reason**: Single admin check; no secondary control.

---

## [HARVESTER] PH-04 (Round-1): Unauthorized alert read reveals sensitive query context

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/alerts.py:24-28` — `AlertResource.get` loads alert and enforces `require_access(..., view_only)` before `serialize_alert`.

**Sanitizers on path**:
- `redash/handlers/alerts.py:26` — `require_access` — Blocks: users without view access are denied.

**Verdict rationale**: Access is explicitly checked before serialization.

**Fragility Score**: Fragile
- **Reason**: Single access-control check; no defense-in-depth.

---

## [HARVESTER] PH-05 (Round-1): Unauthorized alert update enables data exfil via future notifications

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/alerts.py:30-41` — `AlertResource.post` requires `require_admin_or_owner`, then updates and commits the alert.

**Sanitizers on path**:
- `redash/handlers/alerts.py:34` — `require_admin_or_owner` — Blocks: non-admin, non-owner cannot update the alert.

**Verdict rationale**: The update endpoint is restricted to admins or the alert owner.

**Fragility Score**: Fragile
- **Reason**: Single owner/admin check.

---

## [HARVESTER] PH-06 (Round-1): Unauthorized alert deletion suppresses monitoring

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/alerts.py:43-47` — `AlertResource.delete` requires `require_admin_or_owner` before deletion.

**Sanitizers on path**:
- `redash/handlers/alerts.py:45` — `require_admin_or_owner` — Blocks: non-admin, non-owner cannot delete.

**Verdict rationale**: Deletion is restricted to admins or owners.

**Fragility Score**: Fragile
- **Reason**: Single access-control check.

---

## [HARVESTER] PH-07 (Round-1): Unauthorized mute/unmute toggles suppress alerting

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/alerts.py:66-82` — `AlertMuteResource.post/delete` require `require_admin_or_owner` before muting/unmuting.

**Sanitizers on path**:
- `redash/handlers/alerts.py:68` — `require_admin_or_owner` — Blocks: non-admin, non-owner cannot mute.
- `redash/handlers/alerts.py:77` — `require_admin_or_owner` — Blocks: non-admin, non-owner cannot unmute.

**Verdict rationale**: Both mute and unmute endpoints require admin or owner.

**Fragility Score**: Fragile
- **Reason**: Single access-control check per action.

---

## [HARVESTER] PH-08 (Round-1): Subscription list exposes destination URLs to non-admin users

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/alerts.py:143-148` — `AlertSubscriptionListResource.get` loads alert and returns `[s.to_dict() ...]`.
2. `redash/models/__init__.py:1465-1470` — `AlertSubscription.to_dict` includes `destination.to_dict()` when present.
3. `redash/models/__init__.py:1412-1424` — `NotificationDestination.to_dict` returns only id/name/type/icon unless `all=True` (no options/URL).

**Sanitizers on path**:
- `redash/models/__init__.py:1412-1424` — `NotificationDestination.to_dict` — Blocks: destination options (including URLs) are not included when `all=False`.

**Verdict rationale**: The subscription list returns destination metadata only; destination options/URLs are omitted by default.

**Fragility Score**: Fragile
- **Reason**: Single serialization choice (omit options) is the only protection.

---

## [HARVESTER] PH-09 (Round-1): Unauthorized subscription deletion removes alert recipients

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/alerts.py:152-158` — `AlertSubscriptionResource.delete` loads subscription and requires `require_admin_or_owner(subscription.user.id)`.

**Sanitizers on path**:
- `redash/handlers/alerts.py:154` — `require_admin_or_owner` — Blocks: non-admin, non-owner cannot delete another user’s subscription.

**Verdict rationale**: Deletion is restricted to admins or the subscription owner.

**Fragility Score**: Fragile
- **Reason**: Single owner/admin check.

---

## [HARVESTER] PH-10 (Round-1): Alert list enumeration exposes sensitive alert inventory

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/alerts.py:109-112` — `AlertListResource.get` requires `@require_permission("list_alerts")` before listing alerts.

**Sanitizers on path**:
- `redash/handlers/alerts.py:109` — `require_permission("list_alerts")` — Blocks: users without permission cannot list.

**Verdict rationale**: Listing alerts is permission-guarded.

**Fragility Score**: Fragile
- **Reason**: Single permission gate.

---

## [HARVESTER] PH-11 (Round-1): Event log access leaks IP/User-Agent for targeted attacks

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/events.py:65-69` — `EventsResource.get` is guarded by `@require_admin` and paginates events with `serialize_event`.

**Sanitizers on path**:
- `redash/handlers/events.py:65` — `require_admin` — Blocks: non-admin users cannot access event logs.

**Verdict rationale**: Event listing is admin-only.

**Fragility Score**: Fragile
- **Reason**: Single admin check.

---

## [HARVESTER] PH-12 (Round-1): Event webhook envelope still exploitable against internal endpoints

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/events.py:60-63` — `EventsResource.post` accepts JSON list and calls `self.record_event(event)` for each entry.
2. `redash/handlers/base.py:41-61` — `BaseResource.record_event` calls module `record_event`, which enriches options and enqueues `record_event_task.delay`.
3. `redash/tasks/general.py:15-27` — `record_event` records the event and POSTs the `{schema,data}` envelope to each `EVENT_REPORTING_WEBHOOKS` URL via `requests.post`.

**Sanitizers on path**:
- None.

**Verdict rationale**: Authenticated callers can submit arbitrary event payloads to `/api/events`, which are forwarded to configured webhooks without validation or URL restrictions.

---

## [HARVESTER] PH-01 (Round-2): Alert update rebinds to unauthorized query

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:30-37` — `AlertResource.post` accepts `query_id` in `params` and updates the alert after `require_admin_or_owner`.
2. `redash/handlers/alerts.py:36-37` — `update_model` sets attributes directly; no `require_access` on the new `query_id`.

**Sanitizers on path**:
- None (no access validation for updated `query_id`).

**Verdict rationale**: The update path lacks a query access check; owners can rebind alerts to queries they cannot access.

---

## [HARVESTER] PH-02 (Round-2): Alert deletion lacks audit event forwarding

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:43-47` — `AlertResource.delete` deletes and commits without calling `record_event`.

**Sanitizers on path**:
- None.

**Verdict rationale**: The delete path omits event recording, so deletion is not forwarded to event webhooks.

---

## [HARVESTER] PH-03 (Round-2): Subscriber list exposure to view-only users

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:143-148` — `AlertSubscriptionListResource.get` returns `[s.to_dict() ...]` for any user with view access.
2. `redash/models/__init__.py:1465-1467` — `AlertSubscription.to_dict` includes `user.to_dict()`.
3. `redash/models/users.py:128-158` — `User.to_dict` includes `email` and `groups` fields.

**Sanitizers on path**:
- None.

**Verdict rationale**: View-only access permits subscription listing and exposes user emails and group IDs.

---

## [HARVESTER] PH-04 (Round-2): Subscription deletion ignores alert_id context

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:152-156` — `AlertSubscriptionResource.delete` looks up subscription by `subscriber_id` only and deletes after `require_admin_or_owner(subscription.user.id)`.

**Sanitizers on path**:
- `redash/handlers/alerts.py:154` — `require_admin_or_owner` — Partial: only prevents deleting other users’ subscriptions, but does not bind deletion to `alert_id` context.

**Verdict rationale**: The delete operation is authorized solely by subscription ownership and ignores the `alert_id` in the URL.

---

## [HARVESTER] PH-05 (Round-2): Event webhook amplification via record_event

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/base.py:41-61` — `record_event` enriches event data and enqueues `record_event_task.delay` on every call.
2. `redash/tasks/general.py:15-27` — `record_event` POSTs each event envelope to every configured webhook URL.

**Sanitizers on path**:
- None.

**Verdict rationale**: There is no throttling or rate-limit in `record_event`; repeated calls amplify outbound webhook traffic.

---

## [HARVESTER] PH-06 (Round-2): Event webhook envelope still reaches internal JSON endpoints

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/events.py:60-63` — `EventsResource.post` forwards each event via `self.record_event`.
2. `redash/handlers/base.py:41-61` — `record_event` enqueues the task.
3. `redash/tasks/general.py:15-27` — `record_event` POSTs `{schema,data}` envelope to each hook.

**Sanitizers on path**:
- None.

**Verdict rationale**: The event payload is forwarded to webhook URLs without validation or filtering, enabling envelope delivery to internal endpoints.

---

## [HARVESTER] PH-07 (Round-2): Silent enumeration of destination types

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/destinations.py:15-18` — `DestinationTypeListResource.get` returns type list; no `record_event` call.

**Sanitizers on path**:
- None.

**Verdict rationale**: Enumeration is admin-only but is not recorded in events, enabling silent discovery.

---

## [HARVESTER] PH-08 (Round-2): Events listing exposes user metadata without access logging

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/events.py:65-69` — `EventsResource.get` returns `serialize_event` output without calling `record_event`.
2. `redash/handlers/events.py:36-54` — `serialize_event` includes user agent (`browser`) and `location` derived from IP.

**Sanitizers on path**:
- None.

**Verdict rationale**: Admins can list events containing user-agent/IP-derived metadata without generating an audit event.

---

## [HARVESTER] PH-13 (Round-3): Rearm check is not causally gating manual alert notifications

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:55-59` — `should_notify` only gates state update.
2. `redash/handlers/alerts.py:61-62` — `notify_subscriptions` called regardless of `should_notify`.
3. `redash/tasks/alerts.py:11-17` — `notify_subscriptions` iterates and calls `subscription.notify` for each subscription.

**Sanitizers on path**:
- `redash/handlers/alerts.py:56` — `should_notify` — Bypassable: notification still happens even when it returns false.

**Verdict rationale**: Manual evaluation always triggers notifications, enabling spam regardless of rearm gating.

---

## [HARVESTER] PH-14 (Round-3): Subscription list discloses subscriber PII to any alert viewer

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:143-148` — `AlertSubscriptionListResource.get` returns subscriptions for any viewer.
2. `redash/models/__init__.py:1465-1467` — `AlertSubscription.to_dict` includes `user.to_dict()`.
3. `redash/models/users.py:128-148` — `User.to_dict` includes `email`, `groups`, and status fields.

**Sanitizers on path**:
- None.

**Verdict rationale**: View-only access is sufficient to retrieve subscriber emails and group IDs.

---

## [HARVESTER] PH-15 (Round-3): Alert update can rebind to unauthorized queries without access revalidation

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:30-37` — `AlertResource.post` updates `query_id` without calling `require_access` on the new query.

**Sanitizers on path**:
- None.

**Verdict rationale**: The update path lacks query access validation, allowing rebinding by owners.

---

## [HARVESTER] PH-16 (Round-3): Event webhook forwarding relies on external gating of `/api/events`

**Verdict**: INVALIDATED

**Code path**:
1. `redash/handlers/base.py:21-22` — `BaseResource` applies `login_required` to all derived resources.
2. `redash/handlers/events.py:59-63` — `EventsResource.post` inherits the login requirement.

**Sanitizers on path**:
- `redash/handlers/base.py:21-22` — `login_required` — Blocks: unauthenticated requests to `/api/events`.

**Verdict rationale**: The endpoint is guarded by `login_required`; unauthenticated callers are blocked without relying on external gating.

**Fragility Score**: Fragile
- **Reason**: Single authentication check is the only barrier.

---

## [HARVESTER] PH-17 (Round-3): Secret masking is dormant for webhook URLs

**Verdict**: INVALIDATED

**Code path**:
1. `redash/models/__init__.py:1412-1424` — `NotificationDestination.to_dict(all=True)` calls `options.to_dict(mask_secrets=True)`.
2. `redash/utils/configuration.py:61-69` — `ConfigurationContainer.to_dict` masks keys listed in schema `secret`.
3. `redash/destinations/webhook.py:13-23` — Webhook schema marks `url` as secret.
4. `redash/destinations/slack.py:11-18` — Slack schema marks `url` as secret (same for other webhook-like destinations).

**Sanitizers on path**:
- `redash/utils/configuration.py:61-69` — `to_dict(mask_secrets=True)` — Blocks: secrets in schema are replaced with placeholders.

**Verdict rationale**: Destination schemas explicitly mark webhook URLs as secrets, and `mask_secrets=True` hides them in responses.

**Fragility Score**: Fragile
- **Reason**: Single masking mechanism dependent on schema secret list.

---

## [HARVESTER] PH-18 (Round-3): Alert deletion is unaudited by event webhooks

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/alerts.py:43-47` — `AlertResource.delete` deletes and commits without calling `record_event`.

**Sanitizers on path**:
- None.

**Verdict rationale**: The delete path does not record an event for webhook forwarding.

---

## [HARVESTER] PH-19 (Round-3): Destination schema validation is not causally protective against SSRF

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/destinations.py:102-113` — `DestinationListResource.post` validates schema only (type/required fields).
2. `redash/destinations/webhook.py:29-45` — `Webhook.notify` sends `requests.post` to `options.get("url")`.

**Sanitizers on path**:
- `redash/handlers/destinations.py:111-113` — `ConfigurationContainer.is_valid` — Partial: validates structure only, not URL safety.

**Verdict rationale**: URL allowlists or SSRF protections are not enforced; validation only checks schema structure.

---

## [HARVESTER] PH-21 (Round-3): Unvalidated base URL can turn notification links into phishing vectors

**Verdict**: VALIDATED

**Code path**:
1. `redash/tasks/alerts.py:11-13` — `notify_subscriptions` computes `host = utils.base_url(alert.query_rel.org)`.
2. `redash/destinations/hangoutschat.py:69-80` — `HangoutsChat.notify` embeds `host` directly into `openLink.url` when truthy.

**Sanitizers on path**:
- None.

**Verdict rationale**: The host value is used directly in notification links without validation in this path.

---

## [HARVESTER] PH-23 (Round-3): Event log access is unrecorded, enabling stealthy metadata harvesting

**Verdict**: VALIDATED

**Code path**:
1. `redash/handlers/events.py:65-69` — `EventsResource.get` returns events without calling `record_event`.

**Sanitizers on path**:
- None.

**Verdict rationale**: Event log access is not recorded, allowing silent access by admins.

---
