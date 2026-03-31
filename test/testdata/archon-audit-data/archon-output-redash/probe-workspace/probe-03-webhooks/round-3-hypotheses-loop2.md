# Round 3 Hypotheses — Webhooks and Destinations

## PH-13: Rearm check is not causally gating manual alert notifications

- **Reasoning-Model**: Causal
- **Causal Test**: Intervention
- **Origin**: Round-2 PH-02
- **Target**: `redash/handlers/alerts.py:51-62` — `AlertEvaluateResource.post`
- **Attacker starting position**: authenticated user (alert owner/admin)
- **Causal argument**: The apparent protection is `should_notify(alert, new_state)` (rearm logic), but the code calls `notify_subscriptions` regardless of the `should_notify` outcome. Bypassing or preserving the rearm check does not change whether outbound notifications are sent on manual evaluate, so the protection is not causally necessary.
- **Real risk**: Manual evaluation can be spammed to generate unlimited outbound notifications despite rearm safeguards.
- **Attack input**: Repeated `POST /api/alerts/<id>/evaluate` requests from an alert owner.
- **Security consequence**: Notification spam/DoS against webhook destinations (and potential SSRF-style amplification if hooks target internal services).
- **Severity estimate**: MEDIUM
- **Read needed**: `redash/handlers/alerts.py:51-62`
- **Deepening direction**: Confirm whether workers or rate-limiters exist for manual evaluate; assess destination-side rate limits.

---

## PH-14: Subscription list discloses subscriber PII to any alert viewer

- **Reasoning-Model**: Causal
- **Causal Test**: Intervention
- **Origin**: Cross-Model CROSS-02
- **Target**: `redash/handlers/alerts.py:143-148` — `AlertSubscriptionListResource.get`
- **Attacker starting position**: authenticated user with view-only access to an alert
- **Causal argument**: The access check (`require_access(..., view_only)`) is not a confidentiality control for subscriber PII. Even with valid view-only access, `AlertSubscription.to_dict()` returns `user.to_dict()` which includes email and group IDs. Thus the access check is not causally sufficient to prevent exposure of subscriber identity data.
- **Real risk**: Alert viewers can enumerate subscriber emails and group memberships for phishing or targeted social engineering.
- **Attack input**: `GET /api/alerts/<alert_id>/subscriptions` by any user with view access to the alert.
- **Security consequence**: PII disclosure and social engineering enablement.
- **Severity estimate**: MEDIUM
- **Read needed**: `redash/handlers/alerts.py:143-148`, `redash/models/__init__.py:1465-1469`, `redash/models/users.py:128-158`
- **Deepening direction**: Determine whether view-only access is broadly granted (e.g., shared alerts) and whether email visibility is required for UI.

---

## PH-15: Alert update can rebind to unauthorized queries without access revalidation

- **Reasoning-Model**: Causal
- **Causal Test**: Intervention
- **Origin**: Round-1 PH-05 / Cross-Model CROSS-04
- **Target**: `redash/handlers/alerts.py:30-37` — `AlertResource.post`
- **Attacker starting position**: authenticated user who owns the alert but lacks access to the target query
- **Causal argument**: The only protection on update is `require_admin_or_owner(alert.user.id)`; it does not revalidate access to a new `query_id`. Bypassing or keeping the owner check does not prevent an owner from binding the alert to a query they cannot access, so this protection is not causally necessary for query access control.
- **Real risk**: Alerts can be rebound to unauthorized queries, leaking data via notifications.
- **Attack input**: `POST /api/alerts/<id>` with body `{"query_id": <restricted_query_id>, "options": {...}}` followed by evaluation.
- **Security consequence**: Unauthorized data exposure through alert notifications.
- **Severity estimate**: HIGH
- **Read needed**: `redash/handlers/alerts.py:30-37`
- **Deepening direction**: Identify notification payload contents (query result vs summary) to scope exposure.

---

## PH-16: Event webhook forwarding relies on external gating of `/api/events`

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Round-2 PH-03 / Cross-Model CROSS-06
- **Target**: `redash/handlers/events.py:60-63` — `EventsResource.post`; `redash/tasks/general.py:19-27` — `record_event`
- **Attacker starting position**: unauthenticated or authenticated user if `/api/events` is exposed
- **Causal argument**: Safety assumes only trusted internal clients send events. The code does not enforce auth on `EventsResource.post`, and forwarded payloads are sent to `EVENT_REPORTING_WEBHOOKS` without validation. The apparent safety depends on an external gate (network ACL or proxy). If that confounder is absent, attacker input reaches outbound webhook targets unchanged.
- **Real risk**: Untrusted callers can inject event payloads that are forwarded to internal webhook endpoints.
- **Attack input**: `POST /api/events` with a JSON list of crafted events, causing `record_event` to POST the envelope to internal hooks.
- **Security consequence**: SSRF-style access to internal JSON endpoints and potential unintended side effects in systems that accept generic envelopes.
- **Severity estimate**: HIGH
- **Read needed**: `redash/handlers/events.py:60-63`, `redash/tasks/general.py:19-27`
- **Deepening direction**: Determine whether `/api/events` is exposed externally; enumerate configured `EVENT_REPORTING_WEBHOOKS` and their expected schemas.

---

## PH-17: Secret masking is dormant for webhook URLs

- **Reasoning-Model**: Causal
- **Causal Test**: Counterfactual
- **Origin**: Round-1 PH-02
- **Target**: `redash/models/__init__.py:1412-1424` — `NotificationDestination.to_dict`; `redash/handlers/destinations.py:22-25` — `DestinationResource.get`
- **Attacker starting position**: authenticated admin or attacker who can reach admin-only destination read
- **Causal argument**: The apparent protection is `mask_secrets=True` in `options.to_dict`, but URL fields are not marked as secrets in destination schemas. Therefore the masking is dormant for the most sensitive field (webhook URL), and the URL is returned in cleartext even when secrets are masked.
- **Real risk**: Webhook URLs leak to any caller who can access destination details, enabling external message injection or internal endpoint probing.
- **Attack input**: `GET /api/destinations/<id>` and extract `options.url` from the response.
- **Security consequence**: Abuse of notification channels or SSRF-like probing against internal webhook endpoints.
- **Severity estimate**: HIGH
- **Read needed**: `redash/models/__init__.py:1412-1424`, `redash/handlers/destinations.py:22-25`
- **Deepening direction**: Verify destination schemas to see whether URL fields are classified as secrets; assess who can access destination detail responses.

---

## PH-18: Alert deletion is unaudited by event webhooks

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Cross-Model CROSS-05
- **Target**: `redash/handlers/alerts.py:43-47` — `AlertResource.delete`
- **Attacker starting position**: authenticated alert owner/admin
- **Causal argument**: The system appears to rely on event forwarding for audit visibility, but the delete path omits `record_event`. Safety is therefore confounded by external logging/audit systems that may not exist in every deployment.
- **Real risk**: Destructive alert deletions can occur without being forwarded to event webhooks, enabling stealthy monitoring suppression.
- **Attack input**: `DELETE /api/alerts/<id>` by a privileged user.
- **Security consequence**: Loss of forensic visibility and stealthy removal of detection rules.
- **Severity estimate**: MEDIUM
- **Read needed**: `redash/handlers/alerts.py:43-47`
- **Deepening direction**: Confirm whether any DB audit triggers or separate audit logs capture alert deletions.

---

## PH-19: Destination schema validation is not causally protective against SSRF

- **Reasoning-Model**: Causal
- **Causal Test**: Intervention
- **Origin**: Round-2 PH-01
- **Target**: `redash/handlers/destinations.py:103-113` — `DestinationListResource.post`; `redash/destinations/webhook.py:29-43` — `Webhook.notify`
- **Attacker starting position**: authenticated admin (or attacker with destination creation rights)
- **Causal argument**: The apparent protection is schema validation (`ConfigurationContainer` / `config.is_valid()`), but it only checks presence/type of fields, not URL safety. Bypassing this validation would not change whether `requests.post` uses the provided URL, so the validation is not causally necessary for SSRF prevention.
- **Real risk**: Internal or metadata endpoints can be targeted via webhook URLs.
- **Attack input**: Create a destination with `options.url` set to `http://169.254.169.254/latest/meta-data/` or an internal service URL, then trigger notifications.
- **Security consequence**: SSRF to internal network or cloud metadata services.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Check if any URL allowlist/denylist exists in destination configuration or network egress controls.

---

## PH-21: Unvalidated base URL can turn notification links into phishing vectors

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Trust-Assumption (`redash/destinations/hangoutschat.py:70`)
- **Target**: `redash/destinations/hangoutschat.py:70` — `HangoutsChat.notify`
- **Attacker starting position**: authenticated admin or operator who can set org base URL
- **Causal argument**: The code assumes `host` is a valid, trusted URL and uses it directly in link payloads. Safety depends on external configuration discipline (org/base URL settings). If that confounder is absent, notifications embed attacker-controlled links.
- **Real risk**: Alert notifications can direct users to attacker-controlled sites for credential harvesting or malware delivery.
- **Attack input**: Set organization base URL to `https://evil.example`, then trigger any alert notification.
- **Security consequence**: Phishing via trusted notification channels.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Identify where base URL is configured and whether any validation enforces scheme/host.

---

## PH-23: Event log access is unrecorded, enabling stealthy metadata harvesting

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Cross-Model CROSS-09
- **Target**: `redash/handlers/events.py:65-69` — `EventsResource.get`
- **Attacker starting position**: authenticated admin or compromised admin session
- **Causal argument**: The system’s audit trail relies on `record_event`, but event log access does not call it. Safety is confounded by external monitoring of admin actions; if absent, an attacker can harvest metadata without leaving audit hooks.
- **Real risk**: Stealthy bulk extraction of IP/user-agent metadata and activity history.
- **Attack input**: Paginated `GET /api/events?page=N&page_size=250` requests.
- **Security consequence**: Privacy exposure with limited forensic visibility.
- **Severity estimate**: MEDIUM
- **Read needed**: `redash/handlers/events.py:65-69`
- **Deepening direction**: Check if any API gateway or admin audit logs capture event log reads.

---

## Coverage Check

| Round 1+2 Finding | Intervention tested? | Counterfactual tested? | Confounder tested? | New hypothesis? |
|-------------------|:-:|:-:|:-:|:-:|
| PH-02 | YES | YES | YES | PH-17 |
| PH-03 | YES | YES | YES | NO |
| PH-04 | YES | YES | YES | NO |
| PH-05 | YES | YES | YES | PH-15 |
| PH-01 | YES | YES | YES | PH-19 |
| PH-02 | YES | YES | YES | PH-13 |
| PH-03 | YES | YES | YES | PH-16 |

| Cross-Model Seed | Causal analysis done? | Hypothesis generated? |
|-----------------|:-:|:-:|
| CROSS-01 | YES | NO — admin gate enforced in handler; no causal gap without bypass evidence |
| CROSS-02 | YES | PH-14 |
| CROSS-03 | YES | NO — delete bound to subscription owner; missing alert context has limited impact |
| CROSS-04 | YES | PH-15 |
| CROSS-05 | YES | PH-18 |
| CROSS-06 | YES | PH-16 |
| CROSS-07 | YES | NO — amplification depends on external webhook configuration and rate limits |
| CROSS-08 | YES | NO — amplification depends on external webhook configuration and rate limits |
| CROSS-09 | YES | PH-23 |

| Trust Assumption | Confounder test done? | Hypothesis generated? |
|----------------|:-:|:-:|
| `options.get("url")` is a valid URL | YES | PH-19 |
| `host` is valid and includes scheme/hostname (Slack) | YES | NO |
| `colors.get(new_state)` yields acceptable color value | YES | NO |
| `host` presence implies valid URL (Hangouts Chat) | YES | PH-21 |
| `options.get("message_template")` is JSON string | YES | NO |
| `room_id` is provided and valid | YES | NO |
| `options['webex_bot_token']` exists | YES | NO |
| `DATADOG_HOST` environment value is valid hostname | YES | NO |
| `options.get("addresses")` is comma-separated list | YES | NO |
| `alert.query_rel.org` is present | YES | NO |
| `req["type"]` exists in destination update | YES | NO |
| request JSON contains keys for `project` extraction | YES | NO |
| incoming event list items are valid event dicts | YES | NO |
| request context has `user_agent` and `remote_addr` | YES | NO |
| destination notify implementations accept given parameters | YES | NO |
