# Attack Surface Map: Webhooks and destinations

## Entry Points
- `redash/handlers/destinations.py:80-134` — `DestinationListResource.post` — admin JSON body with `type`, `name`, `options` for destination creation.
- `redash/handlers/destinations.py:35-61` — `DestinationResource.post` — admin JSON body to update destination type/name/options.
- `redash/handlers/destinations.py:21-33` — `DestinationResource.get` — admin reads destination details (options returned with schema).
- `redash/handlers/destinations.py:63-77` — `DestinationResource.delete` — admin deletes destination.
- `redash/handlers/alerts.py:116-141` — `AlertSubscriptionListResource.post` — user selects `destination_id` or email subscription.
- `redash/handlers/alerts.py:50-63` — `AlertEvaluateResource.post` — user-triggered evaluation path leads to notifications.
- `redash/handlers/alerts.py:85-107` — `AlertListResource.post` — user creates alerts with `options`, `name`, `query_id` (custom body/subject propagate into notifications).
- `redash/handlers/base.py:50-61` — `record_event` — records event and enqueues job; event properties include user-agent/IP.
- `redash/tasks/general.py:14-30` — `record_event` job — forwards events to each URL in `EVENT_REPORTING_WEBHOOKS`.

## Trust Boundary Crossings
- `redash/handlers/destinations.py:103-126` → `redash/models/__init__.py:1437-1440` → `redash/destinations/*.py:notify` — admin-configured URL crosses from DB-stored configuration into outbound HTTP requests.
- `redash/tasks/alerts.py:11-18` → `redash/models/__init__.py:1477-1486` → `redash/destinations/*.py:notify` — alert state transitions from worker to outbound HTTP/webhook delivery.
- `redash/handlers/base.py:50-61` → `redash/tasks/general.py:14-30` — event data and user metadata cross from web process to worker, then outbound HTTP to configured event webhooks.

## Auth / AuthZ Decision Points
- `redash/handlers/destinations.py:15-18` — `DestinationTypeListResource.get` — `require_admin` gate for listing destination types.
- `redash/handlers/destinations.py:21-33` — `DestinationResource.get` — `require_admin` gate for destination config read.
- `redash/handlers/destinations.py:35-61` — `DestinationResource.post` — `require_admin` gate for destination update.
- `redash/handlers/destinations.py:63-77` — `DestinationResource.delete` — `require_admin` gate for deletion.
- `redash/handlers/alerts.py:24-41` — `AlertResource.get/post` — `require_access` and `require_admin_or_owner` for alert access/update.
- `redash/handlers/alerts.py:50-63` — `AlertEvaluateResource.post` — `require_admin_or_owner` gate before evaluation.
- `redash/handlers/alerts.py:85-107` — `AlertListResource.post` — `require_access` gate for creating alerts.
- `redash/handlers/alerts.py:109-113` — `AlertListResource.get` — `require_permission("list_alerts")` gate.
- `redash/handlers/alerts.py:116-121` — `AlertSubscriptionListResource.post` — `require_access` gate for subscribing to alerts.

## Validation / Sanitization Functions
- `redash/handlers/destinations.py:104-114` — `require_fields` + `ConfigurationContainer.is_valid()` — schema validation of destination options (no URL allowlist).
- `redash/handlers/destinations.py:44-52` — `ValidationError` handling — schema enforcement during update.
- `redash/handlers/base.py:64-67` — `require_fields` — field presence only.
- `redash/destinations/*.py` — per-destination configuration schema only declares types/required fields; no URL protocol/domain validation.

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| HTTP Handler (`/api/destinations`) | Model (`NotificationDestination`) | Admin input is validated against schema | PARTIAL | Schema validates presence/types only; no URL allowlist or protocol validation. |
| Model (`NotificationDestination.notify`) | Destination implementation (`*.notify`) | Destination configuration is safe to use as HTTP target | NO | Event reporting webhooks bypass destinations and use env-provided URLs. |
| Handler/Worker → Destination | HTTP Client (`requests.post`) | Outbound HTTP is restricted from internal/private targets | NO | All destinations use raw `requests.post` without `requests_or_advocate`/ConfiguredSession. |
| Web process | Worker job (`record_event`) | Event metadata is safe to forward | PARTIAL | Event webhooks are configured via env; no validation on hooks list. |
| Worker | External webhook endpoints | Remote endpoints are trustworthy/expected | NO | URLs are admin-configured or env-configured; can target internal services. |

## Trust Chain Gaps (rows where "Alternate Paths" column is NOT empty)
- Destination URLs are validated only by schema type/required fields; no protocol/domain allowlist and no SSRF guard on outbound requests.
- Event reporting webhooks use environment-configured URLs, bypassing destination validation entirely.
- All destinations use raw `requests.post` (no `requests_or_advocate` or private-address blocking), so internal/metadata endpoints remain reachable if configured.
