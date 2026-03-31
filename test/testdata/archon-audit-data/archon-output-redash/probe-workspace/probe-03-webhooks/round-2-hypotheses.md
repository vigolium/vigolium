# Round 2 Hypotheses — Webhooks and Destinations

## PH-01: Destination URL SSRF via schema-only validation

- **Reasoning-Model**: TRIZ
- **Target**: `redash/destinations/webhook.py:29-44` — `Webhook.notify`
- **Attacker starting position**: admin (can create/update destinations)
- **Attack input / strategy**: create or update a webhook destination with `options.url` set to an internal target like `http://169.254.169.254/latest/meta-data/iam/security-credentials/` or `http://127.0.0.1:2375/containers/json`; attach destination to an alert; trigger notifications via `POST /api/alerts/<id>/evaluate`.
- **Tension / Game**: **Compatibility/Convenience vs Security** — destination configuration only enforces required fields/types, favoring broad compatibility for arbitrary webhook endpoints.
- **What was sacrificed / Information accumulated**: URL safety checks (protocol/domain allowlist or private-address blocking) are absent, so the notification pipeline accepts internal or metadata endpoints as valid webhook URLs.
- **Security consequence**: server-origin SSRF to internal services/metadata endpoints, enabling internal action triggers or data exposure via internal side effects.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm whether any destination creation/update code paths or configuration schema add URL validation or block private ranges; verify if requests follows redirects for additional SSRF reach.

---

## PH-02: Manual alert evaluation bypasses rearm gating, enabling repeated SSRF spam

- **Reasoning-Model**: TRIZ + Game-Theory
- **Target**: `redash/handlers/alerts.py:51-62` — `AlertEvaluateResource.post`
- **Attacker starting position**: authenticated user with `admin_or_owner` access to an alert
- **Attack input / strategy**: repeatedly call `POST /api/alerts/<id>/evaluate` in a tight loop after subscribing a webhook destination (or email) to the alert; use a destination URL pointing to a chosen internal host to generate a burst of outbound POSTs.
- **Tension / Game**: **Completeness vs Control** — the evaluation endpoint supports manual checks regardless of alert rearm state, but still triggers `notify_subscriptions` even when `should_notify` is false, enabling multi-interaction amplification.
- **What was sacrificed / Information accumulated**: rearm throttling is bypassable via manual evaluation, allowing an attacker to generate high-rate outbound requests and adapt rate based on observed side effects at the target service.
- **Security consequence**: amplification of SSRF attempts or alert spam; potential DoS against internal webhooks or external endpoints by repeated manual evaluations.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm alert evaluation response timing/visibility for attackers and whether background task retries/queueing amplify outbound volume.

---

## PH-03: Event reporting webhooks allow attacker-controlled payloads to env-configured internal endpoints

- **Reasoning-Model**: TRIZ
- **Target**: `redash/tasks/general.py:14-30` — `record_event`
- **Attacker starting position**: authenticated user with access to `/api/events` (or any path that calls `BaseResource.record_event`)
- **Attack input / strategy**: send `POST /api/events` with crafted JSON event fields; the worker forwards the event to every URL in `EVENT_REPORTING_WEBHOOKS`, including internal endpoints configured for telemetry.
- **Tension / Game**: **Operations telemetry vs Security isolation** — environment-configured event hooks bypass destination validation to simplify deployment and observability.
- **What was sacrificed / Information accumulated**: no validation on hook URLs or payload schemas, so attacker-supplied event data is forwarded to internal services if the env hooks point there.
- **Security consequence**: attacker can drive internal service requests with trusted origin, enabling internal action triggers or poisoning downstream log/analytics systems.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify `EVENT_REPORTING_WEBHOOKS` usage and whether any auth/CSRF protections guard `/api/events` in the current deployment.

---

## Coverage Check

| Entry Point | TRIZ tension found? | Game Theory mechanism found? |
|------------|:-:|:-:|
| `DestinationListResource.post` (`redash/handlers/destinations.py:102-134`) | PH-01 / YES — schema-only URL validation | NO — creation is single-shot, no adaptive feedback loop |
| `DestinationResource.post` (`redash/handlers/destinations.py:35-61`) | PH-01 / YES — update path also accepts arbitrary URLs | NO — update is single-shot |
| `DestinationResource.get` (`redash/handlers/destinations.py:21-33`) | NO — read-only | NO — no repeated-interaction mechanism |
| `DestinationResource.delete` (`redash/handlers/destinations.py:63-77`) | NO — deletion only | NO — no repeated-interaction mechanism |
| `AlertSubscriptionListResource.post` (`redash/handlers/alerts.py:116-141`) | NO — subscription only binds destination | NO — no adaptive feedback loop |
| `AlertEvaluateResource.post` (`redash/handlers/alerts.py:50-63`) | PH-02 / YES — manual evaluate bypasses rearm gating | PH-02 / YES — repeated evaluations enable adaptive spam/SSRF |
| `AlertListResource.post` (`redash/handlers/alerts.py:85-107`) | NO — alert creation only | NO — no repeated-interaction mechanism |
| `record_event` (`redash/handlers/base.py:50-61`) | PH-03 / YES — forwards raw events to hooks | NO — not inherently adaptive without hook response feedback |
| `record_event` job (`redash/tasks/general.py:14-30`) | PH-03 / YES — env webhooks bypass validation | NO — no response channel to attacker |

| Trust Chain Gap | TRIZ hypothesis generated? |
|----------------|:-:|
| Destination URLs are validated only by schema type/required fields; no protocol/domain allowlist and no SSRF guard on outbound requests. | PH-01 / YES — tension confirmed |
| Event reporting webhooks use environment-configured URLs, bypassing destination validation entirely. | PH-03 / YES — tension confirmed |
| All destinations use raw `requests.post` (no private-address blocking), so internal/metadata endpoints remain reachable if configured. | PH-01 / YES — tension confirmed via direct `requests.post` usage |

| Interactive Mechanism | Game Theory hypothesis generated? |
|----------------------|:-:|
| Manual alert evaluation triggers notifications even when `should_notify` is false | PH-02 / YES — repeated evaluations enable adaptive spam/SSRF |
| Event ingestion forwards raw events to webhooks | NO — not applicable: no attacker-visible feedback channel |
