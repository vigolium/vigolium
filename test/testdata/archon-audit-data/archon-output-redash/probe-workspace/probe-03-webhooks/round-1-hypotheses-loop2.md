# Round 1 Hypotheses — Webhooks and Destinations

## PH-01: Non-admin enumeration of destination types enables targeted webhook abuse

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/destinations.py:16` — `DestinationTypeListResource.get`
- **Attacker starting position**: authenticated user (non-admin) leveraging auth gap or misrouting
- **Attack input**: `GET /api/destinations/types` with session cookie for non-admin user
- **Chain**: attacker requests destination types → handler returns full list of enabled destination types → attacker learns which webhook/integration types are available → attacker targets those integrations (e.g., discovers Teams/Slack types to craft phishing or to exploit leaked URLs elsewhere)
- **Catastrophe / Dangerous fallback**: enables targeted abuse of organization’s notification stack (social engineering, impersonation, or downstream webhook compromise)
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify route auth enforcement and confirm whether response includes deprecated/disabled destinations that expand attack options

---

## PH-02: Unauthorized read of destination configuration leaks webhook URLs

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/destinations.py:22` — `DestinationResource.get`
- **Attacker starting position**: authenticated user (non-admin) exploiting auth gap/IDOR
- **Attack input**: `GET /api/destinations/42` with non-admin session
- **Chain**: attacker reads destination → API returns destination dict with options (secrets masked but URL visible) → attacker extracts webhook URL → attacker posts arbitrary notifications to org channels or probes internal HTTP endpoints
- **Catastrophe / Dangerous fallback**: takeover of alerting channels or data exfil through leaked webhook endpoints
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: inspect `NotificationDestination.to_dict(all=True)` masking behavior for URL/credential fields; check if options expose internal hostnames

---

## PH-03: Unauthorized destination deletion causes alerting blackout

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/destinations.py:63` — `DestinationResource.delete`
- **Attacker starting position**: authenticated user (non-admin) exploiting auth gap/IDOR
- **Attack input**: `DELETE /api/destinations/42` with non-admin session
- **Chain**: attacker deletes destination → notification destinations removed from DB → alerts keep evaluating but have nowhere to send → defenders lose monitoring signals
- **Catastrophe / Dangerous fallback**: sustained suppression of incident notifications
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify if deletion has cascading effects on alert subscriptions and whether deletion is logged or surfaced to admins

---

## PH-04: Unauthorized alert read reveals sensitive query context

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/alerts.py:24` — `AlertResource.get`
- **Attacker starting position**: authenticated user (non-admin) exploiting access check gap
- **Attack input**: `GET /api/alerts/99` with non-admin session
- **Chain**: attacker reads alert → serialized alert includes query metadata and alert thresholds → attacker infers sensitive KPIs or internal data model → attacker uses that knowledge to prioritize targets
- **Catastrophe / Dangerous fallback**: disclosure of operational or business-sensitive intelligence
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: inspect `serialize_alert` fields and confirm if it includes query text, URLs, or related object IDs

---

## PH-05: Unauthorized alert update enables data exfil via future notifications

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/alerts.py:30` — `AlertResource.post`
- **Attacker starting position**: authenticated user (non-admin) exploiting owner/admin check gap
- **Attack input**: `POST /api/alerts/99` with JSON body `{"options": {"custom_body": "${query_result}"}, "name": "Quarterly Revenue Alert"}`
- **Chain**: attacker updates alert options → custom_body is stored and used by destinations on future evaluations → sensitive query results are embedded in notifications → data leaks to external webhook/email destinations
- **Catastrophe / Dangerous fallback**: exfiltration of sensitive query results to external systems
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: inspect alert rendering path to see how `custom_body` propagates into webhook/email payloads and whether it escapes or includes raw results

---

## PH-06: Unauthorized alert deletion suppresses monitoring

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/alerts.py:43` — `AlertResource.delete`
- **Attacker starting position**: authenticated user (non-admin) exploiting owner/admin check gap
- **Attack input**: `DELETE /api/alerts/99` with non-admin session
- **Chain**: attacker deletes alert → system stops evaluating that alert → notifications cease permanently → defenders lose visibility into critical conditions
- **Catastrophe / Dangerous fallback**: permanent removal of detection rules
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: check whether deletions are audited or recoverable; verify if delete endpoint is protected by CSRF or admin-only checks

---

## PH-07: Unauthorized mute/unmute toggles suppress alerting

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/alerts.py:66-75` — `AlertMuteResource.post/delete`
- **Attacker starting position**: authenticated user (non-admin) exploiting owner/admin check gap
- **Attack input**: `POST /api/alerts/99/mute` or `DELETE /api/alerts/99/mute` with non-admin session
- **Chain**: attacker toggles muted flag → worker respects muted state and skips notifications → alerts silently stop firing (or re-enabled at attacker’s choice) → defenders unaware of downtime
- **Catastrophe / Dangerous fallback**: stealthy suppression of alerting during compromise window
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify whether mute actions are logged and whether the UI surfaces mute state prominently

---

## PH-08: Subscription list exposes destination URLs to non-admin users

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/alerts.py:143` — `AlertSubscriptionListResource.get`
- **Attacker starting position**: authenticated user with access to alert but not admin
- **Attack input**: `GET /api/alerts/99/subscriptions` with standard user session
- **Chain**: attacker lists subscriptions → response includes destination details via `s.to_dict()` → destination options reveal webhook URLs (masked secrets only) → attacker sends arbitrary messages to those webhooks or uses URLs to probe internal hosts
- **Catastrophe / Dangerous fallback**: misuse of outbound notification channels or internal endpoint discovery
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm whether `AlertSubscription.to_dict()` includes destination options and whether URL fields are treated as secrets

---

## PH-09: Unauthorized subscription deletion removes alert recipients

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/alerts.py:152` — `AlertSubscriptionResource.delete`
- **Attacker starting position**: authenticated user (non-admin) exploiting owner/admin check gap
- **Attack input**: `DELETE /api/alerts/99/subscriptions/3` with non-admin session
- **Chain**: attacker removes subscription → critical recipients no longer notified → alerting appears “healthy” but no one receives it → incident response delayed
- **Catastrophe / Dangerous fallback**: stealth removal of recipients from critical alerts
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: check ownership rules for subscriptions and whether deleting someone else’s subscription is blocked

---

## PH-10: Alert list enumeration exposes sensitive alert inventory

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/alerts.py:109` — `AlertListResource.get`
- **Attacker starting position**: authenticated user lacking list permission exploiting access gap
- **Attack input**: `GET /api/alerts?page=1&page_size=250` with non-admin session
- **Chain**: attacker enumerates all alerts → list reveals names, query IDs, and owners → attacker maps sensitive systems and alerting coverage → attacker selects weakly monitored targets
- **Catastrophe / Dangerous fallback**: organizational recon enabling high-impact follow-on attacks
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: verify the serializer fields returned and confirm list permission enforcement in routing/middleware

---

## PH-11: Event log access leaks IP/User-Agent for targeted attacks

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/events.py:65` — `EventsResource.get`
- **Attacker starting position**: authenticated user lacking event-view permissions
- **Attack input**: `GET /api/events?page=1&page_size=250` with non-admin session
- **Chain**: attacker pulls event history → responses include user agent/IP and activity metadata → attacker maps internal IP ranges and user activity patterns → attacker crafts targeted phishing or lateral movement campaigns
- **Catastrophe / Dangerous fallback**: disclosure of network topology and user behavior
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: confirm whether `serialize_event` exposes IP/user-agent and whether event routes require admin/perm checks

---

## PH-12: Event webhook envelope still exploitable against internal endpoints

- **Reasoning-Model**: Pre-Mortem
- **Target**: `redash/handlers/events.py:60` — `EventsResource.post`
- **Attacker starting position**: authenticated user with access to event submission (or any endpoint that calls `record_event`)
- **Attack input**: `POST /api/events` with JSON body `[{"action":"pipeline.trigger","object_type":"job","object_id":1,"user_agent":"InternalBot/1.0","ip":"10.0.0.5"}]`
- **Chain**: attacker submits raw event dict → `record_event` enqueues task → task wraps event in `{schema, data}` envelope and POSTs to `EVENT_REPORTING_WEBHOOKS` → internal endpoint that accepts the envelope interprets `data.action` as a command → attacker triggers internal automation despite Docker API rejection
- **Catastrophe / Dangerous fallback**: unintended internal workflow execution via event webhook forwarding
- **Severity estimate**: HIGH
- **Read needed**: `redash/tasks/general.py:14-30`
- **Deepening direction**: identify internal endpoints configured in `EVENT_REPORTING_WEBHOOKS` and whether any accept the `schema/data` envelope with side-effecting actions

---

## Coverage Check

| Entry Point | Pre-Mortem covered? | Abductive covered? |
|------------|:-:|:-:|
| DestinationTypeListResource.get | PH-01 | NO — no defensive-pattern clue tied to this entry point |
| DestinationResource.get | PH-02 | NO — no defensive-pattern clue tied to this entry point |
| DestinationResource.delete | PH-03 | NO — no defensive-pattern clue tied to this entry point |
| AlertResource.get | PH-04 | NO — no defensive-pattern clue tied to this entry point |
| AlertResource.post | PH-05 | NO — no defensive-pattern clue tied to this entry point |
| AlertResource.delete | PH-06 | NO — no defensive-pattern clue tied to this entry point |
| AlertMuteResource.post/delete | PH-07 | NO — no defensive-pattern clue tied to this entry point |
| AlertSubscriptionListResource.get | PH-08 | NO — no defensive-pattern clue tied to this entry point |
| AlertSubscriptionResource.delete | PH-09 | NO — no defensive-pattern clue tied to this entry point |
| AlertListResource.get | PH-10 | NO — no defensive-pattern clue tied to this entry point |
| EventsResource.get | PH-11 | NO — no defensive-pattern clue tied to this entry point |

| Defensive Pattern | Abductive hypothesis generated? |
|------------------|:-:|
| redash/destinations/webhook.py:30 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/webhook.py:50 status code check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/webhook.py:42 conditional auth | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/slack.py:52 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/slack.py:55 status code check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/discord.py:57 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/discord.py:64 status code check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/mattermost.py:46 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/mattermost.py:50 status code check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/hangoutschat.py:41 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/hangoutschat.py:70 null check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/hangoutschat.py:90 status code check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/microsoft_teams_webhook.py:18 fallback value | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/microsoft_teams_webhook.py:81 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/microsoft_teams_webhook.py:108 status code check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/chatwork.py:33 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/chatwork.py:58 status code check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/webex.py:43 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/webex.py:106 fallback value | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/webex.py:202 null check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/webex.py:208 length/bounds check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/webex.py:216 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/webex.py:224 status code check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/datadog.py:84 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/datadog.py:87 status code check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/datadog.py:71 fallback value | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/asana.py:50 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/asana.py:58 status code check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/email.py:33 length/bounds check | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/email.py:36 fallback value | NO — not applicable: destination notify path outside focused gaps |
| redash/destinations/email.py:43 try/except | NO — not applicable: destination notify path outside focused gaps |
| redash/tasks/alerts.py:14 try/except | NO — not applicable: alert evaluation path not in focused gaps |
| redash/tasks/alerts.py:22 null check | NO — not applicable: alert evaluation path not in focused gaps |
| redash/tasks/alerts.py:46 redundant check | NO — not applicable: alert evaluation path not in focused gaps |
| redash/tasks/alerts.py:50 null check | NO — not applicable: alert evaluation path not in focused gaps |
| redash/tasks/general.py:19 try/except | PH-12 — defensive swallow of webhook errors suggests fragile webhook target assumptions |
| redash/tasks/general.py:27 status code check | PH-12 — failure logging implies webhook endpoint might be unreliable or internal |
| redash/tasks/general.py:56 try/except | NO — not applicable: email send path outside focused gaps |
| redash/tasks/general.py:65 try/except | NO — not applicable: data source testing path outside focused gaps |
| redash/tasks/general.py:75 try/except | NO — not applicable: schema path outside focused gaps |
| redash/tasks/general.py:87 try/except | NO — not applicable: schema path outside focused gaps |
| redash/handlers/destinations.py:40 null check | NO — not applicable: update/create validation not in focused gaps |
| redash/handlers/destinations.py:51 try/except | NO — not applicable: update/create validation not in focused gaps |
| redash/handlers/destinations.py:53 try/except | NO — not applicable: update/create validation not in focused gaps |
| redash/handlers/destinations.py:108 null check | NO — not applicable: update/create validation not in focused gaps |
| redash/handlers/destinations.py:112 validation check | NO — not applicable: update/create validation not in focused gaps |
| redash/handlers/destinations.py:126 try/except | NO — not applicable: update/create validation not in focused gaps |
| redash/handlers/alerts.py:56 conditional update | NO — not applicable: alert evaluation path not in focused gaps |
| redash/handlers/base.py:66 required fields | NO — not applicable: only field presence checks |
| redash/handlers/base.py:73 null check | NO — not applicable: 404 guard not relevant to hypotheses |
| redash/handlers/base.py:75 try/except | NO — not applicable: 404 guard not relevant to hypotheses |
| redash/handlers/base.py:83 bounds check | NO — not applicable: pagination guard not tied to dangerous fallback |
| redash/handlers/base.py:86 bounds check | NO — not applicable: pagination guard not tied to dangerous fallback |
| redash/handlers/base.py:89 bounds check | NO — not applicable: pagination guard not tied to dangerous fallback |
| redash/handlers/events.py:11 null check | NO — not applicable: geo lookup fallback not a security risk |
| redash/handlers/events.py:15 try/except | NO — not applicable: geo lookup fallback not a security risk |
| redash/models/__init__.py:1468 null check | NO — not applicable: email fallback not in focused gaps |

| Trust Chain Gap | Backward chain traced? |
|----------------|:-:|
| Destination URLs validated only by schema type/required fields; no URL allowlist or SSRF guard | PH-02 / PH-08 — potential URL exposure and abuse paths | 
| Event reporting webhooks use env-configured URLs, bypassing destination validation entirely | PH-12 |
| All destinations use raw requests.post (no private-address blocking) | PH-02 / PH-08 — leaked URLs allow internal probing | 
