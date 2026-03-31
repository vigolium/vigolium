# Round 3 Hypotheses — Webhooks and Destinations

## PH-01: Webhook destination SSRF depends on external egress controls

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Cross-Model CROSS-01
- **Target**: `redash/destinations/webhook.py:43` — `Webhook.notify`
- **Attacker starting position**: admin / destination manager
- **Causal argument**: The only thing preventing internal-url abuse is an external factor (network egress filtering or proxy policy). The code itself accepts any `options.get("url")` and posts to it. If the destination URL is an internal IP or metadata address, nothing in-code blocks it; safety is confounded by deployment network controls that may be absent in test/staging or in internal service-to-service paths.
- **Real risk**: Admin-configured SSRF via webhook destinations when egress filtering is absent or misconfigured.
- **Attack input**: Destination URL set to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (or `http://127.0.0.1:2375/containers/json`) then trigger alert notification.
- **Security consequence**: Internal metadata exposure or internal service control via SSRF.
- **Severity estimate**: HIGH
- **Read needed**: anatomy sufficient
- **Deepening direction**: Confirm whether any URL allowlist or private-address block exists outside this code (reverse proxy, outbound firewall); check if destination options are admin-controlled and if alerts can be triggered by non-admins.

---

## PH-02: Event webhook forwarding enables internal action triggers

- **Reasoning-Model**: Causal
- **Causal Test**: Confounder
- **Origin**: Cross-Model CROSS-02
- **Target**: `redash/tasks/general.py:26` — `record_event`
- **Attacker starting position**: authenticated-user (able to call `/api/events`)
- **Causal argument**: Safety depends on an external assumption: that `EVENT_REPORTING_WEBHOOKS` are safe, external endpoints. The code forwards attacker-supplied event JSON to whatever hook URLs are configured. If those hooks point to internal services, the code becomes a conduit for attacker-controlled payloads into internal endpoints without any schema validation.
- **Real risk**: SSRF-like internal action triggering through event reporting hooks when hook URLs are internal or misconfigured.
- **Attack input**: POST `/api/events` with JSON payload crafted to match an internal webhook schema; hook URL configured as `http://internal-service/hooks`.
- **Security consequence**: Internal service action invocation or data exfiltration via internal webhook endpoints.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Verify `/api/events` authentication/authorization expectations and typical `EVENT_REPORTING_WEBHOOKS` usage (internal vs external), plus whether hook payloads are consumed verbatim.

---

## PH-03: Manual alert evaluation bypasses rearm throttling

- **Reasoning-Model**: Causal
- **Causal Test**: Intervention
- **Origin**: Cross-Model CROSS-03
- **Target**: `redash/handlers/alerts.py:51` — `AlertEvaluateResource.post`
- **Attacker starting position**: alert owner/admin
- **Causal argument**: The rearm/should-notify throttle is not causally necessary for outbound notifications in manual evaluation. Even if `should_notify` is false, `notify_subscriptions` is still called. Bypassing the throttle does not change whether outbound requests occur; therefore the “protection” does not prevent notification spam in this path.
- **Real risk**: Alert owners can spam webhook destinations or amplify SSRF by repeatedly invoking manual evaluation regardless of rearm configuration.
- **Attack input**: Repeated POSTs to `/api/alerts/{id}/evaluate` to trigger outbound webhooks at high frequency.
- **Security consequence**: Outbound request amplification, destination DoS, or SSRF traffic amplification.
- **Severity estimate**: MEDIUM
- **Read needed**: anatomy sufficient
- **Deepening direction**: Confirm rate limiting or other gating at API layer; check if manual evaluate endpoint is exposed to non-admin alert owners.

---

# Coverage Check

| Round 1+2 Finding | Intervention tested? | Counterfactual tested? | Confounder tested? | New hypothesis? |
|-------------------|:-:|:-:|:-:|:-:|
| (none) | N/A | N/A | N/A | NO |

| Cross-Model Seed | Causal analysis done? | Hypothesis generated? |
|-----------------|:-:|:-:|
| CROSS-01 | YES | PH-01 |
| CROSS-02 | YES | PH-02 |
| CROSS-03 | YES | PH-03 |

| Trust Assumption | Confounder test done? | Hypothesis generated? |
|----------------|:-:|:-:|
| `options.get("url")` is a valid URL (`redash/destinations/webhook.py:44`) | YES | PH-01 |
| `host` is valid and includes scheme/hostname (`redash/destinations/slack.py:30`) | YES | NO |
| `colors.get(new_state)` yields acceptable color value (`redash/destinations/discord.py:55`) | YES | NO |
| `host` presence implies valid URL (`redash/destinations/hangoutschat.py:70`) | YES | NO |
| `options.get("message_template")` is JSON string (`redash/destinations/microsoft_teams_webhook.py:86`) | YES | NO |
| `room_id` is provided and valid (`redash/destinations/chatwork.py:35`) | YES | NO |
| `options['webex_bot_token']` exists (`redash/destinations/webex.py:194`) | YES | NO |
| `DATADOG_HOST` env value is valid hostname (`redash/destinations/datadog.py:81`) | YES | NO |
| `options.get("addresses")` is comma-separated list (`redash/destinations/email.py:31`) | YES | NO |
| `alert.query_rel.org` is present (`redash/tasks/alerts.py:12`) | YES | NO |
| `req["type"]` exists (`redash/handlers/destinations.py:40`) | YES | NO |
| request JSON contains keys for `project` extraction (`redash/handlers/alerts.py:32`) | YES | NO |
| incoming event list items are valid event dicts (`redash/handlers/events.py:62`) | YES | PH-02 |
| request context has `user_agent` and `remote_addr` (`redash/handlers/base.py:56`) | YES | NO |
| destination notify implementations accept given parameters (`redash/models/__init__.py:1478`) | YES | NO |
