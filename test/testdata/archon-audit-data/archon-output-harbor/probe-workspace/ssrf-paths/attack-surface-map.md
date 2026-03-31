# Attack Surface Map: SSRF Paths (Webhook, Replication, Preheat) + Configuration & Audit

## Entry Points

- `src/server/v2.0/handler/webhook.go:140` — `CreateWebhookPolicyOfProject` — accepts JSON body with `targets[].address` (URL), `targets[].type`, `targets[].auth_header`, `event_types[]`; project-admin scoped
- `src/server/v2.0/handler/webhook.go:172` — `UpdateWebhookPolicyOfProject` — same fields as create; project-admin scoped
- `src/server/v2.0/handler/webhook.go:405` — `validateTargets` — called by create/update; calls `utils.ParseEndpoint` on target address; normalizes to `scheme://host+path` but NO private IP check
- `src/server/v2.0/handler/registry.go:46` — `CreateRegistry` — accepts JSON body with `url`, `insecure`, `credential.access_key`, `credential.access_secret`, `ca_certificate`; system-admin scoped (SSRF vector for replication)
- `src/server/v2.0/handler/registry.go:132` — `UpdateRegistry` — same fields; system-admin scoped
- `src/server/v2.0/handler/registry.go:179` — `GetRegistryInfo` — triggers live ping to stored registry URL; system-admin scoped
- `src/server/v2.0/handler/config.go:75` — `UpdateConfigurations` — accepts JSON body including `audit_log_forward_endpoint` (syslog TCP target) and LDAP/OIDC endpoint URLs; system-admin scoped; calls `CheckEndpointActive` which makes TCP connection
- `src/server/v2.0/handler/config.go:41` — `GetConfigurations` — returns all config including sensitive values to solution-user; bypasses `RequireSystemAccess` for solution-user path
- `src/server/v2.0/handler/config.go:107` — `GetInternalconfig` — returns raw config including password fields to solution-user; calls `ConvertForGet` with `internal=true`
- `src/jobservice/job/impl/notification/webhook_job.go:68` — `WebhookJob.Run` — executes outbound HTTP POST to `params["address"]` (stored URL); no URL validation at job execution time
- `src/jobservice/job/impl/notification/slack_job.go` — `SlackJob.Run` — similar pattern to webhook; posts to Slack API URL
- `src/jobservice/hook/hook_client.go:80` — `basicClient.SendEvent` — posts job status events to `evt.URL`; no URL validation; used for internal job→core callbacks
- `src/pkg/p2p/preheat/job.go:69` — `Job.Run` — calls `d.GetHealth()` then `d.Preheat()` using stored provider endpoint; no URL validation at job execution
- `src/pkg/p2p/preheat/provider/dragonfly.go:199` — `DragonflyDriver.GetHealth` — calls `lib.ValidateHTTPURL` on endpoint; then HTTP GET to `{endpoint}/healthy`
- `src/pkg/p2p/preheat/provider/dragonfly.go:222` — `DragonflyDriver.Preheat` — HTTP POST to `{endpoint}/oapi/v1/jobs`; includes attacker-controlled `preheatingImage.URL` in POST body sent to the dragonfly provider
- `src/pkg/p2p/preheat/provider/dragonfly.go:288` — `DragonflyDriver.CheckProgress` — HTTP GET to `{endpoint}/oapi/v1/jobs/{taskID}`; `taskID` comes from prior dragonfly response
- `src/pkg/reg/adapter/native/adapter.go:66` — `NewAdapter` — constructs adapter with user-controlled `reg.URL`; HTTP calls go to this URL during replication
- `src/pkg/auditext/dao/dao.go:142` — `dao.Purge` — builds raw SQL with `strings.Join(filterEvents, "','")` injected into the SQL string (though filtered through `permitEventTypes`)
- `src/pkg/audit/forward.go:38` — `LoggerManager.Init` — calls `syslog.Dial("tcp", logEndpoint)` where `logEndpoint` is the admin-configured endpoint

## Trust Boundary Crossings

- **Core API -> Job Service (TB-5)**: When a webhook/preheat/replication job is enqueued, the target URL is stored in Redis as job parameters. The Job Service reads these parameters and executes HTTP to the URL without re-validating it. The trust assumption is that anything stored in the job queue came from a validated Core API call — but the URL was only syntactically validated (scheme, host+path extraction), not checked against a private IP denylist.

- **Core API -> External Registry (via replication adapter)**: Registry URL is stored in the DB and later used by the replication adapter to make outbound HTTP calls. No private IP filtering exists between storing the URL and using it.

- **Core API -> Audit Log Forward Endpoint**: When `audit_log_forward_endpoint` config is updated, a live TCP connection is made to the specified address (via `syslog.Dial`). This is a synchronous SSRF vector from the config update endpoint with no IP filtering.

- **Core API -> P2P Preheat Provider**: Preheat provider endpoint (stored with instance) is used in job execution for both health checks and actual preheat POST requests. The `PreheatImage.URL` field (a Harbor artifact URL constructed internally) is forwarded to the external dragonfly provider as a fetch target — but if attacker can influence headers or extra attrs, those flow into the POST body.

- **Job Service -> External Endpoints (TB-8)**: Final execution point where SSRF materializes. No allowlist/denylist, no private IP check, no DNS pinning.

- **Handler layer -> syslog TCP (audit forward)**: `UpdateConfigurations` path → `updateLogEndpoint` → `CheckEndpointActive` → `syslog.Dial("tcp", address)`. This is a direct TCP connection using an admin-supplied address string, with no URL scheme restriction (unlike webhook validation which only allows http/https).

## Auth / AuthZ Decision Points

- `src/server/v2.0/handler/webhook.go:105` — `RequireProjectAccess(ctx, projectNameOrID, rbac.ActionList, rbac.ResourceNotificationPolicy)` — list webhook policies
- `src/server/v2.0/handler/webhook.go:142` — `RequireProjectAccess(ctx, projectNameOrID, rbac.ActionCreate, rbac.ResourceNotificationPolicy)` — create webhook
- `src/server/v2.0/handler/webhook.go:174` — `RequireProjectAccess(ctx, projectNameOrID, rbac.ActionUpdate, rbac.ResourceNotificationPolicy)` — update webhook
- `src/server/v2.0/handler/webhook.go:208` — `RequireProjectAccess(ctx, projectNameOrID, rbac.ActionDelete, rbac.ResourceNotificationPolicy)` — delete webhook
- `src/server/v2.0/handler/webhook.go:226` — `RequireProjectAccess(ctx, projectID, rbac.ActionRead, rbac.ResourceNotificationPolicy)` — get webhook
- `src/server/v2.0/handler/registry.go:47` — `RequireSystemAccess(ctx, rbac.ActionCreate, rbac.ResourceRegistry)` — create registry (system admin only)
- `src/server/v2.0/handler/registry.go:80` — `RequireSystemAccess(ctx, rbac.ActionRead, rbac.ResourceRegistry)` — get registry
- `src/server/v2.0/handler/config.go:42-63` — dual path: solution-user bypasses `RequireSystemAccess` and gets full `AllConfigs` (including passwords) via the IsSolutionUser branch
- `src/server/v2.0/handler/config.go:76` — `RequireSystemAccess(ctx, rbac.ActionUpdate, rbac.ResourceConfiguration)` — update config
- `src/server/v2.0/handler/config.go:108` — `RequireSolutionUserAccess(ctx)` — GetInternalconfig: solution-user only

## Validation / Sanitization Functions

- `src/server/v2.0/handler/webhook.go:405` — `validateTargets` — calls `utils.ParseEndpoint`; strips to `scheme://host+path`; rejects non-http/https schemes; does NOT filter private IPs (RFC1918, loopback, 169.254.x.x)
- `src/common/utils/utils.go:36` — `ParseEndpoint` — validates scheme is http/https; uses `url.ParseRequestURI`; no private IP check
- `src/lib/endpoint.go:27` — `ValidateHTTPURL` — same as ParseEndpoint but used by preheat/dragonfly path; no private IP check
- `src/controller/config/controller.go:115` — `validateCfg` — validates auth mode, skip-audit-log constraints, and value lengths; does NOT validate LDAP/OIDC URL values for private IPs
- `src/pkg/auditext/dao/dao.go:193` — `permitEventTypes` — allowlist filter for purge SQL injection; filters event types to known values before SQL string interpolation; this IS effective mitigation for that specific SQL path
- `src/controller/config/controller.go:100` — `updateLogEndpoint` — calls `CheckEndpointActive` before `audit.LogMgr.Init`; but `CheckEndpointActive` makes a TCP connection meaning the validation itself is the SSRF probe

## Layer Trust Chain

For each layer transition in this component:

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| HTTP Client | webhook handler | URL is safe if scheme is http/https | NO | Scheme check passes for `http://169.254.169.254/`, `http://10.0.0.1/`, `http://localhost/` |
| webhook handler | job queue (Redis) | Validated URL stored as-is | YES for webhook | Preheat/replication URL stored without ParseEndpoint check |
| job queue | WebhookJob.execute | URL already validated at store time | NO — no re-validation | DNS rebinding: URL was valid at store time, resolves differently at execution |
| job queue | PreheatJob.Run | Endpoint validated by lib.ValidateHTTPURL | YES for endpoint | PreheatImage.URL field is Harbor-generated but headers in it flow to dragonfly |
| Handler | Config controller | All config values validated | NO | `audit_log_forward_endpoint` has no IP filtering; LDAP/OIDC URLs in config have no IP filtering |
| Config controller | syslog.Dial (TCP) | Endpoint address is safe | NO — no IP or scheme check | Any TCP-accessible host reachable |
| Config controller | audit.LogMgr.Init | Endpoint was verified by CheckEndpointActive | NO — check IS the SSRF | CheckEndpointActive itself dials TCP to the attacker-controlled address |
| Replication handler | reg.Adapter | Registry URL was validated at creation | NO — no private IP check | URL `http://169.254.169.254` passes all validation |
| Preheat provider | dragonfly HTTP client | Instance.Endpoint validated at registration | Partial — lib.ValidateHTTPURL called | URL passes if scheme is http/https regardless of target host |
| Job Service | External endpoints | TB-8: no filtering at all | NO | All three vectors (webhook, replication, preheat) reach external HTTP client with no denylist |
| GetConfigurations | response serialization | Passwords stripped for non-solution-users | YES for external API | GetInternalconfig returns passwords; `GetConfigurations` for solution-user also returns passwords via AllConfigs path |

## Trust Chain Gaps

1. **No private IP / RFC1918 denylist anywhere in the webhook/replication/preheat URL validation chain.** `ParseEndpoint` and `ValidateHTTPURL` only check scheme. An attacker with project-admin access can set a webhook URL to `http://169.254.169.254/latest/meta-data/` and the Job Service will fetch it. This applies to all three SSRF vectors.

2. **DNS rebinding window between webhook creation (URL validation at store time) and execution (Job Service HTTP call).** The URL `http://attacker-dns.example.com/` passes validation, but the attacker can change the DNS record to resolve to `169.254.169.254` by the time the Job Service executes the job.

3. **`audit_log_forward_endpoint` config value accepted as a raw TCP host:port string by `syslog.Dial`.** Unlike webhook URLs, there is no scheme check or URL parsing — just a TCP dial. `CheckEndpointActive` itself performs the TCP connection (the probe IS the exploit). A system admin can use this to port-scan internal services.

4. **Replication registry URL (`params.Registry.URL`) has no private IP filtering in `CreateRegistry` / `UpdateRegistry` handlers.** Only system admins can set this, but the value flows directly to `reg.Adapter` HTTP clients without any IP blocklist.

5. **`ConvertForGet` with `internal=true` returns PasswordType fields in plaintext.** Called from `GetInternalconfig` (solution-user only) and `GetConfigurations` (solution-user branch). If solution-user auth is obtained (e.g., internal secret header forgery), full credential exfiltration is possible.

6. **`PreheatImage.URL` + `Headers` in dragonfly Preheat request:** The `URL` field in the dragonfly job request body is set from the artifact's pull URL — which is normally Harbor-controlled — but the `Headers` field carries authentication headers. If an attacker can influence the headers sent to Dragonfly, the preheat provider will use them to fetch from an attacker-controlled registry URL forwarded in the dragonfly job.

7. **`permitEventTypes` allowlist in Purge SQL uses string join into raw SQL with single-quote delimiters.** While the allowlist filter is effective, the pattern is fragile: if `model.EventTypes` ever contains a value with a single quote, SQL injection becomes possible. The current values appear safe, but future additions are a latent risk.
