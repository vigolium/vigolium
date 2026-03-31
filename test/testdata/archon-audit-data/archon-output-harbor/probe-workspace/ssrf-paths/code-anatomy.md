# Code Anatomy: SSRF Paths (Webhook, Replication, Preheat) + Configuration & Audit

## Component Map

### 1. Webhook Handler Layer

**File:** `src/server/v2.0/handler/webhook.go`

Key functions and their roles:

- `CreateWebhookPolicyOfProject` (line 140): Entry point for creating a webhook. Calls `RequireProjectAccess` for project-admin check, then `validateTargets` and `validateEventTypes`. Stores policy in DB via `webhookCtl.CreatePolicy`.
- `UpdateWebhookPolicyOfProject` (line 172): Same pattern as create. Calls `requirePolicyInProject` to verify ownership.
- `validateTargets` (line 405): The ONLY URL validation gate for webhook targets. Calls `utils.ParseEndpoint(target.Address)`, then reconstructs URL as `scheme://host+path`. This strips query strings and fragments but does NOT block private IPs.
- `validateEventTypes` (line 437): Validates event types against a whitelist. Not security-relevant for SSRF.

**Critical observation:** `validateTargets` comment says "Prevent SSRF security issue #3755" but the fix only strips path components to `scheme://host+path` and removes non-http/https schemes. It does NOT block:
- Loopback addresses (`127.0.0.1`, `::1`, `localhost`)
- Private RFC1918 addresses (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`)
- Link-local addresses (`169.254.169.254` — AWS metadata, GCP metadata)
- IPv6 equivalents

### 2. Job Service: Webhook Execution

**File:** `src/jobservice/job/impl/notification/webhook_job.go`

- `WebhookJob.Run` (line 68): Calls `init` then `execute`.
- `WebhookJob.init` (line 85): Selects HTTP client (secure or insecure) based on `skip_cert_verify` param. Insecure client uses `WithInsecure(true)` transport — skips TLS verification entirely.
- `WebhookJob.execute` (line 101): Directly reads `params["address"]` and `params["payload"]` from job parameters. Constructs HTTP POST request. **No URL re-validation at execution time.** The address is the stored webhook target URL.

**File:** `src/jobservice/job/impl/notification/http_helper.go`

- `httpHelper` global: Two HTTP clients — `secure` (uses `commonhttp.GetHTTPTransport()`) and `insecure` (uses `WithInsecure(true)`).
- Both clients are global singletons initialized once. Timeout defaults to 3 seconds (configurable via env).
- No redirect following limits — standard `http.Client` default allows up to 10 redirects.

### 3. Slack Job (SSRF alternate path)

**File:** `src/jobservice/job/impl/notification/slack_job.go`

Similar to webhook_job.go but posts to Slack API endpoint. Target URL also comes from job parameters. Same absence of private IP filtering.

### 4. Preheat Job Layer

**File:** `src/pkg/p2p/preheat/job.go`

- `Job.Run` (line 69): Gets provider driver factory for `p.Vendor`, constructs driver, calls `d.GetHealth()` then `d.Preheat(pi)`.
- `parseParamProvider` (line 214): Deserializes provider instance from JSON job parameter. Validates `Vendor`, `AuthMode`, and `Endpoint` fields are present but does NOT validate endpoint for private IPs.
- `parseParamImage` (line 242): Deserializes `PreheatImage` from JSON. Calls `img.Validate()`.

**File:** `src/pkg/p2p/preheat/provider/dragonfly.go`

- `DragonflyDriver.GetHealth` (line 199): Calls `lib.ValidateHTTPURL(url)` first — this is the ONLY IP-agnostic check. Then HTTP GET to `{endpoint}/healthy`.
- `DragonflyDriver.Preheat` (line 222): Constructs `dragonflyCreateJobRequest` with `Args.URL = preheatingImage.URL` and `Args.Headers = headerToMapString(preheatingImage.Headers)`. POSTs to `{endpoint}/oapi/v1/jobs`. The Dragonfly server is then told to fetch that URL — indirect SSRF via the P2P provider.
- `DragonflyDriver.CheckProgress` (line 288): HTTP GET to `{endpoint}/oapi/v1/jobs/{taskID}` where `taskID` is an integer string from a prior Dragonfly response.

**File:** `src/pkg/p2p/preheat/provider/client/http_client.go`

- `GetHTTPClient(insecure bool)` (line 43): Returns singleton. When `insecure=true`, creates client with `InsecureSkipVerify: true` in TLS config.
- `HTTPClient.Get/Post` (line 85, 150): Logs `url` parameter including credential info in debug logs (potential credential leak if debug logging enabled).
- No redirect limits specified — relies on Go standard library default (10 hops).

### 5. Replication Adapter Layer

**File:** `src/pkg/reg/adapter/native/adapter.go`

- `NewAdapter(reg *model.Registry)` (line 66): Constructs adapter with `reg.URL` as the target registry URL. Credentials are `reg.Credential.AccessKey/AccessSecret`. Creates `registry.NewClientWithCACert(reg.URL, ...)`.
- `HealthCheck` (line 118): Calls `a.Ping()` or `a.PingSimple()` to the stored registry URL. This is triggered by `GetRegistryInfo` API endpoint and any health check scheduling.
- `FetchArtifacts` (line 134): Makes multiple HTTP calls to `reg.URL` to enumerate repositories and artifacts.

**File:** `src/jobservice/job/impl/replication/replication.go`

- `Replication.Run` (line 84): Deserializes `src` and `dst` resources from job parameters (JSON). Calls `trans.Transfer(src, dst, opts)`.
- `parseParams` (line 115): JSON-deserializes registry resources. The registry URL is embedded in the resource's `Registry` field.
- No IP filtering before the registry client makes HTTP calls.

### 6. Registry Handler (Replication SSRF Entry Point)

**File:** `src/server/v2.0/handler/registry.go`

- `CreateRegistry` (line 46): Accepts `params.Registry.URL` without validating it for private IPs. Only validates CA certificate format if provided. Stores URL in DB.
- `UpdateRegistry` (line 132): Same — accepts new URL without private IP check.
- `GetRegistryInfo` (line 179): Triggers a live `HealthCheck` call to the stored registry URL. This is an immediate SSRF trigger for any system admin who knows a registry ID.

### 7. Configuration Handler & Controller

**File:** `src/server/v2.0/handler/config.go`

- `GetConfigurations` (line 41): **Dual path**: If caller is solution-user, calls `AllConfigs` which returns ALL fields including PasswordType fields in plaintext. Falls through to `RequireSystemAccess` for non-solution-users, then calls `UserConfigs` which strips passwords via `ConvertForGet(internal=false)`.
- `UpdateConfigurations` (line 75): After `RequireSystemAccess`, calls `UpdateUserConfigs`. This triggers `updateLogEndpoint` if `audit_log_forward_endpoint` changed.
- `GetInternalconfig` (line 107): Requires solution-user. Calls `ConvertForGet(ctx, cfg, internal=true)` which returns PasswordType fields.

**File:** `src/controller/config/controller.go`

- `updateLogEndpoint` (line 100): Reads the new endpoint from DB config, calls `audit.CheckEndpointActive(auditEP)` (which dials TCP to the address), then calls `audit.LogMgr.Init(ctx, auditEP)`.
- **TCP SSRF vector:** `CheckEndpointActive` → `syslog.Dial("tcp", address)` — the address string is `"host:port"` format accepted by `syslog.Dial`. No URL parsing, no scheme check, no IP filtering. Any valid `"host:port"` string is accepted. This allows port scanning of internal services.
- `validateCfg` (line 115): Validates auth mode and value lengths; does NOT validate any URL-type config values (LDAP URLs, OIDC URLs, audit forward endpoint) for private IPs.
- `ConvertForGet` (line 224): When `internal=true`, PasswordType fields are included in the output (they are only deleted for external calls).

### 8. Audit Log Forward

**File:** `src/pkg/audit/forward.go`

- `LoggerManager.Init` (line 38): Calls `syslog.Dial("tcp", logEndpoint, ...)`. No validation on `logEndpoint`. If dial fails, silently falls back to stdout (no error propagated to caller).
- `CheckEndpointActive` (line 65): Dials TCP to `address`. Returns `true` if connection succeeds. **This function is called from `UpdateConfigurations` validation path as the "verification" step, but the act of verification is itself the SSRF probe.** Error is logged but not returned to the HTTP caller as a security incident.

**File:** `src/pkg/auditext/manager.go`

- `Create` (line 79): If `AuditLogForwardEndpoint` configured, calls `auditV1.LogMgr.DefaultLogger(ctx).Infof(...)`. This logs the audit event to the syslog-over-TCP connection. The log message includes `audit.Username`, `audit.Operation`, `audit.Resource`, and `audit.OperationDescription`.
- Note: These are the sanitized external event fields — not raw credentials. However, if configuration events are forwarded, configuration change operations are logged here.

**File:** `src/pkg/auditext/dao/dao.go`

- `Purge` (line 142): Constructs raw SQL: `"DELETE FROM audit_log_ext WHERE ... AND lower(operation || '_' || resource_type) IN ('" + strings.Join(filterEvents, "','") + "')"`. The `filterEvents` slice is passed through `permitEventTypes` which allowlists against `model.EventTypes`. The SQL is therefore injection-safe for current values, but the pattern is fragile.
- `permitEventTypes` (line 193): Allowlist filter. Only allows event strings present in `model.EventTypes`. Effective mitigation for this specific SQL path.

### 9. Preheat Instance Registration (Provider Entry Point)

**File:** `src/pkg/p2p/preheat/instance/manager.go`

- `CreateInstance`: Stores preheat provider instance (endpoint, auth mode, auth info) in DB. Entry point where attacker-controlled endpoint URL enters the system for preheat SSRF.
- Note: No private IP check on endpoint before storage.

### 10. Configuration Metadata (SSRF-Adjacent Configs)

**File:** `src/lib/config/metadata/metadatalist.go`

- `AuditLogForwardEndpoint` (line 192): Defined as `StringType` with `Editable: false`. The `Editable: false` means the UI should not allow editing, but the API accepts it if the caller has system-admin rights.
- LDAP URL fields (`ldap_url`): Also StringType with no URL validation defined in metadata.
- OIDC endpoint (`oidc_endpoint`): StringType.

None of these string-type config items have validators that check for private IP ranges.

## Data Flow Summary

### Webhook SSRF Path
```
POST /api/v2.0/projects/{id}/webhook/policies (project-admin)
  -> validateTargets: ParseEndpoint(url) -- scheme check only
  -> webhookCtl.CreatePolicy -> DB store
  -> [event trigger] -> notification job enqueued in Redis
  -> Job Service: WebhookJob.execute -> http.Client.Do(POST to stored url)
  -- NO private IP check at any step --
```

### Replication SSRF Path
```
POST /api/v2.0/registries (system-admin)
  -> CreateRegistry: URL stored without IP check
  -> GET /api/v2.0/registries/{id}/info (system-admin) -- immediate SSRF trigger
  -> OR: replication policy triggers -> job enqueued
  -> Job Service: Replication.Run -> adapter.NewAdapter(reg.URL) -> HTTP calls to reg.URL
  -- NO private IP check at any step --
```

### Preheat SSRF Path
```
POST /api/v2.0/p2p/preheat/providers (system-admin) -- registers provider instance with endpoint
  -> preheat policy links to provider
  -> artifact push triggers preheat job
  -> Job Service: preheat.Job.Run -> DragonflyDriver.GetHealth (GET {endpoint}/healthy)
  -> DragonflyDriver.Preheat (POST {endpoint}/oapi/v1/jobs with image URL+headers)
  -- lib.ValidateHTTPURL called on endpoint, but NO private IP check --
  -- SECONDARY: Dragonfly fetches preheatingImage.URL from Harbor -- headers forwarded --
```

### Audit Log SSRF Path
```
PUT /api/v2.0/configurations (system-admin)
  -> UpdateConfigurations -> updateLogEndpoint
  -> CheckEndpointActive: syslog.Dial("tcp", address) -- TCP probe, no IP check
  -> audit.LogMgr.Init: syslog.Dial("tcp", address) -- persistent TCP connection
  -- Accepts raw "host:port" string, no URL parsing, no IP filtering --
```

### Config Credential Leak Path
```
GET /api/v2.0/configurations (solution-user)
  -> GetConfigurations: IsSolutionUser branch -> AllConfigs -> all fields incl. passwords
GET /api/internal/configurations (solution-user)
  -> GetInternalconfig -> ConvertForGet(internal=true) -> passwords returned
  -- If solution-user auth compromised, full credential exfiltration --
```
