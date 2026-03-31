# Round 2 Hypotheses: Contradiction Reasoning (TRIZ / Game-Theory)
## Reasoning Model: contradiction-reasoner-03

Starting from the stated protections and finding internal contradictions, invariant violations, and adversarial game-theory scenarios.

---

## PH-09: validateTargets Comment Claims SSRF Prevention But Protection Is Incomplete

**Reasoning model:** TRIZ Contradiction (the fix claims to prevent SSRF but the mechanism only addresses one SSRF subtype)

**Contradiction identified:**
- Stated protection: `// Prevent SSRF security issue #3755` at `webhook.go:414`
- Actual protection: URL reconstructed as `scheme://host+path` — prevents userinfo-based SSRF (`http://user:pass@host/`) and fragment injection
- Missing protection: No check for destination IP being private/loopback/link-local

**Target:**
- `src/server/v2.0/handler/webhook.go:414` — `target.Address = url.Scheme + "://" + url.Host + url.Path`

**Contradiction:** The code comment creates a false sense of security. Developers reviewing this code see "SSRF prevented" and may not look for additional vectors. The fix address only one SSRF technique (credential injection via userinfo) but leaves four others:
1. Private IP targeting
2. DNS rebinding
3. IPv6 equivalent of private IPs
4. Redirect chains to private IPs

**Test:** Can `http://169.254.169.254/latest/meta-data/` be stored as webhook target? YES — `url.Parse` succeeds, scheme is "http", `url.Host = "169.254.169.254"`, `url.Path = "/latest/meta-data/"`. Reconstruction: `"http://169.254.169.254/latest/meta-data/"` — stored successfully.

**Severity estimate:** HIGH (false-fix creates audit trail gap)

**Status:** VALIDATED (confirmed by reading both ParseEndpoint and ValidateHTTPURL — neither checks IPs)

---

## PH-10: skip_cert_verify Flag Creates Insecure SSRF Transport Path

**Reasoning model:** TRIZ Contradiction (adding flexibility for self-signed certs creates a degraded security path)

**Contradiction identified:**
- Security goal: TLS certificates should be verified for external connections
- Feature requirement: Allow self-signed certs in dev/on-prem deployments
- Result: A user-controlled flag disables ALL certificate verification

**Target:**
- `src/jobservice/job/impl/notification/webhook_job.go:91` — `if skipCertVerify ... wj.client = httpHelper.clients[insecure]`
- `src/jobservice/job/impl/notification/http_helper.go:71` — `clients[insecure] = &http.Client{Transport: commonhttp.GetHTTPTransport(commonhttp.WithInsecure(true))}`

**Attack vector:** Project admin sets `skip_cert_verify = true` when creating webhook. The webhook URL can be any internal HTTPS service — the insecure client will connect to it and trust any self-signed certificate. Combined with SSRF, the attacker can reach internal HTTPS services (e.g., internal Kubernetes API server at `https://kubernetes.default.svc/`) that present self-signed certs.

**Additionally:** The insecure transport also makes man-in-the-middle attacks possible if an internal proxy is present.

**Severity estimate:** HIGH (doubles the SSRF attack surface to include internal HTTPS services)

**Status:** VALIDATED (code confirms insecure client is selected based on user-supplied param)

---

## PH-11: CheckEndpointActive IS the Exploit (Validation-as-SSRF Antipattern)

**Reasoning model:** TRIZ Contradiction (the validation function used to protect against bad endpoints is itself the side-channel attack)

**Contradiction identified:**
- Protection goal: Verify the audit log endpoint is reachable before accepting it
- Implementation: `CheckEndpointActive` dials TCP to the address
- Result: Every validation attempt IS a TCP probe to the specified address

**Target:**
- `src/controller/config/controller.go:107` — `if !audit.CheckEndpointActive(auditEP) { return errors.BadRequestError(...) }`
- `src/pkg/audit/forward.go:65` — `CheckEndpointActive`

**Game-theory analysis:**
- Attacker controls: `audit_log_forward_endpoint` value (system admin required)
- Attacker observes: HTTP response code (400 = BadRequest with message) vs success vs timeout
- Information gained per probe: Whether TCP port is open, closed, or filtered at target host

**Port scanning sequence:**
1. `PUT /api/v2.0/configurations {"audit_log_forward_endpoint": "10.0.0.1:22"}` → response depends on port 22 state
2. `PUT /api/v2.0/configurations {"audit_log_forward_endpoint": "10.0.0.1:80"}` → response depends on port 80 state
3. etc.

**Distinguishing open vs closed:** `syslog.Dial` on an open-but-not-syslog port (e.g., HTTP on port 80) will connect, then get an unexpected response → error logged, function returns `false`. For closed port: `connection refused` — also returns `false`. **Timing difference:** closed port returns immediately; filtered port times out. **Error message difference:** the error text in the 400 response body may differ (syslog framing error vs connection refused).

**Severity estimate:** HIGH (systematic internal port scanning with error oracle)

**Status:** VALIDATED

---

## PH-12: Audit Log Forward Initializes Persistent syslog Connection Without Re-Validation

**Reasoning model:** TRIZ Contradiction (connection validated once, used indefinitely)

**Target:**
- `src/controller/config/controller.go:110` — `audit.LogMgr.Init(ctx, auditEP)`
- `src/pkg/audit/forward.go:38` — `LoggerManager.Init`

**Contradiction:**
- Config update validates endpoint with `CheckEndpointActive` at update time
- `audit.LogMgr.Init` then creates a PERSISTENT `syslog.Writer` to the endpoint
- All subsequent audit log writes go to this syslog connection: `auditV1.LogMgr.DefaultLogger(ctx).Infof("action:%s, resource:%s, ...", audit.Operation, audit.Resource, audit.OperationDescription)`

**Data sent over syslog connection:**
- Operator (username)
- Operation (create, update, delete, push, pull, etc.)
- Resource type and name
- Operation description
- Timestamp

**Security consequence:** Attacker-controlled syslog endpoint receives a copy of ALL audit log events for all Harbor users, indefinitely, until the config is changed back. This is not SSRF in the traditional sense but is data exfiltration via misconfiguration. The `syslog.LOG_INFO` tagged messages reveal user activity patterns.

**Additional finding:** `audit.LogMgr.DefaultLogger(ctx)` is called with a context check — if the endpoint config value changes between calls, it re-initializes. But there is no authentication on the syslog connection (TCP syslog with no TLS).

**Severity estimate:** HIGH (persistent audit log exfiltration to attacker-controlled syslog server)

**Status:** VALIDATED

---

## PH-13: Replication Credential Forwarding to Attacker-Controlled Registry (Credential Theft)

**Reasoning model:** Game-Theory (attacker as registry operator receiving credentials)

**Target:**
- `src/server/v2.0/handler/registry.go:63-68` — credential storage in registry record
- `src/pkg/reg/adapter/native/adapter.go:66` — `NewAdapter` uses `reg.Credential`

**Game-theory model:**
- Attacker operates a malicious registry at `https://evil-registry.example.com`
- Attacker (as system admin OR after compromising a system-admin account) creates a replication rule pointing to this registry with Harbor credentials
- Harbor replication job authenticates to `evil-registry.example.com` using the stored `AccessKey/AccessSecret` — these are Harbor robot account credentials for the source project
- The malicious registry captures the credentials

**Variant:** Attacker creates a replication rule from their own project to an "external" registry they control. The replication job sends HTTP requests to `evil-registry.example.com` including `Authorization: Basic <base64(key:secret)>` headers. The attacker now has valid Harbor robot credentials.

**More critical variant:** If a legitimate replication rule exists pointing to an internal registry, a system admin attacker can update the registry URL to point to their malicious server — all future replication attempts will authenticate to the attacker's server. The stored credentials (from the `credential` field) are sent in HTTP headers.

**Sanitizers on path:** None — the adapter sends whatever credentials are stored in the registry record

**Severity estimate:** HIGH (credential harvesting via replication proxy-of-proxy)

**Status:** VALIDATED (credentials are passed directly to adapter clients)

---

## PH-14: Purge SQL Injection Latent Risk via permitEventTypes Bypass

**Reasoning model:** TRIZ Contradiction (allowlist that uses string join into raw SQL is safe only while the allowlist contains benign values)

**Target:**
- `src/pkg/auditext/dao/dao.go:155` — `"')" + strings.Join(filterEvents, "','") + "')"` in SQL
- `src/pkg/auditext/dao/dao.go:193` — `permitEventTypes` allowlist

**Contradiction:**
- Stated safety: `permitEventTypes` ensures only known event types are included
- Risk: The SQL string is built with string concatenation. If `model.EventTypes` ever contains a value with a single-quote character (e.g., a poorly-named event type like `user's_delete`), SQL injection becomes possible.
- Current state: `model.EventTypes` values appear to be safe (e.g., `create_artifact`, `delete_repository`). But the pattern is an invariant violation waiting for a future developer to add a problematic event type.

**Secondary issue:** The `purge` operation is also called via job service. The event types come from UI/API params which flow through `purge.go` arguments. Need to verify the call chain before asserting user control.

**Severity estimate:** LOW (currently safe, but fragile pattern for future)

**Status:** NEEDS-DEEPER (verify full call chain for purge event type params)

---

## PH-15: GetRegistryInfo Triggers Immediate SSRF Without Additional Confirmation

**Reasoning model:** Game-Theory (what is the fastest path from API call to outbound HTTP?)

**Target:**
- `src/server/v2.0/handler/registry.go:179` — `GetRegistryInfo`

**Attack:** Unlike webhook SSRF which requires waiting for an event to trigger the job, `GetRegistryInfo` makes an IMMEDIATE HTTP call to the stored registry URL. A system admin can:
1. Create registry with URL `http://10.0.0.1:8080`
2. Call `GET /api/v2.0/registries/{id}/info`
3. Immediately receive a response that distinguishes open/closed/filtered ports

**Timing oracle:** The response time of `GetRegistryInfo` leaks whether the internal port is open (fast response/error) vs filtered (timeout).

**Severity estimate:** HIGH (immediate SSRF without waiting for event trigger; port probing oracle)

**Status:** VALIDATED

---

## PH-16: Insecure Preheat HTTP Client Singleton Not Re-Initialized After Insecure Flag Change

**Reasoning model:** TRIZ Contradiction (singleton initialization vs per-request security decisions)

**Target:**
- `src/pkg/p2p/preheat/provider/client/http_client.go:43` — `GetHTTPClient(insecure bool)`

**Contradiction:**
- `GetHTTPClient` returns a singleton: `if defaultInsecureHTTPClient == nil { defaultInsecureHTTPClient = NewHTTPClient(insecure) }`
- The singleton is initialized on first call. For subsequent calls, the `insecure` parameter is IGNORED if the singleton already exists.
- If a preheat provider is first created with `insecure=false`, `defaultHTTPClient` is initialized.
- If then a preheat provider is created with `insecure=true`, `GetHTTPClient(true)` creates `defaultInsecureHTTPClient` (separate singleton).
- This is actually correct behavior — two separate singletons.

**But:** The two singletons share no request isolation. Any goroutine calling `GetHTTPClient(true)` gets the same insecure client used by all insecure preheat providers. This is not a security vulnerability per se but means:

**Real finding:** There is no per-provider HTTP client — all preheat providers sharing the same `insecure` setting use the same HTTP client. Response bodies are not shared (separate requests), but connection pooling means connections to different providers may reuse underlying TCP connections if Host matches. This is normal HTTP client pooling behavior — not directly exploitable.

**Severity estimate:** LOW (design observation, not a direct vulnerability)

**Status:** INVALIDATED (separate singletons for secure/insecure; pooling is expected behavior)

---

## PH-17: Webhook Policy Trigger on ANY Event Allows Event Flooding / Job Queue Exhaustion

**Reasoning model:** Game-Theory (what happens if a webhook policy triggers on high-frequency events?)

**Target:**
- `src/server/v2.0/handler/webhook.go:140` — `CreateWebhookPolicyOfProject`
- Notification system event routing

**Attack:** Project admin creates webhook policy subscribed to `PUSH_ARTIFACT` events pointing to a slow/unresponsive endpoint. Every image push to the project enqueues a webhook job. Job retries up to 3 times (MaxFails=3). If the target is unresponsive (times out at 3 seconds each attempt), each push generates up to 3 jobs that tie up worker threads for 9 seconds each.

**Amplification:** In a project with heavy push traffic (CI/CD pipelines), this could exhaust the Job Service worker pool, delaying all other jobs (GC, replication, scanning).

**Severity estimate:** MEDIUM (resource exhaustion, availability impact)

**Status:** NEEDS-DEEPER (need to verify Job Service concurrency limits and whether webhook job queue is bounded separately)

---

## PH-18: Config Update Allows LDAP/OIDC Endpoint Pivot to Attacker-Controlled Identity Provider

**Reasoning model:** Game-Theory (attacker as system admin modifying auth config)

**Target:**
- `src/server/v2.0/handler/config.go:75` — `UpdateConfigurations`
- `src/controller/config/controller.go:115` — `validateCfg`

**Attack:** System admin (or attacker with system-admin) updates `ldap_url` to point to attacker-controlled LDAP server, or `oidc_endpoint` to attacker-controlled OIDC provider.

**LDAP pivot:**
- Change `ldap_url = "ldap://attacker.example.com:389"` and `ldap_search_password = "newpass"`
- All subsequent LDAP-mode logins will authenticate against attacker's LDAP
- Attacker's LDAP can accept any credentials (null bind) → mass account takeover

**OIDC pivot:**
- Change `oidc_endpoint = "https://attacker.example.com/oidc"` and `oidc_client_id/secret`
- All subsequent OIDC logins flow through attacker's provider
- Attacker controls token claims → can impersonate any Harbor user via `sub` claim mapping

**Note:** This requires system-admin, which is high privilege. But:
1. It is a privilege escalation amplifier (system admin → compromise of ALL users)
2. The `validateCfg` function does NOT validate LDAP/OIDC URLs for scheme, format, or private IP

**Severity estimate:** HIGH (system-admin can compromise all user accounts via auth endpoint pivot)

**Status:** VALIDATED (no LDAP/OIDC URL validation in validateCfg)
