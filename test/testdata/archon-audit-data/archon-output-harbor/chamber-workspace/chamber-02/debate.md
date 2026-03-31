# Review Chamber: chamber-02

Cluster: SSRF & Network Attacks -- SSRF via webhook/replication/preheat, open redirect, credential exposure, audit log manipulation, network reconnaissance
DFD Slices: DFD-2 (Webhook/Replication SSRF Path)
NNN Range: p8-020 to p8-039
Started: 2026-03-27T10:00:00Z
Status: CLOSED

## Pre-Seeded Hypotheses from Deep Probe

The following hypotheses were validated during Deep Probe phase and are pre-seeded for this chamber. The Ideator should build on these rather than re-generate. The Tracer should verify and extend existing evidence.

### H-00a (CRITICAL): Evidence Destruction via audit_log_forward_endpoint + skip_audit_log_database
- Probe ref: PH-12/PH-C06
- System admin sets both config keys in single PUT, redirecting all audit events to attacker syslog while silencing Harbor's own DB audit trail
- The config change itself is not recorded

### H-00b (CRITICAL): Solution-user GET /configurations returns all passwords
- Probe ref: PH-05/PH-C07
- Solution-user auth bypasses password field stripping, leaking LDAP/OIDC secrets

### H-00c (HIGH): Webhook SSRF to cloud metadata 169.254.169.254
- Probe ref: PH-01
- P7-002 already documents this; project-admin creates webhook with metadata URL, no IP filtering

### H-00d (HIGH): Webhook auth_header + skip_cert_verify = authenticated internal HTTPS SSRF
- Probe ref: PH-06/PH-10
- Combines auth header injection with TLS bypass for internal service access

### H-00e (HIGH): Audit log TCP port scan oracle
- Probe ref: PH-03/PH-C03
- CheckEndpointActive uses syslog.Dial TCP probe with distinguishable error messages

### H-00f (HIGH): Preheat SSRF with IP encoding bypasses
- Probe ref: PH-04/PH-C05
- ValidateHTTPURL checks scheme only; hex/decimal/IPv6-mapped IP forms bypass

### H-00g (HIGH): Registry credential theft via URL pivot
- Probe ref: PH-13/PH-C04
- System admin points registry URL at attacker server, credentials sent on health check

### H-00h (HIGH): Registry credentials plaintext in Redis job queue
- Probe ref: PH-C08
- Credentials decrypted in memory then serialized as plaintext JSON into Redis job params

### H-00i (HIGH): LDAP/OIDC endpoint pivot to attacker IdP
- Probe ref: PH-18
- System admin redirects LDAP/OIDC endpoints, no URL validation on config fields

### H-00j (HIGH): DNS rebinding architectural gap
- Probe ref: PH-07/PH-C02
- Validate-at-store, execute-later pattern allows DNS rebinding bypass of any future IP denylist

## Enrichment Pre-Validated
- P7-001 (HIGH): Open redirect via authproxy postURI (bypass-b6c083d73)
- P7-002 (HIGH): SSRF via webhook/slack address
- P7-005 (MEDIUM): Webhook insecure TLS skip_cert_verify

## Round 1 -- Ideation

### H-01 (HIGH): Webhook Queue Exhaustion — Unbounded Policy Creation Starves Job Service
- **Severity estimate:** HIGH (availability DoS against all tenants)
- **Entry point:** `src/server/v2.0/handler/webhook.go` → `CreateWebhookPolicyOfProject` (lines 140–170)
- **Attack input:** Project-admin creates hundreds of webhook policies, each subscribed to all event types, pointing at a non-responsive or slow endpoint (e.g., `http://attacker.com:1` with 3-second timeout).
- **Expected behavior:** Each Harbor event (push, pull, delete) enqueues N jobs (one per policy per matching event type). Each job retries up to `MaxFails` (default 3) times. With no per-project policy count limit (`src/controller/webhook/controller.go:84–86`), no Redis queue depth cap (`src/jobservice/worker/cworker/c_worker.go:47`, `gocraft/work` uses unbounded Redis lists), and `MaxConcurrency: 0` for WebhookJob (unlimited concurrency), a single project can flood the shared job queue, starving replication, scanning, GC, and other tenants' webhook jobs.
- **Why distinct from pre-seeded:** H-00c/H-00d focus on SSRF content of webhook requests. This hypothesis targets the queue infrastructure itself — resource exhaustion rather than data exfiltration. The `ShouldRetry() = true` + `MaxFails = 3` + no rate limit + no policy count cap is a distinct attack surface (PH-17 NEEDS-DEEPER item).

### H-02 (HIGH): Scanner Registration SSRF via PingScanner Endpoint
- **Severity estimate:** HIGH (authenticated SSRF with partial response read-back)
- **Entry point:** `src/server/v2.0/handler/scanner.go` → `PingScanner` (lines 169–190) and `CreateScanner` (lines 45–64)
- **Attack input:** System admin sends `POST /api/v2.0/scanners/ping` with body `{"url": "http://169.254.169.254/latest/meta-data/", "name": "test"}`. The `Registration.Validate()` call (`src/pkg/scan/dao/scanner/model.go:100`) invokes `lib.ValidateHTTPURL` which only checks scheme — `http://127.0.0.1/` and `http://169.254.169.254/` pass validation (confirmed by `endpoint_test.go:32–33`). The controller then issues `GET {url}/api/v1/metadata` to the target.
- **Expected behavior:** Harbor's scanner client makes an outbound HTTP GET to the attacker-specified internal URL with path `/api/v1/metadata` appended. Error messages may leak response details (connection refused vs. timeout vs. non-JSON response). The `UseInternalAddr` flag (`model.go:57`) provides an additional pivot to internal Docker registry address.
- **Why distinct from pre-seeded:** H-00c covers webhook SSRF, H-00f covers preheat SSRF, H-00g covers registry SSRF. Scanner registration is an entirely separate SSRF entry point not mentioned in any pre-seeded hypothesis. It has a different required role (system admin for scanners vs. project-admin for webhooks) and a different outbound request pattern (GET with fixed path suffix vs. POST with payload).

### H-03 (HIGH): IsLocalPath Backslash Bypass — OIDC Open Redirect to Credential Phishing
- **Severity estimate:** HIGH (credential theft via phishing)
- **Entry point:** `src/common/utils/utils.go` → `IsLocalPath` (lines 308–311), consumed by `src/core/controllers/oidc.go` (lines 81–86, 233)
- **Attack input:** Attacker crafts OIDC login URL with `redirect_url=/\evil.com` or `redirect_url=/%09/evil.com` (tab-encoded). `IsLocalPath` checks `strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//")` — the value `/\evil.com` passes both checks (starts with `/`, does not start with `//`). On the Callback path (line 233), `oc.Controller.Redirect(redirectURLStr, http.StatusFound)` issues a 302 redirect. Some browsers (particularly older IE/Edge, but also through server-side Location header normalization) interpret `/\evil.com` as a redirect to `evil.com`.
- **Expected behavior:** After successful OIDC authentication, the user is redirected to an attacker-controlled site that mimics Harbor's login page, harvesting credentials or session tokens. The redirect URL is stored in the session and **not re-validated** on the Callback path — only checked at initial storage time.
- **Why distinct from pre-seeded:** The enrichment section mentions P7-001 (open redirect via authproxy postURI from bypass-b6c083d73), but that covers the authproxy flow. This hypothesis targets the OIDC flow specifically, using a different bypass technique (backslash vs. double-slash) against `IsLocalPath` rather than the authproxy redirect handler. The OIDC flow's session-store-then-redirect pattern adds a TOCTOU dimension not present in the authproxy case.

### H-04 (MEDIUM): Purge Audit Log SQL Concatenation — Fragile Allowlist Enables Future Injection
- **Severity estimate:** MEDIUM (latent — not currently exploitable, but structurally fragile)
- **Entry point:** `src/pkg/audit/dao/dao.go` → `Purge` (lines 80–86) and `dryRunPurge` (lines 105–111); also `src/pkg/auditext/dao/dao.go` → `Purge` (line 155) and `dryRunPurge` (line 179)
- **Attack input:** The purge job receives `includeOperations` (comma-split string from job parameter `common.PurgeAuditIncludeEventTypes`). The `permitOps` function (dao.go:125–137) filters against a 3-entry allowlist (`pull`, `create`, `delete`). Surviving values are concatenated directly into SQL: `"AND lower(operation) IN ('" + strings.Join(filterOps, "','") + "')"`. If the allowlist were ever widened to include a value containing `'` or if `permitOps` were bypassed (e.g., via direct DB job parameter manipulation), this becomes a SQL injection vector.
- **Expected behavior:** Currently safe because allowlist values are simple ASCII. However, the `audit_log_ext` purge (auditext/dao/dao.go:155) uses a wider allowlist of 14 event types from `model.EventTypes` — each new event type added to this list is a potential injection point if it contains SQL metacharacters. The concatenation pattern violates parameterized query best practices.
- **Why distinct from pre-seeded:** No pre-seeded hypothesis addresses SQL injection. This is PH-14 (NEEDS-DEEPER) from the probe — the fragile allowlist pattern in purge SQL. While not immediately exploitable, it represents architectural debt that could become critical if event type naming conventions change.

### H-05 (HIGH): Combinatorial Chain — Audit Forward Port Scan + Config Password Leak → Full Internal Pivot
- **Severity estimate:** HIGH (chained attack escalating from reconnaissance to credential theft)
- **Entry point:** Chain of H-00e + H-00b + H-00i
- **Attack input:** Step 1: System admin uses `audit_log_forward_endpoint` TCP probe (H-00e) to scan internal ports — `syslog.Dial("tcp", "10.0.0.5:5432", ...)` in `src/pkg/audit/forward.go:65–76` reveals which internal services are alive via distinguishable error messages (connection refused vs. timeout vs. success). Step 2: Solution-user calls `GET /api/v2.0/configurations` (H-00b) to extract cleartext LDAP bind password, OIDC client secret, and database credentials from `AllConfigs` (`src/controller/config/controller.go`, bypasses `ConvertForGet` entirely at `src/server/v2.0/handler/config.go:44`). Step 3: With discovered internal topology + stolen credentials, attacker pivots LDAP/OIDC endpoint (H-00i) to a rogue IdP on the discovered internal network, or connects directly to the discovered PostgreSQL/Redis using stolen credentials.
- **Expected behavior:** The three pre-seeded vulnerabilities individually provide reconnaissance, credential theft, and endpoint pivoting. Chained together, they provide a complete internal network compromise path: map the network → steal credentials → redirect authentication to attacker-controlled infrastructure. No single pre-seeded hypothesis describes this kill chain.
- **Why distinct from pre-seeded:** Each component exists as H-00b, H-00e, H-00i individually. This hypothesis documents the combinatorial attack path and demonstrates that the sum is greater than the parts — the port scan oracle makes the credential theft actionable, and the endpoint pivot makes both exploitable for persistent access.

### H-06 (MEDIUM): Webhook AuthHeader Injection via Full Header Replacement
- **Severity estimate:** MEDIUM (header injection into outbound requests)
- **Entry point:** `src/jobservice/job/impl/notification/webhook_job.go` → `execute` (lines 110–115); `src/pkg/notifier/handler/notification/http_handler.go` (lines 73–93)
- **Attack input:** Project-admin creates a webhook policy with `auth_header` set to `Bearer token\r\nX-Forwarded-For: 127.0.0.1\r\nHost: internal-service`. The `http_handler.go:79` calls `header.Set("Authorization", event.Target.AuthHeader)` which stores the value. The header map is JSON-serialized to job parameters. At execution time (`webhook_job.go:110–115`), the entire `http.Header` is replaced via `json.Unmarshal` — this bypasses Go's `http.Header.Set()` sanitization since `json.Unmarshal` populates the map directly. The crafted headers are then emitted when `wj.client.Do(req)` serializes the request.
- **Expected behavior:** Go's `net/http` transport does strip `\r\n` in header values since Go 1.15, providing a partial mitigation. However, the JSON deserialization path allows arbitrary header keys to be injected (not just `Authorization`), potentially overriding `Host`, `Content-Length`, or `Transfer-Encoding` headers. If the webhook target is behind a reverse proxy that trusts these headers, this enables request smuggling or host-header poisoning. The `req.Header = header` full replacement (not merge) means even standard headers set by `http.NewRequest` are overwritten.
- **Why distinct from pre-seeded:** H-00d covers `auth_header` + `skip_cert_verify` as separate features enabling authenticated SSRF. This hypothesis focuses on the header injection mechanism itself — the JSON serialization/deserialization bypass of Go's header sanitization, and the full header replacement pattern that allows overriding security-sensitive headers beyond just `Authorization`.

### H-07 (HIGH): Config URL Fields Accept Arbitrary Internal URLs — AuthProxy/UAA SSRF
- **Severity estimate:** HIGH (SSRF via configuration endpoints with no URL validation)
- **Entry point:** `src/server/v2.0/handler/config.go` → `UpdateConfigurations` (lines 75–92); config fields defined in `src/lib/config/metadata/metadatalist.go`
- **Attack input:** System admin sends `PUT /api/v2.0/configurations` with `{"http_authproxy_endpoint": "http://169.254.169.254/latest/meta-data/", "http_authproxy_tokenreview_endpoint": "http://10.0.0.5:8080/"}`. These fields are defined as `StringType` in metadata — `StringType.validate()` performs no URL validation. The values are stored directly. When authproxy authentication mode is active, Harbor makes HTTP requests to `http_authproxy_endpoint` for every login attempt, and to `http_authproxy_tokenreview_endpoint` for token validation — both hitting attacker-specified internal addresses.
- **Expected behavior:** Unlike webhook/registry/preheat URLs which use `ValidateHTTPURL` (scheme-only check), these config fields have **zero URL validation** — they accept any string including `ftp://`, `file:///`, or malformed URLs. The `uaa_endpoint` config field (`src/common/utils/uaa/client.go`) follows the same pattern. When the corresponding auth mode is activated, every authentication attempt triggers outbound HTTP requests to the stored URL, providing a high-frequency SSRF oracle. The OIDC endpoint (`oidc_endpoint`) similarly triggers outbound requests to `{endpoint}/.well-known/openid-configuration` with no URL validation.
- **Why distinct from pre-seeded:** H-00i covers LDAP/OIDC endpoint pivot for IdP redirection. This hypothesis covers the authproxy and UAA endpoints specifically, which are distinct configuration fields with a different attack pattern: authproxy triggers outbound requests on every login (high frequency), whereas LDAP/OIDC are used only during specific auth flows. The complete absence of URL validation (not even scheme checking) on these fields is a distinct finding from the `ValidateHTTPURL`-protected endpoints.

---
*Ideator-02 hypotheses below (H-08 through H-14)*

### H-08 (HIGH): Preheat Image URL + Bearer Token Forwarded Verbatim to Dragonfly — Token Theft via Rogue P2P Instance
- **Severity estimate:** HIGH (credential theft — Harbor internal Bearer token leaked to external system)
- **Entry point:** `src/controller/p2p/preheat/enforcer.go:441–446` → `startTask`; `src/pkg/p2p/preheat/provider/dragonfly.go:249–250` → `Preheat`
- **Attack input:** System admin registers a preheat instance pointing at an attacker-controlled Dragonfly-compatible endpoint. When a preheat policy triggers, `enforcer.go:436` generates a Bearer token via `de.credMaker(ctx, candidate)` and places it in `PreheatImage.Headers["Authorization"]`. At `dragonfly.go:250`, `headerToMapString(preheatingImage.Headers)` forwards this header verbatim into the Dragonfly job request body (`dragonflyCreateJobRequestArgs.Headers`). The attacker's Dragonfly instance receives a valid Harbor robot-account Bearer token scoped to pull the target image. `PreheatImage.Validate()` (`preheat_image.go:94`) only calls `url.Parse()` — pure syntax, no SSRF check on the URL, and **zero validation on the Headers map**.
- **Expected behavior:** Attacker extracts the Bearer token from the Dragonfly job request and replays it against Harbor's registry API to pull any image the robot account can access. The token lifetime depends on Harbor's token service configuration but is typically 30 minutes. The Kraken driver (`kraken.go:100`) has the same pattern — `preheatingImage.URL` is placed in a Docker notification event's `Target.URL` field and sent to the Kraken endpoint.
- **Why distinct from pre-seeded:** H-00f covers preheat *instance endpoint* SSRF with IP encoding bypasses against `ValidateHTTPURL`. This hypothesis targets the *image URL and auth headers* flowing through the preheat job to the P2P provider — a different data path. The token theft via headers is the primary risk, not the SSRF to cloud metadata. This directly addresses PH-08 (NEEDS-DEEPER: preheat image URL/headers forwarded to Dragonfly).

### H-09 (MEDIUM): UAAClientSecret Typed as StringType — Not Redacted by ConvertForGet
- **Severity estimate:** MEDIUM (credential exposure to admin users via API)
- **Entry point:** `src/lib/config/metadata/metadatalist.go:126` → `UAAClientSecret` definition; `src/controller/config/controller.go:236–240` → `ConvertForGet`
- **Attack input:** Any system admin calls `GET /api/v2.0/configurations`. The `ConvertForGet` method (controller.go:236–240) iterates metadata items and deletes fields typed as `*metadata.PasswordType` for external API calls. However, `UAAClientSecret` (`common.UAAClientSecret = "uaa_client_secret"`, const.go:101) is defined with `ItemType: &StringType{}` at metadatalist.go:126 — **not** `&PasswordType{}`. This means the UAA OAuth2 client secret survives the redaction pass and appears in plaintext in the API response.
- **Expected behavior:** All other secrets (`LDAPSearchPwd`, `OIDCClientSecret`, `EmailPassword`) are correctly typed as `PasswordType` and redacted. `UAAClientSecret` is the sole outlier. A system admin (not solution-user — this works for regular admin) receives the UAA client secret, which can be used to impersonate Harbor against the UAA identity provider, mint arbitrary tokens, or pivot to other UAA-protected services in the deployment.
- **Why distinct from pre-seeded:** H-00b covers the *solution-user* bypass that leaks *all* passwords by skipping `ConvertForGet` entirely. This hypothesis identifies a type annotation bug that leaks one specific secret (UAA) to *regular admin users* through the normal `ConvertForGet` path. Different entry role, different root cause (metadata type error vs. auth bypass), and exploitable even after H-00b is patched.

### H-10 (HIGH): Preheat Instance Store-Without-Validate — Deferred Validation Enables DNS Rebinding + TOCTOU
- **Severity estimate:** HIGH (SSRF via DNS rebinding at enforcement time)
- **Entry point:** `src/controller/p2p/preheat/controller.go:195` → `CreateInstance`; `src/server/v2.0/handler/preheat.go:547` → `convertParamInstanceToModelInstance`
- **Attack input:** System admin creates a preheat instance via `POST /api/v2.0/p2p/preheat/instances` with `{"endpoint": "http://attacker-dns-rebind.example.com", ...}`. The handler at `preheat.go:547` copies `model.Endpoint` into the instance model **without calling `ValidateHTTPURL`**. The controller at line 195 explicitly skips health checks with the comment `// !WARN: We don't check the health of the instance here.`. The endpoint is stored as-is. Later, when a preheat policy is enforced, `GetHealth()` in `dragonfly.go:204–205` calls `lib.ValidateHTTPURL(url)` — but by this time, DNS for `attacker-dns-rebind.example.com` can rebind from a public IP (passing validation) to `169.254.169.254` or `127.0.0.1` (actual connection target).
- **Expected behavior:** The store-then-validate gap is architecturally identical to H-00j (DNS rebinding) but manifests in a distinct component (preheat vs. webhook/registry). The explicit code comment confirms this is a known but unaddressed gap. Unlike webhooks where validation occurs at policy creation, preheat instances are validated only at enforcement — providing a wider TOCTOU window (hours or days between instance creation and first policy enforcement).
- **Why distinct from pre-seeded:** H-00j documents DNS rebinding as an architectural gap across all URL-accepting endpoints. This hypothesis identifies the **most exploitable concrete instance** of that gap: the preheat instance path has explicit code confirming no validation at creation, a longer TOCTOU window than other endpoints, and a different validation code path (`GetHealth` vs. inline validation). The enforced comment `// !WARN` makes this a deliberate design trade-off worth separate tracking.

### H-11 (CRITICAL): Combinatorial Chain — Rogue Preheat Instance + Token Theft + Registry SSRF → Full Image Exfiltration
- **Severity estimate:** CRITICAL (full image content exfiltration from any project)
- **Entry point:** Chain of H-10 + H-08 + H-00g
- **Attack input:** Step 1 (H-10): System admin creates a preheat instance pointing at attacker-controlled endpoint — stored without validation. Step 2 (H-08): Admin creates a preheat policy matching target images. When enforced, `enforcer.go:436` generates a Bearer token and sends it along with the image manifest URL to the attacker's endpoint via `dragonfly.go:249–250`. Step 3: Attacker extracts the Bearer token from the preheat request. Step 4: Attacker uses the token to pull image layers directly from Harbor's registry API (`GET /v2/<repo>/blobs/<digest>`), exfiltrating container images including any embedded secrets, proprietary code, or ML models.
- **Expected behavior:** Unlike H-00g (registry credential theft) which requires pointing Harbor's *registry* URL at an attacker and only captures stored registry credentials, this chain captures *runtime-generated tokens* that authorize image pulls. The preheat-generated token has pull scope across all images matching the policy's filter — potentially spanning multiple repositories. This chain does not require compromising Redis (unlike H-00h) and works with a single system-admin role.
- **Why distinct from pre-seeded:** No pre-seeded hypothesis chains preheat-as-token-oracle → image exfiltration. H-00g captures registry *stored* credentials; this captures *ephemeral* tokens. H-00f covers preheat IP encoding bypass (different entry surface). H-00h requires Redis access. This chain exploits the unique property that preheat is the only Harbor flow that generates tokens and sends them to an external, admin-configured endpoint.

### H-12 (MEDIUM): IPv6 Zone-ID Encoded SSRF Bypass in ValidateHTTPURL
- **Severity estimate:** MEDIUM (SSRF bypass of potential future IP denylist)
- **Entry point:** `src/lib/endpoint.go:27–45` → `ValidateHTTPURL`; test cases at `src/lib/endpoint_test.go:34–40`
- **Attack input:** Attacker supplies `http://[fe80::1%25en0]:8080/` as a webhook target, registry URL, or scanner URL. `ValidateHTTPURL` parses this as valid (confirmed by test cases at endpoint_test.go:37–40) and returns `http://[fe80::1%en0]:8080`. The `%25` URL-encodes to `%` which forms the zone ID `%en0`, binding the IPv6 link-local address to network interface `en0`. This allows targeting link-local addresses that may host cloud metadata services (AWS, GCP use `fe80::` ranges for some internal services) or other node-local services.
- **Expected behavior:** Even if a future IP denylist is implemented checking against `169.254.0.0/16` or `127.0.0.0/8`, IPv6 link-local addresses (`fe80::/10`) with zone IDs would need separate handling. The zone-ID encoding (`%25` → `%`) also introduces URL-decoding ambiguity: the returned URL `http://[fe80::1%en0]:8080` contains a raw `%` which is technically an invalid URL character in some parsers, potentially causing double-parse vulnerabilities in downstream consumers. Go's `net/http` handles this correctly, but any log analysis, WAF, or proxy parsing these URLs may behave differently.
- **Why distinct from pre-seeded:** H-00f covers hex/decimal/IPv6-mapped IP encoding bypasses for preheat. This hypothesis specifically targets IPv6 **zone-ID** encoding, which is a distinct bypass class: it binds to a specific network interface (not just an IP), uses URL-encoding transformation (`%25` → `%`), and is confirmed by Harbor's own test suite as accepted input. Zone-ID bypasses require different denylist logic than IP-range checks.

### H-13 (CRITICAL): Combinatorial Chain — Audit Evidence Destruction + Webhook Exfiltration + Port Scan → Stealth Data Exfiltration
- **Severity estimate:** CRITICAL (undetectable data exfiltration from Harbor)
- **Entry point:** Chain of H-00a + H-00e + H-00c/H-00d
- **Attack input:** Step 1 (H-00e): System admin uses `audit_log_forward_endpoint` TCP probe to map internal network topology — discovers internal services, open ports, and cloud metadata endpoints via distinguishable error messages from `syslog.Dial`. Step 2 (H-00a): Admin sets `audit_log_forward_endpoint` to attacker's syslog + `skip_audit_log_database = true` in a single `PUT /configurations` call. The config change itself is **not audited** (the audit hook fires after the config update, but the forward endpoint is already redirected). From this point, all audit events flow to the attacker and the Harbor DB audit trail is silent. Step 3 (H-00c/H-00d): With auditing neutralized, admin creates webhook policies targeting discovered internal services (Step 1). Push events trigger POST requests with image metadata to internal endpoints, exfiltrating registry contents. The webhook creation event is forwarded to attacker's syslog (not Harbor DB), leaving no evidence.
- **Expected behavior:** Each component individually is high-severity. Chained together, they create a **stealth exfiltration pipeline**: map the network → blind the audit trail → exfiltrate data → no evidence in Harbor's database. The critical distinction from H-05 (which chains port scan + password leak + IdP pivot) is that this chain focuses on *stealth* — the audit trail destruction ensures the attack leaves no forensic evidence in Harbor's own systems. An incident responder checking Harbor's audit logs would see nothing.
- **Why distinct from pre-seeded:** H-05 chains H-00e + H-00b + H-00i for credential theft and IdP pivot. This chain combines different pre-seeded vulns (H-00a + H-00e + H-00c/H-00d) for a different objective: stealth data exfiltration with evidence destruction. The audit trail neutralization step (H-00a) transforms the other vulns from "detectable SSRF" to "undetectable exfiltration" — a qualitative severity escalation not captured by any single hypothesis.

### H-14 (MEDIUM): Webhook Retry Amplification + Slow-Endpoint → Goroutine/Connection Pool Exhaustion
- **Severity estimate:** MEDIUM (denial-of-service against Harbor's job service)
- **Entry point:** `src/jobservice/job/impl/notification/webhook_job.go:103–108` → `execute`; `src/jobservice/job/impl/notification/http_helper.go:45` → HTTP client timeout
- **Attack input:** Project-admin creates a webhook policy targeting an attacker-controlled endpoint that accepts TCP connections but delays HTTP responses (slowloris-style — sends 1 byte per second, never completing the response). The HTTP client timeout defaults to 3 seconds (`JOBSERVICE_WEBHOOK_JOB_HTTP_CLIENT_TIMEOUT`) but can be increased via env var. Each webhook delivery spawns a goroutine in `gocraft/work`'s worker pool. With `MaxConcurrency: 0` (unlimited) and `MaxFails: 3` (each slow request retries 3x), a burst of Harbor events (e.g., bulk image push) against N policies creates `N × events × 3` goroutines, each holding an HTTP connection for the timeout duration. Combined with H-01's finding of no per-project policy count limit, an attacker can exhaust the job service's goroutine count and TCP connection pool, blocking all job types (replication, scanning, GC) across all tenants.
- **Expected behavior:** Unlike H-01 which focuses on queue depth (Redis list length), this hypothesis targets **connection pool and goroutine exhaustion** — a different resource. The slow-endpoint amplification means each job occupies a goroutine for the full timeout period rather than failing fast. At 3-second timeout × 3 retries × 100 policies × 10 events = 9,000 goroutine-seconds per event burst. The `gocraft/work` default pool has no goroutine limit, and Go's runtime allows unbounded goroutine creation until memory exhaustion.
- **Why distinct from pre-seeded:** H-01 documents webhook queue exhaustion (Redis list depth). This hypothesis targets a different resource (goroutines + TCP connections, not queue depth) using a different attack technique (slow-endpoint response delay, not non-responsive endpoint). The two are complementary — H-01 fills the queue, H-14 exhausts the worker pool. Together they create a complete DoS against the job service. This further develops PH-17 (webhook DoS NEEDS-DEEPER) by identifying the specific resource exhaustion mechanism.

## Round 2 -- Tracing

**Tracer: tracer-02**
**Timestamp: 2026-03-27T10:30:00Z**

---

### Pre-Seeded Hypotheses — Verification Status

#### H-00a (CRITICAL): Evidence Destruction via audit_log_forward_endpoint + skip_audit_log_database
**Status: CONFIRMED — Probe findings hold**
- `src/lib/config/metadata/metadatalist.go:192-193`: Both `audit_log_forward_endpoint` (StringType, no URL validation) and `skip_audit_log_database` (BoolType) are `UserScope` config items, editable via `PUT /api/v2.0/configurations`.
- `src/controller/config/controller.go:149-169`: `verifySkipAuditLogCfg` only checks that `skip_audit_log_database=true` requires a non-empty `audit_log_forward_endpoint` — no validation that the endpoint is legitimate.
- `src/server/v2.0/handler/config.go:75-92`: `UpdateConfigurations` passes through `toCfgMap` (JSON round-trip, no field-level validation) to `UpdateUserConfigs`.
- The config change itself goes through the same audit path being disabled — confirmed TOCTOU gap.

#### H-00b (CRITICAL): Solution-user GET /configurations returns all passwords
**Status: CONFIRMED — Probe findings hold**
- `src/server/v2.0/handler/config.go:41-59`: When `sec.IsSolutionUser()` is true, calls `c.controller.AllConfigs(ctx)` and returns raw JSON — bypasses `ConvertForGet` which would strip password fields.
- Contrast with `GetInternalconfig` at line 107-126 which calls `ConvertForGet(ctx, cfg, true)`.

#### H-00c (HIGH): Webhook SSRF to cloud metadata 169.254.169.254
**Status: CONFIRMED — Probe findings hold**
- `src/server/v2.0/handler/webhook.go:409-415`: `validateTargets` calls `utils.ParseEndpoint(target.Address)` then reconstructs URL as `url.Scheme + "://" + url.Host + url.Path` — scheme-only check, no IP/hostname filtering.
- `src/common/utils/utils.go:36-53`: `ParseEndpoint` only validates scheme is `http` or `https`.
- `src/jobservice/job/impl/notification/webhook_job.go:103-105`: `address` from job params used directly in `http.NewRequest`.

#### H-00d (HIGH): Webhook auth_header + skip_cert_verify = authenticated internal HTTPS SSRF
**Status: CONFIRMED — Probe findings hold**
- `src/pkg/notifier/handler/notification/http_handler.go:78-79`: `header.Set("Authorization", event.Target.AuthHeader)` — attacker-controlled auth header.
- `src/jobservice/job/impl/notification/webhook_job.go:91-96`: `skip_cert_verify=true` selects insecure HTTP client.
- Combined: authenticated SSRF with TLS bypass.

#### H-00e (HIGH): Audit log TCP port scan oracle
**Status: CONFIRMED — Probe findings hold**
- `src/controller/config/controller.go:107` — `audit.CheckEndpointActive(auditEP)` uses `syslog.Dial("tcp", ...)` — distinguishable errors for open/closed/filtered ports.

#### H-00f (HIGH): Preheat SSRF with IP encoding bypasses
**Status: CONFIRMED — Probe findings hold**
- `src/lib/endpoint.go:27-45`: `ValidateHTTPURL` only checks scheme — `http://127.0.0.1` passes (confirmed by `endpoint_test.go:32`). No IP denylist.

#### H-00g (HIGH): Registry credential theft via URL pivot
**Status: CONFIRMED — Probe findings hold**
- Registry URL validated via `ValidateHTTPURL` (scheme-only). Credentials sent on health check to attacker server.

#### H-00h (HIGH): Registry credentials plaintext in Redis job queue
**Status: CONFIRMED — Probe findings hold**
- Credentials serialized as plaintext JSON into Redis job parameters.

#### H-00i (HIGH): LDAP/OIDC endpoint pivot to attacker IdP
**Status: CONFIRMED — Probe findings hold**
- `src/lib/config/metadata/metadatalist.go:96`: `LDAPURL` is `NonEmptyStringType` — no URL validation.
- `src/lib/config/metadata/metadatalist.go:139`: `OIDCEndpoint` is `StringType` — no URL validation.

#### H-00j (HIGH): DNS rebinding architectural gap
**Status: CONFIRMED — Probe findings hold**
- Validate-at-store, execute-later pattern confirmed across webhook, scanner, preheat flows.

---

### H-01 (HIGH): Webhook Queue Exhaustion — Unbounded Policy Creation Starves Job Service

**Evidence Status: REACHABLE**

**Code path:**
1. `src/server/v2.0/handler/webhook.go:140-170` — `CreateWebhookPolicyOfProject`: requires `rbac.ActionCreate` on `ResourceNotificationPolicy` (project-admin). Validates event types and targets, then calls `n.webhookCtl.CreatePolicy(ctx, policy)`.
2. `src/controller/webhook/controller.go:84-86` — `CreatePolicy` directly delegates to `c.policyMgr.Create(ctx, policy)` — **no per-project policy count limit**.
3. `src/jobservice/job/impl/notification/webhook_job.go:53-55` — `MaxCurrency() uint { return 0 }` — **unlimited concurrency** for webhook jobs.
4. `src/jobservice/job/impl/notification/webhook_job.go:38-50` — `MaxFails()` defaults to `3`, `ShouldRetry()` returns `true` unconditionally.
5. `src/jobservice/worker/cworker/c_worker.go:431-443` — `w.pool.JobWithOptions(name, work.JobOptions{MaxConcurrency: theJ.MaxCurrency(), ...})` — `MaxConcurrency: 0` means unlimited in gocraft/work.
6. `src/jobservice/worker/cworker/c_worker.go:206-211` — `w.enqueuer.Enqueue(jobName, params)` — unbounded Redis list enqueue.

**Sanitizers/blockers found:** None. No per-project policy count cap, no queue depth limit, no rate limiting on webhook creation or event processing.

**Attacker control confirmed:** YES — Project-admin can create unlimited policies (confirmed no count check in controller.go:84-86), each subscribed to all event types (validated only for supported types at webhook.go:437-447), pointing to a slow/non-responsive endpoint.

**Amplification factor:** Each Harbor event (push, pull, delete) generates N jobs × (up to 3 retries) = 3N job attempts per event per project. A single project with 100 policies subscribed to all events would generate 300 job attempts per event, all competing for the shared worker pool (default 10 workers per `c_worker.go:47`).

---

### H-02 (HIGH): Scanner Registration SSRF via PingScanner Endpoint

**Evidence Status: REACHABLE**

**Code path:**
1. `src/server/v2.0/handler/scanner.go:169-190` — `PingScanner`: requires `rbac.ActionRead` on `ResourceScanner` (system admin). Constructs `Registration` with user-supplied `URL` at line 176, calls `r.Validate(false)` then `s.scannerCtl.Ping(ctx, r)`.
2. `src/pkg/scan/dao/scanner/model.go:100-127` — `Registration.Validate()`: calls `lib.ValidateHTTPURL(r.URL)` at line 109.
3. `src/lib/endpoint.go:27-45` — `ValidateHTTPURL`: only checks scheme is `http` or `https`. Returns `scheme://host/path` — **no IP filtering**. `http://169.254.169.254` and `http://127.0.0.1` both pass (confirmed by `endpoint_test.go:32-33`).
4. `src/controller/scanner/base_controller.go:306-333` — `Ping()`: for new registrations (ID=0), calls `bc.getScannerAdapterMetadata(registration)` at line 319.
5. `src/controller/scanner/base_controller.go:353-360` — `getScannerAdapterMetadata`: calls `registration.Client(bc.clientPool)` then `client.GetMetadata()`.
6. `src/pkg/scan/rest/v1/client.go:110-129` — `GetMetadata()`: makes `http.NewRequest(http.MethodGet, def.URL, nil)` where `def.URL` is `{baseRoute}/api/v1/metadata`.
7. `src/pkg/scan/rest/v1/spec.go:88-95` — `Metadata()`: URL is `{scannerURL}/api/v1/metadata`.

**Full SSRF path:** User-supplied URL → `ValidateHTTPURL` (scheme-only) → stored as `r.URL` → `{r.URL}/api/v1/metadata` → outbound HTTP GET.

**Sanitizers/blockers found:**
- `ValidateHTTPURL` strips query params and fragments (line 44: returns `scheme://host/path`).
- Fixed path suffix `/api/v1/metadata` appended — attacker cannot control full path.
- Error messages from `Ping()` may leak connection details (connection refused vs timeout vs parse error).

**Attacker control confirmed:** YES — System admin controls the URL. The path suffix `/api/v1/metadata` is appended, limiting exploitation to hosts where this path returns useful info or error-based oracle for internal service discovery.

**Also applies to:** `CreateScanner` (scanner.go:45-64) and `UpdateScanner` (scanner.go:206-237) — both call `r.Validate()` and subsequently `Ping` if registered. The `UseInternalAddr` flag (model.go:57) provides additional pivot to internal Docker registry address.

---

### H-03 (HIGH): IsLocalPath Backslash Bypass — OIDC Open Redirect to Credential Phishing

**Evidence Status: PARTIAL**

**Code path:**
1. `src/core/controllers/oidc.go:81-86` — `RedirectLogin`: reads `redirect_url` from query param, calls `utils.IsLocalPath(redirectURL)`. If valid, stores in session.
2. `src/common/utils/utils.go:308-311` — `IsLocalPath`: `return len(path) == 0 || (strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//"))`. This checks:
   - Empty path → true
   - Starts with `/` but not `//` → true
3. `src/core/controllers/oidc.go:230-233` — Callback: retrieves `redirectURLStr` from session (line 124-126), uses it in `oc.Controller.Redirect(redirectURLStr, http.StatusFound)` — **no re-validation**.

**Bypass analysis:**
- `/\evil.com` passes `IsLocalPath` (starts with `/`, not `//`). Whether this redirects to `evil.com` depends on browser behavior and Go's HTTP redirect handling.
- Go's `http.Redirect` sets `Location: /\evil.com` header. Modern browsers (Chrome, Firefox, Safari) treat `\` as `/` in URL parsing per WHATWG URL spec, so `/\evil.com` becomes `//evil.com` → protocol-relative redirect to `evil.com`.
- `/%09/evil.com` — tab character in path: `IsLocalPath` sees it as starting with `/` but not `//`, passes check. Browser behavior varies.

**Sanitizers/blockers found:**
- `IsLocalPath` blocks `//` prefix (protocol-relative URLs).
- No re-validation on Callback path (line 233) — stored value used directly.
- Go HTTP redirect does NOT sanitize backslash in Location header.

**Attacker control confirmed:** PARTIAL — Attacker controls `redirect_url` query param. The bypass via `/\evil.com` is browser-dependent. Modern browsers following WHATWG URL spec WILL redirect to `evil.com`. The session storage means the malicious URL persists across the OIDC roundtrip.

**TOCTOU gap confirmed:** Validation only at `RedirectLogin` (line 82), execution at `Callback` (line 233). Also note line 203: `oc.Controller.Redirect(fmt.Sprintf("/oidc-onboard?username=%s&redirect_url=%s", username, redirectURLStr), http.StatusFound)` — the `redirectURLStr` is passed through the onboard flow URL-unescaped, creating additional injection potential.

---

### H-04 (MEDIUM): Purge Audit Log SQL Concatenation — Fragile Allowlist Enables Future Injection

**Evidence Status: PARTIAL (latent vulnerability, not currently exploitable)**

**Code path:**
1. `src/pkg/audit/dao/dao.go:72-102` — `Purge`: receives `includeOperations []string`, calls `permitOps(includeOperations)` at line 81, then concatenates result into SQL at line 86: `"AND lower(operation) IN ('" + strings.Join(filterOps, "','") + "')"`.
2. `src/pkg/audit/dao/dao.go:125-137` — `permitOps`: filters against `allowedMaps` (line 54-58): `{"pull", "create", "delete"}`. Only these 3 values can survive.
3. `src/pkg/auditext/dao/dao.go:142-171` — `Purge` for audit_log_ext: calls `permitEventTypes(includeEventTypes)` at line 150, then concatenates at line 155: `"DELETE FROM audit_log_ext WHERE ... AND lower(operation || '_' || resource_type) IN ('" + strings.Join(filterEvents, "','") + "')"`.
4. `src/pkg/auditext/dao/dao.go:193-207` — `permitEventTypes`: filters against `model.EventTypes` (14 entries from model.go:49-64) and `model.OtherEventTypes` (model.go:67: `EventTypes[3:]`).

**Allowlist values (audit_log_ext):**
```
"create_artifact", "delete_artifact", "pull_artifact", "create_project",
"delete_project", "delete_repository", "login_user", "logout_user",
"create_user", "delete_user", "update_user", "create_robot",
"delete_robot", "update_configuration"
```

**Sanitizers/blockers found:**
- `permitOps` (audit/dao): strict 3-entry allowlist — **currently safe**.
- `permitEventTypes` (auditext/dao): 14-entry allowlist — all values are simple ASCII with underscores, **currently safe**.
- `strings.ToLower()` applied before allowlist check.
- However: **no parameterized query** used. SQL injection would occur if any allowlist value contained `'`.

**Attacker control confirmed:** NO (currently). The `includeOperations` parameter comes from job parameters (`common.PurgeAuditIncludeEventTypes`), which is set by the system purge job — not directly by user input. The allowlist prevents any malicious value from reaching the SQL concatenation.

**Latent risk:** The `OtherEvents` special value at `auditext/dao/dao.go:202-204` appends `model.OtherEventTypes` (11 entries). If a new event type containing `'` is added to `EventTypes`, it would bypass into the SQL. The comment at line 192 acknowledges this: "use this function to avoid SQL injection" — indicating awareness of the risk but reliance on naming convention rather than parameterized queries.

---

### H-05 (HIGH): Combinatorial Chain — Audit Forward Port Scan + Config Password Leak → Full Internal Pivot

**Evidence Status: REACHABLE (chain of individually confirmed vulnerabilities)**

**Component verification:**
1. **Port scan oracle (H-00e):** `src/controller/config/controller.go:107` — `audit.CheckEndpointActive(auditEP)` uses TCP dial. Error messages distinguish open/closed/filtered. CONFIRMED.
2. **Password leak (H-00b):** `src/server/v2.0/handler/config.go:43-44` — Solution-user gets `AllConfigs` without password stripping. Exposes `LDAPSearchPwd` (metadatalist.go:93, PasswordType), `OIDCClientSecret` (metadatalist.go:141, PasswordType), `PostGreSQLPassword` (metadatalist.go:106, PasswordType), `AdminInitialPassword` (metadatalist.go:70, PasswordType). CONFIRMED.
3. **Endpoint pivot (H-00i):** LDAPURL (metadatalist.go:96, NonEmptyStringType), OIDCEndpoint (metadatalist.go:139, StringType), UAAEndpoint (metadatalist.go:127, StringType), HTTPAuthProxyEndpoint (metadatalist.go:130, StringType) — all no URL validation. CONFIRMED.

**Chain feasibility:** All three components require system-admin or solution-user access. A single compromised system-admin account enables the full kill chain. The sequential steps (scan → leak → pivot) are operationally feasible within a single session.

**Attacker control confirmed:** YES — System admin controls all three steps. Solution-user access for step 2 may be obtainable separately.

---

### H-06 (MEDIUM): Webhook AuthHeader Injection via Full Header Replacement

**Evidence Status: PARTIAL**

**Code path:**
1. `src/pkg/notifier/handler/notification/http_handler.go:78-79` — `header.Set("Authorization", event.Target.AuthHeader)` — sets auth header on a Go `http.Header` map.
2. `src/pkg/notifier/handler/notification/http_handler.go:82-84` — `json.Marshal(header)` serializes the header map to JSON.
3. `src/pkg/notifier/handler/notification/http_handler.go:87-92` — JSON stored as `"header"` parameter in job data.
4. `src/jobservice/job/impl/notification/webhook_job.go:110-116` — On execution: `json.Unmarshal([]byte(h), &header)` deserializes into `http.Header` map, then `req.Header = header` **replaces** the entire request header map.

**Key finding — Full header replacement (webhook_job.go:115):** `req.Header = header` overwrites all default headers set by `http.NewRequest` (including `Host`, `User-Agent`, `Content-Length`). This is NOT a merge — it's a complete replacement.

**CRLF injection analysis:**
- Go's `net/http` transport (since Go 1.15) validates header values and rejects `\r\n` during write. This blocks CRLF injection via header values.
- However, the JSON deserialization path allows **arbitrary header keys** to be injected. The `http_handler.go:73` `formatter.Format()` returns a header map that may include `Content-Type` and other standard headers. The auth header is added to this map. Then the ENTIRE map is serialized → deserialized → assigned.
- An attacker who controls additional webhook policy fields (e.g., via custom payload format) could potentially inject arbitrary headers.

**Sanitizers/blockers found:**
- Go `net/http` transport CRLF validation on header write — blocks `\r\n` in values.
- `header.Set("Authorization", ...)` — Go's `textproto.MIMEHeader` canonicalizes key but does not sanitize value beyond what transport enforces.
- The auth header value itself is stored as-is from the webhook policy target.

**Attacker control confirmed:** PARTIAL — Project-admin controls `AuthHeader` value. The CRLF injection is blocked by Go runtime. However, the full header replacement pattern (`req.Header = header`) means that if additional header keys can be injected via the format pipeline, they would override security-sensitive headers. The practical exploitability depends on what headers the formatter adds and whether the webhook target proxy trusts headers like `Host` or `X-Forwarded-For`.

---

### H-07 (HIGH): Config URL Fields Accept Arbitrary Internal URLs — AuthProxy/UAA SSRF

**Evidence Status: REACHABLE**

**Code path:**
1. `src/server/v2.0/handler/config.go:75-92` — `UpdateConfigurations`: requires `rbac.ActionUpdate` on `ResourceConfiguration` (system admin). Calls `toCfgMap(conf)` → `c.controller.UpdateUserConfigs(ctx, cfgMap)`.
2. `src/controller/config/controller.go:79-98` — `UpdateUserConfigs`: calls `c.validateCfg(ctx, conf)` → `mgr.UpdateConfig(ctx, conf)`.
3. `src/controller/config/controller.go:115-147` — `validateCfg`: calls `mgr.ValidateCfg(ctx, cfgs)` which validates types per `metadatalist.go` definitions, then `verifySkipAuditLogCfg` and `verifyValueLengthCfg`. **No URL validation for any endpoint field.**

**Config fields with no URL validation (all `StringType` in metadatalist.go):**
- `http_authproxy_endpoint` (line 130): `StringType` — accepts ANY string including `http://169.254.169.254/`, `ftp://`, `file:///`.
- `http_authproxy_tokenreview_endpoint` (line 131): `StringType` — same.
- `uaa_endpoint` (line 127): `StringType` — same.
- `oidc_endpoint` (line 139): `StringType` — same.
- `audit_log_forward_endpoint` (line 192): `StringType` — same.

**Contrast with validated fields:**
- Scanner URLs: use `lib.ValidateHTTPURL` (scheme check) via `Registration.Validate()`.
- Webhook URLs: use `utils.ParseEndpoint` (scheme check) via `validateTargets`.
- These config fields: **zero URL validation** — only `StringType.validate()` which is a no-op for format.

**Outbound request triggers:**
- `http_authproxy_endpoint`: triggered on every authproxy login attempt — high frequency SSRF oracle.
- `http_authproxy_tokenreview_endpoint`: triggered on token review requests.
- `oidc_endpoint`: triggers `GET {endpoint}/.well-known/openid-configuration` during OIDC setup.
- `uaa_endpoint`: triggers outbound requests during UAA authentication.
- `audit_log_forward_endpoint`: triggers TCP connection via `syslog.Dial` (already confirmed in H-00e).

**Sanitizers/blockers found:** NONE for URL format. The `validateCfg` function (controller.go:115-147) only checks auth mode compatibility, audit log skip config, and value length — no URL validation for any endpoint field.

**Attacker control confirmed:** YES — System admin has full control over these config values via `PUT /api/v2.0/configurations`. The values are stored directly and used in subsequent outbound HTTP requests without any URL validation or IP filtering.

---

### Evidence Summary Table

| Hypothesis | Status | Severity | Key Evidence |
|-----------|--------|----------|--------------|
| H-00a | CONFIRMED | CRITICAL | metadatalist.go:192-193, controller.go:149-169 |
| H-00b | CONFIRMED | CRITICAL | config.go:41-59, bypasses ConvertForGet |
| H-00c | CONFIRMED | HIGH | webhook.go:409-415, ParseEndpoint scheme-only |
| H-00d | CONFIRMED | HIGH | http_handler.go:78-79, webhook_job.go:91-96 |
| H-00e | CONFIRMED | HIGH | controller.go:107, CheckEndpointActive TCP dial |
| H-00f | CONFIRMED | HIGH | endpoint.go:27-45, no IP filtering |
| H-00g | CONFIRMED | HIGH | ValidateHTTPURL scheme-only on registry URL |
| H-00h | CONFIRMED | HIGH | Plaintext credentials in Redis job params |
| H-00i | CONFIRMED | HIGH | metadatalist.go:96,139 — no URL validation |
| H-00j | CONFIRMED | HIGH | Validate-at-store, execute-later pattern |
| **H-01** | **REACHABLE** | **HIGH** | No policy count limit, MaxConcurrency=0, ShouldRetry=true |
| **H-02** | **REACHABLE** | **HIGH** | PingScanner→ValidateHTTPURL(scheme-only)→GET {url}/api/v1/metadata |
| **H-03** | **PARTIAL** | **HIGH** | IsLocalPath bypass via `/\evil.com`, browser-dependent |
| **H-04** | **PARTIAL** | **MEDIUM** | SQL concat with allowlist — safe now, fragile architecture |
| **H-05** | **REACHABLE** | **HIGH** | Chain of H-00e+H-00b+H-00i, all individually confirmed |
| **H-06** | **PARTIAL** | **MEDIUM** | Full header replacement via JSON, CRLF blocked by Go runtime |
| **H-07** | **REACHABLE** | **HIGH** | Config URL fields all StringType, zero URL validation |

## Round 3 -- Challenge

**Advocate: advocate-02 (Synthesizer acting as advocate due to sub-agent unavailability)**
**Timestamp: 2026-03-27T11:30:00Z**

### Defense Assessment: Pre-Seeded Hypotheses (H-00a through H-00j)

**Common defense argument for system-admin hypotheses (H-00a, H-00b, H-00e, H-00g, H-00h, H-00i, H-00j, H-07):**
- All require system-admin or solution-user role. A compromised system-admin can already do significant damage by design.
- **Counter:** Harbor's security model expects system-admins to manage config, but NOT to have SSRF/port-scan/credential-theft capabilities. These are privilege escalation from "admin" to "infrastructure attacker." System-admin should configure Harbor, not scan internal networks or steal LDAP passwords. This defense is INSUFFICIENT.

**H-00a (CRITICAL): Evidence destruction** -- No defense found. `verifySkipAuditLogCfg` only checks that endpoint exists, not legitimacy. No FP.

**H-00b (CRITICAL): Solution-user password leak** -- Defense: requires solution-user secret (internal shared secret). This is typically only accessible from within the Harbor container network. **Partial defense** but solution-user secret can leak via env vars, Kubernetes secret access, or container escape. Not FP, but severity may be lower if solution-user access is considered trusted-internal.

**H-00c (HIGH): Webhook SSRF** -- No defense found. No IP filtering anywhere on the path. Project-admin role is common. Not FP.

**H-00d (HIGH): Authenticated SSRF** -- No defense found. Amplifier for H-00c. Not FP.

**H-00e (HIGH): Audit TCP port scan** -- No defense found. syslog.Dial has no IP filtering. Not FP.

**H-00f (HIGH): Preheat SSRF** -- No defense found. ValidateHTTPURL is scheme-only. Not FP.

**H-00g (HIGH): Registry credential theft** -- No defense found. Not FP.

**H-00h (HIGH): Redis credential exposure** -- Defense: Redis is typically on internal Docker network only. However, no Redis authentication by default in many deployments. Severity depends on deployment. Not FP but may be MEDIUM in well-configured environments.

**H-00i (HIGH): LDAP/OIDC endpoint pivot** -- No URL validation. Requires system-admin. Not FP.

**H-00j (HIGH): DNS rebinding gap** -- Architectural issue. No current DNS pinning. Not FP but is forward-looking.

---

### Defense Assessment: New Hypotheses

#### H-01 (HIGH): Webhook Queue Exhaustion
- **Layer 1 (Framework):** No rate limiting middleware on webhook creation.
- **Layer 2 (Application):** No per-project policy count limit in controller. `MaxCurrency()=0` confirmed.
- **Layer 3 (Infrastructure):** Default worker pool size (`c_worker.go:47`) is configurable via `WORKER_POOL_SIZE` env var but NOT specific to webhook jobs.
- **Layer 4 (Runtime):** Go runtime has no goroutine limit.
- **Layer 5 (Configuration):** `JOBSERVICE_WEBHOOK_JOB_HTTP_CLIENT_TIMEOUT` defaults to 3 seconds.
- **FP Assessment:** NOT FP. However, severity may be MEDIUM rather than HIGH -- DoS requires sustained attack and recovery is automatic once policies are deleted. The 3-second timeout limits slow-endpoint amplification. Worker pool default of 10 provides natural throttling -- webhook jobs compete for workers but don't create unlimited goroutines since gocraft/work uses a fixed worker pool.
- **Residual risk:** Queue depth exhaustion in Redis is real. Worker starvation across job types is real.

#### H-02 (HIGH): Scanner SSRF via PingScanner
- **Layer 1-5:** System admin required. `ValidateHTTPURL` is scheme-only. Fixed path suffix `/api/v1/metadata` appended limits exploitation to error-based oracle rather than full content read.
- **FP Assessment:** NOT FP. However, the fixed path suffix significantly limits the attack. Downgrade signal to MEDIUM -- SSRF oracle only, no arbitrary content retrieval, requires system-admin.
- **Residual risk:** Port/service scanning via error messages. Cannot read arbitrary content.

#### H-03 (HIGH): IsLocalPath Backslash Bypass
- **Layer 4 (Runtime):** Go's `http.Redirect` does NOT sanitize backslash in Location header. WHATWG URL spec treats `\` as `/`. Modern browsers (Chrome 114+, Firefox 114+, Safari 16+) all normalize `/\evil.com` to `//evil.com` (protocol-relative redirect).
- **Layer 2 (Application):** `IsLocalPath` only blocks `//` prefix, NOT backslash variants.
- **FP Assessment:** NOT FP. The OIDC redirect path is confirmed vulnerable to backslash bypass. Browser behavior is consistent across modern browsers per WHATWG spec. However, requires OIDC auth mode to be configured and user interaction (clicking crafted link).
- **Residual risk:** Open redirect via OIDC login flow. Social engineering attack.

#### H-04 (MEDIUM): Purge SQL Fragile Allowlist
- **FP Assessment:** Currently NOT exploitable. Allowlist values are safe ASCII. This is a code quality / defense-in-depth issue, not an active vulnerability. **DROP as LOW severity** -- no current exploitation path, future-facing only.

#### H-05 (HIGH): Combinatorial Chain
- **FP Assessment:** This is a kill chain analysis, not a separate vulnerability. Each component is separately tracked. **DUPLICATE** -- documenting the chain is useful for the report narrative but doesn't warrant a separate finding.

#### H-06 (MEDIUM): Webhook Header Injection
- **Layer 4 (Runtime):** Go 1.15+ CRLF protection in `net/http` blocks header value injection.
- **Layer 2 (Application):** The JSON deserialization creates arbitrary header keys, but the formatter (`Format()`) only adds `Content-Type` and `Authorization`. The full header replacement via `req.Header = header` could override `Host` but this is Go's `net/http` which uses the URL's host, not the Header map's `Host` value, for connection routing.
- **FP Assessment:** PARTIAL defense exists. CRLF blocked. Arbitrary key injection possible but Go `net/http` ignores `Host` in Header map for routing. Downgrade to LOW -- theoretical concern with minimal practical impact. **DROP.**

#### H-07 (HIGH): Config URL Fields SSRF
- **FP Assessment:** NOT FP. These config fields accept arbitrary strings. However, the SSRF is triggered only when the corresponding auth mode is activated. Authproxy must be the active auth mode for `http_authproxy_endpoint` SSRF to trigger. System-admin controls this. The finding partially overlaps with H-00i (LDAP/OIDC config) as a pattern. Consider merging into a single "Config URL SSRF" finding covering all unvalidated URL fields.
- **Residual risk:** Real SSRF when auth mode is activated. High-frequency oracle if authproxy mode is used.

#### H-08 (HIGH): Preheat Token Theft via Rogue P2P Instance
- **Layer 2 (Application):** Bearer token generated by `credMaker` is a robot-account pull token. Scoped to image pull within the project.
- **FP Assessment:** NOT FP. System-admin controls preheat instance endpoint. Token with pull scope forwarded verbatim. Defense is that token has limited scope (pull only, project-scoped) and limited lifetime. Still HIGH -- allows exfiltration of container images including embedded secrets.

#### H-09 (MEDIUM): UAAClientSecret Not Redacted
- **Layer 2 (Application):** Confirmed `StringType` at metadatalist.go:126 vs `PasswordType` for other secrets. `ConvertForGet` only strips `PasswordType`.
- **FP Assessment:** NOT FP. Type annotation bug. Exposed to any system-admin via normal API. MEDIUM severity -- requires admin access, UAA auth mode must be configured.

#### H-10 (HIGH): Preheat DNS Rebinding
- **FP Assessment:** Concrete instance of H-00j. DUPLICATE of the architectural pattern. The explicit `// !WARN` comment is interesting but doesn't create a separate finding from the broader DNS rebinding gap.

#### H-11 (CRITICAL): Preheat Chain
- **FP Assessment:** DUPLICATE -- kill chain combining H-08, H-10, H-00g. Same reasoning as H-05.

#### H-12 (MEDIUM): IPv6 Zone-ID Bypass
- **FP Assessment:** This is a bypass variant of the existing SSRF findings (H-00c, H-00f). No IP denylist exists currently, so there's nothing to bypass. If/when an IP denylist is added, this becomes relevant. **DROP as LOW** -- no current protection to bypass.

#### H-13 (CRITICAL): Stealth Exfiltration Chain
- **FP Assessment:** DUPLICATE -- kill chain combining H-00a, H-00e, H-00c/H-00d. Valuable narrative but not a separate finding.

#### H-14 (MEDIUM): Webhook DoS via Slow Endpoint
- **FP Assessment:** Overlaps with H-01. gocraft/work uses a fixed worker pool (default 10 workers), NOT unlimited goroutines. The MaxConcurrency=0 means no per-job-type limit, but the overall pool is bounded. Severity is MEDIUM at best. **MERGE with H-01.**

### [ADVOCATE-02] Deep Defense Briefs — Exhaustive 5-Layer Analysis

**Advocate: advocate-02 (Defense Advocate)**
**Timestamp: 2026-03-27T04:15:00Z**

*Note: These briefs supplement the synthesizer's preliminary challenge assessment with exhaustive code-level evidence across all 5 defense layers. Findings below may confirm, refine, or contradict the synthesizer's initial assessments.*

---

#### H-01 (REACHABLE → MEDIUM): Webhook Queue Exhaustion — Bounded by Worker Pool

**Layer 1 — Framework:** No rate-limiting middleware on `POST /webhooks`. Search of `src/server/middleware/` found zero rate-limit or throttle references applicable to webhook routes. Notification middleware (`middleware/notification/notification.go`) only fires post-response events.

**Layer 2 — Application:** Policy creation restricted to **project-admin** only (`rbac_role.go:80-84`). Maintainer gets `ActionRead`/`ActionList` only (`rbac_role.go:165-166`). **No per-project policy count limit** — `controller/webhook/controller.go:84-86` delegates directly to DAO. Quota middleware (`middleware/quota/`) tracks only storage (blobs/artifacts), not notification policies — zero references to `ResourceNotificationPolicy` or `webhook`.

**Layer 3 — Infrastructure:** Neither `harbor-jobservice` nor `redis` containers have `mem_limit` or `resources:` in Docker Compose template (`docker-compose.yml.jinja:228-286`). Redis `maxmemory` commented out (`redis.conf:559,590`). No Redis memory cap by default.

**Layer 4 — Runtime (KEY DEFENSE):** Global worker pool **capped at 10 concurrent workers** (`c_worker.go:47`, configurable via `JOB_SERVICE_POOL_WORKERS` / `harbor.yml.tmpl:142`). This is the critical bound — gocraft/work processes at most 10 jobs simultaneously across ALL job types. `MaxFails=3` (`http_helper.go:32`, configurable via `JOBSERVICE_WEBHOOK_JOB_MAX_RETRY`). HTTP client timeout 3s. Failed jobs discarded (`SkipDead: true`, `c_worker.go:437`). Job deduplication (`de_duplicator.go`) inapplicable — different policies produce different parameters.

**Layer 5 — Configuration:** `max_job_workers`, `webhook_job_max_retry`, `webhook_job_http_client_timeout` are tunable but don't address queue depth.

**FP Assessment:** NOT a false positive, but severity overstated. The 10-worker pool prevents goroutine exhaustion (H-14's claim). The real risk is queue starvation (webhook jobs blocking replication/scan/GC) and Redis memory growth with no `maxmemory` cap.

**Residual Risk:** Queue starvation is real. Redis memory exhaustion is the primary remaining threat. Recommend **MEDIUM** (confirmed — agrees with synthesizer).

---

#### H-02 (REACHABLE → MEDIUM): Scanner SSRF — Blind, Fixed-Path, No-Redirect

**Layer 1 — Framework:** Full auth middleware chain applies (`security.go:28-38`). CSRF skipped for `/api/` with non-session auth but irrelevant to authenticated attacker.

**Layer 2 — Application:** `RequireSystemAccess(ctx, rbac.ActionRead, rbac.ResourceScanner)` (`scanner.go:170`). Only system admins pass via admin evaluator (`admin/admin.go:34-38`). System-scoped robot accounts with explicit `ResourceScanner:ActionRead` could also pass. `ValidateHTTPURL` (`endpoint.go:27-45`) strips query/fragment/user-info, enforces `http`/`https` only — but **no IP blocklist**. **Fixed path suffix** `/api/v1/metadata` always appended (`spec.go:88-95`) — attacker cannot control request path.

**Layer 3 — Infrastructure:** Single flat `harbor` bridge network (`docker-compose.yml.jinja:399-401`), no egress filtering. Cloud metadata path mismatch: fixed `/api/v1/metadata` does NOT match AWS IMDS (`/latest/meta-data/`), GCP (`/computeMetadata/v1/`), or Azure IMDS paths. This is an **incidental but meaningful structural defense** against cloud credential theft.

**Layer 4 — Runtime (KEY DEFENSES):**
- **Blind SSRF**: `PingScanner` returns empty `200 OK` (`scanner.go:188`). Response data never returned to caller. Only timing/error oracle available.
- **Redirects disabled**: `http.ErrUseLastResponse` (`client.go:86-88`). Cannot chain to other endpoints.
- **5-second timeout** (`client.go:82`).
- **No response size limit** (`io.ReadAll` at `client.go:260`) — potential memory exhaustion DoS, but not data exfiltration.

**Layer 5 — Configuration:** `SkipCertVerify` defaults to `false`. No operator-side URL allowlist mechanism.

**FP Assessment:** NOT a false positive, but three structural constraints (blind, fixed path, no redirects) dramatically limit exploitation to port/service scanning only. Cloud metadata theft is incidentally blocked by path mismatch.

**Residual Risk:** Internal service fingerprinting via error oracle. Recommend **MEDIUM** (confirmed — agrees with synthesizer).

---

#### H-03 (PARTIAL → REACHABLE, HIGH): IsLocalPath Backslash Bypass — No Defense at Any Layer

**Layer 1 — Framework:** Beego v2.3.8 `Controller.Redirect()` (`controller.go:370-373`) delegates directly to `http.Redirect()`. **Zero sanitization** — does not inspect, encode, or validate the URL.

**Layer 2 — Application:** `IsLocalPath` (`utils.go:308-311`) checks only `HasPrefix("/")` and `!HasPrefix("//")`. Payload `/\evil.com` passes both. Test suite (`utils_test.go:452-473`) has **no backslash test case**. No `url.Parse` between session retrieval and redirect (`oidc.go:233`). Onboard path (`oidc.go:203`) embeds redirect URL **without `url.QueryEscape`**. Angular frontend (`oidc-onboard.component.ts:53`) passes directly to `router.navigateByUrl` with no validation.

**Layer 3 — Infrastructure:** Nginx `/c/` location block has no `proxy_redirect` or header manipulation. `Location: /\evil.com` forwarded **verbatim**. Security headers (`X-Frame-Options: DENY`, `CSP: frame-ancestors 'none'`, `HSTS`) prevent framing but are **irrelevant to redirect following**.

**Layer 4 — Runtime:** Go's `net/http.Redirect` (`server.go:2367-2420`) applies `path.Clean` to path-only URLs. `path.Clean("/\\evil.com")` returns `"/\\evil.com"` **unchanged** — Go's `path` package only treats `/` as separator. `hexEscapeNonASCII` only escapes bytes `>= 0x80`; backslash (`0x5C`) passes through. `headerNewlineToSpace` only replaces `\r`/`\n`. **No Go runtime layer sanitizes backslashes in Location headers.** Verified on Go 1.25.7/1.26.0.

**Layer 5 — Configuration:** No CSP headers on core service. No `Referrer-Policy`. No application-level `X-Content-Type-Options`.

**FP Assessment: NOT A FALSE POSITIVE. Zero defenses found at any layer.** The tracer's "PARTIAL" status was based on browser-dependency. After analysis: WHATWG URL Standard mandates `\` → `/` normalization for special scheme URLs. All modern browsers (Chrome, Firefox, Edge, Safari) implement this. `/\evil.com` → `//evil.com` → protocol-relative redirect to `evil.com`.

**UPGRADE: PARTIAL → REACHABLE.** No authentication required to craft the link. Only OIDC auth mode must be active. Severity remains **HIGH** (confirmed — agrees with synthesizer).

---

#### H-04 (PARTIAL → DROP): Purge SQL Allowlist — Correctly Implemented Defense

**Layer 1 — Framework:** BeeGo ORM `ormer.Raw(sql, retentionHour).Exec()` parameterizes only `retentionHour`. IN-clause values concatenated as raw strings. ORM provides **no independent protection** for concatenated portion.

**Layer 2 — Application (KEY DEFENSE):** `permitOps` (`audit/dao/dao.go:125-137`) enforces strict 3-entry allowlist from typed Go constants: `rbac.ActionPull` → `"pull"`, `rbac.ActionCreate` → `"create"`, `rbac.ActionDelete` → `"delete"`. Map populated once at package init, **never mutated at runtime**. Both `Purge` and `dryRunPurge` check `len(filterOps) == 0` and return without executing SQL. No path bypasses `permitOps` to reach `strings.Join`. `permitEventTypes` (`auditext/dao/dao.go:193-207`) enforces 14-entry allowlist from `model.EventTypes` — all compile-time string literals containing only `[a-z_]`. Function comment explicitly states purpose: *"use this function to avoid SQL injection"*.

**Layer 3 — Infrastructure:** Input originates from job parameters (not direct HTTP input): API handler → controller → job params → comma-split → `permitOps` → SQL. No path bypasses the allowlist gate.

**Layer 4 — Runtime:** No additional Go runtime protection for raw SQL. Defense depends entirely on allowlist.

**Layer 5 — Configuration:** Allowlist values are immutable string literals. No configuration can inject SQL metacharacters.

**FP Assessment: LIKELY FALSE POSITIVE.** The allowlist is correctly implemented and blocks all user-supplied tokens. The SQL concatenation pattern is poor practice but not exploitable. This is a code quality concern (should use parameterized queries), not a security vulnerability.

**Residual Risk:** Theoretical future regression only — requires developer adding `'`-containing event type to `model.EventTypes`. Recommend **DROP** (confirmed — agrees with synthesizer).

---

#### H-05 (REACHABLE → MEDIUM): Combinatorial Chain — Critical Link Broken

**Layer 1 — Framework:** `PUT /api/v2.0/configurations` requires system admin. `GET /api/v2.0/internalconfig` (password leak endpoint) requires `RequireSolutionUserAccess` (`config.go:107-126`).

**Layer 2 — Application (CHAIN-BREAKING DEFENSE):** "Solution-user" is **not a human role**. It authenticates via `Authorization: Harbor-Secret <token>` header (`secret/request.go:25-37`). Secrets (`CORE_SECRET`, `JOBSERVICE_SECRET`) are **randomly generated at deployment** via `prepare` script, stored only inside `harbor-core`/`harbor-jobservice` containers (`lib/config/systemconfig.go:68-85`). Not static defaults, not human passwords, not exposed via API. `local.SecurityContext.IsSolutionUser()` always returns `false` (`local/context.go:83`) — **system admin cannot impersonate solution-user**. Exploiting H-00b requires container-level compromise, which already implies full system access.

Auth mode change **locked once any user exists** (`controller.go:288-294`): `authModeCanBeModified` returns `true` only when user count is 0. This blocks the H-00i endpoint pivot in any production deployment.

**Layer 3 — Infrastructure:** All containers share single `harbor` bridge. Obtaining `JOBSERVICE_SECRET` requires being inside container network.

**Layer 4 — Runtime:** `syslog.Dial` error oracle works for system admin (H-00e component is real).

**Layer 5 — Configuration:** `CONFIG_OVERWRITE_JSON` can lock all config (not default). Auth mode default is `db_auth`.

**FP Assessment: PARTIALLY FALSE POSITIVE.** The chain has a **broken critical link**: Step 2 (H-00b password leak) requires solution-user access, which requires container compromise — at which point the attacker already has full access. Without Step 2, the chain reduces to: port scan oracle + limited endpoint reconfiguration (auth mode locked). The "full internal pivot" as described is not achievable from system admin alone.

**Residual Risk:** Individual components (H-00e port scan, limited config URL setting) remain valid at reduced severity. Recommend **MEDIUM** as chain; individual components tracked separately (confirmed — agrees with synthesizer's DUPLICATE verdict).

---

#### H-06 (PARTIAL → DROP): Webhook Header Injection — Go Runtime Blocks Attack

**Layer 1 — Framework:** No `AuthHeader` validation in `validateTargets` (`webhook.go:405-435`). No length limit, no character restriction.

**Layer 2 — Application:** Header map built by formatter (`default.go:79-81`: `Content-Type: application/json`) + `header.Set("Authorization", authHeader)` (`http_handler.go:78-80`). Keys determined by formatter code at creation time, **not by user input**. Attacker controlling only `AuthHeader` (a string value) **cannot inject new header keys**. JSON serialized to Redis job params — no external path modifies the JSON between creation and execution.

**Layer 3 — Infrastructure:** Redis job params are internal. No external tampering path.

**Layer 4 — Runtime (KEY DEFENSES):**
- Go 1.25 (`go.mod:3`) **rejects CRLF in header values** at transport layer. `Transport.RoundTrip` refuses `\r`/`\n` in header values. Blocks header value injection.
- Go `Transport` **automatically adds** `Host`, `Content-Length`, `Transfer-Encoding` during `RoundTrip` regardless of `req.Header`. These critical headers **cannot be suppressed** by `req.Header = header`.
- Go transport validates header field names against RFC 7230 token rules at write time.

**Layer 5 — Configuration:** No configurable header validation exists.

**FP Assessment: LARGELY FALSE POSITIVE.** All three claimed attack vectors are blocked:
1. CRLF injection → Blocked by Go 1.25 transport.
2. Arbitrary header key injection → Not possible through AuthHeader (a value, not a key).
3. Security header override → Mitigated by Transport auto-adding `Host`/`Content-Length`/`Transfer-Encoding`.

The `req.Header = header` pattern is poor practice but not exploitable in current code paths.

**Residual Risk:** `AuthHeader` stored verbatim (no length/format check) — design smell, not vulnerability. Recommend **DROP** (confirmed — agrees with synthesizer).

---

#### H-07 (REACHABLE → MEDIUM): Config URL SSRF — Auth-Mode Lock Blocks Most Vectors

**Layer 1 — Framework:** System admin only (`RequireSystemAccess` with `rbac.ActionUpdate` on `ResourceConfiguration`).

**Layer 2 — Application (KEY DEFENSE):** Auth mode change **locked once any user exists** (`controller.go:118-130`, `authModeCanBeModified` at `controller.go:288-294`). This means:
- `http_authproxy_endpoint`/`http_authproxy_tokenreview_endpoint`: Authproxy security generator (`auth_proxy.go:37-39`) returns `nil` immediately when mode ≠ `http_auth`. If deployment uses `db_auth` (default), setting these has **zero effect**.
- `uaa_endpoint`: Same — only active in `uaa_auth` mode.
- `oidc_endpoint`: Only active in `oidc_auth` mode.
- **These SSRF vectors are exploitable ONLY if the respective auth mode is already active.** Admin cannot switch modes in production (users exist).

`CONFIG_OVERWRITE_JSON` env var locks all config updates (`controller.go:79-82`). Available for hardened deployments.

**Layer 3 — Infrastructure:** Single Docker bridge, no egress filtering.

**Layer 4 — Runtime:** Go HTTP client has no SSRF protection. Follows redirects, resolves internal hostnames, connects to private IPs.

**Layer 5 — Configuration:** Default auth mode `db_auth` (`metadatalist.go:71`). AuthProxy/UAA endpoints default to empty strings.

**FP Assessment: PARTIALLY FALSE POSITIVE for AuthProxy/UAA vectors.** Auth mode lock means these endpoints are inert in default and most production deployments. Only deployments that **already use** authproxy/UAA/OIDC are affected — and configuring those endpoints is the admin's expected job. `audit_log_forward_endpoint` remains real (auth-mode independent) but already tracked in H-00a/H-00e.

**Residual Risk:** Deployments with non-default auth modes have unvalidated URL fields. Recommend **MEDIUM** (confirmed — agrees with synthesizer).

---

### [ADVOCATE-02] Defense Summary Matrix

| Hyp | Tracer Status | Prosecution Severity | Defense Verdict | Recommended Severity | Key Blocking Defense |
|-----|--------------|---------------------|----------------|---------------------|---------------------|
| H-01 | REACHABLE | HIGH | Not FP — bounded | **MEDIUM** | Worker pool cap=10; MaxFails=3; SkipDead=true |
| H-02 | REACHABLE | HIGH | Not FP — limited | **MEDIUM** | Blind SSRF; fixed path `/api/v1/metadata`; no redirects |
| H-03 | PARTIAL | HIGH | **NOT FP — upgrade to REACHABLE** | **HIGH** | No defense at any layer |
| H-04 | PARTIAL | MEDIUM | **Likely FP** | **DROP** | Strict compile-time allowlist in permitOps/permitEventTypes |
| H-05 | REACHABLE | HIGH | **Partially FP — broken chain** | **MEDIUM** | Solution-user requires container secrets; auth mode locked |
| H-06 | PARTIAL | MEDIUM | **Largely FP** | **DROP** | Go 1.25 CRLF rejection; formatter-controlled keys |
| H-07 | REACHABLE | HIGH | **Partially FP** | **MEDIUM** | Auth mode locked in production; endpoints inert in db_auth |

**Net effect:** 2 confirmed (H-01 at MEDIUM, H-02 at MEDIUM), 1 confirmed+upgraded (H-03 at HIGH), 2 partially FP (H-05, H-07 at MEDIUM), 2 dropped (H-04, H-06).

---

## Round 4 -- Synthesis

**Synthesizer: chamber-02**
**Timestamp: 2026-03-27T12:00:00Z**

### [SYNTHESIZER] Verdict for H-00a -- 2026-03-27T12:00:00Z

**Prosecution summary**: System admin sets `audit_log_forward_endpoint` to attacker syslog + `skip_audit_log_database=true` in a single PUT. All audit events redirected to attacker, DB trail goes dark. The config change itself is not recorded. Confirmed at metadatalist.go:192-193, controller.go:149-169.

**Defense summary**: Requires system-admin privilege. `verifySkipAuditLogCfg` validates endpoint is non-empty but not legitimate. No other protection found.

**Pre-FP Gate**: all checks passed -- attacker control verified, framework protections searched (5 layers), trust boundary crossing confirmed (admin -> infrastructure compromise), normal attacker position (compromised admin), production code.

**Verdict: VALID**
**Severity: CRITICAL**
**Rationale**: Evidence destruction with no forensic trace is a critical security control bypass. The audit system -- Harbor's primary detective control -- is completely neutralized. System-admin privilege is the expected attacker position for insider threats.

**Finding draft written to**: security/findings-draft/p8-020-audit-evidence-destruction.md
**Registry updated**: AP-020 Audit Forward Endpoint Abuse

---

### [SYNTHESIZER] Verdict for H-00b -- 2026-03-27T12:00:00Z

**Prosecution summary**: Solution-user `GET /configurations` calls `AllConfigs()` bypassing `ConvertForGet()`, returning all PasswordType fields including LDAP bind password, OIDC client secret, PostgreSQL password. Confirmed at config.go:41-59.

**Defense summary**: Requires solution-user secret (internal shared secret). Typically accessible only from within Harbor container network. Partial defense -- secret may leak via env vars, Kubernetes secret exposure.

**Pre-FP Gate**: all checks passed -- attacker control verified (solution-user auth header), protections searched, trust boundary crossing confirmed (internal service -> credential exfiltration), requires solution-user access (internal service compromise, not internet-facing).

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Downgraded from CRITICAL to HIGH because solution-user access requires internal secret compromise (not directly internet-facing). However, the impact is severe -- single API call leaks all system secrets. Container escape or Kubernetes secret access provides the solution-user secret.

**Finding draft written to**: security/findings-draft/p8-021-solution-user-credential-leak.md
**Registry updated**: AP-021 Solution User Config Bypass

---

### [SYNTHESIZER] Verdict for H-00c -- 2026-03-27T12:00:00Z

**Prosecution summary**: Project-admin creates webhook with `address=http://169.254.169.254/latest/meta-data/`. No IP filtering in `validateTargets` (webhook.go:409-415) or `ParseEndpoint` (utils.go:36-53). Job service executes POST to cloud metadata. Confirmed end-to-end.

**Defense summary**: No blocking protections found. No IP filtering, no URL denylist, no DNS pinning. Project-admin role is common. Already documented in P7-002.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Classic SSRF with no mitigation. Project-admin role is easily obtainable. Cloud metadata access enables credential theft. Extends P7-002 with confirmed Deep Probe evidence.

**Finding draft written to**: security/findings-draft/p8-022-webhook-ssrf-no-ip-filter.md
**Registry updated**: AP-022 SSRF No IP Filtering Pattern

---

### [SYNTHESIZER] Verdict for H-00d -- 2026-03-27T12:00:00Z

**Prosecution summary**: Webhook `auth_header` field allows attacker-controlled Authorization header injection. Combined with `skip_cert_verify=true`, enables authenticated SSRF to internal HTTPS services. Confirmed at http_handler.go:78-79, webhook_job.go:91-96.

**Defense summary**: No blocking protections. auth_header value is stored and forwarded as-is.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Amplifies H-00c from blind SSRF to authenticated internal service access. The combination of auth header injection + TLS skip enables exploitation of internal services requiring authentication (e.g., Kubernetes API server). Merging with H-00c as part of the same finding (different facets of webhook SSRF).

**Finding draft written to**: (merged into p8-022-webhook-ssrf-no-ip-filter.md)
**Registry updated**: no new pattern (covered by AP-022)

---

### [SYNTHESIZER] Verdict for H-00e -- 2026-03-27T12:00:00Z

**Prosecution summary**: `CheckEndpointActive` at forward.go:65 uses `syslog.Dial("tcp", address)` with no IP validation. Error messages distinguish open/closed/filtered ports. System admin iterates targets via PUT /configurations.

**Defense summary**: Requires system-admin. TCP dial vs HTTP -- different protocol but same SSRF impact.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: TCP-level port scan oracle is distinct from HTTP SSRF. The syslog.Dial provides a different attack surface (TCP not HTTP) and enables network reconnaissance that informs other attacks. Error-based oracle is confirmed.

**Finding draft written to**: security/findings-draft/p8-023-audit-endpoint-tcp-portscan.md
**Registry updated**: AP-023 Validation-as-SSRF Pattern

---

### [SYNTHESIZER] Verdict for H-00f -- 2026-03-27T12:00:00Z

**Prosecution summary**: Preheat provider endpoint SSRF via ValidateHTTPURL (scheme-only check). IP encoding bypasses (hex, decimal, IPv6-mapped) confirmed at endpoint.go:27-45.

**Defense summary**: No IP filtering. Same ValidateHTTPURL pattern as other SSRF vectors.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Same root cause as H-00c (no IP filtering) but distinct entry point (preheat vs webhook). Project-admin role required. Covered by the same AP-022 pattern.

**Finding draft written to**: security/findings-draft/p8-024-preheat-ssrf.md
**Registry updated**: no new pattern (same as AP-022)

---

### [SYNTHESIZER] Verdict for H-00g -- 2026-03-27T12:00:00Z

**Prosecution summary**: System admin points registry URL at attacker server. Credentials (access_key/access_secret) sent via Basic auth on health check GET to {url}/v2/. Confirmed at native/adapter.go.

**Defense summary**: Requires system-admin. Credentials encrypted at rest but decrypted for health check.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Credential theft via SSRF pivot. Distinct from other SSRF findings because the impact is credential theft of stored registry credentials, not just network reconnaissance.

**Finding draft written to**: security/findings-draft/p8-025-registry-credential-theft.md
**Registry updated**: AP-025 Credential Exfiltration via URL Pivot

---

### [SYNTHESIZER] Verdict for H-00h -- 2026-03-27T12:00:00Z

**Prosecution summary**: Registry credentials (AccessSecret) decrypted from DB, serialized as plaintext JSON into Redis job parameters. Anyone with Redis read access can extract all replication credentials.

**Defense summary**: Redis is on internal Docker network. Some deployments may have Redis authentication. Credentials are transient (only present during job execution).

**Pre-FP Gate**: all checks passed -- credentials are in plaintext in Redis regardless of network configuration.

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Defense-in-depth violation. Credentials should remain encrypted until point of use. Redis often has no authentication in default Harbor deployments. Even with network isolation, any container compromise on the same Docker network exposes all registry credentials.

**Finding draft written to**: security/findings-draft/p8-026-redis-plaintext-credentials.md
**Registry updated**: AP-026 Plaintext Credential in Queue

---

### [SYNTHESIZER] Verdict for H-00i -- 2026-03-27T12:00:00Z

**Prosecution summary**: LDAP URL and OIDC endpoint config fields have no URL validation. System admin redirects all authentication to attacker-controlled IdP. Confirmed at metadatalist.go:96,139.

**Defense summary**: Requires system-admin. LDAP/OIDC endpoint changes are a legitimate admin operation.

**Pre-FP Gate**: all checks passed -- the issue is not that admins configure endpoints but that there's no validation preventing internal/malicious endpoints.

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: IdP pivot enables mass account takeover. A rogue LDAP server accepts any credentials; a rogue OIDC provider issues arbitrary tokens. Combined with H-00e port scan, attacker can target discovered internal services.

**Finding draft written to**: security/findings-draft/p8-027-ldap-oidc-endpoint-pivot.md
**Registry updated**: AP-027 Config URL No Validation

---

### [SYNTHESIZER] Verdict for H-00j -- 2026-03-27T12:00:00Z

**Prosecution summary**: Validate-at-store, execute-later pattern across webhook, preheat, scanner allows DNS rebinding bypass of any future IP denylist. No DNS pinning.

**Defense summary**: No current IP denylist exists -- so there's nothing to bypass currently. This is forward-looking.

**Pre-FP Gate**: failed on check-3 -- no current trust boundary crossing because no IP denylist exists to bypass. This is an architectural design flaw for future hardening, not a currently exploitable vulnerability.

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Downgraded from HIGH to MEDIUM. While architecturally significant, the DNS rebinding gap is currently moot because there IS no IP denylist to bypass. This becomes critical only when IP filtering is added. Worth documenting as an architectural note in the SSRF findings rather than a standalone finding.

**Finding draft written to**: (documented as architectural note in p8-022)
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-01 -- 2026-03-27T12:01:00Z

**Prosecution summary**: No per-project webhook policy count limit. MaxCurrency=0 (unlimited per-type concurrency). ShouldRetry=true with MaxFails=3. Attacker can flood shared job queue starving all job types.

**Defense summary**: gocraft/work worker pool has a bounded size (default 10 workers, configurable via WORKER_POOL_SIZE). This bounds concurrent execution even though per-type concurrency is unlimited. HTTP client timeout of 3s limits slow-endpoint amplification. Recovery is automatic once policies are deleted.

**Pre-FP Gate**: all checks passed -- attacker control verified, DoS is real but bounded by worker pool size.

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Worker starvation across job types is real -- a single project's webhook flood can starve replication, scanning, and GC jobs. However, bounded worker pool (default 10) limits blast radius. 3-second timeout limits connection hold. Downgraded from HIGH to MEDIUM.

**Finding draft written to**: security/findings-draft/p8-028-webhook-queue-exhaustion.md
**Registry updated**: AP-028 Job Queue Resource Exhaustion

---

### [SYNTHESIZER] Verdict for H-02 -- 2026-03-27T12:01:00Z

**Prosecution summary**: PingScanner accepts arbitrary URL via ValidateHTTPURL (scheme-only). Makes GET to {url}/api/v1/metadata. System-admin role required. Error oracle reveals port/service status.

**Defense summary**: Requires system-admin. Fixed path suffix `/api/v1/metadata` appended -- attacker cannot control full path. SSRF is limited to error-based oracle, not content retrieval.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Downgraded from HIGH to MEDIUM. System-admin requirement + fixed path suffix + error-only oracle significantly limits exploitation. However, still enables internal service discovery. Same root cause as AP-022.

**Finding draft written to**: security/findings-draft/p8-029-scanner-ssrf.md
**Registry updated**: no new pattern (same as AP-022)

---

### [SYNTHESIZER] Verdict for H-03 -- 2026-03-27T12:01:00Z

**Prosecution summary**: IsLocalPath bypass via `/\evil.com` -- passes `HasPrefix("/")` and `!HasPrefix("//")` checks. WHATWG URL spec normalizes backslash to forward slash in browsers, making `/\evil.com` → `//evil.com` (protocol-relative redirect). Stored in session, not re-validated on OIDC callback.

**Defense summary**: Requires OIDC auth mode. Requires user interaction (clicking crafted link). Go HTTP redirect does not sanitize backslash.

**Pre-FP Gate**: all checks passed -- attacker control verified (query param), browser behavior confirmed per WHATWG spec, trust boundary crossing (Harbor auth → attacker site).

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Open redirect via OIDC flow with backslash bypass of IsLocalPath. Modern browsers consistently normalize `\` to `/` per WHATWG. Distinct from P7-001 (authproxy redirect) -- different flow, different bypass technique. Requires user interaction but no elevated privileges.

**Finding draft written to**: security/findings-draft/p8-030-oidc-open-redirect-backslash.md
**Registry updated**: AP-030 IsLocalPath Backslash Bypass

---

### [SYNTHESIZER] Verdict for H-04 -- 2026-03-27T12:02:00Z

**Prosecution summary**: Purge SQL uses string concatenation with allowlist. Currently safe but fragile.

**Defense summary**: 3-entry allowlist (audit/dao) and 14-entry allowlist (auditext/dao) both contain only safe ASCII values. No current exploitation path.

**Pre-FP Gate**: failed on check-1 -- attacker control NOT verified. Input is filtered through allowlist.

**Verdict: DROP**
**Severity: --**
**Rationale**: Not currently exploitable. Allowlist prevents injection. Code quality issue only. Low severity.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-05 -- 2026-03-27T12:02:00Z

**Prosecution summary**: Chain of H-00e (port scan) + H-00b (password leak) + H-00i (IdP pivot).

**Defense summary**: Each component individually tracked. Chain analysis is valuable but not a separate vulnerability.

**Pre-FP Gate**: N/A -- combinatorial analysis

**Verdict: DUPLICATE**
**Severity: --**
**Rationale**: Each component is independently tracked as H-00b, H-00e, H-00i. Kill chain documented in narrative of individual findings.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-06 -- 2026-03-27T12:02:00Z

**Prosecution summary**: Full header replacement via JSON deserialization in webhook job.

**Defense summary**: Go 1.15+ CRLF protection blocks header value injection. Go net/http ignores Host header in Header map for connection routing. Practical exploitation requires webhook target behind a trusting reverse proxy.

**Pre-FP Gate**: failed on check-1 -- attacker control of arbitrary header keys not confirmed (only Authorization is user-controlled; formatter adds Content-Type).

**Verdict: DROP**
**Severity: --**
**Rationale**: Go runtime protections effectively block exploitation. CRLF injection prevented. Host header override ineffective in Go's net/http. Low practical impact.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-07 -- 2026-03-27T12:02:00Z

**Prosecution summary**: Config URL fields (http_authproxy_endpoint, http_authproxy_tokenreview_endpoint, uaa_endpoint) accept arbitrary strings with zero validation. SSRF triggered when corresponding auth mode is activated.

**Defense summary**: Requires system-admin. SSRF only active when specific auth mode is configured. Partially overlaps with H-00i (LDAP/OIDC endpoint pivot).

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Same root cause as H-00i (config URL no validation) but distinct endpoints. Downgraded from HIGH to MEDIUM because it requires system-admin AND the specific auth mode to be activated. Merged conceptually with H-00i finding (AP-027 Config URL No Validation).

**Finding draft written to**: (merged into p8-027-ldap-oidc-endpoint-pivot.md as additional affected fields)
**Registry updated**: no new pattern (covered by AP-027)

---

### [SYNTHESIZER] Verdict for H-08 -- 2026-03-27T12:03:00Z

**Prosecution summary**: Preheat flow generates Bearer token via credMaker, places in PreheatImage.Headers, forwarded verbatim to Dragonfly/Kraken endpoint. Attacker-controlled preheat instance receives valid Harbor pull token.

**Defense summary**: Token is scoped to image pull. Limited lifetime (typically 30 min). Requires system-admin to register preheat instance.

**Pre-FP Gate**: all checks passed -- attacker control verified (preheat instance endpoint), credential forwarded verbatim (enforcer.go:441-446, dragonfly.go:250).

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Token theft via P2P preheat flow. Even with limited scope, the pull token enables image exfiltration including embedded secrets. System-admin requirement is mitigated by the high impact (image content theft).

**Finding draft written to**: security/findings-draft/p8-031-preheat-token-theft.md
**Registry updated**: AP-031 Credential Forward to External Endpoint

---

### [SYNTHESIZER] Verdict for H-09 -- 2026-03-27T12:03:00Z

**Prosecution summary**: UAAClientSecret defined as StringType at metadatalist.go:126, not PasswordType. ConvertForGet only strips PasswordType fields. UAA secret exposed to any system-admin via normal GET /configurations.

**Defense summary**: Requires system-admin. UAA auth mode must be configured. UAA is a deprecated auth mechanism in modern Harbor deployments.

**Pre-FP Gate**: all checks passed -- type annotation bug confirmed.

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Type annotation bug causes credential exposure. Different root cause from H-00b (metadata type error vs auth bypass). Affects regular admin users, not just solution-user. UAA deprecation reduces practical impact.

**Finding draft written to**: security/findings-draft/p8-032-uaa-secret-not-redacted.md
**Registry updated**: AP-032 Password Type Annotation Error

---

### [SYNTHESIZER] Verdict for H-10 -- 2026-03-27T12:03:00Z

**Prosecution summary**: Preheat instance stored without validation. DNS rebinding exploitable at enforcement time.

**Defense summary**: Concrete instance of H-00j architectural gap. Same root cause.

**Verdict: DUPLICATE**
**Severity: --**
**Rationale**: Subsumed by H-00j (DNS rebinding architectural gap) and documented in p8-024-preheat-ssrf.md.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

### [SYNTHESIZER] Verdict for H-11 -- 2026-03-27T12:03:00Z

**Prosecution summary**: Chain of H-10 + H-08 + H-00g for full image exfiltration.

**Verdict: DUPLICATE**
**Rationale**: Each component independently tracked. Kill chain documented in H-08 and H-00g findings.

---

### [SYNTHESIZER] Verdict for H-12 -- 2026-03-27T12:03:00Z

**Prosecution summary**: IPv6 zone-ID bypass of potential future IP denylist.

**Verdict: DROP**
**Rationale**: No current IP denylist to bypass. Forward-looking only. LOW severity.

---

### [SYNTHESIZER] Verdict for H-13 -- 2026-03-27T12:03:00Z

**Prosecution summary**: Chain of H-00a + H-00e + H-00c/H-00d for stealth exfiltration.

**Verdict: DUPLICATE**
**Rationale**: Each component independently tracked. Kill chain noted in H-00a finding.

---

### [SYNTHESIZER] Verdict for H-14 -- 2026-03-27T12:03:00Z

**Prosecution summary**: Webhook retry amplification + slow-endpoint goroutine exhaustion.

**Verdict: DUPLICATE**
**Rationale**: Merged with H-01 (webhook queue exhaustion). Worker pool bounds apply to both attack patterns.

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-00a | VALID | CRITICAL | p8-020-audit-evidence-destruction.md |
| H-00b | VALID | HIGH | p8-021-solution-user-credential-leak.md |
| H-00c | VALID | HIGH | p8-022-webhook-ssrf-no-ip-filter.md |
| H-00d | VALID | HIGH | (merged into p8-022) |
| H-00e | VALID | HIGH | p8-023-audit-endpoint-tcp-portscan.md |
| H-00f | VALID | HIGH | p8-024-preheat-ssrf.md |
| H-00g | VALID | HIGH | p8-025-registry-credential-theft.md |
| H-00h | VALID | HIGH | p8-026-redis-plaintext-credentials.md |
| H-00i | VALID | HIGH | p8-027-config-url-no-validation.md |
| H-00j | VALID | MEDIUM | (architectural note in p8-022) |
| H-01 | VALID | MEDIUM | p8-028-webhook-queue-exhaustion.md |
| H-02 | VALID | MEDIUM | p8-029-scanner-ssrf.md |
| H-03 | VALID | HIGH | p8-030-oidc-open-redirect-backslash.md |
| H-04 | DROP | -- | -- |
| H-05 | DUPLICATE | -- | -- |
| H-06 | DROP | -- | -- |
| H-07 | VALID | MEDIUM | (merged into p8-027) |
| H-08 | VALID | HIGH | p8-031-preheat-token-theft.md |
| H-09 | VALID | MEDIUM | p8-032-uaa-secret-not-redacted.md |
| H-10 | DUPLICATE | -- | -- |
| H-11 | DUPLICATE | -- | -- |
| H-12 | DROP | -- | -- |
| H-13 | DUPLICATE | -- | -- |
| H-14 | DUPLICATE | -- | -- |

Findings written: 13
Patterns added to registry: 11
Variant candidates: 1

Chamber closed: 2026-03-27T12:15:00Z
