# Round 1 Hypotheses: Backward Reasoning (Pre-Mortem / Abductive)
## Reasoning Model: backward-reasoner-03

Starting from known bad outcomes (SSRF, credential leak, port scan) and reasoning backward to find the code paths that lead to them.

---

## PH-01: Webhook SSRF to Cloud Metadata Service

**Reasoning model:** Pre-Mortem (what would have to be true for SSRF to succeed against 169.254.169.254?)

**Assumption being broken:** The fix for CVE issue #3755 (comment in validateTargets) reconstructs URL as `scheme://host+path`. The fix was intended to prevent credential injection via `http://user:pass@host/`. It does NOT prevent routing to private IPs.

**Target:**
- `src/server/v2.0/handler/webhook.go:405` — `validateTargets`
- `src/jobservice/job/impl/notification/webhook_job.go:101` — `execute`

**Attack input:** Project admin submits webhook policy with target address `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS) or `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (GCP).

**Code path:**
1. `validateTargets` calls `utils.ParseEndpoint("http://169.254.169.254/latest/meta-data/...")` → returns `url.URL{Scheme:"http", Host:"169.254.169.254", Path:"/latest/meta-data/..."}` — no error
2. `target.Address` set to `"http://169.254.169.254/latest/meta-data/..."`
3. Policy stored in DB
4. Harbor event fires → notification job enqueued with `address = "http://169.254.169.254/..."`
5. Job Service: `WebhookJob.execute` → `http.NewRequest(POST, "http://169.254.169.254/...")` → `wj.client.Do(req)` → response body returned; if response is non-2xx it's logged (metadata APIs typically return 200)

**Sanitizers on path:** `ParseEndpoint` (scheme check only) — bypassable: does not check destination IP

**Security consequence:** Job Service makes HTTP POST to cloud metadata endpoint. Response body (AWS credentials, GCP tokens) is available if the attacker has access to webhook execution logs or if they create a controlled endpoint to receive echoed metadata.

**Severity estimate:** HIGH

**DNS rebinding variant:** Attacker registers `http://evil.example.com/` with a short TTL. At webhook creation time, `evil.example.com` resolves to a public IP (passes validation). By execution time in Job Service, DNS has been changed to `169.254.169.254`. This bypasses even a hypothetical IP check at creation time.

**Status:** VALIDATED (no private IP filtering code found anywhere in the path)

---

## PH-02: Replication Registry SSRF via GetRegistryInfo

**Reasoning model:** Pre-Mortem (what path triggers immediate HTTP to attacker-controlled host?)

**Target:**
- `src/server/v2.0/handler/registry.go:46` — `CreateRegistry`
- `src/server/v2.0/handler/registry.go:179` — `GetRegistryInfo`
- `src/pkg/reg/adapter/native/adapter.go:118` — `HealthCheck`

**Attack input:** System admin (or attacker with system-admin credentials) creates a registry with `url = "http://10.0.0.1:8080"`. Then calls `GET /api/v2.0/registries/{id}/info`.

**Code path:**
1. `CreateRegistry`: stores `url="http://10.0.0.1:8080"` in DB — no validation beyond CACert check
2. `GetRegistryInfo` → calls registry controller's `GetInfo` → instantiates adapter → `HealthCheck` → `a.Ping()` or `a.PingSimple()` → HTTP GET to `http://10.0.0.1:8080/v2/`
3. Response (or error) returned to caller. Attacker can distinguish "connection refused", "connection timeout", "HTTP 200", "HTTP 401" to map internal network.

**Sanitizers on path:** None

**Security consequence:** System admin can probe internal network services reachable from the Job Service / Core container. Can fingerprint running services.

**Severity estimate:** MEDIUM (requires system-admin but system-admin should not have SSRF capability)

**Note:** The `HealthCheck` is also called periodically by the replication scheduler — not just on-demand. The SSRF executes repeatedly.

**Status:** VALIDATED

---

## PH-03: Audit Log Forward Endpoint TCP Port Scan

**Reasoning model:** Abductive (given that `syslog.Dial("tcp", address)` is called with admin-supplied address, what does the attacker gain?)

**Target:**
- `src/controller/config/controller.go:100` — `updateLogEndpoint`
- `src/pkg/audit/forward.go:65` — `CheckEndpointActive`

**Attack input:** System admin updates `audit_log_forward_endpoint` to `"10.0.0.1:22"` (SSH), `"10.0.0.1:5432"` (PostgreSQL), `"10.0.0.1:6379"` (Redis), etc.

**Code path:**
1. `UpdateConfigurations` → `UpdateUserConfigs` → `updateLogEndpoint`
2. `updateLogEndpoint`: reads new endpoint, calls `audit.CheckEndpointActive("10.0.0.1:22")`
3. `CheckEndpointActive` → `syslog.Dial("tcp", "10.0.0.1:22", syslog.LOG_INFO, "audit")`
4. TCP SYN sent to `10.0.0.1:22`. If port open: TCP handshake completes, syslog handshake fails, function returns `false`. If port closed: connection refused, returns `false`. If filtered: timeout, returns `false`.
5. The **return value** of `CheckEndpointActive` is checked: if `false`, `UpdateConfigurations` returns error to HTTP caller: `"could not connect to the audit endpoint: 10.0.0.1:22"`.

**Critical finding:** The error message `"could not connect to the audit endpoint: 10.0.0.1:22"` IS returned to the HTTP caller. This creates a distinguishable oracle — the caller sees different error messages (or timing) for:
- Open port (TCP connects, syslog protocol fails): returns false with syslog error
- Closed port (connection refused immediately): returns false with connection refused
- Filtered port (timeout): returns false after timeout delay

**Sanitizers on path:** None — `syslog.Dial` accepts arbitrary `"host:port"` string

**Additional vector:** Even if `CheckEndpointActive` returns false, if `auditEP` is non-empty AND `CheckEndpointActive` behavior is to log-and-return-false (not abort), the config update may still proceed. Looking at the code: `updateLogEndpoint` returns `errors.BadRequestError(fmt.Errorf("could not connect to the audit endpoint: %v", auditEP))` if `!audit.CheckEndpointActive(auditEP)`. So the update is blocked, but the TCP probe already occurred and the attacker gets the error text oracle.

**Severity estimate:** HIGH (TCP port scan of internal network from Core API container, no IP filtering, error oracle)

**Status:** VALIDATED

---

## PH-04: Preheat Provider Endpoint SSRF with lib.ValidateHTTPURL Bypass via URL Encoding

**Reasoning model:** Abductive (lib.ValidateHTTPURL uses url.Parse — does it normalize encoded IPs?)

**Target:**
- `src/pkg/p2p/preheat/provider/dragonfly.go:199` — `DragonflyDriver.GetHealth`
- `src/lib/endpoint.go:27` — `ValidateHTTPURL`

**Attack input:** Preheat provider endpoint set to `http://169.254.169.254/` during provider registration. The `lib.ValidateHTTPURL` is called in `GetHealth`, but the URL was already stored.

**Code path:**
1. System admin registers preheat provider instance with `endpoint = "http://169.254.169.254/"`
2. Preheat job triggered → `DragonflyDriver.GetHealth`:
   - `url = "http://169.254.169.254/healthy"`
   - `lib.ValidateHTTPURL(url)` → `url.Parse("http://169.254.169.254/healthy")` → returns `"http://169.254.169.254/healthy"` — scheme is http, no error
   - `client.GetHTTPClient(dd.instance.Insecure).Get(url, ...)` → HTTP GET to `169.254.169.254`

**IP encoding bypass variants to test:**
- `http://0x7f000001/` (hex IP)
- `http://2130706433/` (decimal IP for 127.0.0.1)
- `http://[::ffff:169.254.169.254]/` (IPv6 mapped)
- `http://169.254.169.254.nip.io/` (DNS rebinding via wildcard DNS)

**Sanitizers on path:** `lib.ValidateHTTPURL` — bypassable: only checks scheme, not destination IP

**Security consequence:** Job Service HTTP client makes GET request to cloud metadata endpoint. `GetHealth` response (body) is consumed internally but errors are propagated to the job log.

**Severity estimate:** HIGH (preheat jobs run in Job Service, same SSRF risk as webhook)

**Status:** VALIDATED (ValidateHTTPURL confirmed to do no IP filtering)

---

## PH-05: Credential Leak via Solution-User GetConfigurations Branch

**Reasoning model:** Pre-Mortem (what if solution-user auth token is obtained?)

**Target:**
- `src/server/v2.0/handler/config.go:41` — `GetConfigurations`
- `src/controller/config/controller.go:73` — `AllConfigs`

**Attack input:** Attacker obtains solution-user credentials (internal service secret). Sends `GET /api/v2.0/configurations` with solution-user auth.

**Code path:**
1. `GetConfigurations` checks `sec.IsSolutionUser()` → if true, calls `c.controller.AllConfigs(ctx)` → returns all config including PasswordType fields
2. Response is JSON-marshaled and returned — no field stripping for solution-user

**Contrast with normal flow:** Non-solution-user path calls `UserConfigs` → `ConvertForGet(internal=false)` which explicitly deletes PasswordType items (`delete(cfg, item.Name)` at line 239).

**Fields leaked if PasswordType:** LDAP bind password (`ldap_search_password`), OIDC client secret, token service private key material (if stored as config).

**Sanitizers on path:** `IsSolutionUser()` check — bypassable only if solution-user auth is compromised. But this creates an all-or-nothing risk: solution-user = full credential exfiltration.

**Severity estimate:** CRITICAL (if solution-user secret compromised, full LDAP/OIDC credential theft)

**Status:** VALIDATED (code confirms PasswordType fields returned in AllConfigs for solution-user path)

---

## PH-06: Webhook Header Injection via Custom auth_header Field

**Reasoning model:** Abductive (webhook targets have an `auth_header` field — what does it contain and how is it used?)

**Target:**
- `src/jobservice/job/impl/notification/webhook_job.go:110` — header parsing in `execute`
- Webhook policy model `targets[].auth_header`

**Attack input:** Project admin creates webhook with `targets[0].auth_header = '{"Authorization": "Bearer token123", "X-Internal-Secret": "secret"}'`. URL points to an internal service.

**Code path:**
1. `execute`: if `params["header"]` exists, unmarshals it as `http.Header`
2. `req.Header = header` — sets ALL headers from attacker-controlled JSON
3. HTTP request sent to the target URL with these headers

**Security consequence:** Attacker can set arbitrary HTTP headers on SSRF requests. This allows:
- Bypassing internal service authentication (if service accepts `Authorization` header)
- Adding `Host` header to bypass virtual hosting
- Adding `X-Forwarded-For` to bypass IP-based access controls on internal services

**Sanitizers on path:** None — headers are set directly from user-supplied JSON

**Severity estimate:** HIGH (amplifies SSRF impact significantly)

**Status:** VALIDATED (code at line 110-116 confirms unrestricted header injection)

---

## PH-07: DNS Rebinding to Bypass Webhook URL Validation

**Reasoning model:** Pre-Mortem (what timing-based attack survives the current ParseEndpoint check?)

**Target:**
- `src/server/v2.0/handler/webhook.go:405` — `validateTargets` (validation at store time)
- `src/jobservice/job/impl/notification/webhook_job.go:101` — `execute` (execution at trigger time)

**Attack scenario:**
1. Register domain `webhook-ssrf.attacker.com` with 1-second TTL, resolving to `1.2.3.4` (public IP)
2. Create webhook with `address = "http://webhook-ssrf.attacker.com/"` — passes validation
3. Change DNS record for `webhook-ssrf.attacker.com` to `169.254.169.254`
4. Trigger webhook (push an image, create a scan, etc.)
5. Job Service resolves `webhook-ssrf.attacker.com` → `169.254.169.254` → HTTP POST

**Sanitizers on path:** DNS resolution happens at execution time, not at validation time. No TTL pinning. No connection-time IP check.

**Severity estimate:** HIGH (bypasses any future IP-based validation if added only at store time)

**Status:** VALIDATED as a design flaw — the validation gap between store-time and execute-time is architectural

---

## PH-08: Preheat Image URL + Headers Forwarded to P2P Provider as SSRF Amplifier

**Reasoning model:** Abductive (dragonfly.go sends `preheatingImage.URL` and `Headers` to external Dragonfly server — what if Dragonfly fetches that URL?)

**Target:**
- `src/pkg/p2p/preheat/provider/dragonfly.go:248` — `Args.URL = preheatingImage.URL`
- `src/pkg/p2p/preheat/provider/dragonfly.go:249` — `Args.Headers = headerToMapString(preheatingImage.Headers)`

**Context:** The `preheatingImage.URL` is set to the Harbor artifact's pull URL (e.g., `https://harbor.example.com/project/image:tag`). The Dragonfly P2P system then fetches this URL to cache the image blobs.

**Headers:** The `preheatingImage.Headers` map contains authentication headers (Bearer tokens, etc.) that allow Dragonfly to pull from Harbor. These are forwarded in the POST body to Dragonfly.

**Attack vector:** If Dragonfly is configured as a preheat provider but is operated by a partially-trusted party, or if Dragonfly has a vulnerability allowing header manipulation, the Bearer token forwarded in the request could be stolen. The token grants access to Harbor artifacts.

**Severity estimate:** MEDIUM (depends on Dragonfly operator trust level; the token expiry limits window)

**Status:** NEEDS-DEEPER (depends on deployment context; headers are legitimately needed for Dragonfly to pull from Harbor)
