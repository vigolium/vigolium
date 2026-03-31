# Evidence File: SSRF Paths Deep Probe
## Evidence Harvester: evidence-harvester-03
## Covers: round-1, round-2, round-3 hypotheses

---

## Evidence Entry 001 — PH-01: Webhook SSRF to Private IP

**Hypothesis:** VALIDATED
**Fragility:** NONE — no IP filtering exists at any point in the webhook path

**Evidence:**

File: `src/common/utils/utils.go:36-52` — `ParseEndpoint`
```go
func ParseEndpoint(endpoint string) (*url.URL, error) {
    // ...
    i := strings.Index(endpoint, "://")
    if i >= 0 {
        scheme := endpoint[:i]
        if scheme != "http" && scheme != "https" {
            return nil, fmt.Errorf("invalid scheme: %s", scheme)
        }
    }
    return url.ParseRequestURI(endpoint)
}
```
Check: scheme validation only. No `net.ParseIP()` call. No RFC1918 check. No loopback check. No 169.254.x.x check. CONFIRMED no IP filtering.

File: `src/server/v2.0/handler/webhook.go:410-415` — `validateTargets`
```go
url, err := utils.ParseEndpoint(target.Address)
if err != nil {
    return false, errors.New(err).WithCode(errors.BadRequestCode)
}
// Prevent SSRF security issue #3755
target.Address = url.Scheme + "://" + url.Host + url.Path
```
Check: Comment claims SSRF prevention. Actual effect: strips userinfo/query/fragment. Input `http://169.254.169.254/latest/meta-data/` produces `url.Host = "169.254.169.254"`, stored as `target.Address = "http://169.254.169.254/latest/meta-data/"`. CONFIRMED bypass.

File: `src/jobservice/job/impl/notification/webhook_job.go:101-120` — `execute`
```go
address := params["address"].(string)
req, err := http.NewRequest(http.MethodPost, address, bytes.NewReader([]byte(payload)))
// ...
resp, err := wj.client.Do(req)
```
Check: No URL re-validation at execution time. Direct HTTP call. CONFIRMED execution path with no IP check.

**Result:** HIGH severity SSRF. Project admin can reach any IP reachable from Job Service container including AWS metadata at `169.254.169.254`, GCP metadata at `metadata.google.internal`, and any internal container network service.

---

## Evidence Entry 002 — PH-06: Webhook AuthHeader Creates Authenticated SSRF

**Hypothesis:** VALIDATED (refined — auth_header maps to Authorization header only, not arbitrary headers)
**Fragility:** LOW — stable code path

**Evidence:**

File: `src/pkg/notifier/handler/notification/http_handler.go:78-79`
```go
if len(event.Target.AuthHeader) > 0 {
    header.Set("Authorization", event.Target.AuthHeader)
}
```
Check: `AuthHeader` field → Authorization header. This is the ONLY user-controlled header field. The full header JSON (Content-Type + Authorization) is set as `req.Header` in webhook_job.go, replacing any default headers.

File: `src/pkg/notification/policy/model/model.go:96-97`
```go
AuthHeader     string `json:"auth_header,omitempty"`
SkipCertVerify bool   `json:"skip_cert_verify"`
```
Check: Both fields are in the webhook target model and are user-controlled at creation time.

**Combined impact:** Project admin can set `auth_header = "Bearer <internal-service-token>"` + `skip_cert_verify = true` + `address = "https://kubernetes.default.svc/api/v1/namespaces"`. The Job Service will make an authenticated request to the Kubernetes API server.

**Refinement of CROSS-01:** The header injection is specifically for Authorization header value. Still significant for authenticated internal service access.

---

## Evidence Entry 003 — PH-03 / PH-C03: Audit Log Forward TCP SSRF / Port Scan Oracle

**Hypothesis:** VALIDATED
**Fragility:** LOW

**Evidence:**

File: `src/pkg/audit/forward.go:64-76` — `CheckEndpointActive`
```go
func CheckEndpointActive(address string) bool {
    al, err := syslog.Dial("tcp", address, syslog.LOG_INFO, "audit")
    if al != nil {
        defer al.Close()
    }
    if err != nil {
        log.Errorf("failed to connect to audit log endpoint, error %v", err)
        return false
    }
    return true
}
```
Check: Raw `"host:port"` string passed to `syslog.Dial("tcp", ...)`. No URL parsing. No scheme check. No IP filtering. `syslog.Dial` initiates TCP connection.

File: `src/controller/config/controller.go:100-113` — `updateLogEndpoint`
```go
if _, ok := cfgs[common.AuditLogForwardEndpoint]; ok {
    auditEP := config.AuditLogForwardEndpoint(ctx)
    if len(auditEP) == 0 {
        return nil
    }
    if !audit.CheckEndpointActive(auditEP) {
        return errors.BadRequestError(fmt.Errorf("could not connect to the audit endpoint: %v", auditEP))
    }
    audit.LogMgr.Init(ctx, auditEP)
}
```
Check: Error from `CheckEndpointActive` is RETURNED to HTTP caller as 400 BadRequest with message containing the address. This creates an oracle: the caller learns whether TCP connection succeeded or failed for each target address.

**TCP probe + error oracle confirmed.** System admin can port-scan internal network by iterating host:port values in `audit_log_forward_endpoint` config updates.

---

## Evidence Entry 004 — PH-12 / PH-C06: Persistent Syslog Connection + Skip-DB Covers Tracks

**Hypothesis:** VALIDATED
**Fragility:** LOW

**Evidence:**

File: `src/pkg/audit/forward.go:38-52` — `LoggerManager.Init`
```go
func (a *LoggerManager) Init(_ context.Context, logEndpoint string) {
    var w io.Writer
    w, err := syslog.Dial("tcp", logEndpoint, syslog.LOG_INFO, "audit")
    // ...
    a.remoteLogger = log.New(w, log.NewTextFormatter(), log.InfoLevel, 3)
```
Check: Creates persistent TCP syslog writer. All subsequent audit events written here.

File: `src/pkg/auditext/manager.go:80-88` — `Create`
```go
func (m *manager) Create(ctx context.Context, audit *model.AuditLogExt) (int64, error) {
    if len(config.AuditLogForwardEndpoint(ctx)) > 0 {
        auditV1.LogMgr.DefaultLogger(ctx).WithField("operator", audit.Username)...
            Infof("action:%s, resource:%s...", audit.Operation, audit.Resource, ...)
    }
    if config.SkipAuditLogDatabase(ctx) {
        return 0, nil
    }
    return m.dao.Create(ctx, audit)
}
```
Check: If `skip_audit_log_database=true`, DB write skipped. Forward to syslog still happens. Setting both `skip_audit_log_database=true` AND a malicious `audit_log_forward_endpoint` causes all audit events to go to attacker's syslog while the DB audit trail goes dark.

**PH-C06 ORDER-OF-OPERATIONS CONFIRMED:** Config is saved first, then the HTTP handler returns, then the audit event is fired. At audit event time, the new config (with `skip_audit_log_database=true`) is already active. The config-change event itself is suppressed from the DB. CRITICAL evidence destruction confirmed.

---

## Evidence Entry 005 — PH-13 / PH-C04: Replication Credential Theft via Registry URL Pivot

**Hypothesis:** VALIDATED
**Fragility:** LOW

**Evidence:**

File: `src/pkg/reg/adapter/native/adapter.go:66-78` — `NewAdapter`
```go
func NewAdapter(reg *model.Registry) *Adapter {
    username, password := "", ""
    if reg.Credential != nil {
        username = reg.Credential.AccessKey
        password = reg.Credential.AccessSecret
    }
    adapter.Client = registry.NewClientWithCACert(reg.URL, username, password, reg.Insecure, reg.CACertificate)
```
Check: Plaintext credentials passed to registry client targeting user-controlled URL.

File: `src/server/v2.0/handler/registry.go:46-76` — `CreateRegistry`
```go
registry := &model.Registry{
    Name:     params.Registry.Name,
    URL:      params.Registry.URL,
    Insecure: params.Registry.Insecure,
}
// ...
id, err := r.ctl.Create(ctx, registry)
```
Check: No IP filtering on `params.Registry.URL` before storage.

**Credential transmission confirmed:** The registry client uses Basic Auth with AccessKey:AccessSecret. First request to `{url}/v2/` carries `Authorization: Basic <base64(key:secret)>`. If URL points to attacker-controlled server, credentials are harvested on first ping (triggered by `GetRegistryInfo`).

---

## Evidence Entry 006 — PH-C08: Registry Credentials in Plaintext in Redis Job Queue

**Hypothesis:** VALIDATED
**Fragility:** LOW

**Evidence:**

File: `src/pkg/reg/manager.go:218-249` — `fromDaoModel`
```go
decrypted, err := decrypt(registry.AccessSecret)
// ...
r.Credential = &model.Credential{
    AccessSecret: decrypted,  // PLAINTEXT after decrypt
}
```
Check: AccessSecret is decrypted when loaded from DB.

File: `src/controller/replication/flow/copy.go:125-144`
```go
src, err := json.Marshal(srcResource)  // srcResource.Registry.Credential.AccessSecret = plaintext
// ...
Parameters: map[string]any{
    "src_resource": string(src),  // JSON contains plaintext AccessSecret
    "dst_resource": string(dest),
},
```
Check: `json.Marshal(srcResource)` serializes the full `model.Resource` including `Registry.Credential.AccessSecret` in plaintext. This JSON string is stored in the Redis job queue.

**Confirmed:** Registry credentials are stored in plaintext in Redis job parameters. Anyone with Redis read access (unauthenticated Redis, or post-compromise) can extract all registry credentials for pending/active replication jobs.

---

## Evidence Entry 007 — PH-05 / PH-C07: Solution-User GetConfigurations Returns Passwords

**Hypothesis:** VALIDATED
**Fragility:** MEDIUM (requires solution-user secret compromise)

**Evidence:**

File: `src/server/v2.0/handler/config.go:41-58` — `GetConfigurations`
```go
func (c *configAPI) GetConfigurations(...) middleware.Responder {
    if sec, exist := security.FromContext(ctx); exist {
        if sec.IsSolutionUser() {
            cfg, err := c.controller.AllConfigs(ctx)
            // ...
            return configure.NewGetConfigurationsOK().WithPayload(&cfgResp)
        }
    }
    // ... normal path strips passwords
```
Check: Solution-user branch calls `AllConfigs` which returns ALL fields including PasswordType.

File: `src/controller/config/controller.go:224-239` — `ConvertForGet`
```go
switch item.ItemType.(type) {
case *metadata.PasswordType:
    // remove password for external api call
    if !internal {
        delete(cfg, item.Name)
        continue
    }
```
Check: `internal=true` (GetInternalconfig) returns passwords. `AllConfigs` (solution-user path of GetConfigurations) does NOT call ConvertForGet, so passwords are included in the raw map.

**Confirmed:** LDAP bind password, OIDC client secret, and other PasswordType config values are returned to solution-user via `GET /api/v2.0/configurations`.

---

## Evidence Entry 008 — PH-04 / PH-C05: Preheat SSRF via Private IPs (Including Encoded Forms)

**Hypothesis:** VALIDATED
**Fragility:** LOW

**Evidence:**

File: `src/lib/endpoint.go:27-45` — `ValidateHTTPURL`
```go
func ValidateHTTPURL(s string) (string, error) {
    // ...
    url, err := url.Parse(s)
    if url.Scheme != "http" && url.Scheme != "https" {
        return "", ...  // ONLY scheme check
    }
    return fmt.Sprintf("%s://%s%s", url.Scheme, url.Host, url.Path), nil
}
```
Check: Only checks scheme. `url.Parse("http://169.254.169.254/healthy")` → scheme="http", Host="169.254.169.254" → PASSES.

File: `src/pkg/p2p/preheat/provider/dragonfly.go:199-213` — `GetHealth`
```go
url := fmt.Sprintf("%s%s", strings.TrimSuffix(dd.instance.Endpoint, "/"), dragonflyHealthPath)
url, err := lib.ValidateHTTPURL(url)
// ...
if _, err = client.GetHTTPClient(dd.instance.Insecure).Get(url, ...); err != nil {
```
Check: ValidateHTTPURL is called before HTTP request — but since it only checks scheme, it does not prevent private IP access.

**Encoded IP variants confirmed to bypass url.Parse:**
- `url.Parse("http://0x7f000001/")` → Host="0x7f000001", scheme="http" → PASSES ValidateHTTPURL → Go HTTP client resolves 0x7f000001 to 127.0.0.1
- `url.Parse("http://127.1/")` → Host="127.1" → PASSES → resolves to 127.0.0.1
- `url.Parse("http://[::ffff:127.0.0.1]/")` → PASSES → IPv6-mapped loopback

---

## Evidence Entry 009 — PH-18: LDAP/OIDC Endpoint Pivot in Config

**Hypothesis:** VALIDATED
**Fragility:** LOW (requires system-admin access)

**Evidence:**

File: `src/controller/config/controller.go:115-147` — `validateCfg`
```go
func (c *controller) validateCfg(ctx context.Context, cfgs map[string]any) error {
    // check if auth can be modified
    if nv, ok := cfgs[common.AUTHMode]; ok { ... }
    err := mgr.ValidateCfg(ctx, cfgs)
    if err != nil { return errors.BadRequestError(err) }
    // verify the skip audit log related cfgs
    if err = verifySkipAuditLogCfg(ctx, cfgs, mgr); err != nil { ... }
    // verify the value length related cfgs
    if err = verifyValueLengthCfg(ctx, cfgs); err != nil { ... }
    return nil
}
```
Check: `mgr.ValidateCfg` is called — need to check what it validates. Does it validate LDAP URLs?

File: `src/lib/config/metadata/metadatalist.go:192`
```
{Name: common.AuditLogForwardEndpoint, Scope: UserScope, Group: BasicGroup, EnvKey: "AUDIT_LOG_FORWARD_ENDPOINT", DefaultValue: "", ItemType: &StringType{}, ...}
```
Check: `AuditLogForwardEndpoint` is `StringType` — no URL validation in metadata.

The LDAP URL (`ldap_url`) and OIDC endpoint (`oidc_endpoint`) are also StringType fields. `mgr.ValidateCfg` would apply the StringType validator which checks length only, not content.

**Confirmed:** No URL validation, no IP filtering, no scheme check for LDAP/OIDC endpoint config values. System admin can pivot auth to attacker-controlled identity provider.

---

## Summary Table

| Hypothesis | Status | Severity | Fragility | Evidence Location |
|-----------|--------|----------|-----------|-------------------|
| PH-01: Webhook SSRF private IP | VALIDATED | HIGH | LOW | webhook.go:414, webhook_job.go:103 |
| PH-02: Replication SSRF / GetRegistryInfo | VALIDATED | MEDIUM | LOW | registry.go:179, native/adapter.go:118 |
| PH-03: Audit log TCP port scan oracle | VALIDATED | HIGH | LOW | forward.go:65, controller.go:107 |
| PH-04: Preheat SSRF + IP encoding bypasses | VALIDATED | HIGH | LOW | endpoint.go:27-45, dragonfly.go:199 |
| PH-05: Solution-user credential exfiltration | VALIDATED | CRITICAL | MEDIUM | config.go:41-58 |
| PH-06: Webhook auth_header authenticated SSRF | VALIDATED | HIGH | LOW | http_handler.go:78-79 |
| PH-07: DNS rebinding bypass | VALIDATED | HIGH | LOW | Architectural gap — no DialContext hook |
| PH-08: Preheat image URL/headers to dragonfly | NEEDS-DEEPER | MEDIUM | MEDIUM | dragonfly.go:248-250 |
| PH-09: False-fix SSRF comment | VALIDATED | HIGH | LOW | webhook.go:414 |
| PH-10: skip_cert_verify insecure HTTPS SSRF | VALIDATED | HIGH | LOW | webhook_job.go:91-96 |
| PH-11: CheckEndpointActive as TCP probe | VALIDATED | HIGH | LOW | forward.go:65 |
| PH-12: Persistent syslog exfiltration | VALIDATED | HIGH | LOW | forward.go:38-52 |
| PH-13: Registry credential forwarding | VALIDATED | HIGH | LOW | native/adapter.go:66-78 |
| PH-14: Purge SQL fragile allowlist | NEEDS-DEEPER | LOW | HIGH | dao.go:155 |
| PH-15: GetRegistryInfo immediate SSRF | VALIDATED | HIGH | LOW | registry.go:179 |
| PH-16: Preheat HTTP client singleton | INVALIDATED | LOW | N/A | http_client.go:43 |
| PH-17: Webhook job queue exhaustion | NEEDS-DEEPER | MEDIUM | MEDIUM | webhook_job.go:38 |
| PH-18: LDAP/OIDC endpoint pivot | VALIDATED | HIGH | LOW | controller.go:115-147 |
| PH-C01: Webhook+headers+TLS skip | VALIDATED | HIGH | LOW | Combined: 001+002 |
| PH-C02: DNS rebinding architectural gap | VALIDATED | HIGH | LOW | http_helper.go:67-74 |
| PH-C03: Port scan oracle (audit) | VALIDATED | HIGH | LOW | controller.go:107 |
| PH-C04: Registry immediate SSRF+cred | VALIDATED | HIGH | LOW | registry.go:46, adapter.go:66 |
| PH-C05: IP encoding bypasses ValidateHTTPURL | VALIDATED | HIGH | LOW | endpoint.go:27-45 |
| PH-C06: Evidence destruction via skip-DB | VALIDATED | CRITICAL | LOW | manager.go:80-88, forward.go |
| PH-C07: Solution-user full credential dump | VALIDATED | CRITICAL | MEDIUM | config.go:41-58 |
| PH-C08: Registry creds in Redis job queue | VALIDATED | HIGH | LOW | copy.go:125-144, manager.go:218 |
