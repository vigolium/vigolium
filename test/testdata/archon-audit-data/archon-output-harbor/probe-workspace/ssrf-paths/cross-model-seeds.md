# Cross-Model Seeds: SSRF Paths

Cross-pollination of round-1 (backward-reasoner-03) and round-2 (contradiction-reasoner-03) hypotheses.

---

## CROSS-01: Webhook SSRF + Custom Headers = Authenticated Internal Service Access

**Source-A:** PH-01 (backward-reasoner) — Webhook SSRF to cloud metadata service; no private IP filtering in validateTargets/execute path
**Source-B:** PH-06 (backward-reasoner) + PH-10 (contradiction-reasoner) — Webhook header injection via auth_header field; skip_cert_verify for HTTPS services

**Connection:** PH-01 establishes that SSRF reaches any IP. PH-06 establishes that arbitrary HTTP headers can be injected. PH-10 establishes that HTTPS internal services are also reachable (with skip_cert_verify). These three findings combine:

**Combined hypothesis:** A project admin can create a webhook with:
- `address = "https://kubernetes.default.svc/api/v1/namespaces/default/secrets"` (internal K8s API)
- `skip_cert_verify = true` (bypasses K8s self-signed cert)
- `auth_header = '{"Authorization": "Bearer <stolen-service-account-token>"}'`

The webhook delivery reaches the Kubernetes API server and the response body (Kubernetes secret data) is included in the Job Service error log if the K8s API returns non-2xx, or is silently consumed if it returns 200. Combined with webhook execution log access (also project-admin visible), the attacker can exfiltrate Kubernetes secrets.

**Test direction for causal-verifier:** Verify that (1) skip_cert_verify=true is accepted in webhook creation, (2) the auth_header JSON is passed verbatim to req.Header, (3) there is no filtering of target hostnames against cluster-internal service names (`.svc`, `.cluster.local`), and (4) webhook task logs are accessible to the project admin.

---

## CROSS-02: DNS Rebinding + False-Fix Comment = Bypasses ANY Future IP Denylist Added Only at Store Time

**Source-A:** PH-07 (backward-reasoner) — DNS rebinding window between store-time and execute-time validation
**Source-B:** PH-09 (contradiction-reasoner) — validateTargets comment claims SSRF prevention but only strips userinfo

**Connection:** Both findings target the same validation function (`validateTargets`) and the same trust assumption (URL is safe after `ParseEndpoint`). PH-09 explains WHY the protection is incomplete (only userinfo SSRF was addressed). PH-07 explains that even if IP filtering were added at store time, DNS rebinding would bypass it at execution time.

**Combined hypothesis:** The architectural flaw is that URL validation happens only once, at store time, in the Core API. The Job Service never re-validates the URL at execution time. Any future IP-based denylist added to `validateTargets` or `ParseEndpoint` would be bypassed by DNS rebinding. A proper fix requires either (a) IP validation at execution time in Job Service, or (b) DNS pre-resolution + connection-time IP check.

**Test direction for causal-verifier:** Verify there is no IP check in `WebhookJob.execute`, `SlackJob.Run`, or in the HTTP transport layer. Confirm that `http.Client` in Job Service performs DNS resolution at request time (not cached from store time). Check if any custom `DialContext` with IP validation is present in the HTTP transports.

---

## CROSS-03: CheckEndpointActive Port Scan + Audit Log Exfiltration = Two-Stage Internal Attack

**Source-A:** PH-03 (backward-reasoner) — Audit log TCP SSRF / port scan via CheckEndpointActive
**Source-B:** PH-12 (contradiction-reasoner) — Persistent syslog connection sends all audit events to attacker endpoint

**Connection:** Both reference the same audit log forward endpoint config. PH-03 shows the port scan capability (discovery phase). PH-12 shows the persistent data exfiltration capability (collection phase). Together they form a complete attack:

**Combined hypothesis:** A system admin can:
1. Use `UpdateConfigurations` with various `host:port` values to port-scan the internal network (PH-03). The error timing and message distinguish open/closed/filtered ports.
2. Once an internal syslog receiver is identified (or attacker deploys their own), set `audit_log_forward_endpoint` to that address.
3. All subsequent audit log events are forwarded to the attacker's syslog server (PH-12), including the username, resource type, and operation for every action every Harbor user takes.
4. This provides persistent visibility into Harbor activity without leaving traces in Harbor's own audit log (since the DB write is conditional on `SkipAuditLogDatabase`).

**Additional finding:** If `skip_audit_log_database = true` is also set (requires endpoint to be configured first per `verifySkipAuditLogCfg`), then Harbor stops writing audit logs to its own DB while still forwarding to the attacker's syslog — making the exfiltration invisible to other Harbor admins querying audit logs.

**Test direction for causal-verifier:** Verify (1) that `syslog.Dial` error text is returned in the HTTP response body of `UpdateConfigurations` (confirming error oracle), (2) that setting `skip_audit_log_database=true` + `audit_log_forward_endpoint=attacker:514` causes DB audit writes to stop, and (3) that there is no integrity check on the syslog connection after initialization.

---

## CROSS-04: GetRegistryInfo Immediate SSRF + Replication Credential Forwarding = Rogue Registry Attack

**Source-A:** PH-02 (backward-reasoner) — Replication registry SSRF via GetRegistryInfo
**Source-B:** PH-13 (contradiction-reasoner) — Replication credential forwarding to attacker-controlled registry

**Connection:** PH-02 establishes that a system admin can trigger immediate SSRF via `GetRegistryInfo`. PH-13 establishes that the stored credentials are forwarded during replication. They target the same data flow (registry URL → HTTP client) but at different execution points.

**Combined hypothesis:** A system admin can perform a two-step credential extraction attack:
1. Create a registry record pointing to attacker-controlled server. `CreateRegistry` stores credentials alongside URL.
2. Call `GetRegistryInfo` — this triggers `HealthCheck` → `Ping()` → HTTP GET to `{url}/v2/` with `Authorization: Basic <base64(accessKey:accessSecret)>` header.
3. The attacker's server receives the Base64-encoded credentials in the Authorization header on the FIRST request (health check), without needing to wait for a replication job to run.

**Extended attack:** Update an existing legitimate registry's URL to point to the attacker's server. All replication jobs that use this registry will now authenticate to the attacker's server. The stored credentials (which could be a system-level robot account) are harvested.

**Test direction for causal-verifier:** Verify that `Ping()` / `PingSimple()` in the native adapter sends Authorization headers. Check that `GetRegistryInfo` triggers a health check that includes credential transmission. Verify that `UpdateRegistry` does not re-validate whether the URL changed points to a different network zone.

---

## CROSS-05: Preheat SSRF + lib.ValidateHTTPURL False Safety = IP Encoding Bypasses

**Source-A:** PH-04 (backward-reasoner) — Preheat provider endpoint SSRF; lib.ValidateHTTPURL does no IP filtering
**Source-B:** PH-09 (contradiction-reasoner) — False-fix pattern where comment says "SSRF prevented" but protection is partial

**Connection:** Both findings touch the same root cause: URL validation functions in Harbor check scheme only. PH-04 applies to the preheat path (lib.ValidateHTTPURL), PH-09 applies to the webhook path (ParseEndpoint / comment). Both functions have the same structural gap.

**Combined hypothesis:** IP encoding bypasses that would work against `lib.ValidateHTTPURL`:
- `http://0x7f000001/healthy` → `url.Parse` accepts hex IP; `url.Scheme = "http"` passes validation; HTTP client resolves to `127.0.0.1`
- `http://2130706433/healthy` → decimal representation of `127.0.0.1` — `url.Parse` accepts this
- `http://[::ffff:127.0.0.1]/healthy` → IPv6 mapped address
- `http://127.1/healthy` → shortened notation for `127.0.0.1`

**Test direction for causal-verifier:** Test each encoding variant against `lib.ValidateHTTPURL` and `utils.ParseEndpoint`. Verify which encodings `url.Parse` and `url.ParseRequestURI` normalize vs. pass through. Determine if Go's HTTP client (`http.Client`) normalizes these to the actual IP before dialing.

---

## CROSS-06: Auth Config Pivot + Audit Log Exfiltration = Evidence Destruction

**Source-A:** PH-18 (contradiction-reasoner) — LDAP/OIDC endpoint pivot to attacker-controlled identity provider
**Source-B:** PH-12 (contradiction-reasoner) — Persistent audit log exfiltration to attacker-controlled syslog

**Connection:** Both are system-admin-level attacks against the configuration API. PH-18 allows compromising all user accounts; PH-12 allows exfiltrating all audit activity. Together:

**Combined hypothesis:** A malicious system admin (or attacker who has obtained system-admin credentials) can:
1. Point `audit_log_forward_endpoint` to their syslog server — now receives all audit events
2. Set `skip_audit_log_database = true` — Harbor's own audit log goes dark
3. Change `ldap_url` or `oidc_endpoint` to attacker's identity server — gains ability to authenticate as any user
4. All of these configuration changes are themselves audit log events, but since `skip_audit_log_database` is now true and the syslog endpoint is attacker-controlled, the evidence trail is destroyed

**Test direction for causal-verifier:** Verify the ORDER of operations in `UpdateConfigurations` — does the skip-audit-DB flag take effect before or after the config-change event is logged? If the config change event is written AFTER the new config is applied, then setting `skip_audit_log_database=true` in the same request may prevent the config-change itself from being logged.
