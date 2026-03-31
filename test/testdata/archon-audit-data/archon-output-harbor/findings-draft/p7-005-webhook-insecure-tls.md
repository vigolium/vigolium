# Phase 7 Enriched Finding: P7-005

## Finding Details

| Field | Value |
|-------|-------|
| **Finding ID** | P7-005 |
| **Source SAST ID** | SAST-012 |
| **Tool** | Manual code review |
| **Title** | Insecure Webhook HTTP Transport with User-Controllable skip_cert_verify Flag |
| **Severity** | MEDIUM |
| **Confidence** | HIGH |
| **CWE** | CWE-295 (Improper Certificate Validation) |

## Vulnerability Classification

**Type**: Security (Man-in-the-middle attack vector via misconfiguration)

## Reachability Assessment

**Status**: CONFIRMED REACHABLE

**Evidence**:
- User-controlled parameter: `skip_cert_verify` in webhook policy
- Code path: Parameter flows from REST API → database → job service
- Sink: HTTP client configured with `InsecureSkipVerify: true`
- Trust Boundary: TB-8 (Job Service ↔ External webhook targets)

## Attacker-Controlled Input Path

**Entry Point**: HTTP POST API for webhook policy creation

```
POST /api/v2.0/projects/{projectId}/webhook/policies
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "my-webhook",
  "event_types": ["ARTIFACT_PUSHED"],
  "address": "https://internal-service:8443/webhook",
  "skip_cert_verify": true  // <- ATTACKER CONTROLLED
}
```

**Attack Flow**:
1. Project admin (or malicious admin) creates webhook policy with `skip_cert_verify=true`
2. Policy persisted to database
3. Event triggers webhook job
4. JobService retrieves job parameters from Redis queue
5. WebhookJob.init() reads skip_cert_verify parameter (line 91-96)
6. If true, HTTP client switched to insecure transport
7. HTTP request sent to webhook target
8. Network attacker can MitM the webhook delivery

## Code Location & Snippet

**File**: `src/jobservice/job/impl/notification/webhook_job.go`
**Lines**: 91-96
**Function**: `WebhookJob.init()`

```go
func (wj *WebhookJob) init(ctx job.Context, params map[string]any) error {
    wj.logger = ctx.GetLogger()
    wj.ctx = ctx

    // default use secure transport
    wj.client = httpHelper.clients[secure]

    // [VULNERABLE: skip_cert_verify is user-controlled]
    if v, ok := params["skip_cert_verify"]; ok {
        if skipCertVerify, ok := v.(bool); ok && skipCertVerify {
            // if skip cert verify is true, it means not verify remote cert, use insecure client
            // [PROBLEM: Allows user to disable TLS verification]
            wj.client = httpHelper.clients[insecure]
        }
    }
    return nil
}
```

**Consequence**:
- HTTP client configured with `InsecureSkipVerify: true`
- TLS certificate validation completely disabled
- Network attacker can present any certificate
- Webhook payload intercepted and modified in flight

## Vulnerability Analysis

### Attack Scenarios

#### Scenario 1: Webhook Response Interception

```
1. Project admin creates webhook for CI/CD system:
   POST /api/v2.0/projects/1/webhook/policies
   {
     "address": "https://ci-system.internal:8443/trigger",
     "skip_cert_verify": true
   }

2. Attacker on network (same VPC, compromised host):
   - Performs DNS spoofing or ARP poisoning
   - Intercepts webhook HTTPS connection
   - Presents attacker certificate (rejected by proper clients)
   - With skip_cert_verify=true, Harbor accepts ANY cert

3. Attacker receives webhook JSON payload:
   {
     "repository": "company/secret-app",
     "artifact": "sha256:...",
     "webhook_event": "ARTIFACT_PUSHED"
   }

4. Attacker modifies response:
   - Injects command to CI system: "Deploy this artifact to production WITHOUT approval"
   - Returns modified payload to CI system
   - CI system processes attacker's instruction

5. Result: Unauthorized deployment, integrity violation
```

#### Scenario 2: Webhook Payload Modification

```
1. Organization uses webhooks for security scanning:
   POST /api/v2.0/projects/2/webhook/policies
   {
     "address": "https://security-scanner.internal:443/scan",
     "skip_cert_verify": true
   }

2. Artifact pushed triggers webhook delivery

3. Attacker MitM intercepts:
   - Original: { "repository": "app", "digest": "sha256:abc...", "severity": "CRITICAL" }
   - Attacker modifies: { "repository": "app", "digest": "sha256:def...", "severity": "LOW" }
   - Security scanner marks malicious artifact as "LOW" severity
   - Artifact allowed to proceed to production
```

#### Scenario 3: Credential Harvesting

```
1. Webhook includes Bearer token in Authorization header

2. Attacker MitM intercepts:
   - Captures: Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
   - Token is API token for internal service
   - Attacker uses token for unauthorized access
```

#### Scenario 4: Combined with SSRF (SAST-002)

```
1. Attacker creates webhook with:
   - address: "http://internal-database:5432"  (SSRF)
   - skip_cert_verify: true  (allows raw TCP without cert)

2. JobService connects to internal Postgres
3. Attacker MitM: intercepts database responses
4. Modifies database responses before webhook delivery
5. Compromise of data consistency
```

### Risk Assessment

| Factor | Assessment | Notes |
|--------|-----------|-------|
| **Who can enable?** | Project admin (or system admin) | Relatively common role |
| **Detectability** | Low | No alerts when skip_cert_verify enabled |
| **Attack Requirements** | Network position + admin role | Privilege escalation or compromised admin |
| **Data at Risk** | Webhook payloads | Potentially sensitive (artifact info, deployment data) |
| **Exploitability** | MEDIUM | Requires network position + misconfiguration |
| **Impact** | MEDIUM | Integrity (MitM modification), confidentiality (interception) |

### Why This Is a Design Issue

**The Fundamental Problem**:
- TLS certificate verification is a **security control** (prevents MitM attacks)
- Disabling it should be:
  1. Not user-controllable (requires code deployment)
  2. Only enabled with explicit admin approval
  3. Logged/audited
  4. Time-limited or scoped

**Current Implementation**:
- Any project admin can disable cert verification
- No logging/audit trail
- No time limit
- Enables indefinite MitM attacks

## Recommended Fix

### Fix Option 1: Restrict to System Admins Only

```go
func (wj *WebhookJob) init(ctx job.Context, params map[string]any) error {
    wj.logger = ctx.GetLogger()
    wj.ctx = ctx

    // default use secure transport
    wj.client = httpHelper.clients[secure]

    if v, ok := params["skip_cert_verify"]; ok {
        if skipCertVerify, ok := v.(bool); ok && skipCertVerify {
            // RESTRICT: Only allow if user is system admin
            if !wj.isSystemAdmin(ctx) {
                wj.logger.Warningf("skip_cert_verify requested by non-admin user")
                // Ignore the flag, use secure client anyway
                return nil
            }

            // Log security event
            wj.logger.Warnf("Using insecure transport (skip_cert_verify=true) for webhook")
            wj.client = httpHelper.clients[insecure]
        }
    }
    return nil
}

func (wj *WebhookJob) isSystemAdmin(ctx job.Context) bool {
    // Check if user is system admin in security context
    secCtx := libsec.FromContext(ctx)
    return secCtx.IsSysAdmin()
}
```

### Fix Option 2: Require Explicit Allow-List in Config

```go
// In Harbor config (environment variable or config file)
INSECURE_WEBHOOKS_ALLOWED=false

func (wj *WebhookJob) init(ctx job.Context, params map[string]any) error {
    wj.client = httpHelper.clients[secure]

    if v, ok := params["skip_cert_verify"]; ok {
        if skipCertVerify, ok := v.(bool); ok && skipCertVerify {
            // REQUIRE: Explicit config to allow insecure webhooks
            insecureAllowed := config.GetBool("INSECURE_WEBHOOKS_ALLOWED", false)
            if !insecureAllowed {
                wj.logger.Warnf("skip_cert_verify requested but INSECURE_WEBHOOKS_ALLOWED=false")
                return nil
            }

            wj.logger.Errorf("SECURITY WARNING: Webhook will use insecure transport (cert verification disabled)")
            wj.client = httpHelper.clients[insecure]
        }
    }
    return nil
}
```

### Fix Option 3: Comprehensive Audit + Restrict

```go
func (wj *WebhookJob) init(ctx job.Context, params map[string]any) error {
    wj.client = httpHelper.clients[secure]

    if v, ok := params["skip_cert_verify"]; ok {
        if skipCertVerify, ok := v.(bool); ok && skipCertVerify {
            // LOG SECURITY EVENT
            auditLog.Log(ctx, "WEBHOOK_INSECURE_TLS_REQUESTED", map[string]interface{}{
                "address": params["address"],
                "user": getUsername(ctx),
                "timestamp": time.Now(),
            })

            // RESTRICT: System admin only
            if !wj.isSystemAdmin(ctx) {
                wj.logger.Warnf("skip_cert_verify requested by non-admin")
                return fmt.Errorf("insecure webhooks restricted to system administrators")
            }

            wj.client = httpHelper.clients[insecure]
        }
    }
    return nil
}
```

## Phase 8 Chamber Assignment

**Chamber**: **Man-in-the-Middle Attacks (MitM-001)**

**Rationale**:
- Allows TLS certificate verification bypass
- Creates MitM attack vector on webhook delivery
- Exploitable by network-adjacent attacker + admin misconfiguration
- Compounded by SAST-002 (SSRF) which can target internal services
- Affects integrity of webhook data in flight

## References

- **CWE-295**: [Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- **CWE-476**: [Null Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- **OWASP**: [Man-in-the-middle attack](https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack)
- **Go Security**: [net/http - InsecureSkipVerify](https://golang.org/doc/effective_go#concurrency)
- **KB Report**:
  - TB-8: Job Service ↔ External Endpoints (no SSL/TLS enforcement)
  - Attack Surface: "Webhook endpoint URL" with user-control over parameters

## Notes for Reviewers

1. **Severity**: MEDIUM (not HIGH) because:
   - Requires network position (not trivial)
   - Requires admin misconfiguration
   - Doesn't directly breach data (but enables MitM)

2. **Exploitability**: MEDIUM
   - Requires network position (same VPC, compromised host, DNS spoofing, ARP poisoning)
   - Easy to exploit once position obtained
   - Can be leveraged for data modification or credential harvesting

3. **Relationship to SAST-002**:
   - SAST-002 (SSRF) enables reaching internal services
   - SAST-012 (insecure TLS) enables MitM on those internal services
   - Combined: Attacker can reach AND intercept internal HTTPS services

4. **User Education**:
   - Document that skip_cert_verify disables security control
   - Warn in UI: "Warning: TLS certificate verification disabled. This endpoint will accept self-signed or forged certificates."
   - Recommend: Use proper certificates, not skip verification

5. **Testing Recommendations**:
   - Create webhook with skip_cert_verify=true
   - Set up MitM proxy (mitmproxy, Burp Suite)
   - Verify webhook payload can be intercepted and modified
   - Confirm without fix, modifications are not detected

6. **Recommended Priority**:
   - Fix Option 1 (System admin only) = Immediate
   - Fix Option 3 (Audit + restrict) = Better long-term
