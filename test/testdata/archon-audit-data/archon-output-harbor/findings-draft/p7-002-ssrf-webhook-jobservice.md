# Phase 7 Enriched Finding: P7-002

## Finding Details

| Field | Value |
|-------|-------|
| **Finding ID** | P7-002 |
| **Source SAST IDs** | SAST-002 |
| **Tool** | Semgrep (harbor-ssrf-job-http-client) + manual analysis |
| **Title** | SSRF via User-Controlled Webhook and Slack Job Address Parameters |
| **Severity** | HIGH |
| **Confidence** | HIGH |
| **CWE** | CWE-918 (Server-Side Request Forgery) |

PoC-Status: theoretical

## Vulnerability Classification

**Type**: Security (exploitable vulnerability with privilege escalation)

## Reachability Assessment

**Status**: CONFIRMED REACHABLE

**Evidence**:
- CodeQL: Data flow slice `DFD-2` in `call-graph-slices.json` confirms end-to-end path
- Semgrep: Custom rule `harbor-ssrf-job-http-client` confirms SSRF pattern
- Trust Boundaries: TB-5 (Core API <-> Job Service) and TB-8 (Job Service -> External)
- Sinks File: `sinks.json` lists both webhook and slack job at `http.Client.Do()` calls

## Attacker-Controlled Input Path

**Entry Point 1 (Webhook)**: HTTP POST API
```
POST /api/v2.0/projects/{id}/webhook/policies
Content-Type: application/json

{
  "name": "my-webhook",
  "event_types": ["ARTIFACT_PUSHED"],
  "address": "http://169.254.169.254/latest/meta-data/",  // <- ATTACKER CONTROLLED
  "skip_cert_verify": true
}
```

**Entry Point 2 (Slack via Preheat)**: HTTP POST API
```
POST /api/v2.0/projects/{id}/preheat/policies
Content-Type: application/json

{
  "provider_name": "slack",
  "name": "preheat-to-internal",
  "dest_registry": "http://internal-registry:5000",  // <- ATTACKER CONTROLLED
  "address": "http://192.168.1.100:8080/internal-admin"  // <- SSRF TARGET
}
```

**Attack Flow**:
1. Attacker with project-admin role creates webhook/preheat policy with internal URL
2. Policy stored in database (`notification_policy` or `p2p_preheat_policy` table)
3. Event trigger (artifact pushed, preheat scheduled) -> job queued to Redis
4. JobService dequeues job -> `WebhookJob.execute()` or `SlackJob.execute()` invoked
5. Job parameters extracted: `address` field (line 103 webhook_job.go, line 120 slack_job.go)
6. HTTP request constructed to attacker-specified URL: `http.NewRequest(POST, address, ...)`
7. HTTP client executes request: `wj.client.Do(req)` (line 120 webhook_job.go)
8. **No validation** of URL scheme, destination IP range, or DNS target

## Code Locations & Snippets

### Webhook Job (Primary SSRF Point)

**File**: `src/jobservice/job/impl/notification/webhook_job.go`
**Lines**: 103-120
**Function**: `WebhookJob.execute()`

```go
// Line 103: Address read from params (user-controlled)
address := params["address"].(string)

// Line 105: HTTP request constructed with user-controlled URL
req, err := http.NewRequest(http.MethodPost, address, bytes.NewReader([]byte(payload)))

// Lines 91-96: skip_cert_verify also user-controlled
if v, ok := params["skip_cert_verify"]; ok {
    if skipCertVerify, ok := v.(bool); ok && skipCertVerify {
        // TLS verification disabled for this request
        wj.client = httpHelper.clients[insecure]
    }
}

// Line 120: SINK - HTTP client executes the request
resp, err := wj.client.Do(req)
```

### Slack Job (Secondary SSRF Point)

**File**: `src/jobservice/job/impl/notification/slack_job.go`
**Lines**: 120-136
**Function**: `SlackJob.execute()`

```go
// Similar pattern: address from params, no validation, request sent to user-controlled URL
address := params["address"].(string)
req, err := http.NewRequest(http.MethodPost, address, bytes.NewReader([]byte(payload)))
resp, err := sj.client.Do(req)
```

## Vulnerability Analysis

### Trust Boundary Crossing

- **Primary Boundary**: TB-5 (Core API <-> Job Service via Redis queue)
  - Cross-service communication, shared secret auth protects Core-to-JobService
  - But Job Service runs with different privilege context (system-level outbound access)

- **Secondary Boundary**: TB-8 (Job Service -> External/Internal endpoints)
  - Job Service makes HTTP requests to arbitrary targets
  - **NO URL validation**, no allowlist, no denylist

### Attack Scenarios

#### Scenario 1: Cloud Metadata Service Exfiltration
```
1. Attacker (project-admin) creates webhook with address="http://169.254.169.254/latest/meta-data/"
2. Artifact push event triggers webhook
3. JobService makes HTTP POST to 169.254.169.254:80 (AWS/GCP/Azure metadata service)
4. Response contains credentials, instance metadata, role ARNs, secrets
5. Response logged in Job Service or returned to webhook callback
6. Attacker reads logs -> cloud credentials compromised
```

#### Scenario 2: Internal Service Port Scanning & Exploitation
```
1. Attacker enumerates internal IPs: 10.0.0.0/8
2. Creates webhooks with addresses like "http://10.0.0.50:8080/admin", "http://10.0.0.50:6379"
3. JobService probes internal network topology
4. Discovers Redis (6379), Postgres (5432), internal admin panels
5. Sends crafted HTTP payloads to exploit internal services
```

#### Scenario 3: Denial of Service on Internal Services
```
1. Attacker creates 1000 webhooks pointing to http://postgres-db:5432
2. Each webhook event sends HTTP request to Postgres
3. Internal service overwhelmed with HTTP connection attempts
4. Database connection pool exhausted -> service degradation
```

#### Scenario 4: Combined with skip_cert_verify for MitM
```
1. Attacker is network-adjacent (same VPC, compromised host)
2. Creates webhook with skip_cert_verify=true
3. Targets internal TLS service (e.g., internal-api:443)
4. MitM attack on webhook delivery: attacker intercepts & modifies webhook payload
5. Internal system receives attacker-modified data
```

### No Defensive Measures

Current code has **ZERO** URL validation:

| Validation | Present? | Details |
|-----------|----------|---------|
| Private IP filtering | NO | 10.x, 172.16-31.x, 192.168.x all allowed |
| Link-local filtering | NO | 169.254.x.x (AWS metadata) not blocked |
| Localhost filtering | NO | 127.0.0.1, ::1 allowed |
| Scheme allowlist | NO | ftp://, file://, gopher://, etc. all allowed |
| DNS pinning | NO | DNS resolution not pinned, rebinding possible |
| Timeout enforcement | IMPLICIT ONLY | Relies on HTTP client defaults |
| Port filtering | NO | All ports allowed |

## Data Flow

```
Project Admin User (authenticated)
    |
POST /api/v2.0/projects/{id}/webhook/policies
    |
go-swagger param binding -> notificationAPI.CreateWebhookPolicyOfProject()
    |
RequireProjectAccess() CHECK [PRESENT - authorization gate]
    |
notificationController.CreatePolicy(ctx, policy)
    |
policy.EventType = "ARTIFACT_PUSHED"
policy.Address = "http://169.254.169.254/latest/meta-data/"  [TAINT: user-controlled]
    |
persistPolicy(ctx, policy)  [DATABASE STORE]
    |
[TIME PASSES: Artifact pushed to repository]
    |
Event triggered -> Redis job queue
    |
JobService dequeue -> WebhookJob.Run()
    |
params["address"] = "http://169.254.169.254/latest/meta-data/"  [TAINT from DB]
    |
http.NewRequest(POST, address, payload)  [NO VALIDATION]
    |
wj.client.Do(req)  [SINK: SSRF executed]
    |
Response from 169.254.169.254 [INFORMATION DISCLOSURE]
```

## Recommended Fix

Implement URL validation layer in `webhook_job.go` and `slack_job.go`:

```go
func validateWebhookAddress(address string) error {
    u, err := url.Parse(address)
    if err != nil {
        return fmt.Errorf("invalid URL: %w", err)
    }

    // Reject non-HTTP(S) schemes
    if u.Scheme != "http" && u.Scheme != "https" {
        return fmt.Errorf("only http and https schemes allowed, got: %s", u.Scheme)
    }

    // Resolve hostname to IP
    host := u.Hostname()
    ips, err := net.LookupIP(host)
    if err != nil {
        return fmt.Errorf("hostname resolution failed: %w", err)
    }

    // Check each resolved IP
    for _, ip := range ips {
        // Reject RFC1918 private ranges
        if ip.IsPrivate() {
            return fmt.Errorf("private IP range not allowed: %s", ip)
        }

        // Reject link-local/metadata service
        if ip.IsLinkLocalUnicast() || ip.String() == "169.254.169.254" {
            return fmt.Errorf("metadata service/link-local not allowed: %s", ip)
        }

        // Reject loopback
        if ip.IsLoopback() {
            return fmt.Errorf("loopback address not allowed: %s", ip)
        }
    }

    return nil
}
```

Then call in `execute()` before making request:

```go
func (wj *WebhookJob) execute(_ job.Context, params map[string]any) error {
    address := params["address"].(string)

    // ADD THIS VALIDATION
    if err := validateWebhookAddress(address); err != nil {
        return fmt.Errorf("webhook address validation failed: %w", err)
    }

    // ... rest of existing code
}
```

## Phase 8 Chamber Assignment

**Chamber**: **Server-Side Request Forgery (SSRF-001)**

**Rationale**:
- Exploitable by project-admin role (privilege escalation from user role)
- Reaches internal/external endpoints via job service
- Can access cloud metadata services (AWS/GCP/Azure credentials)
- Can probe/attack internal network topology
- High impact: credential disclosure, internal network reconnaissance, DoS

## References

- **CWE-918**: [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- **OWASP**: [Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server-Side_Request_Forgery)
- **KB Report**:
  - TB-5: Core API <-> Job Service
  - TB-8: Job Service <-> External Endpoints (no URL allowlist/denylist)
  - Attack Surface: "Webhook endpoint URL" (line 183), "P2P preheat endpoint" (line 185)
- **Exploit Status**: Known vulnerability class; similar patterns in other registries (Harbor advisory 2020)

## Notes for Reviewers

1. **Severity Justification**: HIGH because:
   - Reaches internal services (metadata, databases, admin panels)
   - Can disclose cloud credentials
   - Available to project-admin role (relatively common privilege level)
   - No detection/logging of SSRF attempts

2. **Exploitability**: VERY HIGH
   - No user interaction required (automatic on event trigger)
   - Can be triggered repeatedly
   - Works from any network location if project-admin role obtained

3. **Impact**: CRITICAL
   - Credential exfiltration (cloud credentials, internal secrets)
   - Internal network reconnaissance
   - Denial of service on internal services
   - Combined with skip_cert_verify: MitM attacks on internal HTTPS

4. **Related Findings**: SAST-012 (skip_cert_verify) compounds this vulnerability
