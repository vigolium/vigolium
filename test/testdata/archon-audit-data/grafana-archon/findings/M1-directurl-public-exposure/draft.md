Phase: 8
Sequence: 004
Slug: directurl-public-exposure
Verdict: VALID
Rationale: Confirmed internal URL disclosure to unauthenticated viewers via shared simplejson map reference. No credential exposure but reveals internal network topology. Advocate found no blocking protection.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-1/debate.md

## Summary

Internal Prometheus, Amazon Prometheus, and Azure Prometheus datasource URLs are exposed to unauthenticated public dashboard viewers via the `jsonData.directUrl` field in the frontend settings response. This occurs because `ds.JsonData.Set("directUrl", ds.URL)` modifies the same underlying map that was returned by `ds.JsonData.MustMap()` and assigned to `dsDTO.JSONData`, due to simplejson's reference semantics. No `IsPublicDashboardView()` guard exists around this assignment.

## Location

- **Map reference**: `pkg/api/frontendsettings.go:538` -- `dsDTO.JSONData = ds.JsonData.MustMap()` (returns reference)
- **URL injection**: `pkg/api/frontendsettings.go:594-596` -- `ds.JsonData.Set("directUrl", ds.URL)` (modifies same backing map)

## Attacker Control

No attacker input required beyond accessing a public dashboard that uses a Prometheus datasource.

## Trust Boundary Crossed

Unauthenticated internet user -> internal datasource URL (e.g., `http://prometheus.internal:9090`).

## Impact

- **Internal network topology disclosure**: Reveals internal hostnames, IP addresses, and ports of Prometheus infrastructure
- **Reconnaissance**: Attacker gains information useful for targeted attacks against internal services
- **Combined with SSRF**: If combined with other SSRF vulnerabilities, the disclosed URLs provide direct targets

## Evidence

```go
// pkg/api/frontendsettings.go:538 -- MustMap returns REFERENCE to underlying map
dsDTO.JSONData = ds.JsonData.MustMap()

// pkg/api/frontendsettings.go:594-596 -- Set modifies the SAME map
if ds.Type == datasources.DS_PROMETHEUS || ds.Type == datasources.DS_AMAZON_PROMETHEUS || ds.Type == datasources.DS_AZURE_PROMETHEUS {
    ds.JsonData.Set("directUrl", ds.URL)
}
// At this point dsDTO.JSONData["directUrl"] = ds.URL (internal URL)
```

## Reproduction Steps

1. Configure a Prometheus datasource with URL `http://prometheus.internal:9090` in proxy mode
2. Create a dashboard using this datasource and enable public sharing
3. As an unauthenticated user, request frontend settings for the public dashboard
4. Observe `jsonData.directUrl` contains `http://prometheus.internal:9090` in the response
