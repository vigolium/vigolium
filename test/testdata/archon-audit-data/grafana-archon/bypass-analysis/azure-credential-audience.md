# Bypass Analysis: Azure Monitor Credential Audience Fix

**Commit**: `a8b373144f6eeb4ecb5fa3820b8873a1c12b2df9`
**Component**: Azure Monitor datasource -- batch metrics credential proxy
**Tag**: [undisclosed]
**Cluster ID**: azure-credential-audience

## Patch Summary

**Vulnerability**: Batch metrics requests to `metrics.monitor.azure.com` were sent using an HTTP client authenticated with an ARM (`management.azure.com`) audience token. This means the Grafana credential proxy was issuing tokens scoped to the Azure Resource Manager audience and attaching them to requests destined for a different Azure data-plane service. This bypasses the principle of least privilege and, depending on Azure AD token validation behavior, could allow:

1. ARM-scoped tokens to be accepted by the metrics data-plane (token audience mismatch, typically rejected but misconfigurable).
2. The ARM credential proxy to inadvertently forward requests to an unintended endpoint without proper audience restriction.

**Fix mechanism**: The patch introduces a new route constant `azureMonitorBatchMetrics` ("Azure Monitor Batch Metrics") with its own URL (`https://metrics.monitor.azure.com`), OAuth scopes (`https://metrics.monitor.azure.com/.default`), and a dedicated HTTP client. The `executeBatchTimeSeriesQuery` function now uses this dedicated `batchClient` instead of the ARM-audience `client` for batch API calls.

## Bypass Verdict: **bypassable** (partial -- customized cloud path)

## Evidence

### Bypass 1: Customized Cloud Fallback (CONFIRMED)

The `getCustomizedCloudRoutes()` function at `routes.go:93-106` returns routes directly from user-supplied JSON (`customizedRoutes`). There is no enforcement that a customized cloud configuration must include an `azureMonitorBatchMetrics` route entry. When this route is absent:

- `azuremonitor.go` line: `if _, ok := routesForModel[azureMonitorBatchMetrics]; ok {` -- the batch service is simply not created.
- `azuremonitor-datasource.go` line: `if svc, ok := dsInfo.Services["Azure Monitor Batch Metrics"]; ok {` -- the fallback uses `batchClient = client`, which is the ARM-audience client.

**Impact**: Customized cloud users who configure batch-capable endpoints but do not add the `azureMonitorBatchMetrics` route will continue to send batch requests with ARM-audience tokens. The patch explicitly acknowledges this in comments ("customized cloud users must supply the metricsDataPlane route themselves") but does not warn, log, or fail when the route is missing. This is a silent degradation to the vulnerable behavior.

### Bypass 2: Sovereign Cloud `metricsDataPlane` Property (LOW RISK)

The patch reads `cloudSettings.Properties["metricsDataPlane"]` to allow sovereign clouds to override the batch metrics URL. However, this property is not defined in the `grafana-azure-sdk-go` v2.4.0 cloud settings for any cloud (AzurePublic, AzureChina, AzureUSGovernment). This means:

- For all standard clouds, the hardcoded fallback `https://metrics.monitor.azure.com` is always used.
- Sovereign clouds (AzureChina, AzureUSGovernment) that have different metrics data-plane endpoints will use the **public cloud** URL with the **public cloud** audience scope, which will fail at the Azure AD level (wrong audience for the sovereign tenant). This is a functionality bug rather than a security bypass -- requests will be rejected, not accepted with wrong credentials.

### Bypass 3: Non-Batchable Query Fallback (NOT A BYPASS)

Non-batchable queries (custom namespace / Guest OS metrics) in `executeBatchTimeSeriesQuery` continue to use the ARM `client` for individual `executeQuery` calls against the ARM endpoint. This is correct behavior -- these queries target `management.azure.com`, not `metrics.monitor.azure.com`.

### Bypass 4: Resource Handler Path (NOT A BYPASS)

The resource handler (`azuremonitor-resource-handler.go`) only routes to `azureMonitor`, `azureLogAnalytics`, and `azureResourceGraph` services. There is no resource handler path for batch metrics, so this is not an alternate entry point.

### Sibling Services Audit

| Service | Route Key | Audience | Client | Status |
|---------|-----------|----------|--------|--------|
| Azure Monitor | `Azure Monitor` | `management.azure.com/.default` | Dedicated | Correct |
| Azure Log Analytics | `Azure Log Analytics` | `api.loganalytics.io/.default` | Dedicated | Correct |
| Azure Resource Graph | `Azure Resource Graph` | `management.azure.com/.default` | Same as ARM | Correct (uses ARM) |
| Azure Traces | `Azure Traces` | `api.loganalytics.io/.default` | Same as Log Analytics | Correct |
| Azure Monitor Batch Metrics | `Azure Monitor Batch Metrics` | `metrics.monitor.azure.com/.default` | Dedicated (post-fix) | Fixed for standard clouds |

No other services appear to use a mismatched audience. The Log Analytics, Resource Graph, and Traces services all correctly match their endpoint to their audience scope.

## Recommendations

1. **Log a warning** when the `azureMonitorBatchMetrics` route is absent from customized cloud configurations, so operators are aware of the audience mismatch.
2. **Add `metricsDataPlane` property** to the `grafana-azure-sdk-go` cloud settings for AzureChina and AzureUSGovernment sovereign clouds to ensure correct endpoints.
3. Consider **failing** batch requests when the dedicated client is absent rather than silently falling back to the ARM client.
