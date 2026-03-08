package aspnet_service_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-aspnet-service-exposure"
	ModuleName  = "ASP.NET Service Exposure"
	ModuleShort = "Detects exposed ASP.NET service endpoints including ASMX, WCF, OData, and legacy service paths"
)

var (
	ModuleDesc = `## Description
Probes for exposed ASP.NET service endpoints. For .asmx URLs in traffic, probes
?WSDL and ?disco for WSDL disclosure. For .svc URLs, probes ?wsdl and sends
malformed SOAP to detect WCF detailed faults. Also probes common paths for
OData metadata and legacy service endpoints.

## Notes
- Runs once per host
- Traffic-aware: inspects original request URL for .asmx/.svc extensions
- Probes OData $metadata and common service paths
- Tests WCF for verbose fault disclosure (includeExceptionDetailInFaults)
- Fingerprints 404 to avoid false positives

## References
- https://learn.microsoft.com/en-us/dotnet/framework/wcf/
- https://learn.microsoft.com/en-us/aspnet/web-api/overview/odata-support-in-aspnet-web-api/`

	ModuleConfirmation = "Confirmed when service endpoints return WSDL definitions, OData metadata, or verbose fault details"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "info-disclosure", "probe", "light"}
)
