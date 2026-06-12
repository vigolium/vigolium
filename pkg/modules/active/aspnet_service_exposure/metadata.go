package aspnet_service_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-service-exposure"
	ModuleName  = "ASP.NET Service Exposure"
	ModuleShort = "Detects exposed ASP.NET service endpoints including ASMX, WCF, OData, and legacy service paths"
)

var (
	ModuleDesc = `**What it means:** An ASP.NET web service is leaking its internal definition or error details. The scanner confirmed at least one of: an ASMX or WCF service serving its WSDL/discovery document, an OData service exposing its $metadata entity model, a SharePoint or Services directory listing, or a WCF endpoint returning verbose .NET exception faults (includeExceptionDetailInFaults left on). This hands an outsider a map of the backend that should not be public.

**How it's exploited:** An attacker reads the WSDL, discovery, or OData metadata to enumerate every operation, parameter, and data type the service accepts, then crafts targeted SOAP or OData calls to reach functionality that was assumed hidden. Verbose WCF faults leak stack traces, type names, and file paths that reveal internal structure and aid further attacks. The disclosure itself is not code execution but sharply lowers the effort to find and abuse weak operations.

**Fix:** Disable WSDL/metadata publishing on production service endpoints, restrict directory browsing, and set includeExceptionDetailInFaults to false so WCF returns generic faults.`

	ModuleConfirmation = "Confirmed when service endpoints return WSDL definitions, OData metadata, or verbose fault details"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "info-disclosure", "probe", "light"}
)
