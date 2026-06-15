package aspnet_service_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-service-exposure"
	ModuleName  = "ASP.NET Service Exposure"
	ModuleShort = "Detects exposed ASP.NET service endpoints including ASMX, WCF, OData, and legacy service paths"
)

var (
	ModuleDesc = `**What it means:** An ASP.NET web service leaks its internal definition or error details - an ASMX/WCF service serving its WSDL, an OData service exposing $metadata, or a WCF endpoint returning verbose .NET faults (includeExceptionDetailInFaults left on).

**How it's exploited:** An attacker reads the WSDL or OData metadata to enumerate every operation, parameter, and data type, then crafts targeted SOAP or OData calls to reach hidden functionality. Verbose faults leak stack traces and file paths, easing further attacks.

**Fix:** Disable WSDL/metadata publishing on production endpoints, restrict directory browsing, and set includeExceptionDetailInFaults to false.`

	ModuleConfirmation = "Confirmed when service endpoints return WSDL definitions, OData metadata, or verbose fault details"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "info-disclosure", "probe", "light"}
)
