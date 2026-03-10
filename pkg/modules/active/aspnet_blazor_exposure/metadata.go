package aspnet_blazor_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-blazor-exposure"
	ModuleName  = "ASP.NET Blazor Exposure"
	ModuleShort = "Detects exposed Blazor WebAssembly assemblies and Blazor Server endpoints"
)

var (
	ModuleDesc = `## Description
Probes for exposed Blazor WebAssembly and Blazor Server endpoints. Blazor WASM
ships .NET DLL assemblies to the browser; if the boot manifest is accessible,
attackers can download and decompile all application assemblies to recover source
code, API keys, and business logic. Blazor Server exposes a SignalR hub that
reveals real-time communication infrastructure.

## Notes
- Runs once per host
- Probes boot manifest, runtime JS, and SignalR negotiate endpoint
- If boot manifest found, extracts assembly names as evidence
- Fingerprints 404 to avoid false positives

## References
- https://learn.microsoft.com/en-us/aspnet/core/blazor/
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration`

	ModuleConfirmation = "Confirmed when Blazor boot manifest or framework DLLs are publicly accessible"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "info-disclosure", "probe", "light"}
)
