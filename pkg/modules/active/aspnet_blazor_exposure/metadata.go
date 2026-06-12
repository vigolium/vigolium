package aspnet_blazor_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-blazor-exposure"
	ModuleName  = "ASP.NET Blazor Exposure"
	ModuleShort = "Detects exposed Blazor WebAssembly assemblies and Blazor Server endpoints"
)

var (
	ModuleDesc = `**What it means:** The target serves ASP.NET Blazor framework resources that are reachable without authentication. The scanner confirmed one or more of: the Blazor WebAssembly boot manifest (/_framework/blazor.boot.json), the WASM or Server runtime scripts, the .NET WASM binary, a SignalR hub negotiate endpoint (/_blazor/negotiate), or a component-library content directory listing. The most serious case is the boot manifest, which enumerates every .NET assembly the app ships to the browser. This is information disclosure that maps the application's internals and, for Blazor WASM, exposes its compiled code.

**How it's exploited:** Because Blazor WebAssembly runs client-side, an attacker downloads each listed .dll/.wasm assembly via the boot manifest and decompiles them with tools like ILSpy or dnSpy to recover source code, embedded API keys, connection strings, and business logic that was never meant to be readable. The negotiate endpoint and runtime fingerprints reveal the framework version and real-time hub surface to target further attacks.

**Fix:** Restrict or remove public access to /_framework, /_blazor, and /_content; keep secrets server-side instead of in WASM assemblies.`

	ModuleConfirmation = "Confirmed when Blazor boot manifest or framework DLLs are publicly accessible"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "info-disclosure", "probe", "light"}
)
