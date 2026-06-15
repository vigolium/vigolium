package aspnet_blazor_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aspnet-blazor-exposure"
	ModuleName  = "ASP.NET Blazor Exposure"
	ModuleShort = "Detects exposed Blazor WebAssembly assemblies and Blazor Server endpoints"
)

var (
	ModuleDesc = `**What it means:** The target serves ASP.NET Blazor resources without authentication - the WebAssembly boot manifest (/_framework/blazor.boot.json), runtime scripts, the .NET WASM binary, a SignalR negotiate endpoint (/_blazor/negotiate), or a /_content listing. The boot manifest enumerates every .NET assembly shipped to the browser.

**How it's exploited:** Since Blazor WASM runs client-side, an attacker downloads each listed .dll/.wasm and decompiles them with ILSpy or dnSpy to recover source code, embedded API keys, connection strings, and business logic.

**Fix:** Restrict or remove public access to /_framework, /_blazor, and /_content; keep secrets server-side, not in WASM assemblies.`

	ModuleConfirmation = "Confirmed when Blazor boot manifest or framework DLLs are publicly accessible"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aspnet", "info-disclosure", "probe", "light"}
)
