package aspnet_blazor_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
}

var probes = []probe{
	{
		path:        "/_framework/blazor.boot.json",
		name:        "Blazor WASM Boot Manifest",
		markers:     []string{"assembly", "resources", "mainAssemblyName", "linkerEnabled"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.High,
		desc:        "Blazor WebAssembly boot manifest exposed, listing all .NET assemblies available for download and decompilation",
	},
	{
		path:        "/_framework/blazor.webassembly.js",
		name:        "Blazor WASM Runtime",
		markers:     []string{"Blazor", "blazor", "WebAssembly", "_framework"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "Blazor WebAssembly runtime JavaScript accessible, confirming Blazor WASM deployment",
	},
	{
		path:        "/_framework/blazor.server.js",
		name:        "Blazor Server Runtime",
		markers:     []string{"Blazor", "blazor", "signalR", "HubConnection"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "Blazor Server runtime JavaScript accessible, confirming Blazor Server deployment",
	},
	{
		path:        "/_blazor/negotiate",
		name:        "Blazor Server Hub Negotiate",
		markers:     []string{"connectionId", "connectionToken", "negotiateVersion", "availableTransports"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "Blazor Server SignalR hub negotiate endpoint exposed, revealing real-time communication infrastructure details",
	},
	{
		path:        "/_content/",
		name:        "Blazor Content Directory",
		markers:     []string{"<pre>", "Parent Directory", "Index of", "<DIR>"},
		antiMarkers: []string{"404", "Not Found", "403", "Forbidden"},
		sev:         severity.Medium,
		desc:        "Blazor Razor component library content directory listing exposed",
	},
	{
		path:        "/_framework/dotnet.wasm",
		name:        "Blazor .NET WASM Runtime",
		markers:     []string{"\x00asm"}, // WebAssembly magic bytes
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "Blazor .NET WebAssembly runtime binary accessible, confirming Blazor WASM deployment",
	},
}
