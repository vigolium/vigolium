package aspnet_misconfig

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
		path:        "/trace.axd",
		name:        "ASP.NET Trace",
		markers:     []string{"Application Trace", "Request Details", "Trace Information"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.High,
		desc:        "ASP.NET trace handler is exposed, revealing detailed request/response information and application internals",
	},
	{
		path:        "/elmah.axd",
		name:        "ELMAH Error Log",
		markers:     []string{"ELMAH", "Error Log for", "Error Filtering"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.High,
		desc:        "ELMAH error logging handler is exposed, revealing application errors, stack traces, and server details",
	},
	{
		path:        "/glimpse.axd",
		name:        "Glimpse Diagnostics",
		markers:     []string{"Glimpse", "glimpseData"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "Glimpse diagnostics endpoint is exposed, revealing server-side execution details",
	},
	{
		path:        "/glimpse",
		name:        "Glimpse Diagnostics",
		markers:     []string{"Glimpse", "glimpseData"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "Glimpse diagnostics endpoint is exposed, revealing server-side execution details",
	},
	{
		path:        "/mini-profiler-resources/results",
		name:        "MiniProfiler",
		markers:     []string{"MiniProfiler", "profiler"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "MiniProfiler results endpoint is exposed, revealing SQL queries and performance data",
	},
	{
		path:        "/hangfire",
		name:        "Hangfire Dashboard",
		markers:     []string{"Hangfire", "hangfire", "Dashboard"},
		antiMarkers: []string{"404", "Not Found", "login", "Login"},
		sev:         severity.High,
		desc:        "Hangfire background job dashboard is publicly accessible, potentially allowing job manipulation",
	},
	{
		path:        "/signalr/negotiate",
		name:        "SignalR Negotiate",
		markers:     []string{"connectionId", "negotiateVersion"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "SignalR negotiate endpoint is exposed, revealing real-time communication infrastructure",
	},
	{
		path:        "/signalr/hubs",
		name:        "SignalR Hubs",
		markers:     []string{"signalR", "hubConnection"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "SignalR hubs endpoint is exposed, revealing available real-time communication hubs",
	},
}
