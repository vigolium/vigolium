package aspnet_health_exposure

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
	// Standard ASP.NET health check endpoints
	{
		path:        "/health",
		name:        "Health Check Endpoint",
		markers:     []string{"Healthy", "Unhealthy", "Degraded", "status", "entries"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "ASP.NET health check endpoint exposed, potentially revealing component health status and infrastructure details",
	},
	{
		path:        "/healthz",
		name:        "Health Check (K8s-style)",
		markers:     []string{"Healthy", "Unhealthy", "Degraded", "status", "entries"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Kubernetes-style health check endpoint exposed with potential infrastructure status details",
	},
	{
		path:        "/health/ready",
		name:        "Readiness Probe",
		markers:     []string{"Healthy", "Unhealthy", "Degraded", "ready"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Readiness probe endpoint exposed, revealing service dependency status",
	},
	{
		path:        "/health/live",
		name:        "Liveness Probe",
		markers:     []string{"Healthy", "Unhealthy", "Degraded", "alive"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "Liveness probe endpoint exposed, confirming application operational status",
	},
	// Health Checks UI dashboard
	{
		path:        "/healthchecks-ui",
		name:        "Health Checks UI Dashboard",
		markers:     []string{"HealthChecksUI", "healthchecks-ui", "health-checks", "AspNetCore.HealthChecks.UI"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.High,
		desc:        "ASP.NET Health Checks UI dashboard exposed without authentication, revealing detailed infrastructure health with database, cache, and external service status",
	},
	{
		path:        "/healthchecks-api",
		name:        "Health Checks API",
		markers:     []string{"entries", "status", "duration", "description"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Health Checks API endpoint exposed, returning detailed JSON health data for all registered checks",
	},
	// Prometheus / OpenTelemetry metrics
	{
		path:        "/metrics",
		name:        "Prometheus Metrics",
		markers:     []string{"# HELP", "# TYPE", "process_", "dotnet_", "http_request"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "Prometheus metrics endpoint exposed, revealing application performance data, request patterns, and system resource usage",
	},
	// Visual Studio Browser Link
	{
		path:        "/_vs/browserLink",
		name:        "VS Browser Link",
		markers:     []string{"browserLink", "BrowserLink", "signalr"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "Visual Studio Browser Link endpoint active in production, indicating development tooling left enabled",
	},
	// .NET Aspire dashboard
	{
		path:        "/dashboard",
		name:        "Aspire Dashboard",
		markers:     []string{"Aspire", "aspire", "FluentUI", "Resources"},
		antiMarkers: []string{"404", "Not Found", "login", "Login", "Sign in"},
		sev:         severity.High,
		desc:        ".NET Aspire dashboard exposed without authentication, revealing distributed application topology and telemetry",
	},
	// Environment endpoint (sometimes exposed by developers)
	{
		path:        "/environment",
		name:        "Environment Info",
		markers:     []string{"ASPNETCORE_ENVIRONMENT", "DOTNET_ENVIRONMENT", "Production", "Development", "ContentRootPath"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.High,
		desc:        "ASP.NET environment information endpoint exposed, revealing runtime configuration and environment variables",
	},
}
