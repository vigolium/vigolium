package spring_boot_admin_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-boot-admin-exposure"
	ModuleName  = "Spring Boot Admin Exposure"
	ModuleShort = "Detects exposed Spring Boot Admin dashboards providing centralized access to actuator data"
)

var (
	ModuleDesc = `**What it means:** A Spring Boot Admin (SBA) dashboard or its instances/applications API is reachable on this host without authentication. SBA aggregates actuator data from every registered Spring Boot service, so an exposed dashboard centralizes health, metrics, environment, and configuration details for the whole fleet behind one unprotected console.

**How it's exploited:** An attacker browses the dashboard or queries the JSON API to enumerate all registered services along with their management and health URLs, then pivots to those actuator endpoints to read environment variables, configuration, and secrets, trigger log-file downloads, or change log levels and other runtime settings, escalating a single exposure into broad multi-service compromise.

**Fix:** Place the Spring Boot Admin server behind authentication and network restrictions, and require credentials on the SBA UI and its underlying APIs so the aggregated actuator data is never anonymously accessible.`

	ModuleConfirmation = "Confirmed when Spring Boot Admin dashboard UI or API is accessible without authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
