package spring_boot_admin_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-boot-admin-exposure"
	ModuleName  = "Spring Boot Admin Exposure"
	ModuleShort = "Detects exposed Spring Boot Admin dashboards providing centralized access to actuator data"
)

var (
	ModuleDesc = `**What it means:** A Spring Boot Admin (SBA) dashboard or its instances/applications API is reachable without authentication. SBA aggregates actuator data from every registered service, centralizing health, metrics, environment, and configuration for the whole fleet behind one unprotected console.

**How it's exploited:** An attacker queries the dashboard or JSON API to enumerate all registered services and their management URLs, then pivots to those actuator endpoints to read environment variables and secrets or change runtime settings - escalating one exposure into multi-service compromise.

**Fix:** Place the SBA server behind authentication and network restrictions, requiring credentials on its UI and APIs.`

	ModuleConfirmation = "Confirmed when Spring Boot Admin dashboard UI or API is accessible without authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
