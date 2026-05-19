package spring_boot_admin_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-boot-admin-exposure"
	ModuleName  = "Spring Boot Admin Exposure"
	ModuleShort = "Detects exposed Spring Boot Admin dashboards providing centralized access to actuator data"
)

var (
	ModuleDesc = `## Description
Probes for exposed Spring Boot Admin (SBA) dashboards. SBA aggregates actuator
data from multiple registered Spring Boot services, providing a centralized
view of health, metrics, configuration, and environment details. An exposed
SBA dashboard can enable broad infrastructure compromise through access to
multiple services' actuator endpoints.

## Notes
- Runs once per host
- Checks common SBA paths: /admin, /boot-admin, /sba, /springbootadmin
- Validates using SBA-specific UI markers
- Fingerprints 404 responses to reduce false positives

## References
- https://codecentric.github.io/spring-boot-admin/current/
- https://github.com/codecentric/spring-boot-admin`

	ModuleConfirmation = "Confirmed when Spring Boot Admin dashboard UI or API is accessible without authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "misconfiguration", "info-disclosure", "light"}
)
