package spring_data_rest_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-data-rest-exposure"
	ModuleName  = "Spring Data REST Exposure"
	ModuleShort = "Detects auto-exposed Spring Data REST repository endpoints with HAL/HATEOAS discovery"
)

var (
	ModuleDesc = `## Description
Probes for Spring Data REST auto-exposed repository endpoints. Spring Data REST
automatically creates RESTful endpoints for JPA repositories, which may expose
entities without proper authorization. The module detects HAL-style API roots
and ALPS profile endpoints that reveal the full data model.

## Notes
- Runs once per host
- Checks for HAL/HATEOAS discovery responses
- Detects ALPS profile metadata endpoints
- Validates using Spring Data REST JSON markers
- Fingerprints 404 responses to reduce false positives

## References
- https://docs.spring.io/spring-data/rest/docs/current/reference/html/
- https://spring.io/projects/spring-data-rest`

	ModuleConfirmation = "Confirmed when HAL-style API root or ALPS profile endpoint returns Spring Data REST repository links"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"spring", "java", "api", "info-disclosure", "light"}
)
