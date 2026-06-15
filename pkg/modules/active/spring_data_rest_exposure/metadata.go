package spring_data_rest_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-data-rest-exposure"
	ModuleName  = "Spring Data REST Exposure"
	ModuleShort = "Detects auto-exposed Spring Data REST repository endpoints with HAL/HATEOAS discovery"
)

var (
	ModuleDesc = `**What it means:** Spring Data REST is auto-exposing JPA repository endpoints over HTTP. The scanner confirmed a reachable HAL/HATEOAS API root (/api) or ALPS profile endpoint (/api/profile) returning discovery links that publish the entity catalog and per-entity CRUD URLs.

**How it's exploited:** An attacker reads the HAL _links and ALPS profile to map every persisted entity, then follows them to read, page through, and (if write methods are not locked down) create, update, or delete records.

**Fix:** Restrict repositories with authorization, disable auto-exposure for sensitive entities (@RepositoryRestResource(exported = false)), and require authentication on /api and profile endpoints.`

	ModuleConfirmation = "Confirmed when HAL-style API root or ALPS profile endpoint returns Spring Data REST repository links"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "api", "info-disclosure", "light"}
)
