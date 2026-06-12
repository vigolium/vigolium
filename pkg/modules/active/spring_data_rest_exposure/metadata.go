package spring_data_rest_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "spring-data-rest-exposure"
	ModuleName  = "Spring Data REST Exposure"
	ModuleShort = "Detects auto-exposed Spring Data REST repository endpoints with HAL/HATEOAS discovery"
)

var (
	ModuleDesc = `**What it means:** Spring Data REST is auto-exposing JPA repository endpoints over HTTP. The scanner confirmed a reachable HAL/HATEOAS API root (/api) or an ALPS profile endpoint (/api/profile or /profile) that returns Spring Data REST discovery links and data-model descriptors. These endpoints publish the application's entity catalog, relationships, and per-entity CRUD URLs, and are frequently exposed without proper authorization.

**How it's exploited:** An attacker browses the HAL _links and ALPS profile to map every persisted entity and its self/collection URLs, then follows those links to read, page through, and (if write methods are not locked down) create, update, or delete records via the auto-generated REST API. The profile metadata also reveals field names and relations, accelerating targeted data exfiltration or tampering.

**Fix:** Restrict Spring Data REST repositories with authorization, disable auto-exposure for sensitive entities (@RepositoryRestResource(exported = false) or detection strategy), and require authentication on /api and profile endpoints.`

	ModuleConfirmation = "Confirmed when HAL-style API root or ALPS profile endpoint returns Spring Data REST repository links"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"spring", "java", "api", "info-disclosure", "light"}
)
