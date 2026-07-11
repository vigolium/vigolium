package tomcat_manager_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "tomcat-manager-exposure"
	ModuleName  = "Tomcat Manager Exposure"
	ModuleShort = "Detects exposed Apache Tomcat Manager and Host Manager interfaces"
)

var (
	ModuleDesc = `**What it means:** Credential-free probes identified a Tomcat administrative or default surface using grouped framework markers and path controls. An authentication challenge or docs/examples page is an observation; an open manager UI is a candidate.

**How it's exploited:** Separate weak credentials may let attackers deploy a WAR. A direct 401 proves access was denied, while a successful path-normalization probe demonstrates an actual proxy ACL bypass and is promoted to a finding.

**Fix:** Remove or restrict these apps, and require strong credentials over TLS plus network controls for any admin interface that must remain.`

	ModuleConfirmation = "Observation for Tomcat auth challenge/default apps; candidate for anonymous manager controls; finding only when a blocked direct path is reached through a normalization bypass"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"tomcat", "java", "misconfiguration", "authentication", "light"}
)
