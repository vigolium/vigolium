package unauth_service_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "unauth-service-exposure"
	ModuleName  = "Unauthenticated Infrastructure Service Exposure"
	ModuleShort = "Detects unauthenticated Docker/Kubernetes/datastore APIs exposed over HTTP"
)

var (
	ModuleDesc = `**What it means:** A credential-free client reached a native Docker, Kubernetes, or datastore API. Banners are observations, administrative metadata is a candidate, and anonymously returned workload or document data is a finding.

**How it's exploited:** An attacker queries exposed management endpoints for configuration or private data. Write access, command execution, and host compromise are not inferred without direct evidence.

**Fix:** Require authentication or mTLS, bind management services to private interfaces, and firewall their ports.`

	ModuleConfirmation = "Classified by reproduced credential-free evidence: native service identity (observation), administrative/resource metadata (candidate), or actual workload/document content (finding)"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"exposure", "infrastructure", "misconfiguration", "moderate"}
)
