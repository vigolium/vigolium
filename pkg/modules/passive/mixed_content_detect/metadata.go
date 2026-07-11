package mixed_content_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mixed-content-detect"
	ModuleName  = "Mixed Content Detect"
	ModuleShort = "Classifies insecure subresources and HTTP form submissions on HTTPS pages"
)

var (
	ModuleDesc = `**What it means:** An HTTPS page loads an HTTP subresource or submits a form over HTTP. Ordinary HTTP hyperlinks are excluded. The reference is a deployment observation, not proof that current browsers executed it or sent sensitive data.

**How it's exploited:** A network attacker may alter an insecure resource or intercept downgraded form data when the browser permits the request.

**Fix:** Serve all subresources and form actions over HTTPS and enable Content-Security-Policy upgrade-insecure-requests.`

	ModuleConfirmation = "Candidate or observation when an HTTPS document contains a real HTTP subresource load or HTTP form action; ordinary hyperlinks are excluded"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"misconfiguration", "cryptography", "light"}
)
