package dashboard_exposure

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "dashboard-exposure"
	ModuleName  = "Exposed Third-Party Dashboard"
	ModuleShort = "Probes for exposed third-party dashboards/consoles (Grafana, Airflow, GitLab, Jenkins, Ollama, ...) and unauthenticated version/config/data leaks"

	ModuleDesc = `**What it means:** A known third-party dashboard or self-hosted app - Grafana, Airflow, GitLab, Jenkins, Vault, an LLM API - is reachable on this host. When a health/version/config endpoint returns internal data without authentication it is a High-severity leak; otherwise the console is attack surface.

**How it's exploited:** Attackers match the confirmed product and version against default-credential lists and known CVEs, then pivot through unauthenticated endpoints. The module also tries the product's documented default credentials; a working pair is Critical.

**Fix:** Put the console behind authentication, an allow-list, or a VPN; restrict unauthenticated endpoints; remove default credentials; patch.`

	ModuleConfirmation = "A request to a product-specific endpoint returned a response matching that product's fingerprint; UnauthLeak endpoints additionally disclosed internal data without authentication; default-credentials findings additionally authenticated with a documented default pair (negative-control gated)."
)

var (
	ModuleSeverity   = severity.Medium
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"dashboard", "exposure", "discovery", "info-leak", "default-login", "light"}
)
