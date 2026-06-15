package dashboard_fingerprint

import (
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	ModuleID    = "dashboard-fingerprint"
	ModuleName  = "Third-Party Dashboard Detected"
	ModuleShort = "Recognises self-hosted dashboards, admin consoles and developer tools (Grafana, Airflow, GitLab, Jenkins, Ollama, ...) in observed responses"

	ModuleDesc = `**What it means:** The response carries the fingerprint of a known dashboard or admin console - Grafana, Apache Airflow, GitLab, Jenkins, Kibana, HashiCorp Vault, or an OpenAI-compatible LLM API. This is attack-surface inventory so product-specific checks and CVE matching can follow. Informational recon.

**How it's exploited:** Attackers prioritise by the software a host runs. Knowing it serves Grafana or Ollama lets them pull matching default-credential lists and version-specific CVEs. The active companion (dashboard-exposure) escalates when the product leaks data unauthenticated.

**Fix:** Put admin/console products on internet-facing hosts behind authentication or a VPN; keep them patched and remove default credentials.`

	ModuleConfirmation = "A response matched a catalogued product fingerprint (unique header, body markers, or a distinctive cookie plus a name reference)."
)

var (
	ModuleSeverity   = severity.Info
	ModuleConfidence = severity.Firm
	ModuleTags       = []string{"dashboard", "fingerprint", "discovery", "info"}
)
