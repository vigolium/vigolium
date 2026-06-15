package reverse_proxy_path_confusion

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "reverse-proxy-path-confusion"
	ModuleName  = "Reverse Proxy Path Confusion"
	ModuleShort = "Reaches restricted backend endpoints via proxy-vs-backend path-parsing disagreement"
)

var (
	ModuleDesc = `**What it means:** A reverse proxy and its backend disagree about which path a request names, so a proxy-enforced access-control rule is sidestepped. The scanner confirmed an endpoint blocked directly (Tomcat Manager, Spring Actuator, Prometheus) became reachable via path confusion.

**How it's exploited:** An attacker wraps the blocked path in a confusion shell (fragment truncation, path-parameter traversal like /..;, or encoded-slash) to slip past the proxy ACL, leaking config, credentials, and metrics, or via Tomcat Manager allowing deployment that leads to remote code execution.

**Fix:** Enforce access control on the normalized path at the backend, and reject ambiguous path encodings.`

	ModuleConfirmation = "Confirmed when a path-confusion shell reaches a restricted backend endpoint (matching its content fingerprint) that is blocked when requested directly, surviving a decoy-target negative, multi-round replay, and an introduced-content differential"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"proxy", "access-control", "heavy"}
)
