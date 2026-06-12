package reverse_proxy_path_confusion

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "reverse-proxy-path-confusion"
	ModuleName  = "Reverse Proxy Path Confusion"
	ModuleShort = "Reaches restricted backend endpoints via proxy-vs-backend path-parsing disagreement"
)

var (
	ModuleDesc = `**What it means:** A reverse proxy and its backend disagree about which path a request names, so an access-control rule enforced at the proxy can be sidestepped. A specially shaped path that the proxy reads as harmless is normalized by the backend back into a restricted admin endpoint and served. This module confirmed that a sensitive endpoint blocked when requested directly (such as Tomcat Manager, Spring Boot Actuator, Apache mod_status, nginx stub_status, or Prometheus metrics) became reachable through a path-confusion trick.

**How it's exploited:** An attacker wraps the blocked path in a confusion shell (encoded fragment truncation like /%23/.., path-parameter traversal like /..; or /.;, or encoded-slash traversal) to slip past the proxy ACL and reach the backend. The exposed endpoint can leak configuration, environment variables, credentials, and internal metrics, or, for Tomcat Manager, allow application deployment leading to remote code execution.

**Fix:** Enforce access control on the normalized path at the backend itself, and configure the proxy to reject or canonicalize ambiguous path encodings before routing.`

	ModuleConfirmation = "Confirmed when a path-confusion shell reaches a restricted backend endpoint (matching its content fingerprint) that is blocked when requested directly, surviving a decoy-target negative, multi-round replay, and an introduced-content differential"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"proxy", "access-control", "heavy"}
)
