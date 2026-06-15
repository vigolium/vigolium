package wp_xmlrpc

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-xmlrpc"
	ModuleName  = "WordPress XML-RPC Abuse"
	ModuleShort = "Detects enabled WordPress XML-RPC with multicall brute-force and pingback abuse potential"
)

var (
	ModuleDesc = `**What it means:** The site exposes an enabled WordPress XML-RPC endpoint at /xmlrpc.php that answers method-listing requests and may advertise the dangerous system.multicall and pingback.ping methods - a well-known abuse surface most modern sites do not need.

**How it's exploited:** With system.multicall an attacker batches hundreds of login attempts into one request, defeating rate limits to brute-force credentials at scale. With pingback.ping they coerce the server into outbound requests to attacker-chosen URLs, enabling SSRF-style probing and reflected DDoS amplification.

**Fix:** Disable XML-RPC if unused, or block /xmlrpc.php at the web server or WAF, and at minimum disable pingbacks and system.multicall.`

	ModuleConfirmation = "Confirmed when /xmlrpc.php returns a valid methodResponse containing method names"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"wordpress", "cms", "php", "misconfiguration", "light"}
)
