package wp_xmlrpc

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wp-xmlrpc"
	ModuleName  = "WordPress XML-RPC Abuse"
	ModuleShort = "Detects enabled WordPress XML-RPC with multicall brute-force and pingback abuse potential"
)

var (
	ModuleDesc = `## Description
Tests whether the WordPress XML-RPC endpoint is enabled and checks for dangerous
methods: system.multicall (enables amplified brute-force attacks in a single request)
and pingback.ping (enables SSRF-like outbound requests and DDoS amplification).

## Notes
- Runs once per host
- Sends a benign system.listMethods call to confirm XML-RPC is active
- Checks for multicall and pingback methods in the response
- Does not attempt actual brute-force or pingback abuse

## References
- https://developer.wordpress.org/plugins/security/data-validation/
- https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core`

	ModuleConfirmation = "Confirmed when /xmlrpc.php returns a valid methodResponse containing method names"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"wordpress", "cms", "php", "misconfiguration", "light"}
)
