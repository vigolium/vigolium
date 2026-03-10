package proxy

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "proxy"
	ModuleName  = "Proxy"
	ModuleShort = "Replay all requests through configured proxy for inspection"
)

var (
	ModuleDesc = `## Description
Forwards all scanned traffic through a configured HTTP proxy for manual inspection
and integration with external tools like Burp Suite or OWASP ZAP.

## Notes
- Does not detect vulnerabilities; used for traffic inspection
- Replays requests through the configured proxy address
- Useful for combining automated scanning with manual review`

	ModuleConfirmation = ""
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"utility", "light"}
)
