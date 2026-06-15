package ssrf_protocol_smuggling

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-protocol-smuggling"
	ModuleName  = "SSRF Protocol Smuggling (CRLF in URL)"
	ModuleShort = "Detects SSRF sinks that fetch CRLF-laden URLs enabling cross-protocol smuggling via OAST"
)

var (
	ModuleDesc = `**What it means:** A URL-accepting parameter drives a server-side fetch that follows a URL with embedded CR-LF sequences. This Server-Side Request Forgery (SSRF) sink can smuggle a second protocol to internal services it should never reach.

**How it's exploited:** Confirmed by injecting URLs at an out-of-band (OAST) host whose path carried CR-LF plus Redis, SMTP, or gopher commands; the server connected back. An attacker swaps the host for an internal address to issue back-end commands - cache poisoning, queue/mail injection.

**Fix:** Reject CR, LF, and non-HTTP schemes in fetched URLs, allowlist hosts and protocols, and pin the target.`

	ModuleConfirmation = "Confirmed when the target makes an outbound request (OAST callback) to a URL carrying embedded CR-LF and cross-protocol commands; smuggling of the embedded protocol requires raw-capture OAST to fully verify"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "heavy"}
)
