package ssrf_protocol_smuggling

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssrf-protocol-smuggling"
	ModuleName  = "SSRF Protocol Smuggling (CRLF in URL)"
	ModuleShort = "Detects SSRF sinks that fetch CRLF-laden URLs enabling cross-protocol smuggling via OAST"
)

var (
	ModuleDesc = `**What it means:** A URL-accepting parameter drives a server-side fetch that follows a supplied URL containing embedded CR-LF sequences and cross-protocol commands. This is a Server-Side Request Forgery (SSRF) sink that can smuggle a second protocol over the fetcher's outbound connection, letting an attacker make the server talk to internal services it should never reach.

**How it's exploited:** The scanner injected URLs pointing at an out-of-band (OAST) host whose path carried CR-LF plus Redis, SMTP, Memcached, gopher, or unicode-CRLF protocol commands, and the server connected back, proving it fetched the CRLF-laden URL. A real attacker swaps the OAST host for an internal address to issue commands to back-end services (cache poisoning, queue/mail injection, internal data access). Note: the OAST callback confirms the fetch reached the attacker host; fully verifying the smuggled commands were honored needs a raw-capture listener.

**Fix:** Reject CR, LF, and non-HTTP schemes in fetched URLs, enforce a strict allowlist of hosts and protocols, and resolve and pin the target before connecting.`

	ModuleConfirmation = "Confirmed when the target makes an outbound request (OAST callback) to a URL carrying embedded CR-LF and cross-protocol commands; smuggling of the embedded protocol requires raw-capture OAST to fully verify"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "heavy"}
)
