package egress

import (
	"slices"

	"github.com/vigolium/vigolium/pkg/scanevents"
)

// inventoryEntry is one outbound path of a native scan. phases names the scan
// phases that use it; an empty list means "whenever the scan reaches a target".
type inventoryEntry struct {
	path   string
	reason string // exempt paths only
	phases []string
	// budget says how an EXEMPT path meets the request budget: counted (its
	// requests are tracked and the soft watcher stops the scan once the total
	// passes --max-requests), notTarget (it never reaches the target, so the
	// budget does not apply), or uncounted (zero value: the budget cannot see
	// it). Gated paths are always held to the budget exactly.
	budget exemptBudget
}

// exemptBudget is how an exempt path meets the request budget.
type exemptBudget int

const (
	budgetUncounted exemptBudget = iota
	budgetCounted
	budgetNotTarget
)

// Request-cap enforcement levels, per phase, as scan.started reports them.
const (
	// EnforcementHard: every target request the phase sends is admitted by the
	// gate, so --max-requests and --max-requests-per-host hold exactly.
	EnforcementHard = "hard"
	// EnforcementSoft: some of the phase's traffic bypasses the gate but is
	// counted; the scan is stopped within one watcher interval of the total
	// passing --max-requests (per-host limits do not apply to it).
	EnforcementSoft = "soft"
	// EnforcementPartial: some of the phase's traffic is neither gated nor
	// counted, and no request cap sees it.
	EnforcementPartial = "partial"
)

// gatedPaths go through a Gate: global rate token, host slot, quarantine,
// wire-attempt count.
var gatedPaths = []inventoryEntry{
	// Modules, executor fetches, seed, heuristics, probe, JS extensions — every
	// pkg/http.Requester send, one token per wire attempt (retries and redirect
	// hops included).
	{path: "http-requester"},
	// The deparos engine: its own token bucket (discovery.rate_limit, global
	// across concurrent discovery targets) plus the shared host slots and
	// quarantine.
	{path: "discovery", phases: []string{"discovery"}},
	// Session login flows, on the priority lane.
	{path: "login"},
	// The HTTP confirm step; the TCP pre-filter dials are counted, not paced.
	{path: "port-sweep", phases: []string{"port-sweep"}},
	// tls_cert_recon and tls_protocol_cipher_audit: one gated attempt per
	// handshake.
	{path: "tls-modules", phases: []string{"dynamic-assessment"}},
}

// exemptPaths bypass the gate. Listed so a consumer of scan.started can see
// exactly which traffic --rate-limit and max-per-host do not govern.
var exemptPaths = []inventoryEntry{
	{path: "known-issue-scan", reason: "own HTTP stack (nuclei): its own rate and concurrency apply, not the shared host slots or quarantine; requests are counted, not gated",
		phases: []string{"known-issue-scan"}, budget: budgetCounted},
	{path: "spidering", reason: "browser (Chrome): requests are counted, not gated",
		phases: []string{"spidering", "targeted-respider"}, budget: budgetCounted},
	{path: "browser-confirmations", reason: "browser (Chrome) used by confirmation modules: low volume, not gated or counted",
		phases: []string{"dynamic-assessment"}},
	{path: "http_request_smuggling.cl0", reason: "own dialer (raw socket): bypasses --proxy, the rate limit and host slots",
		phases: []string{"dynamic-assessment"}},
	{path: "probe-tls", reason: "own dialer: one TLS handshake per host:port for certificate metadata, cached",
		phases: []string{"probe", "fingerprint"}},
	{path: "scheme-detection", reason: "bare TCP connect to choose http or https for a schemeless target",
		phases: []string{"probe", "fingerprint"}},
	{path: "external-harvest", reason: "not target traffic: archive services only",
		phases: []string{"external-harvest"}, budget: budgetNotTarget},
	{path: "oast", reason: "not target traffic: the out-of-band interaction server", budget: budgetNotTarget},
	{path: "npm-registry", reason: "not target traffic: dependency_confusion registry lookups",
		phases: []string{"dynamic-assessment"}, budget: budgetNotTarget},
}

// RequestCapEnforcement reports, for each of the given phases (canonical ids),
// how strictly --max-requests / --max-requests-per-host hold for its traffic:
// EnforcementHard, EnforcementSoft or EnforcementPartial. It is derived from the
// exempt-path table above, so a new bypass is reflected without a second list.
func RequestCapEnforcement(phases []string) map[string]string {
	out := make(map[string]string, len(phases))
	for _, phase := range phases {
		level := EnforcementHard
		for _, e := range exemptPaths {
			if !slices.Contains(e.phases, phase) {
				continue
			}
			switch e.budget {
			case budgetUncounted:
				level = EnforcementPartial
			case budgetCounted:
				if level == EnforcementHard {
					level = EnforcementSoft
				}
			}
		}
		out[phase] = level
	}
	return out
}

// Inventory returns the scan.started egress table for a scan that runs the
// given phases (canonical phase ids). A nil list includes every path.
func Inventory(phases []string) *scanevents.Egress {
	var planned map[string]bool
	if phases != nil {
		planned = make(map[string]bool, len(phases))
		for _, p := range phases {
			planned[p] = true
		}
	}
	applies := func(e inventoryEntry) bool {
		if planned == nil || len(e.phases) == 0 {
			return true
		}
		for _, p := range e.phases {
			if planned[p] {
				return true
			}
		}
		return false
	}
	out := &scanevents.Egress{Gated: []string{}, Exempt: []scanevents.EgressExemption{}}
	for _, e := range gatedPaths {
		if applies(e) {
			out.Gated = append(out.Gated, e.path)
		}
	}
	for _, e := range exemptPaths {
		if applies(e) {
			out.Exempt = append(out.Exempt, scanevents.EgressExemption{Path: e.path, Reason: e.reason})
		}
	}
	return out
}
