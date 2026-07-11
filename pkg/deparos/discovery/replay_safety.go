package discovery

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
)

// ReplaySafety is the method-level safety ladder for JS-extracted request replay.
// It is orthogonal to the confidence-based ReplayMode (exact/conservative/off):
// ReplayMode decides HOW SURE we must be that a recovered request is real, while
// ReplaySafety decides WHICH recovered requests are safe to actually send during
// a discovery-only run. A request recovered from a bundle is high-confidence yet
// may be destructive (a DELETE /account, a GraphQL mutation, a form submission),
// and confidence is not execution safety. Requests a policy forbids are still
// retained in the template registry (available to controlled consumers via
// All()); they are simply not auto-replayed.
type ReplaySafety int

const (
	// ReplaySafetyMetadataOnly persists templates but sends nothing.
	ReplaySafetyMetadataOnly ReplaySafety = iota
	// ReplaySafetyReadOnly permits GET/HEAD/OPTIONS and GraphQL queries.
	ReplaySafetyReadOnly
	// ReplaySafetyBaseline additionally permits the idempotent writes PUT/DELETE
	// (repeatable per RFC 7231 §4.2.2), but not POST/PATCH or GraphQL mutations.
	ReplaySafetyBaseline
	// ReplaySafetyStateChanging permits every method plus GraphQL mutations.
	// Opt-in only.
	ReplaySafetyStateChanging
)

// ParseReplaySafety maps a config string to a policy. The default — and any
// unknown or empty value — is the safe ReadOnly policy, so a misconfiguration
// fails closed rather than firing state-changing traffic.
func ParseReplaySafety(name string) ReplaySafety {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "metadata-only", "metadata":
		return ReplaySafetyMetadataOnly
	case "safe-baseline", "baseline":
		return ReplaySafetyBaseline
	case "state-changing", "state":
		return ReplaySafetyStateChanging
	default: // "read-only" and unknown/empty
		return ReplaySafetyReadOnly
	}
}

// AllowsFact reports whether the policy permits actually sending the given
// recovered request during discovery.
func (p ReplaySafety) AllowsFact(fact *jstangle.HTTPRequestFact) bool {
	if fact == nil || p == ReplaySafetyMetadataOnly {
		return false
	}
	method := strings.ToUpper(strings.TrimSpace(fact.Method.Rendered))
	if method == "" {
		method = "GET"
	}
	// Protocol upgrades (WS/SSE) are never replayed as ordinary HTTP — defer to the
	// single source of truth the variant generator also honors.
	if !isReplayableMethod(method) {
		return false
	}
	// GraphQL tunnels its verb through a POST body: a query is read-only, while a
	// mutation (or an unlabeled/subscription operation, treated conservatively) is
	// state-changing regardless of the transport POST.
	if strings.EqualFold(fact.Client, "graphql") {
		if strings.EqualFold(fact.OperationType, "query") {
			return p >= ReplaySafetyReadOnly
		}
		return p >= ReplaySafetyStateChanging
	}
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return p >= ReplaySafetyReadOnly
	case "PUT", "DELETE":
		return p >= ReplaySafetyBaseline
	default: // POST, PATCH, and any other write verb
		return p >= ReplaySafetyStateChanging
	}
}
