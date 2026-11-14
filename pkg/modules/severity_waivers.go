package modules

// The severity rule: a Tentative finding is an unproven oracle and files at
// Suspect or below ("Potential …"), never Low-and-up. The registry contract
// test enforces it on module metadata and the executor clamps it at emit time
// (Metadata["claimed_severity"] keeps what the module asked for).
//
// TentativeSeverityWaivers lists the modules allowed to file a Tentative
// finding above Suspect, each with the reason its Tentative tier still rests on
// a proof. Keep it short: a waiver is a claim that the oracle is a proof and
// only the exploitation step is unconfirmed.
var TentativeSeverityWaivers = map[string]string{
	"xss-light-url-params":      xssReflectionOnlyWaiver,
	"xss-light-path":            xssReflectionOnlyWaiver,
	"xss-light-param-discovery": xssReflectionOnlyWaiver,
	"xss-light-encoded":         xssReflectionOnlyWaiver,
	"xss-light-body-params":     xssReflectionOnlyWaiver,
}

const xssReflectionOnlyWaiver = "reflection-only tier is Low/Tentative: an executable payload was proven to survive " +
	"unescaped in the response (HTTP breakout observed); only browser execution is unconfirmed"

// TentativeSeverityWaived reports whether moduleID may file a Tentative finding
// above Suspect.
func TentativeSeverityWaived(moduleID string) bool {
	_, ok := TentativeSeverityWaivers[moduleID]
	return ok
}
