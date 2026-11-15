package cli

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// sendOutcomeError is the outcome of a command that sent requests by hand
// (replay, fuzz, kit param-mine), returned after its document was written.
//
// Send failures used to be reported only inside the document, with ok:true and
// exit 0, so "the target refused every request" read like a clean answer. Now:
// none failed is success; some failed is partial (exit 5); all failed is
// no_targets_reachable (exit 1).
func sendOutcomeError(what string, sent, failed int) error {
	switch {
	case failed <= 0 || sent <= 0:
		return nil
	case failed >= sent:
		return clicommon.CLIError{
			Err:  fmt.Errorf("every %s failed (%d of %d): no response was received", what, failed, sent),
			Code: apicontract.CodeNoTargetsReachable,
			Hint: "Check that the target is up and reachable from here (and --proxy, if one is set)",
		}
	default:
		return incompleteErrorf(apicontract.CodePartial, "%d of %d %s(s) failed; the result covers the rest", failed, sent, what)
	}
}
