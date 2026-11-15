package cli

import (
	"os"
	"strings"
	"sync/atomic"

	"github.com/vigolium/vigolium/internal/runner"
)

// scanStopBy names who stopped this invocation's scan through a stop request
// ("" when nobody did); withFailOnGate reports it as the interrupt's cause.
var scanStopBy atomic.Value

// noteScanStopRequest records (or, with "", clears) the stop request that
// ended this invocation's scan.
func noteScanStopRequest(by string) { scanStopBy.Store(strings.TrimSpace(by)) }

// scanStopRequestedBy names who stopped this invocation's scan, "" for nobody.
func scanStopRequestedBy() string {
	v, _ := scanStopBy.Load().(string)
	return v
}

// interruptSelfOnStopRequest ends a direct scan-url / scan-request pass on a
// stop request by interrupting this process, exactly as Ctrl-C would: the
// invocation's one signal context stops the batch and every row is finalized
// as interrupted. Signalling our own pid is safe where signalling a recorded
// one is not. Where the platform cannot deliver os.Interrupt to itself the
// request is still recorded, and the scan runs to its end.
func interruptSelfOnStopRequest(req runner.StopRequest) {
	by := req.By
	if by == "" {
		by = "unknown"
	}
	noteScanStopRequest(by)
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		_ = p.Signal(os.Interrupt)
	}
}
