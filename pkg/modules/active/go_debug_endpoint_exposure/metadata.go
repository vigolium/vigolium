package go_debug_endpoint_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "go-debug-endpoint-exposure"
	ModuleName  = "Go Debug Endpoint Exposure"
	ModuleShort = "Detects exposed Go net/http/pprof and expvar debug endpoints"
)

var (
	ModuleDesc = `**What it means:** A Go application serves its net/http/pprof profiling handlers or the expvar /debug/vars endpoint without authentication. These operator-only interfaces disclose runtime internals: the process command line (including flag-passed secrets), heap profiles, goroutine stack dumps, and memory statistics.

**How it's exploited:** An attacker reads /debug/pprof/cmdline for flag-passed credentials, pulls /debug/pprof/heap to recover in-memory secrets, and repeatedly hits /debug/pprof/profile to run 30-second CPU profiles as a denial-of-service primitive.

**Fix:** Never mount net/http/pprof or expvar on a public listener; bind them to localhost or an authenticated admin interface, or gate them behind network controls.`

	ModuleConfirmation = "Confirmed when a pprof or expvar path returns its handler-specific structural output (heap/MemStats markers, the goroutine-profile header, the expvar cmdline+memstats JSON, etc.), the response is not the host's wildcard/soft-404 shell, a guaranteed-nonexistent sibling under the same directory does not return the same content, and the markers reproduce on a second fetch"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"golang", "pprof", "expvar", "debug", "info-disclosure", "misconfiguration", "light"}
)
