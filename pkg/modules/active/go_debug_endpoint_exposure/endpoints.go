package go_debug_endpoint_exposure

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

// pprofIndexPath is the conventional net/http/pprof mount prefix. Endpoint paths
// below are suffixes appended to each candidate base path, so a pprof mux mounted
// under a context path (/api/debug/pprof/...) is probed alongside one at the web
// root.
const pprofIndexPath = "/debug/pprof/"

// debugEndpoint describes one Go debug handler to probe. Each carries a confirm
// predicate that recognizes the handler's *own* structural output — never a
// single generic word — so a catch-all/SPA shell that merely contains a token
// like "heap" or "goroutine" is not mistaken for the real endpoint. Every
// endpoint is reported at Medium severity (info-disclosure / debug-surface
// exposure), regardless of the individual handler's blast radius.
type debugEndpoint struct {
	id       string // short slug for finding evidence
	path     string // suffix appended to a candidate base path (may carry ?debug=1)
	name     string
	sev      severity.Severity
	conf     severity.Confidence
	ctMatch  string // required Content-Type substring, lowercased ("" = any)
	deepOnly bool   // probed only under --intensity=deep
	confirm  func(body string) bool
	desc     string
}

func containsAll(body string, subs ...string) bool {
	for _, s := range subs {
		if !strings.Contains(body, s) {
			return false
		}
	}
	return true
}

func containsAny(body string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(body, s) {
			return true
		}
	}
	return false
}

// cmdlinePathRe matches a leading executable path as emitted by os.Args[0] in the
// /debug/pprof/cmdline response: an absolute or ./../ relative unix path, or a
// Windows drive path. It corroborates the NUL-separated-args signal so a generic
// text/plain body is not mistaken for the process command line.
var cmdlinePathRe = regexp.MustCompile(`^(?:\.{0,2}/|[A-Za-z]:\\)\S`)

// cmdlineConfirm recognizes the /debug/pprof/cmdline body: os.Args joined by NUL
// bytes. A multi-arg process carries a NUL separator; a single-arg process is its
// executable path. Either way the body is structured, not free-form prose, and
// never HTML. The paired soft-404/sibling baselines (a real pprof mux 404s an
// unknown sub-path) keep this Firm despite the otherwise weak content shape.
func cmdlineConfirm(b string) bool {
	t := strings.TrimSpace(b)
	if t == "" {
		return false
	}
	lower := strings.ToLower(t)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
		return false
	}
	return strings.Contains(b, "\x00") || cmdlinePathRe.MatchString(t)
}

// heapProfileConfirm recognizes the debug=1 text output shared by the /heap and
// /allocs handlers (both are views of the same runtime heap profile): the
// "heap profile:" header line plus the trailing "# runtime.MemStats" block.
func heapProfileConfirm(b string) bool {
	return containsAll(b, "heap profile:", "# runtime.MemStats")
}

// pprofEndpoints returns the actively-probed pprof handlers. The time-based
// /profile and /trace handlers are deliberately absent here — see
// inferredFromIndex; we never request them because doing so loads the target
// (a 30-second CPU profile is a free DoS).
func pprofEndpoints() []debugEndpoint {
	return []debugEndpoint{
		{
			id:      "index",
			path:    "/debug/pprof/",
			name:    "Go pprof Debug Index Exposed",
			sev:     severity.Medium,
			conf:    severity.Certain,
			ctMatch: "text/html",
			// Two strong, co-occurring anchors from the pprof index template. The
			// bare word "heap"/"goroutine" appears anywhere; "Types of profiles
			// available" + "full goroutine stack dump" together are unique to it.
			confirm: func(b string) bool {
				return strings.Contains(b, "Types of profiles available") &&
					containsAny(b, "full goroutine stack dump", "Profile Descriptions")
			},
			desc: "The net/http/pprof debug index is reachable without authentication. It lists every runtime profile and links the cmdline, heap, goroutine, profile, and trace handlers — the application's full internal debugging surface.",
		},
		{
			id:      "cmdline",
			path:    "/debug/pprof/cmdline",
			name:    "Go pprof Command Line Exposed",
			sev:     severity.Medium,
			conf:    severity.Firm,
			ctMatch: "text/plain",
			confirm: cmdlineConfirm,
			desc:    "The /debug/pprof/cmdline handler returns the server process command line and its arguments. Secrets passed as flags — database DSNs, API keys, tokens — are disclosed verbatim.",
		},
		{
			id:      "heap",
			path:    "/debug/pprof/heap?debug=1",
			name:    "Go pprof Heap Profile Exposed",
			sev:     severity.Medium,
			conf:    severity.Certain,
			ctMatch: "text/plain",
			confirm: heapProfileConfirm,
			desc:    "The /debug/pprof/heap handler returns a live heap memory profile and full runtime memory statistics. Allocation sites and retained-object data can expose in-memory secrets, tokens, and request contents.",
		},
		{
			id:       "allocs",
			path:     "/debug/pprof/allocs?debug=1",
			name:     "Go pprof Allocations Profile Exposed",
			sev:      severity.Medium,
			conf:     severity.Certain,
			ctMatch:  "text/plain",
			deepOnly: true,
			confirm:  heapProfileConfirm,
			desc:     "The /debug/pprof/allocs handler returns the cumulative allocation profile, exposing memory-allocation sites and runtime memory statistics.",
		},
		{
			id:      "goroutine",
			path:    "/debug/pprof/goroutine?debug=1",
			name:    "Go pprof Goroutine Dump Exposed",
			sev:     severity.Medium,
			conf:    severity.Certain,
			ctMatch: "text/plain",
			confirm: func(b string) bool { return strings.Contains(b, "goroutine profile: total") },
			desc:    "The /debug/pprof/goroutine handler returns a full goroutine stack dump, revealing internal code paths, in-flight request handlers, and sometimes argument values.",
		},
		{
			id:       "block",
			path:     "/debug/pprof/block?debug=1",
			name:     "Go pprof Block Profile Exposed",
			sev:      severity.Medium,
			conf:     severity.Certain,
			ctMatch:  "text/plain",
			deepOnly: true,
			confirm:  func(b string) bool { return containsAll(b, "--- contention:", "cycles/second=") },
			desc:     "The /debug/pprof/block handler returns the blocking profile, disclosing synchronization hot spots and internal call stacks.",
		},
		{
			id:       "mutex",
			path:     "/debug/pprof/mutex?debug=1",
			name:     "Go pprof Mutex Profile Exposed",
			sev:      severity.Medium,
			conf:     severity.Certain,
			ctMatch:  "text/plain",
			deepOnly: true,
			confirm:  func(b string) bool { return containsAll(b, "--- mutex:", "cycles/second=") },
			desc:     "The /debug/pprof/mutex handler returns the mutex contention profile, disclosing lock-contention call stacks.",
		},
		{
			id:       "threadcreate",
			path:     "/debug/pprof/threadcreate?debug=1",
			name:     "Go pprof Threadcreate Profile Exposed",
			sev:      severity.Medium,
			conf:     severity.Certain,
			ctMatch:  "text/plain",
			deepOnly: true,
			confirm:  func(b string) bool { return strings.Contains(b, "threadcreate profile: total") },
			desc:     "The /debug/pprof/threadcreate handler returns the OS-thread creation profile and its call stacks.",
		},
		{
			id:       "symbol",
			path:     "/debug/pprof/symbol",
			name:     "Go pprof Symbol Endpoint Exposed",
			sev:      severity.Medium,
			conf:     severity.Certain,
			ctMatch:  "text/plain",
			deepOnly: true,
			confirm:  func(b string) bool { return strings.Contains(b, "num_symbols:") },
			desc:     "The /debug/pprof/symbol handler resolves program counters to function names, confirming the pprof debugging surface is mounted and aiding binary reverse engineering.",
		},
	}
}

// expvarEndpoint is the standard-library expvar handler, mounted at /debug/vars
// independently of the pprof mux (importing expvar auto-registers it). It always
// publishes the cmdline and memstats variables plus any application-defined ones.
func expvarEndpoint() debugEndpoint {
	return debugEndpoint{
		id:      "expvar",
		path:    "/debug/vars",
		name:    "Go expvar Debug Variables Exposed",
		sev:     severity.Medium,
		conf:    severity.Certain,
		ctMatch: "application/json",
		confirm: func(b string) bool {
			return containsAll(b, `"cmdline"`, `"memstats"`) &&
				containsAny(b, `"Alloc"`, `"HeapAlloc"`, `"NumGC"`, `"PauseNs"`, `"BySize"`)
		},
		desc: "The expvar /debug/vars endpoint is reachable without authentication. It publishes the process command line, full runtime memory statistics, and any application-defined variables — which sometimes include configuration values or secrets.",
	}
}

// inferredFromIndex are the time-based pprof handlers we deliberately never
// request: /profile runs a 30-second CPU profile and /trace an execution trace,
// both of which load the target (a free denial-of-service). When the index
// confirms the pprof mux is mounted, these handlers are necessarily registered
// too — net/http/pprof installs them in the same init — so we report them from
// the index evidence without invoking them. Confidence is Firm (inferred, not
// directly fetched).
func inferredFromIndex() []debugEndpoint {
	return []debugEndpoint{
		{
			id:   "profile",
			path: "/debug/pprof/profile",
			name: "Go pprof CPU Profile Endpoint Exposed",
			sev:  severity.Medium,
			conf: severity.Firm,
			desc: "The /debug/pprof/profile handler runs a 30-second CPU profile on demand; repeated requests are a low-effort denial-of-service primitive. Exposure was confirmed from the pprof index listing — the scanner does not invoke this handler, to avoid loading the target.",
		},
		{
			id:   "trace",
			path: "/debug/pprof/trace",
			name: "Go pprof Execution Trace Endpoint Exposed",
			sev:  severity.Medium,
			conf: severity.Firm,
			desc: "The /debug/pprof/trace handler emits a runtime execution trace, loading the target while it records. Exposure was confirmed from the pprof index listing — the scanner does not invoke this handler, to avoid loading the target.",
		},
	}
}
