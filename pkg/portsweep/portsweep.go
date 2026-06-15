// Package portsweep provides a fast, concurrent TCP-connect + HTTP-confirm port
// sweep used during deep / --follow-subdomains scans to discover additional web
// services listening on common alternate HTTP(S) ports of an already-targeted
// host.
//
// The flow per host is: dial every configured port (cheap TCP connect, short
// timeout, bounded concurrency); for each port that accepts a connection, send a
// lightweight HTTP GET to confirm it actually speaks HTTP (so non-HTTP services
// like SSH/redis are dropped) and capture a small fingerprint. A honeypot/tarpit
// guard then discards the whole host when a high fraction of ports are open AND
// the confirmed HTTP responses look near-identical — the classic "every port
// open, same banner everywhere" signature — so we never feed a fake fleet of
// services into the scanner.
//
// The package is self-contained: it owns its own net.Dialer and http.Client
// (TLS verification disabled, redirects not followed) rather than routing through
// the vigolium request middleware, keeping the sweep fast and unit-testable.
package portsweep

import (
	"context"
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Default sweep parameters. These are the single source of truth for the
// built-in port-sweep configuration; the config layer (internal/config) builds
// its DefaultPortSweepConfig from them so the values never drift.
const (
	DefaultConcurrency   = 50   // max concurrent port probes per host
	DefaultDialTimeoutMs = 1500 // per-port TCP connect timeout, milliseconds
	DefaultHTTPTimeoutMs = 4000 // per-port HTTP confirm timeout, milliseconds
	DefaultHoneypotRatio = 0.7  // open/probed ratio at/above which a host is honeypot-suspect
)

// httpsHintPorts are ports we try over TLS first; everything else tries plain
// HTTP first. Both fall back to the other scheme on failure, so the hint only
// affects which scheme is attempted first (and thus latency), not correctness.
var httpsHintPorts = map[int]struct{}{
	8443: {},
	9443: {},
}

// DefaultPorts is the built-in list of common alternate HTTP(S) ports swept when
// no override is configured.
var DefaultPorts = []int{3000, 5000, 8000, 8008, 8080, 8081, 8082, 8083, 8088, 8888, 9000, 8443, 9443}

// Options tunes a single-host sweep. Zero-valued fields are filled with
// sensible defaults by normalize.
type Options struct {
	Ports         []int         // ports to probe; defaults to DefaultPorts
	Concurrency   int           // max concurrent port probes for this host; default 50
	DialTimeout   time.Duration // per-port TCP connect timeout; default 1.5s
	HTTPTimeout   time.Duration // per-port HTTP confirm timeout; default 4s
	HoneypotRatio float64       // open/probed ratio at/above which the host is honeypot-suspect; default 0.7, <=0 disables the ratio gate
}

func (o Options) normalize() Options {
	if len(o.Ports) == 0 {
		o.Ports = DefaultPorts
	}
	if o.Concurrency <= 0 {
		o.Concurrency = DefaultConcurrency
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeoutMs * time.Millisecond
	}
	if o.HTTPTimeout <= 0 {
		o.HTTPTimeout = DefaultHTTPTimeoutMs * time.Millisecond
	}
	if o.HoneypotRatio == 0 {
		o.HoneypotRatio = DefaultHoneypotRatio
	}
	return o
}

// PortResult describes one HTTP-confirmed open port.
type PortResult struct {
	Port   int
	Scheme string // "http" | "https"
	Status int    // HTTP status code observed
	Server string // Server response header (may be empty)

	// fp is the honeypot fingerprint: status + server + body-hash prefix.
	// Two ports that return effectively the same response share an fp.
	fp string
}

// URL renders the confirmed service as a scheme://host:port/ URL, bracketing
// bare IPv6 hosts so the result is a valid URL.
func (p PortResult) URL(host string) string {
	return fmt.Sprintf("%s://%s/", p.Scheme, net.JoinHostPort(host, strconv.Itoa(p.Port)))
}

// Result is the outcome of sweeping one host.
type Result struct {
	Host     string
	Open     []PortResult // HTTP-confirmed ports; empty when Honeypot is true
	Honeypot bool         // host looked like an all-ports-open tarpit; Open was discarded
	Probed   int          // number of ports probed
	TCPOpen  int          // number of ports that accepted a TCP connection
}

// Sweep probes host across opts.Ports and returns the confirmed web services.
// host must be a bare hostname or IP (no scheme, no port). The context bounds the
// whole sweep; a cancelled context returns whatever was confirmed so far.
func Sweep(ctx context.Context, host string, opts Options) Result {
	opts = opts.normalize()
	res := Result{Host: host, Probed: len(opts.Ports)}
	if host == "" || len(opts.Ports) == 0 {
		return res
	}

	dialer := &net.Dialer{Timeout: opts.DialTimeout}
	client := &http.Client{
		Timeout:       opts.HTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // sweep confirmation only; we never trust these endpoints
			TLSHandshakeTimeout: opts.HTTPTimeout,
			DisableKeepAlives:   true,
		},
	}

	var (
		mu      sync.Mutex
		open    []PortResult
		tcpOpen int
		wg      sync.WaitGroup
		sem     = make(chan struct{}, opts.Concurrency)
	)

	for _, port := range opts.Ports {
		select {
		case <-ctx.Done():
			// Stop launching new probes once cancelled; report what we have.
			wg.Wait()
			return finalize(res, open, tcpOpen, opts.HoneypotRatio)
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			// Cheap TCP pre-filter: a closed port fails the short DialTimeout
			// instead of waiting out the longer HTTP/TLS timeout, and the open
			// count feeds the honeypot ratio. The follow-up HTTP confirm dials
			// again — one extra handshake per open port, by design.
			if !tcpReachable(ctx, dialer, host, port) {
				return
			}
			mu.Lock()
			tcpOpen++
			mu.Unlock()

			pr, ok := confirmHTTP(ctx, client, host, port)
			if !ok {
				return
			}
			mu.Lock()
			open = append(open, pr)
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	return finalize(res, open, tcpOpen, opts.HoneypotRatio)
}

// finalize sorts confirmed ports, runs the honeypot guard, and returns the
// completed Result. Kept separate so the cancellation path and the normal path
// share identical post-processing.
func finalize(res Result, open []PortResult, tcpOpen int, honeypotRatio float64) Result {
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	res.TCPOpen = tcpOpen

	if isHoneypot(res.Probed, tcpOpen, open, honeypotRatio) {
		res.Honeypot = true
		res.Open = nil
		return res
	}
	res.Open = open
	return res
}

// tcpReachable reports whether a TCP connection to host:port succeeds within the
// dialer's timeout.
func tcpReachable(ctx context.Context, dialer *net.Dialer, host string, port int) bool {
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// confirmHTTP sends a GET to host:port over the hinted scheme, falling back to
// the other scheme on transport error. It returns a PortResult when the endpoint
// answers with an HTTP response (any status code — a 401/403 still proves a web
// server is listening).
func confirmHTTP(ctx context.Context, client *http.Client, host string, port int) (PortResult, bool) {
	primary, secondary := "http", "https"
	if _, ok := httpsHintPorts[port]; ok {
		primary, secondary = "https", "http"
	}
	if pr, ok := tryScheme(ctx, client, host, port, primary); ok {
		return pr, true
	}
	return tryScheme(ctx, client, host, port, secondary)
}

// tryScheme performs one GET and, on an HTTP response, builds the PortResult and
// its honeypot fingerprint.
func tryScheme(ctx context.Context, client *http.Client, host string, port int, scheme string) (PortResult, bool) {
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return PortResult{}, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return PortResult{}, false
	}
	defer func() { _ = resp.Body.Close() }()

	// Read a bounded slice of the body for the fingerprint.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	server := resp.Header.Get("Server")

	return PortResult{
		Port:   port,
		Scheme: scheme,
		Status: resp.StatusCode,
		Server: server,
		fp:     fingerprint(resp.StatusCode, server, body),
	}, true
}

// fingerprint reduces a response to a stable token used for honeypot detection.
// Identical pages served on many ports collapse to the same fingerprint.
func fingerprint(status int, server string, body []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(body)
	return fmt.Sprintf("%d|%s|%x", status, server, h.Sum64())
}

// isHoneypot decides whether a host's sweep looks like an all-ports-open tarpit.
// Both signals must hold: (1) a high fraction of probed ports accepted a TCP
// connection, and (2) the HTTP-confirmed responses are near-identical (one
// fingerprint dominates). A host running a few genuinely distinct services
// survives because its fingerprints differ; a single confirmed port can never be
// a honeypot.
func isHoneypot(probed, tcpOpen int, open []PortResult, ratioThreshold float64) bool {
	if probed == 0 || ratioThreshold <= 0 {
		return false
	}
	ratio := float64(tcpOpen) / float64(probed)
	if ratio < ratioThreshold {
		return false
	}
	// Need at least 3 confirmed HTTP services before "they all look the same" is
	// meaningful — two endpoints can coincidentally match.
	if len(open) < 3 {
		return false
	}
	counts := make(map[string]int, len(open))
	dominant := 0
	for _, pr := range open {
		counts[pr.fp]++
		if counts[pr.fp] > dominant {
			dominant = counts[pr.fp]
		}
	}
	// Honeypot when ≥80% of confirmed ports share one fingerprint.
	return float64(dominant)/float64(len(open)) >= 0.8
}
