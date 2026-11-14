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
// the vigolium request middleware, keeping the sweep fast and unit-testable. The
// scan still governs it through two hooks: WrapTransport puts the HTTP confirm
// step behind the scan's egress gate (rate token, host slot, quarantine), and
// OnDial counts each TCP pre-filter dial, which is counted but not paced.
//
// Proxy: the HTTP confirm step goes through Options.ProxyURL when one is set, so
// an operator's --proxy sees every request the sweep sends. The TCP pre-filter
// cannot: it is a bare connect with no HTTP to proxy, so it always dials the host
// directly. A sweep run behind a proxy therefore still leaks one SYN per probed
// port from this machine; an operator who must not touch the target directly
// should skip the port-sweep phase.
package portsweep

import (
	"context"
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/core/network"
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
	// ProxyURL routes the HTTP confirm requests through this proxy (the scan's
	// --proxy). The TCP pre-filter always dials directly; see the package doc.
	ProxyURL string
	// WrapTransport, when set, wraps the confirm client's transport — the scan
	// passes its egress gate here so every confirm request is admitted like any
	// other target request. nil = ungated.
	WrapTransport func(http.RoundTripper) http.RoundTripper
	// OnDial, when set, is called once per TCP pre-filter dial attempt. A bare
	// connect has no request to rate, but it reaches the host, so the scan
	// counts it.
	OnDial func()
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
	// plainToTLS marks a plain-HTTP answer saying the port speaks TLS.
	plainToTLS bool
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
	var transport http.RoundTripper = &http.Transport{
		Proxy:               proxyFunc(opts.ProxyURL),
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, ClientSessionCache: network.TLSSessionCache()}, //nolint:gosec // sweep confirmation only; we never trust these endpoints
		TLSHandshakeTimeout: opts.HTTPTimeout,
		DisableKeepAlives:   true,
	}
	if opts.WrapTransport != nil {
		transport = opts.WrapTransport(transport)
	}
	client := &http.Client{
		Timeout:       opts.HTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     transport,
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
			if opts.OnDial != nil {
				opts.OnDial()
			}
			if !TCPReachable(ctx, dialer, host, port) {
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

// proxyFunc returns the transport Proxy func for raw: nil (direct) when raw is
// empty, otherwise a fixed proxy. An explicit URL rather than
// ProxyFromEnvironment, which would bypass the proxy for a loopback target.
//
// An unparseable proxy fails every confirm request rather than falling back to a
// direct connection: the operator asked for their traffic to go through a proxy,
// and confirming ports around it is the one outcome they ruled out.
func proxyFunc(raw string) func(*http.Request) (*url.URL, error) {
	if raw == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		if err == nil {
			err = fmt.Errorf("proxy URL %q has no host", raw)
		}
		return func(*http.Request) (*url.URL, error) { return nil, err }
	}
	return http.ProxyURL(parsed)
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

// TCPReachable reports whether a TCP connection to host:port succeeds within
// the dialer's timeout. Exported because the probe phase asks the same question
// to decide which scheme a schemeless target speaks, and two independently
// tuned connect probes would be two answers to "is this port open".
func TCPReachable(ctx context.Context, dialer *net.Dialer, host string, port int) bool {
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
		// A TLS port answering a plain-HTTP request with a 400/497 "plain HTTP
		// request was sent to HTTPS port" page is an HTTPS service: recording it
		// as http:// would point every later phase at the error page.
		if primary == "http" && pr.plainToTLS {
			if tls, ok := tryScheme(ctx, client, host, port, "https"); ok {
				return tls, true
			}
		}
		return pr, true
	}
	return tryScheme(ctx, client, host, port, secondary)
}

// plainHTTPToTLSMarkers are the bodies servers send when plain HTTP reaches a
// TLS listener (nginx, Apache, Tomcat/Jetty, generic proxies).
var plainHTTPToTLSMarkers = []string{
	"plain http request was sent to https port",
	"speaking plain http to an ssl-enabled server",
	"http request to an https server",
	"http to https port",
	"this combination of host and port requires tls",
	"the plain http request was sent",
}

// looksLikeTLSPort reports a plain-HTTP answer that says the port speaks TLS:
// nginx's 497, or a 400 whose body names the mismatch.
func looksLikeTLSPort(status int, body []byte) bool {
	if status == 497 {
		return true
	}
	if status != http.StatusBadRequest {
		return false
	}
	lower := strings.ToLower(string(body))
	for _, m := range plainHTTPToTLSMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
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
		Port:       port,
		Scheme:     scheme,
		Status:     resp.StatusCode,
		Server:     server,
		fp:         fingerprint(resp.StatusCode, server, body),
		plainToTLS: scheme == "http" && looksLikeTLSPort(resp.StatusCode, body),
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
