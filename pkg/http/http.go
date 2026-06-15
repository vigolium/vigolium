package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
)

const (
	MaxBodyRead           = int64(30 * 1024 * 1024) // 30MB
	responseHeaderTimeout = 5 * time.Second
)

// Options per-request
type Options struct {
	NoRedirects           bool
	RawRequest            bool
	IgnoreTimeoutTracking bool
	NoClustering          bool
	DisableCompression    bool // skip Accept-Encoding header so Go auto-decompresses
	// RawRequestTarget, when non-empty, is written verbatim as the HTTP
	// request-line target (request-URI) while the TCP/TLS connection still goes
	// to the request's real host. It enables routing-based SSRF / "Cracking the
	// lens" request-line attacks — e.g. connecting to a victim proxy but writing
	// an absolute-form target "http://127.0.0.1:8080/", a userinfo trick
	// "@collab.net/", or a protocol-relative "//collab.net/". Requires
	// RawRequest=true (it is routed through the rawhttp client); ignored otherwise.
	RawRequestTarget string
}

// Requester executes HTTP requests with rate limiting and host error tracking
type Requester struct {
	client           *retryablehttp.Client
	clientNoRedir    *retryablehttp.Client
	rawClient        *rawhttp.Client
	rawClientNoRedir *rawhttp.Client
	services         *services.Services
	customHeaders    map[string]string
	clusterer        *RequestClusterer
	// defaultCtx, when non-nil, is the context the context-less Execute attaches
	// to outgoing requests. Set per scan task via WithContext so cancellation
	// reaches modules that call Execute (not ExecuteContext). nil → Background.
	defaultCtx context.Context
}

// WithContext returns a shallow copy of the Requester whose context-less Execute
// uses ctx for cancellation. The copy shares the underlying HTTP clients, rate
// limiter, clusterer, and headers — only the default context differs — so it is
// cheap to create per scan task. The executor hands each active-module task a
// context-bound requester so a per-module timeout or scan shutdown aborts the
// module's in-flight requests even when the module calls Execute directly.
// A nil ctx returns the receiver unchanged.
func (r *Requester) WithContext(ctx context.Context) *Requester {
	if ctx == nil {
		return r
	}
	clone := *r
	clone.defaultCtx = ctx
	return &clone
}

// getProxyURL returns proxy URL from CLI flag or environment variable.
// CLI flag takes precedence over environment variables.
// Uses explicit proxy URL (not ProxyFromEnvironment) to ensure localhost is proxied.
func getProxyURL(cliProxy string) string {
	if cliProxy != "" {
		return cliProxy
	}
	// Check environment variables (uppercase first, then lowercase)
	if p := os.Getenv("HTTP_PROXY"); p != "" {
		return p
	}
	if p := os.Getenv("http_proxy"); p != "" {
		return p
	}
	if p := os.Getenv("HTTPS_PROXY"); p != "" {
		return p
	}
	if p := os.Getenv("https_proxy"); p != "" {
		return p
	}
	return ""
}

// NewRequester creates a new Requester with all HTTP clients initialized
func NewRequester(options *types.Options, services *services.Services) (*Requester, error) {
	dialer := network.CurrentDialer()
	if dialer == nil {
		return nil, errors.New("network.Dialer not initialized")
	}

	timeout := options.Timeout

	// TLS config - hardcoded for pentesting (insecure, max compat).
	//
	// This permissiveness is SCOPED TO SCANNER/TARGET TRAFFIC: scan targets
	// routinely present self-signed, expired, or wrong-host certs, and a scanner
	// that refused them would be useless. It deliberately does NOT apply to
	// vigolium's own infrastructure calls — OSINT harvesting (pkg/harvester),
	// cloud storage, AI providers, tool downloads, webhooks — which verify certs
	// using Go's secure defaults. Keep that split: don't copy InsecureSkipVerify
	// into non-target/infra HTTP clients.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		Renegotiation:      tls.RenegotiateOnceAsClient,
		MinVersion:         tls.VersionTLS10,
	}
	if options.SNI != "" {
		tlsConfig.ServerName = options.SNI
	}

	// Size the idle-connection pool to the per-host concurrency cap. A scanner
	// fans out many requests at the same host, so the transport must keep at
	// least MaxPerHost keep-alive connections warm — otherwise every request past
	// MaxIdleConnsPerHost closes its connection on return and the next one pays a
	// fresh TCP+TLS handshake (~50-150ms). The old hardcoded 10 throttled reuse
	// badly: MaxPerHost defaults to 50, so 40 of every 50 connections churned.
	// Floor at the old 10 and cap at 256 so a pathological --max-per-host can't
	// pin an unbounded idle pool of file descriptors.
	maxIdlePerHost := min(max(options.MaxPerHost, 10), 256)
	// The global idle pool scales with the per-host cap so multi-host scans keep
	// enough warm connections across hosts. maxIdlePerHost >= 10 guarantees this is
	// always >= the old 100 floor.
	maxIdleConns := maxIdlePerHost * 10

	// Transport factory
	makeTransport := func() *http.Transport {
		t := &http.Transport{
			// NOTE: ForceAttemptHTTP2 is currently inert. Setting a custom
			// DialTLSContext makes Go skip its own TLS+ALPN handling, so the
			// transport never negotiates h2 and never populates TLSNextProto —
			// regardless of this flag. This is deliberate: the scanner operates over
			// HTTP/1.1 so request smuggling, header-ordering, raw-request, and
			// timing modules keep a 1:1 request↔connection mapping that h2
			// multiplexing would break. To ever enable h2, the custom
			// DialTLSContext below must be removed and ALPN wired via the shared
			// tlsConfig (NextProtos) / http2.ConfigureTransport.
			ForceAttemptHTTP2: options.ForceAttemptHTTP2,
			DialContext:       dialer.Dial,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialTLS(ctx, network, addr)
			},
			TLSClientConfig:        tlsConfig,
			DisableKeepAlives:      false,
			MaxIdleConns:           maxIdleConns,
			MaxIdleConnsPerHost:    maxIdlePerHost,
			IdleConnTimeout:        90 * time.Second,
			ResponseHeaderTimeout:  responseHeaderTimeout,
			MaxResponseHeaderBytes: 48 * 1024,
			ReadBufferSize:         16 * 1024,
		}
		// Use explicit proxy URL (CLI flag or env var) to ensure localhost is proxied.
		// Go's ProxyFromEnvironment bypasses proxy for localhost requests.
		if proxyURL := getProxyURL(options.ProxyURL); proxyURL != "" {
			if parsed, err := url.Parse(proxyURL); err == nil {
				t.Proxy = http.ProxyURL(parsed)
			} else {
				zap.L().Warn("Invalid proxy URL", zap.String("url", proxyURL), zap.Error(err))
			}
		}
		return t
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, errors.Wrap(err, "could not create cookiejar")
	}

	retryOpts := retryablehttp.DefaultOptionsSpraying
	retryOpts.RetryMax = options.Retries
	retryOpts.RetryWaitMax = 10 * time.Second

	maxRedir := options.MaxRedirects
	if maxRedir == 0 {
		maxRedir = 10
	}

	// Single shared transport — connection pooling is a transport-level concern.
	// Redirect policy is a client-level concern configured via CheckRedirect.
	// Sharing the transport means connections are reused across both client variants.
	sharedTransport := makeTransport()

	// Client with redirects
	client := retryablehttp.NewWithHTTPClient(&http.Client{
		Transport:     sharedTransport,
		Timeout:       timeout,
		Jar:           jar,
		CheckRedirect: makeRedirectFunc(options.FollowHostRedirects, maxRedir),
	}, retryOpts)

	// Client without redirects
	clientNoRedir := retryablehttp.NewWithHTTPClient(&http.Client{
		Transport:     sharedTransport,
		Timeout:       timeout,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, retryOpts)

	// Raw HTTP clients. rawhttp.DefaultOptions is a shared package-level
	// *Options; copy it by value so per-requester tuning stays local. The old
	// `rawOpts := rawhttp.DefaultOptions` aliased the global pointer, so every
	// field write below mutated the shared default — racing when requesters were
	// constructed concurrently, and leaking the no-redirect tuning back onto the
	// redirect client (both pointed at the same struct).
	rawOpts := *rawhttp.DefaultOptions
	rawOpts.Timeout = timeout
	if proxyURL := getProxyURL(options.ProxyURL); proxyURL != "" {
		rawOpts.Proxy = proxyURL
	} else {
		rawOpts.FastDialer = dialer
	}
	rawOpts.FollowRedirects = true
	rawOpts.MaxRedirects = maxRedir
	rawClient := rawhttp.NewClient(&rawOpts)

	rawOptsNoRedir := rawOpts
	rawOptsNoRedir.FollowRedirects = false
	rawOptsNoRedir.MaxRedirects = 0
	rawClientNoRedir := rawhttp.NewClient(&rawOptsNoRedir)

	r := &Requester{
		client:           client,
		clientNoRedir:    clientNoRedir,
		rawClient:        rawClient,
		rawClientNoRedir: rawClientNoRedir,
		services:         services,
		customHeaders:    parseHeaders(options.Headers),
	}

	if options.ClusterRequests {
		// Size the dedup LRU to scan concurrency so a wide active-module fan-out
		// doesn't evict still-fresh entries before their TTL elapses.
		r.clusterer = NewRequestClustererWithSize(ClustererSizeForConcurrency(options.Concurrency))
	}

	return r, nil
}

// parseHeaders parses header strings in "Name: Value" format.
func parseHeaders(headers []string) map[string]string {
	result := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

func makeRedirectFunc(sameHostOnly bool, maxRedirects int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		if sameHostOnly && req.URL.Host != via[0].URL.Host {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

// Execute sends HTTP request with rate limiting, host error tracking,
// and optional request clustering to deduplicate concurrent identical requests.
// It uses the context bound via WithContext (if any) so callers that never touch
// ExecuteContext still honour scan/module cancellation; otherwise it is
// equivalent to the non-cancellable legacy behaviour.
func (r *Requester) Execute(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, int, error) {
	ctx := r.defaultCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return r.ExecuteContext(ctx, input, opts)
}

// ExecuteContext is the cancellable variant of Execute: ctx is attached to the
// outgoing HTTP request, so cancelling it (scan shutdown or a per-module/active
// timeout) aborts the in-flight request and its retry loop instead of leaving
// the goroutine to drain on its own. A context.Background() ctx is equivalent to
// the legacy non-cancellable Execute.
func (r *Requester) ExecuteContext(ctx context.Context, input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, int, error) {
	if r.clusterer != nil && !opts.NoClustering {
		return r.clusterer.Execute(input, opts, func(in *httpmsg.HttpRequestResponse, o Options) (*httpUtils.ResponseChain, int, error) {
			return r.executeDirectly(ctx, in, o)
		})
	}
	return r.executeDirectly(ctx, input, opts)
}

// Clusterer returns the request clusterer (nil if clustering is disabled).
func (r *Requester) Clusterer() *RequestClusterer {
	return r.clusterer
}

// executeDirectly sends HTTP request with rate limiting and host error tracking.
// ctx is propagated to the outgoing request for cancellation.
func (r *Requester) executeDirectly(ctx context.Context, input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, int, error) {
	host := ""
	if input.Service() != nil {
		host = input.Service().Host()
	}

	// Per-host rate limiting (concurrency control)
	if r.services.HostLimiter != nil && host != "" {
		if err := r.services.HostLimiter.AcquireWithTimeout(host); err != nil {
			// Acquire timeout is our own saturation, not host distress — don't
			// feed it back to the adaptive controller.
			return nil, 0, err
		}
		defer r.services.HostLimiter.Release(host)
	}

	if r.services.HostErrors != nil && r.services.HostErrors.Check(input.ID()) {
		return nil, 0, hosterrors.ErrUnresponsiveHost
	}

	start := time.Now()
	resp, err := r.doRequest(ctx, input, opts)
	if err != nil {
		if r.services.HostErrors != nil {
			r.services.HostErrors.MarkFailed(input.ID(), err, opts.IgnoreTimeoutTracking)
		}
		// Feed transport failures (timeout/reset/refused) to the adaptive limiter
		// so it can back the host off; a no-op in static mode.
		r.reportHostFeedback(host, 0, err)
		return nil, 0, err
	}

	if r.services.HostErrors != nil {
		r.services.HostErrors.MarkSuccess(input.ID())
	}
	r.reportHostFeedback(host, responseChainStatus(resp), nil)
	return resp, int(time.Since(start).Seconds()), nil
}

// reportHostFeedback forwards a per-request outcome to the adaptive host limiter.
// No-op without a limiter/host; in static mode Feedback itself is a no-op. It runs
// only on the executeDirectly path, so a clusterer cache hit (no network request)
// correctly produces no feedback.
func (r *Requester) reportHostFeedback(host string, statusCode int, err error) {
	if host == "" || r.services.HostLimiter == nil {
		return
	}
	r.services.HostLimiter.Feedback(host, statusCode, err)
}

// responseChainStatus returns the HTTP status code from a response chain, or 0
// when unavailable.
func responseChainStatus(resp *httpUtils.ResponseChain) int {
	if resp == nil {
		return 0
	}
	if r := resp.Response(); r != nil {
		return r.StatusCode
	}
	return 0
}

func (r *Requester) doRequest(ctx context.Context, input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, error) {
	start := time.Now()

	req, err := input.BuildRetryableRequestWithContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build request")
	}

	// Apply default browser headers (only if not already set in request).
	// User-Agent is resolved via DefaultUserAgent() so a configured global
	// override (http.user_agent) wins over the built-in Chrome string.
	for name, value := range httpmsg.DefaultBrowserHeaders {
		if opts.DisableCompression && strings.EqualFold(name, "Accept-Encoding") {
			continue
		}
		if strings.EqualFold(name, "User-Agent") {
			value = httpmsg.DefaultUserAgent()
		}
		if req.Header.Get(name) == "" {
			req.Header.Set(name, value)
		}
	}

	// Normalize host header (remove port)
	if host := req.Header.Get("Host"); host != "" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			req.Header.Set("Host", h)
		}
	}

	// Apply custom headers (after defaults to allow override)
	for name, value := range r.customHeaders {
		req.Header.Set(name, value)
	}

	if r.services.Options.Debug {
		zap.L().Debug("HTTP Request", zap.String("url", req.String()))
		rawReq, err := req.Dump()
		if err == nil {
			zap.L().Debug("HTTP Request Raw", zap.ByteString("raw", rawReq))
		}
	}

	var resp *http.Response
	if opts.RawRequest {
		rawClient := r.rawClient
		if opts.NoRedirects {
			rawClient = r.rawClientNoRedir
		}
		if opts.RawRequestTarget != "" {
			// Routing-based SSRF / request-line attacks ("Cracking the lens"):
			// connect to the real host (req.URL) but emit an attacker-chosen,
			// literal request target on the wire — rawhttp sends the uripath arg
			// verbatim. AutomaticHostHeader is disabled for this call so the
			// request's own Host header (carried in req.Header by
			// BuildRetryableRequest) is sent as-is instead of being overwritten
			// with the connection host; the Host/target mismatch is the whole
			// point of these attacks. The client's options are copied so the
			// shared rawhttp default (used by the smuggling module via Dor) is
			// left untouched.
			rawOpts := *rawClient.Options
			rawOpts.AutomaticHostHeader = false
			// req embeds *urlutil.URL (retryablehttp.Request), so req.String() is the
			// promoted request URL — rawhttp dials its host while RawRequestTarget
			// overrides the on-the-wire request-line target.
			connURL := req.String()
			resp, err = rawClient.DoRawWithOptions(
				req.Method, connURL, opts.RawRequestTarget,
				req.Header, req.Body, &rawOpts,
			)
		} else {
			resp, err = rawClient.Dor(req)
		}
	} else {
		if opts.NoRedirects {
			resp, err = r.clientNoRedir.Do(req)
		} else {
			resp, err = r.client.Do(req)
		}
	}

	if err != nil {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		return nil, err
	}

	if r.services.Options.DumpTraffic {
		dumpTraffic(req.Request, resp, time.Since(start))
	}

	respChain := httpUtils.NewResponseChain(resp, MaxBodyRead)
	for respChain.Has() {
		if err := respChain.Fill(); err != nil {
			// NewResponseChain checks two buffers out of projectdiscovery's
			// global, fixed-size pool (default 10000). On this error path the
			// chain is never handed to the caller, so nothing downstream will
			// Close() it — we must release the buffers here or they leak. Because
			// the pool's getBuffer() acquires with context.Background() (a
			// non-cancellable wait), enough accumulated leaks exhaust the pool and
			// every subsequent request blocks forever, deadlocking the whole scan.
			respChain.Close()
			return nil, errors.Wrap(err, "could not generate response chain")
		}
		if !respChain.Previous() {
			break
		}
	}
	return respChain, nil
}

const (
	dumpMaxBody    = 4096
	dumpColorReset = "\033[0m"
	dumpColorCyan  = "\033[36m"
	dumpColorGreen = "\033[32m"
)

// dumpTraffic prints an HTTP request/response pair to stderr in a Burp-style format.
func dumpTraffic(req *http.Request, resp *http.Response, elapsed time.Duration) {
	var reqDump, respDump []byte

	if req != nil {
		reqDump, _ = httputil.DumpRequestOut(req, true)
	}
	if resp != nil {
		respDump, _ = httputil.DumpResponse(resp, true)
	}

	method := ""
	fullURL := ""
	if req != nil {
		method = req.Method
		fullURL = req.URL.String()
	}

	status := ""
	if resp != nil {
		status = resp.Status
	}

	// Truncate response dump if too long
	respBody := string(respDump)
	if len(respDump) > dumpMaxBody {
		respBody = string(respDump[:dumpMaxBody]) + fmt.Sprintf("\n... (%d bytes truncated)", len(respDump)-dumpMaxBody)
	}

	fmt.Fprintf(os.Stderr,
		"\n%s╔══════════════════════════════════════════════════════════════╗%s\n"+
			"%s║ >> %-57s║%s\n"+
			"%s╚══════════════════════════════════════════════════════════════╝%s\n"+
			"%s\n"+
			"%s╔══════════════════════════════════════════════════════════════╗%s\n"+
			"%s║ << %-57s║%s\n"+
			"%s╚══════════════════════════════════════════════════════════════╝%s\n"+
			"%s\n",
		dumpColorCyan, dumpColorReset,
		dumpColorCyan, fmt.Sprintf("%s %s", method, fullURL), dumpColorReset,
		dumpColorCyan, dumpColorReset,
		string(reqDump),
		dumpColorGreen, dumpColorReset,
		dumpColorGreen, fmt.Sprintf("%s  (%.3fs)", status, elapsed.Seconds()), dumpColorReset,
		dumpColorGreen, dumpColorReset,
		respBody,
	)
}
