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

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	httpUtils "github.com/projectdiscovery/utils/http"
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
	dialer := network.Dialer
	if dialer == nil {
		return nil, errors.New("network.Dialer not initialized")
	}

	timeout := options.Timeout

	// TLS config - hardcoded for pentesting (insecure, max compat)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		Renegotiation:      tls.RenegotiateOnceAsClient,
		MinVersion:         tls.VersionTLS10,
	}
	if options.SNI != "" {
		tlsConfig.ServerName = options.SNI
	}

	// Transport factory
	makeTransport := func() *http.Transport {
		t := &http.Transport{
			ForceAttemptHTTP2: options.ForceAttemptHTTP2,
			DialContext:       dialer.Dial,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialTLS(ctx, network, addr)
			},
			TLSClientConfig:        tlsConfig,
			DisableKeepAlives:      false,
			MaxIdleConns:           100,
			MaxIdleConnsPerHost:    10,
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

	// Raw HTTP clients
	rawOpts := rawhttp.DefaultOptions
	rawOpts.Timeout = timeout
	if proxyURL := getProxyURL(options.ProxyURL); proxyURL != "" {
		rawOpts.Proxy = proxyURL
	} else {
		rawOpts.FastDialer = dialer
	}
	rawOpts.FollowRedirects = true
	rawOpts.MaxRedirects = maxRedir
	rawClient := rawhttp.NewClient(rawOpts)

	rawOptsNoRedir := rawOpts
	rawOptsNoRedir.FollowRedirects = false
	rawOptsNoRedir.MaxRedirects = 0
	rawClientNoRedir := rawhttp.NewClient(rawOptsNoRedir)

	r := &Requester{
		client:           client,
		clientNoRedir:    clientNoRedir,
		rawClient:        rawClient,
		rawClientNoRedir: rawClientNoRedir,
		services:         services,
		customHeaders:    parseHeaders(options.Headers),
	}

	if options.ClusterRequests {
		r.clusterer = NewRequestClusterer()
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
func (r *Requester) Execute(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, int, error) {
	if r.clusterer != nil && !opts.NoClustering {
		return r.clusterer.Execute(input, opts, r.executeDirectly)
	}
	return r.executeDirectly(input, opts)
}

// Clusterer returns the request clusterer (nil if clustering is disabled).
func (r *Requester) Clusterer() *RequestClusterer {
	return r.clusterer
}

// executeDirectly sends HTTP request with rate limiting and host error tracking.
func (r *Requester) executeDirectly(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, int, error) {
	// Per-host rate limiting (concurrency control)
	if r.services.HostLimiter != nil {
		host := ""
		if input.Service() != nil {
			host = input.Service().Host()
		}
		if host != "" {
			if err := r.services.HostLimiter.AcquireWithTimeout(host); err != nil {
				return nil, 0, err
			}
			defer r.services.HostLimiter.Release(host)
		}
	}

	if r.services.HostErrors != nil && r.services.HostErrors.Check(input.ID()) {
		return nil, 0, hosterrors.ErrUnresponsiveHost
	}

	start := time.Now()
	resp, err := r.doRequest(input, opts)
	if err != nil {
		if r.services.HostErrors != nil {
			r.services.HostErrors.MarkFailed(input.ID(), err, opts.IgnoreTimeoutTracking)
		}
		return nil, 0, err
	}

	if r.services.HostErrors != nil {
		r.services.HostErrors.MarkSuccess(input.ID())
	}
	return resp, int(time.Since(start).Seconds()), nil
}

func (r *Requester) doRequest(input *httpmsg.HttpRequestResponse, opts Options) (*httpUtils.ResponseChain, error) {
	start := time.Now()

	req, err := input.BuildRetryableRequest()
	if err != nil {
		return nil, errors.Wrap(err, "failed to build request")
	}

	// Apply default browser headers (only if not already set in request)
	for name, value := range httpmsg.DefaultBrowserHeaders {
		if opts.DisableCompression && strings.EqualFold(name, "Accept-Encoding") {
			continue
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
		if opts.NoRedirects {
			resp, err = r.rawClientNoRedir.Dor(req)
		} else {
			resp, err = r.rawClient.Dor(req)
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
