package replay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/proxytarget"
)

const (
	// defaultUserAgent is set when the raw request didn't carry one;
	// some WAFs reject empty UA outright and we'd waste turns debugging
	// the resulting 403 vs the real baseline.
	defaultUserAgent = "Mozilla/5.0 (vigolium-replay)"

	defaultMaxResponseBytes = 5 * 1024 * 1024

	// DefaultTimeout is the per-request wall-clock budget used by
	// NewDefaultClient when callers don't supply one.
	DefaultTimeout = 25 * time.Second
)

// NewDefaultClient returns an *http.Client suitable for replay traffic.
// TLS verification is off because targets are often localhost or
// self-signed staging. Proxy is read from HTTP_PROXY / HTTPS_PROXY so an
// operator can pipe through Burp; SetProxy replaces it. The transport is a
// proxytarget.Transport, so a request whose Host header differs from its
// destination still reaches an HTTP proxy addressed to the destination's
// host:port. Pass jar=nil for stateless replays.
func NewDefaultClient(jar gohttp.CookieJar, timeout time.Duration) *gohttp.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &gohttp.Client{
		Timeout: timeout,
		Jar:     jar,
		Transport: proxytarget.Wrap(&gohttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ClientSessionCache: network.TLSSessionCache()}, //nolint:gosec // intentional for replay
			Proxy:           proxyFromEnv,
		}),
	}
}

// SetProxy routes client's traffic through proxyURL, or connects directly when
// proxyURL is nil. It reports false, changing nothing, when client's transport
// is neither an *http.Transport nor a proxytarget.Transport.
func SetProxy(client *gohttp.Client, proxyURL *url.URL) bool {
	if client == nil {
		return false
	}
	t, ok := proxytarget.Base(client.Transport)
	if !ok {
		return false
	}
	if proxyURL == nil {
		t.Proxy = nil
	} else {
		t.Proxy = gohttp.ProxyURL(proxyURL)
	}
	return true
}

// proxyFromEnv mirrors the precedence vigolium's own Requester uses:
// HTTP_PROXY / HTTPS_PROXY (uppercase first, lowercase fallback).
// NO_PROXY is deliberately ignored — attack-validation traffic is
// rarely something an operator wants the proxy to skip, and a stale
// NO_PROXY would silently hide the very traffic Burp is meant to show.
func proxyFromEnv(req *gohttp.Request) (*url.URL, error) {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if v := os.Getenv(k); v != "" {
			return url.Parse(v)
		}
	}
	return nil, nil
}

// isDefaultPort reports whether port is the well-known default for scheme and
// can therefore be omitted from an authority.
func isDefaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

// Authority returns the URL authority for a destination: host:port, with the
// port omitted when it is zero or the scheme's default (80 for http, 443 for
// https; an empty scheme means http). An IPv6 literal is bracketed whether or
// not a port follows, and hostname may arrive bracketed already.
func Authority(scheme, hostname string, port int) string {
	if scheme == "" {
		scheme = "http"
	}
	host := strings.TrimSuffix(strings.TrimPrefix(hostname, "["), "]")
	if port > 0 && !isDefaultPort(strings.ToLower(scheme), port) {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// sendRawHTTP parses raw request bytes, points the request at the supplied
// scheme/hostname/port, and sends via client. A *Summary is returned even on
// transport error so callers always get a structured response. noRedirects
// clones the client to avoid mutating shared redirect policy across calls.
//
// The destination (the connection, and the absolute-form target an HTTP proxy
// receives) is always scheme://Authority(scheme, hostname, port). The Host
// header is the raw request's own, sent as written, so a fuzzed or mutated
// Host and a request replayed against another environment keep the Host the
// caller wrote — the same bytes the Burp-bridge Sender sends. A raw request
// with no Host header gets the destination's authority. Through an HTTP proxy
// a Host that differs from the destination relies on the client's transport
// being a proxytarget.Transport (NewDefaultClient's is).
func sendRawHTTP(ctx context.Context, client *gohttp.Client, raw []byte, scheme, hostname string, port int, noRedirects bool, excerptCap int) *Summary {
	if excerptCap <= 0 {
		excerptCap = DefaultExcerptCap
	}

	req, err := gohttp.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return &Summary{Error: fmt.Sprintf("parse request: %v", err)}
	}
	defer func() {
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
	}()

	if scheme == "" {
		scheme = "http"
	}
	// RawPath must be carried over, not just Path. Path is the *decoded*
	// target, so rebuilding the URL without RawPath re-encodes it from
	// scratch and silently normalizes percent-escapes on the wire —
	// "/a/..%2fadmin" would leave as "/a/../admin" and "/%2e%2e/x" as
	// "/../x". For a scanner those escapes are the payload: they're exactly
	// what distinguishes a proxy-normalization bypass probe from a plain
	// traversal. net/http emits RawPath verbatim whenever it's a valid
	// encoding of Path, so preserving it keeps the operator's bytes intact.
	// ForceQuery keeps a bare trailing "?" from being dropped.
	req.URL = &url.URL{
		Scheme:     scheme,
		Host:       Authority(scheme, hostname, port),
		Path:       req.URL.Path,
		RawPath:    req.URL.RawPath,
		RawQuery:   req.URL.RawQuery,
		ForceQuery: req.URL.ForceQuery,
	}
	// req.Host already holds the raw Host header (ReadRequest moves it there);
	// when it is empty net/http sends req.URL.Host, the destination authority.
	req.RequestURI = ""

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultUserAgent)
	}

	sendClient := client
	if noRedirects {
		sendClient = &gohttp.Client{
			Timeout:   client.Timeout,
			Transport: client.Transport,
			Jar:       client.Jar,
			CheckRedirect: func(*gohttp.Request, []*gohttp.Request) error {
				return gohttp.ErrUseLastResponse
			},
		}
	}

	req = req.WithContext(ctx)
	start := time.Now()
	resp, err := sendClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return &Summary{
			Error:          fmt.Sprintf("request failed: %v", err),
			ResponseTimeMs: elapsed.Milliseconds(),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, defaultMaxResponseBytes))
	sum := sha256.Sum256(bodyBytes)
	excerpt, truncated := clipBytes(bodyBytes, excerptCap)
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	return &Summary{
		FinalURL:       finalURL,
		Status:         resp.StatusCode,
		ResponseLen:    len(bodyBytes),
		ContentHash:    hex.EncodeToString(sum[:8]),
		ResponseTimeMs: elapsed.Milliseconds(),
		Headers:        resp.Header,
		Excerpt:        excerpt,
		Truncated:      truncated,
		RawBody:        bodyBytes,
	}
}

// SendRaw sends raw request bytes against scheme://hostname:port using
// client and returns a structured *Summary (populated even on transport
// error, so callers always get something to inspect). It is the exact
// send + body-capture + hashing path Do() uses internally; it is exported
// so sibling engines — notably pkg/fuzz — can reuse it without reimplementing
// request parsing, redirect handling, or response hashing. Pass excerptCap=0
// for DefaultExcerptCap.
func SendRaw(ctx context.Context, client *gohttp.Client, raw []byte, scheme, hostname string, port int, noRedirects bool, excerptCap int) *Summary {
	return sendRawHTTP(ctx, client, raw, scheme, hostname, port, noRedirects, excerptCap)
}

// Do applies mutations (or the raw override), overlays headers, sends,
// and returns a baseline-vs-replay Result.
//
// Errors signal configuration/parse problems; network failures land in
// result.Replay.Error so callers always get a structured response they
// can show the operator or feed to an LLM.
//
// Caller responsibilities not handled here: rate limiting, project/scope
// enforcement, cookie persistence between calls (provide a jar on
// opts.Client), persisting the replay back to DB.
func Do(ctx context.Context, opts Options) (*Result, error) {
	if opts.Client == nil && opts.Sender == nil {
		return nil, fmt.Errorf("replay.Do: opts.Client or opts.Sender is required")
	}
	if len(opts.BaselineRequest) == 0 && len(opts.RawRequest) == 0 {
		return nil, fmt.Errorf("replay.Do: BaselineRequest or RawRequest is required")
	}
	if opts.Hostname == "" {
		return nil, fmt.Errorf("replay.Do: Hostname is required")
	}

	excerptCap := opts.ExcerptCap
	if excerptCap <= 0 {
		excerptCap = DefaultExcerptCap
	}

	var (
		mutated          []byte
		payloads         []string
		unmatched        []string
		additionalGroups int
	)
	switch {
	case len(opts.RawRequest) > 0:
		mutated = opts.RawRequest
	case len(opts.Mutations) > 0:
		m, p, u, ag, err := applyMutations(opts.BaselineRequest, opts.Mutations)
		if err != nil {
			return nil, err
		}
		mutated, payloads, unmatched, additionalGroups = m, p, u, ag
	default:
		// No mutations, no override — replay the baseline verbatim.
		// Useful for re-checking a stored record under fresh cookies.
		mutated = opts.BaselineRequest
	}

	if len(opts.HeaderOverlay) > 0 {
		mutated = overlayHeaders(mutated, opts.HeaderOverlay)
	}

	// send routes one request through the caller's Sender (e.g. the Burp bridge)
	// when set, else the built-in net/http path — so via-Burp and native replays
	// share the identical baseline/replay/diff logic below.
	send := func(raw []byte) *Summary {
		if opts.Sender != nil {
			return opts.Sender(ctx, raw)
		}
		return sendRawHTTP(ctx, opts.Client, raw, opts.Scheme, opts.Hostname, opts.Port, opts.NoRedirects, excerptCap)
	}

	sentReq, sentTrunc := clipBytes(mutated, excerptCap)

	var baseline *Summary
	switch {
	case len(opts.BaselineResponse) > 0:
		baseline = baselineFromResponse(opts.BaselineResponse, opts.BaselineStatus, opts.BaselineResponseTime, excerptCap)
	case len(opts.BaselineRequest) > 0 && !opts.SendBaseline && bytes.Equal(mutated, opts.BaselineRequest):
		// The request is its own baseline: send it once, with nothing to diff.
		return &Result{
			MutatedRequest:      sentReq,
			MutatedRequestTrunc: sentTrunc,
			Replay:              send(mutated),
			AdditionalGroups:    additionalGroups,
			Unmatched:           unmatched,
			RawMutatedRequest:   append([]byte(nil), mutated...),
		}, nil
	case len(opts.BaselineRequest) > 0:
		baseline = send(opts.BaselineRequest)
	default:
		baseline = &Summary{}
	}

	replay := send(mutated)
	diff := computeDiff(baseline, replay, payloads)

	return &Result{
		MutatedRequest:      sentReq,
		MutatedRequestTrunc: sentTrunc,
		Baseline:            baseline,
		Replay:              replay,
		Diff:                diff,
		AdditionalGroups:    additionalGroups,
		Unmatched:           unmatched,
		RawMutatedRequest:   append([]byte(nil), mutated...),
	}, nil
}
