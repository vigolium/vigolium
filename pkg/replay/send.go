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
	gohttp "net/http"
	"net/url"
	"os"
	"time"
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
// operator can pipe through Burp. Pass jar=nil for stateless replays.
func NewDefaultClient(jar gohttp.CookieJar, timeout time.Duration) *gohttp.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &gohttp.Client{
		Timeout: timeout,
		Jar:     jar,
		Transport: &gohttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for replay
			Proxy:           proxyFromEnv,
		},
	}
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

// sendRawHTTP parses raw request bytes, rewrites the URL with the
// supplied scheme/hostname/port, and sends via client. A *Summary is
// returned even on transport error so callers always get a structured
// response. noRedirects clones the client to avoid mutating shared
// redirect policy across calls.
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
	host := hostname
	if port > 0 && !((scheme == "http" && port == 80) || (scheme == "https" && port == 443)) {
		host = fmt.Sprintf("%s:%d", hostname, port)
	}
	req.URL = &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
	}
	req.Host = hostname
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

	return &Summary{
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
	if opts.Client == nil {
		return nil, fmt.Errorf("replay.Do: opts.Client is required")
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

	var baseline *Summary
	if len(opts.BaselineResponse) > 0 {
		baseline = baselineFromResponse(opts.BaselineResponse, opts.BaselineStatus, opts.BaselineResponseTime, excerptCap)
	} else if len(opts.BaselineRequest) > 0 {
		baseline = sendRawHTTP(ctx, opts.Client, opts.BaselineRequest, opts.Scheme, opts.Hostname, opts.Port, opts.NoRedirects, excerptCap)
	} else {
		baseline = &Summary{}
	}

	replay := sendRawHTTP(ctx, opts.Client, mutated, opts.Scheme, opts.Hostname, opts.Port, opts.NoRedirects, excerptCap)
	diff := computeDiff(baseline, replay, payloads)

	sentReq, sentTrunc := clipBytes(mutated, excerptCap)

	return &Result{
		MutatedRequest:      sentReq,
		MutatedRequestTrunc: sentTrunc,
		Baseline:            baseline,
		Replay:              replay,
		Diff:                diff,
		AdditionalGroups:    additionalGroups,
		Unmatched:           unmatched,
	}, nil
}
