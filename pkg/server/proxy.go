package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/server/mitm"
	"go.uber.org/zap"
)

// newIngestProxy creates a transparent HTTP forward proxy that records
// request/response pairs into the database.
//
// When mitmCA is non-nil, HTTPS CONNECT tunnels are intercepted: the proxy
// terminates TLS with a leaf certificate minted by mitmCA, records the
// decrypted request/response, and re-originates to the real target. When nil,
// CONNECT tunnels are passed through unmodified (HTTPS traffic is not recorded).
// upstreamInsecure skips verification of the real server's certificate during
// re-origination (only meaningful when mitmCA is set).
func newIngestProxy(addr string, db *database.DB, repo *database.Repository, rw *database.RecordWriter, settings *config.Settings, getScopeMatcher func() *config.ScopeMatcher, mitmCA *mitm.CA, upstreamInsecure bool) *http.Server {
	handler := &proxyHandler{
		db:              db,
		repo:            repo,
		recordWriter:    rw,
		settings:        settings,
		transport:       &http.Transport{},
		getScopeMatcher: getScopeMatcher,
		mitmCA:          mitmCA,
	}

	if mitmCA != nil {
		handler.upstreamTransport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// #nosec G402 — verification is on by default; only skipped when
				// the operator explicitly passes --proxy-insecure.
				InsecureSkipVerify: upstreamInsecure,
				NextProtos:         []string{"http/1.1"}, // keep upstream HTTP/1.1
			},
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	}

	return &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}

type proxyHandler struct {
	db              *database.DB
	repo            *database.Repository
	recordWriter    *database.RecordWriter
	settings        *config.Settings
	transport       *http.Transport
	getScopeMatcher func() *config.ScopeMatcher

	// mitmCA, when non-nil, enables TLS interception of CONNECT tunnels.
	mitmCA *mitm.CA
	// upstreamTransport re-originates intercepted requests to the real target.
	// Non-nil only when mitmCA is set.
	upstreamTransport *http.Transport
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// defaultMaxProxyBodySize is the maximum body size (request or response) that
// the proxy will buffer for recording. Larger bodies are still forwarded to
// the client but skipped for database recording to prevent OOM.
const defaultMaxProxyBodySize = 10 * 1024 * 1024 // 10 MB

// handleHTTP forwards plain HTTP requests and records the transaction.
func (p *proxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	const maxBody = defaultMaxProxyBodySize

	// Buffer request body with size limit
	var reqBody []byte
	if r.Body != nil {
		limited := io.LimitReader(r.Body, maxBody+1)
		var err error
		reqBody, err = io.ReadAll(limited)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadGateway)
			return
		}
		if int64(len(reqBody)) > maxBody {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	// Ensure absolute URL for proxy
	if !r.URL.IsAbs() {
		http.Error(w, "absolute URL required for proxy", http.StatusBadRequest)
		return
	}

	// Forward the request
	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		zap.L().Debug("Proxy forward failed", zap.String("url", r.URL.String()), zap.Error(err))
		http.Error(w, "proxy forward failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// If response is known to be too large, stream directly and skip recording
	if resp.ContentLength > maxBody {
		zap.L().Debug("Proxy: response too large, streaming without recording",
			zap.String("url", r.URL.String()),
			zap.Int64("content_length", resp.ContentLength))
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	// Buffer response body with size limit
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		http.Error(w, "failed to read response", http.StatusBadGateway)
		return
	}

	// Write response back to client
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	// If response exceeded limit mid-read, skip recording
	if int64(len(respBody)) > maxBody {
		zap.L().Debug("Proxy: response exceeded size limit, skipping recording",
			zap.String("url", r.URL.String()))
		return
	}

	// Record transaction in background
	go p.recordTransaction(r, reqBody, resp, respBody)
}

// handleConnect handles HTTPS CONNECT. With a MITM CA configured it intercepts
// and records the TLS traffic; otherwise it tunnels through without recording.
func (p *proxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	if p.mitmCA != nil {
		p.interceptConnect(w, r)
		return
	}
	p.tunnelConnect(w, r)
}

// tunnelConnect blindly pipes a CONNECT tunnel between client and target. The
// proxy never sees the plaintext, so nothing is recorded.
func (p *proxyHandler) tunnelConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "cannot reach destination", http.StatusBadGateway)
		return
	}

	// Hijack BEFORE acknowledging so we write the CONNECT response onto the raw
	// connection ourselves (calling WriteHeader first leaves the server in
	// control of the framing, which corrupts the tunnel).
	clientConn, err := hijackConn(w)
	if err != nil {
		_ = destConn.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = destConn.Close()
		_ = clientConn.Close()
		return
	}

	go func() {
		defer func() { _ = destConn.Close() }()
		defer func() { _ = clientConn.Close() }()
		_, _ = io.Copy(destConn, clientConn)
	}()
	go func() {
		defer func() { _ = destConn.Close() }()
		defer func() { _ = clientConn.Close() }()
		_, _ = io.Copy(clientConn, destConn)
	}()
}

// interceptConnect terminates the client's TLS using a minted leaf certificate,
// then serves the decrypted requests over the tunnel — recording each and
// re-originating to the real target.
func (p *proxyHandler) interceptConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host // authority form, e.g. "example.com:443"

	clientConn, err := hijackConn(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tlsConn := tls.Server(clientConn, p.mitmCA.TLSConfigForHost(hostPort))
	if err := tlsConn.Handshake(); err != nil {
		zap.L().Debug("Proxy MITM: client TLS handshake failed",
			zap.String("host", hostPort), zap.Error(err))
		return
	}
	defer func() { _ = tlsConn.Close() }()

	p.serveDecrypted(tlsConn, hostPort)
}

// serveDecrypted reads plaintext HTTP requests off an intercepted TLS
// connection (honoring keep-alive), forwards each to the real target, records
// the transaction, and writes the response back to the client.
func (p *proxyHandler) serveDecrypted(tlsConn *tls.Conn, hostPort string) {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				zap.L().Debug("Proxy MITM: read request", zap.String("host", host), zap.Error(err))
			}
			return
		}

		// Buffer the request body (size-limited) so it can be both forwarded
		// and recorded.
		var reqBody []byte
		if req.Body != nil {
			reqBody, _ = io.ReadAll(io.LimitReader(req.Body, defaultMaxProxyBodySize+1))
			_ = req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader(reqBody))
		}

		// Turn the origin-form request into an absolute one for the client
		// transport and strip fields that don't belong on an outbound request.
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		if req.URL.Host == "" {
			req.URL.Host = hostPort
			req.Host = host
		}
		req.RequestURI = "" // must be empty on a client request
		req.Header.Del("Proxy-Connection")
		// Let the transport negotiate (and transparently decompress) encoding so
		// recorded + returned bodies are plaintext — far more useful to the
		// scanner than gzipped bytes.
		req.Header.Del("Accept-Encoding")

		resp, err := p.upstreamTransport.RoundTrip(req)
		if err != nil {
			zap.L().Debug("Proxy MITM: upstream round-trip failed",
				zap.String("url", req.URL.String()), zap.Error(err))
			writeBadGateway(tlsConn, err)
			return
		}

		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, defaultMaxProxyBodySize+1))
		_ = resp.Body.Close()
		keepAlive := !resp.Close && !req.Close

		// Write the response back to the client first, then record. Recording
		// after the write keeps the client off the DB-write latency path and
		// avoids racing recordTransaction against writeIntercepted's mutation
		// of resp (both touch resp.Header).
		if err := writeIntercepted(tlsConn, resp, respBody); err != nil {
			return
		}
		p.recordTransaction(req, reqBody, resp, respBody)

		if !keepAlive {
			return
		}
	}
}

// hijackConn takes over the underlying TCP connection from the ResponseWriter.
func hijackConn(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("hijacking not supported")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack connection: %w", err)
	}
	return conn, nil
}

// writeIntercepted serializes resp (with the already-buffered body) back to the
// client over the intercepted TLS connection.
func writeIntercepted(w io.Writer, resp *http.Response, body []byte) error {
	// The transport may have decompressed the body, so the upstream
	// Content-Length / Transfer-Encoding no longer apply. Drop them and let
	// resp.Write recompute Content-Length from the buffered body.
	resp.Header.Del("Content-Length")
	resp.Header.Del("Transfer-Encoding")
	resp.TransferEncoding = nil
	resp.ContentLength = int64(len(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp.Write(w)
}

// writeBadGateway emits a minimal 502 onto a raw connection.
func writeBadGateway(w io.Writer, cause error) {
	body := "proxy forward failed: " + cause.Error()
	_, _ = fmt.Fprintf(w,
		"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

// recordTransaction builds an HttpRequestResponse and saves it to the database.
func (p *proxyHandler) recordTransaction(r *http.Request, reqBody []byte, resp *http.Response, respBody []byte) {
	if p.repo == nil {
		return
	}

	// Build raw HTTP request string
	var rawReq strings.Builder
	fmt.Fprintf(&rawReq, "%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
	fmt.Fprintf(&rawReq, "Host: %s\r\n", r.Host)
	for k, vv := range r.Header {
		for _, v := range vv {
			fmt.Fprintf(&rawReq, "%s: %s\r\n", k, v)
		}
	}
	rawReq.WriteString("\r\n")
	if len(reqBody) > 0 {
		rawReq.Write(reqBody)
	}

	rr, err := httpmsg.ParseRawRequestWithURL(rawReq.String(), r.URL.String())
	if err != nil {
		zap.L().Debug("Proxy: failed to parse recorded request", zap.Error(err))
		return
	}

	// Build raw HTTP response
	var rawResp strings.Builder
	fmt.Fprintf(&rawResp, "%s %s\r\n", resp.Proto, resp.Status)
	for k, vv := range resp.Header {
		for _, v := range vv {
			fmt.Fprintf(&rawResp, "%s: %s\r\n", k, v)
		}
	}
	rawResp.WriteString("\r\n")
	if len(respBody) > 0 {
		rawResp.Write(respBody)
	}

	httpResp := httpmsg.NewHttpResponse([]byte(rawResp.String()))
	if httpResp != nil {
		rr = rr.WithResponse(httpResp)
	}

	if p.settings != nil {
		matcher := p.getScopeMatcher()
		if matcher != nil {
			if matcher.IsStaticFile(rr.Request().Path()) {
				return
			}
			if p.settings.Scope.AppliedOnIngest && !matcher.InScope(buildScopeMatchInput(rr)) {
				return
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if p.recordWriter != nil {
		if _, err := p.recordWriter.Write(ctx, rr, "ingest-proxy", database.DefaultProjectUUID); err != nil {
			zap.L().Debug("Proxy: failed to save record", zap.Error(err))
		}
	} else if _, err := p.repo.SaveRecord(ctx, rr, "ingest-proxy", database.DefaultProjectUUID); err != nil {
		zap.L().Debug("Proxy: failed to save record", zap.Error(err))
	}
}
