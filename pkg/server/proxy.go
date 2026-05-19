package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// newIngestProxy creates a transparent HTTP forward proxy that records
// request/response pairs into the database.
func newIngestProxy(addr string, db *database.DB, repo *database.Repository, rw *database.RecordWriter, settings *config.Settings, getScopeMatcher func() *config.ScopeMatcher) *http.Server {
	handler := &proxyHandler{
		db:              db,
		repo:            repo,
		recordWriter:    rw,
		settings:        settings,
		transport:       &http.Transport{},
		getScopeMatcher: getScopeMatcher,
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

// handleConnect handles HTTPS CONNECT tunneling (pass-through, no recording).
func (p *proxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "cannot reach destination", http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		_ = destConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		_ = destConn.Close()
		return
	}

	// Bidirectional copy
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
