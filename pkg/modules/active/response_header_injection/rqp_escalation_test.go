package response_header_injection

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// echoServer reflects the decoded query parameter into the body so the module's
// CRLF body-break payload is confirmed (mirrors the positive detection test).
func echoServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("echo: " + r.URL.Query().Get("q")))
	}))
}

func hasRQPEvidence(extracted []string) bool {
	for _, e := range extracted {
		if strings.HasPrefix(e, "rqp-amplification=") {
			return true
		}
	}
	return false
}

// TestScanPerInsertionPoint_RQPEscalation confirms that when the captured
// response indicates an HTTP/1.1 keep-alive connection behind a pooling cache/CDN,
// a confirmed header injection is escalated to High and tagged with RQP evidence.
func TestScanPerInsertionPoint_RQPEscalation(t *testing.T) {
	t.Parallel()
	srv := echoServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	// Captured original response: HTTP/1.1 keep-alive behind a CDN/cache layer.
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nX-Cache: MISS\r\nServer: cloudflare\r\n\r\necho: test"))
	ctx := httpmsg.NewHttpRequestResponse(rr.Request(), resp)
	ip := modtest.InsertionPoint(t, ctx, "q")

	res, err := New().ScanPerInsertionPoint(ctx, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a confirmed response-injection finding")
	assert.Equal(t, severity.High, res[0].Info.Severity, "RQP amplification must escalate the finding to High")
	assert.True(t, hasRQPEvidence(res[0].ExtractedResults), "RQP amplification evidence must be recorded")
}

// TestScanPerInsertionPoint_NoRQPWithoutProxy confirms that without a pooling
// front-end the same injection is NOT escalated (severity left to the module
// default, no RQP evidence).
func TestScanPerInsertionPoint_NoRQPWithoutProxy(t *testing.T) {
	t.Parallel()
	srv := echoServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	// Captured original response: plain HTTP/1.1 origin, no cache/proxy layer.
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\necho: test"))
	ctx := httpmsg.NewHttpRequestResponse(rr.Request(), resp)
	ip := modtest.InsertionPoint(t, ctx, "q")

	res, err := New().ScanPerInsertionPoint(ctx, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a confirmed response-injection finding")
	assert.Equal(t, severity.Undefined, res[0].Info.Severity, "no proxy layer means no RQP escalation")
	assert.False(t, hasRQPEvidence(res[0].ExtractedResults), "no RQP evidence without a pooling front-end")
}
