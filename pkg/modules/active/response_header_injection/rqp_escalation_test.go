package response_header_injection

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func hasRQPEvidence(extracted []string) bool {
	for _, e := range extracted {
		if strings.HasPrefix(e, "rqp-amplification=") {
			return true
		}
	}
	return false
}

// TestScanPerInsertionPoint_RQPEscalation confirms that when a genuine header
// injection rides an HTTP/1.1 keep-alive connection behind a pooling cache/CDN,
// it is escalated to High and tagged with RQP evidence.
func TestScanPerInsertionPoint_RQPEscalation(t *testing.T) {
	t.Parallel()
	srv := headerSplitServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	// Captured original response: HTTP/1.1 keep-alive behind a CDN/cache layer.
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nX-Cache: MISS\r\nServer: cloudflare\r\n\r\nok"))
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
	srv := headerSplitServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	// Captured original response: plain HTTP/1.1 origin, no cache/proxy layer.
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"))
	ctx := httpmsg.NewHttpRequestResponse(rr.Request(), resp)
	ip := modtest.InsertionPoint(t, ctx, "q")

	res, err := New().ScanPerInsertionPoint(ctx, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a confirmed response-injection finding")
	assert.Equal(t, severity.Undefined, res[0].Info.Severity, "no proxy layer means no RQP escalation")
	assert.False(t, hasRQPEvidence(res[0].ExtractedResults), "no RQP evidence without a pooling front-end")
}

// TestScanPerInsertionPoint_BodyReflectionNeverEscalates is the core regression
// for the reported false positive: even when the captured response shows a
// pooling front-end (envoy/CloudFront keep-alive), a value reflected into the
// JSON body must NOT be escalated to RQP/High. It stays a Suspect finding with
// no RQP evidence.
func TestScanPerInsertionPoint_BodyReflectionNeverEscalates(t *testing.T) {
	t.Parallel()
	srv := jsonReflectServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	// Captured original response mirrors the reported finding: HTTP/1.1 keep-alive
	// behind envoy + CloudFront — the precondition RQP would otherwise key on.
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 202 Accepted\r\nServer: envoy\r\nX-Cache: Miss from cloudfront\r\nVia: 1.1 cloudfront\r\n\r\n{}"))
	ctx := httpmsg.NewHttpRequestResponse(rr.Request(), resp)
	ip := modtest.InsertionPoint(t, ctx, "q")

	res, err := New().ScanPerInsertionPoint(ctx, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "value reflection should surface as a Suspect finding")
	assert.Equal(t, locBodyReflection, extractedLocation(res[0].ExtractedResults))
	assert.Equal(t, severity.Suspect, res[0].Info.Severity,
		"a body reflection behind a proxy must NOT be escalated to RQP/High")
	assert.False(t, hasRQPEvidence(res[0].ExtractedResults),
		"reflection-only findings are not RQP-escalatable")
}
