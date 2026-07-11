package grpc_web_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/grpcweb"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func makeHTTPCtx(rawReq, rawResp string) *httpmsg.HttpRequestResponse {
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_ResponseContentType drives a response with a gRPC-Web
// content type and expects an endpoint finding.
func TestScanPerRequest_ResponseContentType(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"POST /svc.Service/Method HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\n\r\n",
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "gRPC-Web Endpoint Detected", results[0].Info.Name)
}

// TestScanPerRequest_GrpcStatusHeader drives a response carrying a grpc-status
// header and expects detection.
func TestScanPerRequest_GrpcStatusHeader(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"POST /svc.Service/Method HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\ngrpc-status: 0\r\n\r\n",
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_RequestContentType drives a request with a grpc content
// type and expects detection from the request side.
func TestScanPerRequest_RequestContentType(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"POST /svc.Service/Method HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/grpc-web\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_MarksTechAndDecodesTrailer drives a real gRPC-Web
// response (framed data + trailer) on an RPC-shaped path and asserts:
//   - the "grpc-web" tech tag is published to the registry once for the host,
//   - the RPC method path is surfaced as an indicator,
//   - the grpc-status/grpc-message are decoded from the trailer frame.
func TestScanPerRequest_MarksTechAndDecodesTrailer(t *testing.T) {
	t.Parallel()
	m := New()

	body := append(
		grpcweb.EncodeFrame(false, []byte("payload-bytes")),
		grpcweb.EncodeFrame(true, []byte("grpc-status:0\r\ngrpc-message:OK\r\n"))...,
	)
	rawResp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: %d\r\n\r\n%s",
		len(body), string(body),
	)
	ctx := makeHTTPCtx(
		"POST /pkg.Svc/GetThing HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/grpc-web+proto\r\n\r\n",
		rawResp,
	)

	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	u, err := ctx.URL()
	require.NoError(t, err)
	host := u.Host

	results, err := m.ScanPerRequest(ctx, sc)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.True(t, sc.TechStack.Has(host, "grpc-web"), "grpc-web tech tag must be published for the host")

	extracted := results[0].ExtractedResults
	assert.Contains(t, extracted, "RPC: /pkg.Svc/GetThing")
	assert.Contains(t, extracted, "grpc-status: 0")
	assert.Contains(t, extracted, "grpc-message: OK")
}

// TestScanPerRequest_NoGrpc drives a plain HTTP request/response with no gRPC
// indicators and expects no findings.
func TestScanPerRequest_NoGrpc(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
