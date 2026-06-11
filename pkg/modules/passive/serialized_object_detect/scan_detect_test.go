package serialized_object_detect

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeReqCtx builds a request/response pair with the given GET request path+query.
func makeReqCtx(pathQuery string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", pathQuery))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// makeParamCtx builds a GET request carrying a single, properly URL-encoded
// query parameter. Parameters() round-trips the value back to its decoded form.
func makeParamCtx(name, value string) *httpmsg.HttpRequestResponse {
	q := url.Values{}
	q.Set(name, value)
	return makeReqCtx("/load?" + q.Encode())
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_PHPSerialized drives a request parameter carrying a PHP
// serialized object and expects a finding flagging the format and parameter.
func TestScanPerRequest_PHPSerialized(t *testing.T) {
	t.Parallel()
	m := New()
	// O:8:"stdClass":1:{...} URL-encoded
	ctx := makeReqCtx(`/load?data=O%3A8%3A%22stdClass%22%3A1%3A%7Bs%3A4%3A%22name%22%3Bs%3A3%3A%22bob%22%3B%7D`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "data", results[0].FuzzingParameter)
	assert.Equal(t, "Serialized PHP Object in Parameter", results[0].Info.Name)
}

// TestScanPerRequest_JavaSerialized drives a Java serialized object (base64
// prefix rO0AB) in a parameter and expects a finding.
func TestScanPerRequest_JavaSerialized(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx(`/load?obj=rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbg`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Serialized Java Object in Parameter", results[0].Info.Name)
}

// TestScanPerRequest_NodeSerialize drives a node-serialize payload carrying the
// _$$ND_FUNC$$_ RCE marker and expects a Node.js finding.
func TestScanPerRequest_NodeSerialize(t *testing.T) {
	t.Parallel()
	m := New()
	payload := `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}`
	ctx := makeParamCtx("obj", payload)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Serialized Node.js Object in Parameter", results[0].Info.Name)
}

// TestScanPerRequest_RubyMarshalBase64 drives a base64-wrapped Ruby Marshal
// stream (version header 0x04 0x08) and expects a base64-wrapped Ruby finding.
func TestScanPerRequest_RubyMarshalBase64(t *testing.T) {
	t.Parallel()
	m := New()
	// Marshal.dump([1, 2]) => "\x04\b[\ai\x06i\a"
	marshal := []byte{0x04, 0x08, '[', 0x07, 'i', 0x06, 'i', 0x07}
	ctx := makeParamCtx("state", base64.StdEncoding.EncodeToString(marshal))
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Serialized Ruby (base64-wrapped) Object in Parameter", results[0].Info.Name)
}

// TestScanPerRequest_PHPBase64Wrapped drives a base64-wrapped PHP serialized
// object — previously missed because the raw matcher only saw the base64 text.
func TestScanPerRequest_PHPBase64Wrapped(t *testing.T) {
	t.Parallel()
	m := New()
	php := `O:8:"stdClass":1:{s:4:"name";s:3:"bob";}`
	ctx := makeParamCtx("data", base64.StdEncoding.EncodeToString([]byte(php)))
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Serialized PHP (base64-wrapped) Object in Parameter", results[0].Info.Name)
}

// TestScanPerRequest_PythonPickleBase64 drives a base64-wrapped pickle stream
// (PROTO opcode 0x80 + protocol version 4).
func TestScanPerRequest_PythonPickleBase64(t *testing.T) {
	t.Parallel()
	m := New()
	pickle := []byte{0x80, 0x04, 0x95, 0x10, 0x00, 0x00, 0x00, 0x2e}
	ctx := makeParamCtx("p", base64.StdEncoding.EncodeToString(pickle))
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "Serialized Python (base64-wrapped) Object in Parameter", results[0].Info.Name)
}

// TestScanPerRequest_Benign drives a benign parameter value and expects no
// findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("/search?q=hello+world")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_EncryptedTokenBenign is a regression guard: an AES-GCM
// encrypted token wrapped as base64 JSON ({"i":<iv>,"t":<ciphertext+tag>}) is
// not a serialized object and must not be flagged, even though it base64-decodes
// cleanly to JSON. This is the real-world aliId envelope shape.
func TestScanPerRequest_EncryptedTokenBenign(t *testing.T) {
	t.Parallel()
	m := New()
	aliID := "eyJpIjoiNUNmUzc0K1pYTVVVN2lRRCIsInQiOiJCUzYyNHpWejlVTkp5XC9OS1A3XC9Ubnc9PSJ9"
	ctx := makeParamCtx("aliId", aliID)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_BenignBase64 guards against the decode pass flagging an
// ordinary base64 value that decodes to plain text.
func TestScanPerRequest_BenignBase64(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeParamCtx("token", base64.StdEncoding.EncodeToString([]byte("hello world this is fine")))
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
