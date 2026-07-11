package jackson_deserialize_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func makeHTTPCtx(contentType, body string) *httpmsg.HttpRequestResponse {
	return makeHTTPCtxStatus("200 OK", contentType, body)
}

func makeHTTPCtxStatus(status, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /api/obj HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: %s\r\n\r\n%s", status, contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_TypeField drives a JSON response carrying a Jackson type
// discriminator (@class) and expects a deserialization-indicator finding.
func TestScanPerRequest_TypeField(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"@class":"com.example.User","name":"alice"}`
	ctx := makeHTTPCtx("application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Jackson/Java Deserialization Indicators", results[0].Info.Name)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}

// TestScanPerRequest_JacksonError drives a body with a Jackson mapping exception
// (any content type) and expects a finding.
func TestScanPerRequest_JacksonError(t *testing.T) {
	t.Parallel()
	m := New()
	body := `com.fasterxml.jackson.databind.JsonMappingException: cannot deserialize`
	ctx := makeHTTPCtx("text/plain", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

// TestScanPerRequest_DeserError drives a Java ObjectInputStream deserialization
// error and expects a finding.
func TestScanPerRequest_DeserError(t *testing.T) {
	t.Parallel()
	m := New()
	body := `java.io.InvalidClassException: local class incompatible`
	ctx := makeHTTPCtx("text/plain", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

func TestScanPerRequest_CorroboratedErrorResponseIsCandidate(t *testing.T) {
	t.Parallel()
	m := New()
	body := `com.fasterxml.jackson.databind.JsonMappingException: cannot deserialize value at [Source: input; line: 1, column: 8]`
	ctx := makeHTTPCtxStatus("500 Internal Server Error", "text/plain", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	assert.Equal(t, false, results[0].Metadata["code_execution_tested"])
}

func TestScanPerRequest_TypeFieldInsideStringIgnored(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"message":"Example payload: {\"@class\":\"com.example.User\"}"}`
	ctx := makeHTTPCtx("application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_JSAssetReverseDNS is a regression for the FP class where a
// minified JS bundle (served text/javascript) full of reverse-DNS identifiers
// like "io.foo"/"com.app.title" tripped the Java-class-ref needle into a Medium.
func TestScanPerRequest_JSAssetReverseDNS(t *testing.T) {
	t.Parallel()
	m := New()
	body := `var a={"com.app.title":"x","io.module.name":"y"};function NN(){return a}`
	ctx := makeHTTPCtx("text/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_BareClassRefNoDiscriminator ensures a JSON body with a
// Java-package-shaped string but NO @class/@type discriminator does not fire —
// a bare class reference is not evidence of polymorphic deserialization.
func TestScanPerRequest_BareClassRefNoDiscriminator(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"plugin":"com.example.SomeThing","enabled":true}`
	ctx := makeHTTPCtx("application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign drives a plain JSON response with no Jackson/Java
// indicators and expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"name":"alice","age":30}`
	ctx := makeHTTPCtx("application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
