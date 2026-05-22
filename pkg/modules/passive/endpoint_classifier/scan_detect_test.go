package endpoint_classifier

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// fakeResolver maps every request hash to a fixed UUID.
type fakeResolver struct{ uuid string }

func (f *fakeResolver) ResolveRequestUUID(string) string { return f.uuid }

// fakeAnnotator records the remarks appended during a scan.
type fakeAnnotator struct {
	got map[string][]string
}

func (f *fakeAnnotator) AppendRemarks(_ context.Context, annotations map[string][]string) error {
	if f.got == nil {
		f.got = map[string][]string{}
	}
	for k, v := range annotations {
		f.got[k] = append(f.got[k], v...)
	}
	return nil
}

// makeHTTPCtx builds a request/response pair with the given method, path,
// request Content-Type, response Content-Type, status, and Authorization header.
func makeHTTPCtx(method, path, reqCT, respCT string, status int, auth string) *httpmsg.HttpRequestResponse {
	rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: example.com\r\n", method, path)
	if reqCT != "" {
		rawReq += fmt.Sprintf("Content-Type: %s\r\n", reqCT)
	}
	if auth != "" {
		rawReq += fmt.Sprintf("Authorization: %s\r\n", auth)
	}
	rawReq += "\r\n"
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	rawResp := fmt.Sprintf("HTTP/1.1 %d OK\r\nContent-Type: %s\r\n\r\n{}", status, respCT)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_AnnotatesAPIEndpoint drives an authenticated JSON API
// endpoint and asserts the derived semantic tags are appended to the record.
func TestScanPerRequest_AnnotatesAPIEndpoint(t *testing.T) {
	t.Parallel()
	m := New()
	annot := &fakeAnnotator{}
	scanCtx := &modkit.ScanContext{
		RemarksAnnotator:    annot,
		RequestUUIDResolver: &fakeResolver{uuid: "rec-1"},
	}
	ctx := makeHTTPCtx("GET", "/api/users", "", "application/json", 200, "Bearer token123")

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	// This module annotates the DB record rather than emitting findings.
	assert.Empty(t, results)

	tags := annot.got["rec-1"]
	require.NotEmpty(t, tags)
	assert.Contains(t, tags, "api-endpoint")
	assert.Contains(t, tags, "authenticated")
	assert.Contains(t, tags, "json-api")
}

// TestScanPerRequest_NoAnnotatorIsNoop verifies that without an annotator and
// resolver wired in, the module is a safe no-op.
func TestScanPerRequest_NoAnnotatorIsNoop(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("GET", "/api/users", "", "application/json", 200, "")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_PlainPageNoTags verifies a plain root request with no
// classifiable characteristics still leaves the record unannotated.
func TestScanPerRequest_PlainPageNoTags(t *testing.T) {
	t.Parallel()
	m := New()
	annot := &fakeAnnotator{}
	scanCtx := &modkit.ScanContext{
		RemarksAnnotator:    annot,
		RequestUUIDResolver: &fakeResolver{uuid: "rec-2"},
	}
	// A 200 with no content type and no other signals yields no tags.
	ctx := makeHTTPCtx("GET", "/", "", "", 200, "")
	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
	assert.Empty(t, annot.got["rec-2"])
}
