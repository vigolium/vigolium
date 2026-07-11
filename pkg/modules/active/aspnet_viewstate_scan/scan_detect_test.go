package aspnet_viewstate_scan

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// validViewState returns a base64-encoded ViewState long enough (>=20 chars and
// >=10 decoded bytes) for the module's MAC-tampering logic to engage.
func validViewState() string {
	return base64.StdEncoding.EncodeToString([]byte("dummy-viewstate-payload-bytes-0123456789"))
}

// htmlWithViewState builds an ASP.NET WebForms HTML page carrying a __VIEWSTATE
// hidden field inside a POST form, the shape the module parses from the baseline.
func htmlWithViewState() string {
	return `<html><body><form method="post" action="/page.aspx">` +
		`<input type="hidden" name="__VIEWSTATE" value="` + validViewState() + `" />` +
		`<input type="hidden" name="__VIEWSTATEGENERATOR" value="CA0B0334" />` +
		`</form></body></html>`
}

// seedWithHTMLResponse builds a request with an HTML baseline response attached
// (the module reads __VIEWSTATE from ctx.Response()).
func seedWithHTMLResponse(t *testing.T, srvURL, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr := modtest.Request(t, srvURL+"/page.aspx")
	return modtest.Response(rr, "text/html; charset=utf-8", body)
}

// TestScanPerRequest_ViewStateDifferentialCandidate drives the valid/tampered/
// malformed controls. Syntactically valid base64 state is processed, while a
// malformed control is rejected; without a semantic effect this remains a
// candidate rather than a confirmed finding.
func TestScanPerRequest_ViewStateDifferentialCandidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if _, err := base64.StdEncoding.DecodeString(r.FormValue("__VIEWSTATE")); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid viewstate encoding"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(htmlWithViewState()))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seedWithHTMLResponse(t, srv.URL, htmlWithViewState())

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeDifferential, res[0].EvidenceGrade)
}

func TestScanPerRequest_Generic200DoesNotProveMACDisabled(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>" + strings.Repeat("generic landing page ", 20) + "</body></html>"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(seedWithHTMLResponse(t, srv.URL, htmlWithViewState()), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a generic 200 response that does not process ViewState is not evidence of disabled MAC")
}

// TestScanPerRequest_DetectsCookielessSession exercises the cookieless-session
// detector, which fires purely from the baseline response body without sending any
// new request.
func TestScanPerRequest_DetectsCookielessSession(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	body := `<html><body><a href="/(S(lit3py55t21z5v55vlm25s55))/default.aspx">home</a></body></html>`
	rr := seedWithHTMLResponse(t, srv.URL, body)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a cookieless-session finding when the body embeds an (S(...)) token")
}

// TestScanPerRequest_NoFalsePositive ensures a page where MAC validation rejects
// the tampered ViewState (verbose error) yields no MAC-disabled finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Concise MAC failure with no stack trace -> module treats MAC as enabled.
		_, _ = w.Write([]byte("Validation of viewstate MAC failed"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seedWithHTMLResponse(t, srv.URL, htmlWithViewState())

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an enabled-MAC page (MAC failure, no stack trace) must not yield a finding")
}

// TestCanProcess_RequiresResponse verifies the module only runs with a baseline response.
func TestCanProcess_RequiresResponse(t *testing.T) {
	t.Parallel()
	m := New()
	bare := modtest.Request(t, "http://example.com/page.aspx")
	assert.False(t, m.CanProcess(bare))
	assert.True(t, m.CanProcess(modtest.Response(bare, "text/html", "<html></html>")))
}

func TestEventValidationMissingIsCandidateOnlyWithRealPostback(t *testing.T) {
	t.Parallel()
	body := htmlWithViewState() + `<script>__doPostBack('ctl00$Main$Save','')</script>`
	rr := modtest.Response(modtest.Request(t, "http://example.com/page.aspx"), "text/html", body)
	result := eventValidationCandidate(rr, body)
	require.NotNil(t, result)
	assert.Equal(t, output.RecordKindCandidate, result.RecordKind)
	assert.Contains(t, result.ExtractedResults[0], "ctl00$Main$Save")
}
