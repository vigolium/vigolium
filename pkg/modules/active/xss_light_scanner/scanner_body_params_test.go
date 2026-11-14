package xss_light_scanner

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// A POST handler that reflects a form field unescaped is found by the body
// scanner — the URL scanner only reached it through POST→GET, which
// this handler (POST only) rejects. Not navigable, so the finding is a lead.
func TestBodyParams_ReflectedFormField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		b, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body><p>Hello "+v.Get("comment")+"</p></body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.RequestMethod(t, http.MethodPost, srv.URL+"/feedback", "comment=helloworld"),
		"text/html", "<html><body><p>Hello helloworld</p></body></html>")

	m := NewBodyParamsScanner()
	m.Probe = nil
	require.True(t, m.CanProcess(rr))
	res, err := m.ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "reflected POST body field must be found")
	assert.Equal(t, BodyParamsModuleID, res[0].ModuleID)
	assert.Equal(t, severity.Suspect, res[0].Info.Severity)
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence)
}

// The passive prefilter: a body parameter whose value does not reflect in the
// stored response costs no request.
func TestBodyParams_NonReflectingFieldSendsNothing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = io.WriteString(w, "<html>ok</html>")
	}))
	defer srv.Close()

	rr := modtest.Response(
		modtest.RequestMethod(t, http.MethodPost, srv.URL+"/feedback", "comment=helloworld"),
		"text/html", "<html>thanks</html>")
	m := NewBodyParamsScanner()
	m.Probe = nil
	res, err := m.ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Zero(t, hits)
}
