package spring_jolokia_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsJolokiaAgent drives the real scan method against a
// host that exposes the Jolokia JMX agent at /jolokia. The module fingerprints a
// random 404 path first, then probes the fixed jolokia paths; the
// agent/protocol/config JSON markers on a 200 response trigger a finding.
func TestScanPerRequest_DetectsJolokiaAgent(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jolokia" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"request":{"type":"version"},"value":{"agent":"1.6.2","protocol":"7.2","config":{"agentId":"jolokia"}},"status":200}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a Jolokia finding when /jolokia exposes the agent")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every jolokia
// probe yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 404s all jolokia paths must not yield a finding")
}

// TestCanProcess covers the module gate: it requires a non-nil response baseline.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil), "nil ctx must not be processed")

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "a request without a response baseline must not be processed")

	withResp := httpmsg.NewHttpRequestResponse(rr.Request(), httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\n")))
	assert.True(t, m.CanProcess(withResp), "a request with a response baseline must be processed")
}
