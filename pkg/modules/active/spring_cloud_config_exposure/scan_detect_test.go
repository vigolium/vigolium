package spring_cloud_config_exposure

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

// TestScanPerRequest_DetectsConfigServer drives the real scan method against a
// host that exposes a Spring Cloud Config Server at /application/default. The
// module fingerprints a random 404 path first, then probes the fixed config
// paths; the propertySources JSON markers on a 200 response trigger a finding.
func TestScanPerRequest_DetectsConfigServer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/application/default" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"application","profiles":["default"],"propertySources":[{"name":"classpath:/application.yml","source":{"spring.datasource.password":"s3cr3t"}}]}`))
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
	require.NotEmpty(t, res, "expected a config-server finding when /application/default exposes propertySources")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every config probe
// yields no finding.
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
	assert.Empty(t, res, "a host that 404s all config paths must not yield a finding")
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
