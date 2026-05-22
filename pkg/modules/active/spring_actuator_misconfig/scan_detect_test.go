package spring_actuator_misconfig

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsActuatorEnv drives the real scan method against a
// server that exposes a Spring Boot actuator /env endpoint: status 200, a JSON
// content type, and a body carrying the telltale "server.port" property. The
// module derives candidate paths from the seed path and probes each with the
// actuator payloads, so returning the env body for any path ending in /env
// fires detection.
func TestScanPerRequest_DetectsActuatorEnv(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/env") {
			w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"activeProfiles":[],"propertySources":[{"name":"systemProperties","properties":{"server.port":{"value":"8080"},"local.server.port":{"value":"8080"}}}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/v1/users")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an actuator finding when /env returns server.port JSON")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every actuator
// probe yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/v1/users")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 404s all actuator paths must not yield a finding")
}
