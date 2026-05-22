package aspnet_service_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsODataMetadata serves an OData $metadata document. The
// module fingerprints a random 404 then probes the common service paths and should
// flag /odata/$metadata (200 + edmx/EntityType markers).
func TestScanPerRequest_DetectsODataMetadata(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/odata/$metadata" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<edmx:Edmx Version="4.0"><EntityType Name="Order"/></edmx:Edmx>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not-here unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a service-exposure finding when /odata/$metadata is exposed")
}

// TestScanPerRequest_DetectsASMXWSDL drives the traffic-aware branch: when the seed
// URL ends in .asmx, the module probes <path>?WSDL and flags a WSDL disclosure.
func TestScanPerRequest_DetectsASMXWSDL(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/Service.asmx" && r.URL.Query().Has("WSDL") {
			w.Header().Set("Content-Type", "text/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<wsdl:definitions><wsdl:types/><wsdl:portType/></wsdl:definitions>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not-here unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/Service.asmx"), "text/xml", "<soap/>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a WSDL disclosure finding for an .asmx endpoint serving ?WSDL")
}

// TestScanPerRequest_NoFalsePositive ensures a host with no exposed services
// (all probes 404) produces no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 Not Found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed services must not yield a finding")
}

// TestCanProcess_RequiresResponse verifies the module only runs with a baseline response.
func TestCanProcess_RequiresResponse(t *testing.T) {
	t.Parallel()
	m := New()
	bare := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(bare))
	assert.True(t, m.CanProcess(modtest.Response(bare, "text/html", "<html></html>")))
}
