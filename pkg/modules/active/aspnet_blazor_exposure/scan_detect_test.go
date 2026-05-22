package aspnet_blazor_exposure

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

// TestScanPerRequest_DetectsBlazorBootManifest serves a Blazor WASM boot manifest
// at /_framework/blazor.boot.json. The module fingerprints a random 404, probes the
// fixed Blazor paths, and should flag the manifest (200 + marker keywords) plus the
// assembly-enumeration follow-up finding.
func TestScanPerRequest_DetectsBlazorBootManifest(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_framework/blazor.boot.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"mainAssemblyName":"App","linkerEnabled":true,"resources":{"assembly":{"App.dll":"sha256-x","System.dll":"sha256-y"}}}`))
			return
		}
		// Distinct 404 body for the random fingerprint path and everything else.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a Blazor exposure finding when the boot manifest is served")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every Blazor probe
// (the random fingerprint and the fixed paths look identical) yields no finding.
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
	assert.Empty(t, res, "a host with no Blazor endpoints must not yield a finding")
}

// TestCanProcess_RequiresResponse verifies the module only runs when a baseline
// response is attached.
func TestCanProcess_RequiresResponse(t *testing.T) {
	t.Parallel()
	m := New()
	bare := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(bare), "no baseline response means CanProcess is false")

	withResp := modtest.Response(bare, "text/html", "<html></html>")
	assert.True(t, m.CanProcess(withResp), "a baseline response makes CanProcess true")
}

// TestExtractAssemblyNames covers the boot-manifest parser across .NET formats.
func TestExtractAssemblyNames(t *testing.T) {
	t.Parallel()
	manifest := map[string]interface{}{
		"resources": map[string]interface{}{
			"assembly": map[string]interface{}{
				"App.dll":      "sha256-a",
				"System.dll":   "sha256-b",
				"ignore.txt":   "sha256-c",
				"runtime.wasm": "sha256-d",
			},
		},
	}
	names := extractAssemblyNames(manifest)
	require.NotEmpty(t, names)
	joined := strings.Join(names, ",")
	assert.Contains(t, joined, "App.dll")
	assert.NotContains(t, joined, "ignore.txt", "non-dll/wasm resources must be skipped")
}
