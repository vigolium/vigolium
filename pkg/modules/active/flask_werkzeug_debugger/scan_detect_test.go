package flask_werkzeug_debugger

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

// TestScanPerRequest_DetectsWerkzeugDebugger drives the real scan method against
// a host that returns the interactive Werkzeug debugger markers on any error
// page. The module's 404/500 probes should surface a critical RCE finding.
func TestScanPerRequest_DetectsWerkzeugDebugger(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// Telltale interactive debugger console markup.
		_, _ = w.Write([]byte(`<html><head><title>Werkzeug Debugger</title>` +
			`<script src="?__debugger__=yes&cmd=resource&f=debugger.js"></script></head>` +
			`<body class="console-active"><div class="traceback-repr">` +
			`Traceback (most recent call last): The debugger caught an exception</div></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a Werkzeug debugger finding when debugger markers are present")
	assert.Contains(t, strings.ToLower(res[0].Info.Name), "werkzeug")
}

// TestScanPerRequest_NoFalsePositive ensures a benign error page lacking
// Werkzeug markers yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a plain 404 must not yield a Werkzeug debugger finding")
}
