package lfi_generic

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

// passwdEcho simulates a server vulnerable to LFI: when the named parameter's
// value targets /etc/passwd, it returns the contents of that file — the
// observable effect of a successful path-traversal include.
func passwdEcho(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		if strings.Contains(v, "etc/passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		_, _ = w.Write([]byte("file not found"))
	}
}

// TestScanPerInsertionPoint_DetectsLFI drives the real scan method against a
// server that returns /etc/passwd content for a traversal payload.
func TestScanPerInsertionPoint_DetectsLFI(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(passwdEcho("file"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?file=index.html")
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an LFI finding when /etc/passwd content is returned")
	assert.Equal(t, "file", res[0].FuzzingParameter)
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a server that never reflects
// file contents yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?file=index.html")
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never leaks file contents must not yield an LFI finding")
}

// TestScanPerInsertionPoint_UnrelatedParamSkipped ensures a parameter that is
// neither a top LFI param name nor path-like is skipped entirely.
func TestScanPerInsertionPoint_UnrelatedParamSkipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(passwdEcho("token"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?token=abc")
	ip := modtest.InsertionPoint(t, rr, "token")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an unrelated, non-path parameter must be skipped")
}
