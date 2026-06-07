package lfi_generic

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// a 1px PNG, base64-encoded the way CDN/static 404 pages embed data-URI logos.
// This is exactly the kind of incidental base64 the old `^[A-Za-z0-9+/=]{50,}`
// regex flagged as a php://filter read.
const embeddedPNGBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

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

// TestScanPerInsertionPoint_DetectsPHPFilter drives the php://filter base64
// read path: a vulnerable server returns the base64-encoded source of a PHP
// file, which must decode to real PHP and yield a finding.
func TestScanPerInsertionPoint_DetectsPHPFilter(t *testing.T) {
	t.Parallel()
	phpSrc := "<?php\n$db_host = \"localhost\";\necho \"hi\";\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(phpSrc))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "php://filter") {
			_, _ = w.Write([]byte(encoded))
			return
		}
		_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?file=index.html")
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when php://filter returns base64-encoded PHP source")
}

// TestScanPerInsertionPoint_NoFPOnEmbeddedBase64 reproduces the reported false
// positive: a page that simply embeds a base64 data-URI image (as CDN/static
// 404 pages do) must NOT be flagged as a php://filter read, because the base64
// decodes to a PNG, not PHP source.
func TestScanPerInsertionPoint_NoFPOnEmbeddedBase64(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><body><img src="data:image/png;base64,` + embeddedPNGBase64 + `"></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?file=index.html")
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a page embedding a base64 data-URI image must not be flagged as LFI")
}

// TestScanPerInsertionPoint_NoFPOn404WithBase64 mirrors the exact production
// false positive: a 404 page (GitHub Pages) whose body carries base64 data-URI
// logos. The status gate alone must drop it regardless of body content.
func TestScanPerInsertionPoint_NoFPOn404WithBase64(t *testing.T) {
	t.Parallel()
	body := `<!DOCTYPE html><html><body>404 not found<img src="data:image/png;base64,` + embeddedPNGBase64 + `"></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?file=index.html")
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 404 error page must never be flagged as a successful file read")
}
