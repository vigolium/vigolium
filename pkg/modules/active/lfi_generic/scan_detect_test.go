package lfi_generic

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
	"github.com/vigolium/vigolium/pkg/types/severity"
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

// TestScanPerInsertionPoint_NoFPOnReflectedRequest reproduces the reported
// Salesforce-Aura false positive: the endpoint echoes the request parameter
// back in its (200) response. The data:// probe base64-encodes PHP, so its
// reflection decodes straight back to PHP — but no file was ever read and no
// code ran, so it must NOT be flagged.
func TestScanPerInsertionPoint_NoFPOnReflectedRequest(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the parameter back into a JSON body, mimicking an endpoint that
		// reflects its request context.
		_, _ = w.Write([]byte(`{"echo":"` + r.URL.Query().Get("file") + `","status":"ok"}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?file=index.html")
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an endpoint that merely reflects the request must not be flagged as LFI")
}

// TestScanPerInsertionPoint_DetectsWinIni drives the Windows win.ini read path:
// a vulnerable server returns real win.ini content (multiple bracketed section
// headers), which must be confirmed and yield a finding.
func TestScanPerInsertionPoint_DetectsWinIni(t *testing.T) {
	t.Parallel()
	winIni := "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n[Mail]\r\nMAPI=1\r\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "win.ini") {
			_, _ = w.Write([]byte(winIni))
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
	require.NotEmpty(t, res, "expected a finding when win.ini content is returned")
}

// TestScanPerInsertionPoint_DetectsDotEnv drives the .env read path: a server
// returns real Laravel .env content with sensitive KEY=VALUE assignments.
func TestScanPerInsertionPoint_DetectsDotEnv(t *testing.T) {
	t.Parallel()
	envContent := "APP_NAME=Laravel\nAPP_ENV=production\nAPP_KEY=base64:abcd1234\nDB_CONNECTION=mysql\nDB_PASSWORD=supersecret\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), ".env") {
			_, _ = w.Write([]byte(envContent))
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
	require.NotEmpty(t, res, "expected a finding when .env content is returned")
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

// publishedHtaccess is the genuine .htaccess an S3/CloudFront-fronted static site
// publishes at its web root. Its Apache directives satisfy confirmAppConfig — the
// content really is a .htaccess — which is precisely why the body alone cannot
// decide whether it was *included* or simply *fetched*.
const publishedHtaccess = `RewriteEngine on

RewriteCond %{HTTP:X-Forwarded-Proto} =http
RewriteRule ^(.*)$ https://%{HTTP_HOST}%1 [L,NE,R=301]

RewriteRule ^edit(/.*)?$ /index.html [PT]
ErrorDocument 404 /index.html
`

// TestScanPerInsertionPoint_PathPointPublishedFileDowngradesToInfo mirrors the
// production false positive: a static site (S3 behind CloudFront) that publishes
// a real .htaccess at its web root. Fuzzing the /index-prod.html *path filename*
// with the `.htaccess` payload just requests that published file over HTTP — the
// server reads nothing on the caller's behalf — yet the returned body is a
// genuine .htaccess, so the confirm step fired and reported Critical LFI.
//
// The exposure is still worth surfacing, so the result is kept but downgraded to
// informational and re-anchored at the file's own URL.
func TestScanPerInsertionPoint_PathPointPublishedFileDowngradesToInfo(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.htaccess") {
			_, _ = w.Write([]byte(publishedHtaccess))
			return
		}
		_, _ = w.Write([]byte("<html><body>app shell</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/index-prod.html")
	ip := modtest.InsertionPointByType(t, rr, httpmsg.INS_URL_PATH_FILENAME)

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "the exposure is still worth reporting")
	assert.Equal(t, severity.Info, res[0].Info.Severity,
		"a published web-root file fetched by its own URL is exposure, not LFI")
	assert.Contains(t, res[0].URL, "/.htaccess", "the finding must point at the exposed file")
}

// TestScanPerInsertionPoint_ParamPointKeepsLFISeverity is the counterpart: the
// same .htaccess content reached through a *query parameter* really is a
// server-side read, and must keep the module's file-inclusion severity.
func TestScanPerInsertionPoint_ParamPointKeepsLFISeverity(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), ".htaccess") {
			_, _ = w.Write([]byte(publishedHtaccess))
			return
		}
		_, _ = w.Write([]byte("<html><body>app shell</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?file=index.html")
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, severity.Undefined, res[0].Info.Severity,
		"a parameter-driven read must inherit the module's own severity, not the Info downgrade")
}

// TestScanPerInsertionPoint_PathPointDetectsTraversal guards the other side of
// the same gate: path insertion points must still catch a traversal that reaches
// a file no web root can ever hold, so the docroot-relative skip stays narrow.
func TestScanPerInsertionPoint_PathPointDetectsTraversal(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "etc/passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		_, _ = w.Write([]byte("<html><body>app shell</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/files/report.pdf")
	ip := modtest.InsertionPointByType(t, rr, httpmsg.INS_URL_PATH_FILENAME)

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an LFI finding when /etc/passwd content is returned")
}
