package crlf_injection

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

// reflectSmuggledCookie simulates a server vulnerable to CRLF header injection:
// it pulls the named query parameter, and if the value smuggles a "Set-cookie:"
// line (the module injects one via %0d%0a / raw CRLF payloads), it reflects that
// cookie back as a real Set-Cookie response header — the observable effect of a
// successful CRLF split. net/http won't emit raw CRLF itself, so we reproduce
// the effect a vulnerable upstream would.
func reflectSmuggledCookie(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		if i := strings.Index(strings.ToLower(v), "set-cookie:"); i >= 0 {
			injected := v[i+len("set-cookie:"):]
			// Stop at the first CR/LF — the cookie token is the first line.
			injected = strings.FieldsFunc(injected, func(r rune) bool { return r == '\r' || r == '\n' })[0]
			w.Header().Set("Set-Cookie", strings.TrimSpace(injected))
		}
		w.WriteHeader(http.StatusOK)
	}
}

// TestScanPerInsertionPoint_DetectsCRLF drives the real scan method against a
// server that reflects a smuggled Set-Cookie header, and asserts the module
// reports a finding.
func TestScanPerInsertionPoint_DetectsCRLF(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(reflectSmuggledCookie("redirect"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?redirect=1")
	ip := modtest.InsertionPoint(t, rr, "redirect")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a CRLF finding when the injected Set-Cookie is reflected")
	assert.Equal(t, "redirect", res[0].FuzzingParameter)
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a server that never reflects
// the parameter into a response header yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?redirect=1")
	ip := modtest.InsertionPoint(t, rr, "redirect")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that ignores the parameter must not yield a CRLF finding")
}
