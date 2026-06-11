package nextjs_data_leakage

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
)

// nextBody is an HTML shell carrying the __NEXT_DATA__ marker and a buildId, so
// jsframework.LooksLikeNextJS and the BuildID fallback both succeed.
const nextBuildID = "abc123buildid"

var nextBody = `<!DOCTYPE html><html><body><script id="__NEXT_DATA__" type="application/json">` +
	`{"buildId":"` + nextBuildID + `","props":{"pageProps":{}}}</script></body></html>`

// responseWith attaches a synthetic response with an arbitrary status, header set
// and body to rr's request (modtest.Response only builds 200s).
func responseWith(rr *httpmsg.HttpRequestResponse, status int, statusText string, headers map[string]string, body string) *httpmsg.HttpRequestResponse {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, statusText)
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", len(body), body)
	return httpmsg.NewHttpRequestResponse(rr.Request(), httpmsg.NewHttpResponse([]byte(b.String())))
}

// dataRouteServer serves a 200 JSON pageProps payload at the Next.js data route
// for /dashboard and 404 elsewhere, modelling an unprotected data route.
func dataRouteServer(t *testing.T, dataBody string) *httptest.Server {
	t.Helper()
	want := fmt.Sprintf("/_next/data/%s/dashboard.json", nextBuildID)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != want {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(dataBody))
	}))
}

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.ID() != ModuleID {
		t.Errorf("ID = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name = %q, want %q", m.Name(), ModuleName)
	}
}

// TestScanPerRequest_LoginRedirectLeak confirms a real leak still fires: the page
// 302-redirects to /login (genuine auth gate) but its data route returns 200 JSON
// with pageProps without credentials.
func TestScanPerRequest_LoginRedirectLeak(t *testing.T) {
	srv := dataRouteServer(t, `{"pageProps":{"secret":"data"}}`)
	defer srv.Close()

	client := modtest.Requester(t)
	base := modtest.Request(t, srv.URL+"/dashboard")
	rr := responseWith(base, 302, "Found", map[string]string{"Location": "/login?next=/dashboard"}, nextBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a login-gated page whose data route leaks pageProps must be flagged")
}

// TestScanPerRequest_LocaleRedirectNoFalsePositive guards the new gate: a 302 that
// is a locale/canonical redirect (not a login redirect) must not be treated as
// auth-protected, even though the public page's data route returns 200 pageProps.
func TestScanPerRequest_LocaleRedirectNoFalsePositive(t *testing.T) {
	srv := dataRouteServer(t, `{"pageProps":{"products":[]}}`)
	defer srv.Close()

	client := modtest.Requester(t)
	base := modtest.Request(t, srv.URL+"/dashboard")
	// 302 → /en/dashboard: a locale redirect, not an auth gate.
	rr := responseWith(base, 302, "Found", map[string]string{"Location": "/en/dashboard"}, nextBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-login 302 (locale/canonical redirect) must not be flagged as a data leak")
}

// TestScanPerRequest_DataRouteRedirectNoFalsePositive guards the __N_REDIRECT
// check: a 401 page whose data route enforces auth by returning a Next.js redirect
// payload is not a leak.
func TestScanPerRequest_DataRouteRedirectNoFalsePositive(t *testing.T) {
	srv := dataRouteServer(t, `{"pageProps":{"__N_REDIRECT":"/login","__N_REDIRECT_STATUS":307}}`)
	defer srv.Close()

	client := modtest.Requester(t)
	base := modtest.Request(t, srv.URL+"/dashboard")
	rr := responseWith(base, 401, "Unauthorized", nil, nextBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a data route that itself redirects to login must not be flagged as a leak")
}

func TestBuildIDRegex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"buildId":"abc123"`, "abc123"},
		{`"buildId": "my-build-456"`, "my-build-456"},
		{`no match`, ""},
	}
	for _, tt := range tests {
		m := jsframework.BuildIDRegex.FindStringSubmatch(tt.input)
		got := ""
		if len(m) > 1 {
			got = m[1]
		}
		if got != tt.want {
			t.Errorf("input=%q: got %q, want %q", tt.input, got, tt.want)
		}
	}
}
