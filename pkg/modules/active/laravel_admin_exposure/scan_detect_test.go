package laravel_admin_exposure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsOpenAPISpec drives the real scan method against a
// host exposing /openapi.json. The module fingerprints a 404, then probes the
// admin/api paths; the OpenAPI markers must surface a finding.
func TestScanPerRequest_DetectsOpenAPISpec(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"API","version":"1.0"},` +
				`"paths":{"/users":{}},"components":{"schemas":{}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an admin-exposure finding when /openapi.json is public")
	assert.Contains(t, strings.ToLower(res[0].Info.Name), "laravel admin exposure")
}

// TestScanPerRequest_DetectsNovaLogin confirms the grouped-marker tightening did
// not kill the true positive: a genuine Nova login page (carrying the
// "laravel-nova" anchor plus a login form) must still surface a finding.
func TestScanPerRequest_DetectsNovaLogin(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nova/login" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><link href="/nova-api/scripts/laravel-nova.js"></head>` +
				`<body><div id="nova-login"><form><input name="email" type="email"/>` +
				`<input name="password" type="password"/><button>Sign in</button></form></div></body></html>`))
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
	require.NotEmpty(t, res, "a genuine Nova login page must still yield a finding")
	assert.Contains(t, strings.ToLower(res[0].Info.Name), "nova")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
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
	assert.Empty(t, res, "a host that 404s every probe must not yield an admin-exposure finding")
}

// loginShell renders the captured login page (Grab e-invoice). The probe path is
// reflected into the <form action> and a password field is present, so the only
// reason a bare "admin" marker matched was our own request path bouncing back.
func loginShell(reqPath string) string {
	return `<!DOCTYPE html><html><head><title>Dang nhap / SignIn</title></head><body>
<div class="wrapper"><div id="main-menu"><a href="/tai-khoan/dang-nhap">Sign in</a></div>
<form action="` + reqPath + `" class="form-horizontal" method="post">
<input name="__RequestVerificationToken" type="hidden" value="kW1prIAWLkYOdqm7sqhDg4gpS" />
<input class="form-control" id="UserName" maxlength="50" name="UserName" required="required" type="text" value="" />
<input class="form-control" id="Password" maxlength="30" name="Password" required="required" type="password" />
<button class="btn" type="submit">Dang nhap / Sign In</button>
</form>
<footer>Cong ty TNHH Grab</footer></body></html>`
}

// salesforceLoginShell renders a Salesforce/Visualforce login shell like the one
// at login-uat.example.com: it contains the generic words "login", "email"
// and a password field, but NO Laravel framework token. The per-request token
// (a unique ViewState-style blob) makes every response body distinct, defeating
// the soft-404 hash/length fingerprint — exactly the property that let the old
// single-OR-token matcher fire on the bare word "login".
func salesforceLoginShell(token string) string {
	return `<!DOCTYPE html><html lang=""><head><title>Welcome</title></head><body>
<form id="j_id0:form" name="j_id0:form" method="post" action="/DLG_Access_Login">
<input type="hidden" id="com.salesforce.visualforce.ViewState" value="` + token + `" />
<input type="email" name="username" placeholder="email" />
<input type="password" name="pw" />
<script>$Lightning.use("c:APP_LoginPage");</script>
<div>This feature is not available in your country. Please login.</div>
</form></body></html>`
}

// TestScanPerRequest_NoFP_SalesforceLoginShell reproduces the
// login-uat.example.com false positive: a Salesforce/Visualforce app returns
// the SAME login shell (200) for every probed path, embedding a per-request token
// so the soft-404 fingerprint never matches. The old matcher fired on the generic
// word "login" for /nova/login, /filament/login, etc. The grouped-marker
// confirmation (which requires a framework anchor the shell never carries) must
// suppress every probe.
func TestScanPerRequest_NoFP_SalesforceLoginShell(t *testing.T) {
	t.Parallel()
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The random fingerprint path 404s so the soft-404 guard does NOT fire,
		// isolating the grouped-marker confirmation as the suppressing layer.
		if strings.Contains(r.URL.Path, "vigolium-admin-404-") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		n++
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(salesforceLoginShell(fmt.Sprintf("viewstate-%d-%s", n, strings.Repeat("A", 64)))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a Salesforce login shell with no Laravel framework token must not yield a finding")
}

// TestScanPerRequest_NoFP_ReflectedLoginWall reproduces the einvoice.grab.com
// false positive: a path-routing app serves the SAME login page for every
// sub-path and reflects the requested path into the <form action>. The old code
// matched the generic /admin "admin" marker against the reflected
// action="/tai-khoan/dang-nhap/admin". The reflected-path strip, the login-wall
// guard, and the observed-shell guard must each independently suppress it.
func TestScanPerRequest_NoFP_ReflectedLoginWall(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Random soft-404 fingerprint path 404s, so the existing fingerprint
		// guard does NOT fire — isolating the new layers.
		if strings.Contains(r.URL.Path, "vigolium-admin-404-") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Everything else (including each probed sub-path) re-renders the login
		// shell, echoing the requested path into the form action.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(loginShell(r.URL.Path)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Observe the login page at the base path and attach it as the baseline so the
	// observed-shell guard has a page to compare against (mirrors the executor).
	rr := modtest.Request(t, srv.URL+"/tai-khoan/dang-nhap/")
	rr = modtest.Response(rr, "text/html; charset=utf-8", loginShell("/tai-khoan/dang-nhap/"))

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a reflected-path login wall must not yield an admin-exposure finding")
}
