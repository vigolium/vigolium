package ldap_injection

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// ldapErrorEcho simulates a server that leaks an LDAP filter error when the
// named parameter carries LDAP filter metacharacters — the telltale of an
// error-based LDAP injection.
func ldapErrorEcho(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		if strings.ContainsAny(v, "()*\\") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("javax.naming.directory.InvalidSearchFilterException: invalid attribute description"))
			return
		}
		_, _ = w.Write([]byte("login page"))
	}
}

// TestScanPerInsertionPoint_DetectsLDAPError drives the real scan method against
// a server that leaks an LDAP error on injection into an LDAP-related param.
func TestScanPerInsertionPoint_DetectsLDAPError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(ldapErrorEcho("username"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?username=alice")
	ip := modtest.InsertionPoint(t, rr, "username")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an LDAP injection finding when an LDAP error is leaked")
	assert.Equal(t, "username", res[0].FuzzingParameter)
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a server that never emits an
// LDAP error and behaves identically for any input yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Fixed response regardless of input: no error, no body divergence.
		_, _ = w.Write([]byte("<html><body>login</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?username=alice")
	ip := modtest.InsertionPoint(t, rr, "username")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a stable, error-free endpoint must not yield an LDAP injection finding")
}

// TestScanPerInsertionPoint_ChallengePageNotLDAP reproduces the cross-module
// false-positive class: a WAF/CDN challenge page (here a Cloudflare 429
// "Cf-Mitigated: challenge") whose body happens to carry an LDAP-error token
// must not be reported as injection — the block gate must reject it before the
// signature match runs.
func TestScanPerInsertionPoint_ChallengePageNotLDAP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(http.StatusTooManyRequests)
		// Challenge body that nonetheless contains an LDAP-error token.
		_, _ = w.Write([]byte("Just a moment... javax.naming.directory.InvalidSearchFilterException"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?username=alice")
	ip := modtest.InsertionPoint(t, rr, "username")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a WAF/CDN challenge page must not be reported as LDAP injection")
}

// TestScanPerInsertionPoint_SkipsCDNInfraPath ensures a Cloudflare /cdn-cgi/ edge
// path is skipped outright — even against a server that WOULD leak an LDAP error —
// because no LDAP-backed application lives under the CDN's reserved namespace and
// its challenge bodies fool the differential. The injection-validity gate must
// short-circuit before any probe is sent.
func TestScanPerInsertionPoint_SkipsCDNInfraPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(ldapErrorEcho("uid"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/cdn-cgi/challenge-platform/h/b/fo/123?uid=alice")
	ip := modtest.InsertionPoint(t, rr, "uid")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a /cdn-cgi/ CDN-edge path must be skipped before any LDAP probe")
}

// TestScanPerInsertionPoint_NonLDAPParamSkipped ensures a parameter whose name
// does not suggest LDAP usage is skipped without sending any probes.
func TestScanPerInsertionPoint_NonLDAPParamSkipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(ldapErrorEcho("color"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?color=red")
	ip := modtest.InsertionPoint(t, rr, "color")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-LDAP parameter must be skipped")
}

// TestScanPerInsertionPoint_BooleanStatusFlipNotLDAP: the wildcard `*` produces a
// large body but on a NON-2xx status (a 500 error render / 302 redirect), while the
// baseline and control are 200. The old logic (isAccessDenied only screens
// 401/403/429/503) let a 500/302 wildcard's body delta fire; the status-discipline
// gate now rejects it — a status flip is not LDAP filter expansion.
func TestScanPerInsertionPoint_BooleanStatusFlipNotLDAP(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("a", 5000)
	small := strings.Repeat("b", 400)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Query().Get("username") == "*" {
			w.WriteHeader(http.StatusInternalServerError) // status flip, not filter expansion
			_, _ = io.WriteString(w, big)
			return
		}
		_, _ = io.WriteString(w, small)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/login?username=bob", "")
	rr = modtest.Response(rr, "text/html", small)
	ip := modtest.InsertionPoint(t, rr, "username")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a wildcard that flips the status (500/302) must not be reported as boolean-based LDAP injection")
}

// TestScanPerInsertionPoint_BooleanNonDeterministicNotLDAP: the wildcard produces a
// large body, but the ORIGINAL value's response flaps between a small and a large
// body per request (a dynamic search page). The determinism precondition re-fetches
// the original twice, sees them disagree, and drops the finding — the wildcard delta
// is dynamic-content noise, not filter expansion.
func TestScanPerInsertionPoint_BooleanNonDeterministicNotLDAP(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("a", 5000)
	small := strings.Repeat("b", 400)
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		v := r.URL.Query().Get("username")
		switch v {
		case "*":
			_, _ = io.WriteString(w, big)
		case controlPayload:
			_, _ = io.WriteString(w, small)
		default:
			// The original value flaps between small and large per request.
			if atomic.AddInt64(&n, 1)%2 == 0 {
				_, _ = io.WriteString(w, big)
				return
			}
			_, _ = io.WriteString(w, small)
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/login?username=bob", "")
	rr = modtest.Response(rr, "text/html", small)
	ip := modtest.InsertionPoint(t, rr, "username")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-deterministic (flapping) endpoint must not yield a boolean-based LDAP finding")
}

// TestIsLDAPRelatedParam exercises the pure parameter-name gate.
func TestIsLDAPRelatedParam(t *testing.T) {
	t.Parallel()
	assert.True(t, isLDAPRelatedParam("username"))
	assert.True(t, isLDAPRelatedParam("userId"), "substring match is case-insensitive")
	assert.True(t, isLDAPRelatedParam("ldap_filter"))
	assert.False(t, isLDAPRelatedParam("color"))
}

// TestContainsLDAPError exercises the pure error-detection helper.
func TestContainsLDAPError(t *testing.T) {
	t.Parallel()
	assert.True(t, containsLDAPError("javax.naming.NamingException"))
	assert.True(t, containsLDAPError("Bad search filter near token"))
	assert.False(t, containsLDAPError("everything is fine"))
}

// TestContainsLDAPError_GenericTokensNotFlagged pins the generic-token false
// positive: ordinary English / UI phrasing that merely mentions LDAP or a "search
// filter" must NOT be read as an LDAP-layer error, while genuine driver-class /
// error-envelope signatures still are.
func TestContainsLDAPError_GenericTokensNotFlagged(t *testing.T) {
	t.Parallel()

	// Generic phrasing that used to trip the removed bare tokens — must stay quiet.
	assert.False(t, containsLDAPError(`<a href="/sso">Login with LDAP</a>`), "a bare LDAP mention is not an error")
	assert.False(t, containsLDAPError(`Please adjust your search filter and try again`), "a UI 'search filter' phrase is not an error")
	assert.False(t, containsLDAPError(`<div class="invalid attribute">check the form</div>`), "a generic 'invalid attribute' is not an LDAP error")
	assert.False(t, containsLDAPError(`image filter error while rendering thumbnail`), "a generic 'filter error' is not an LDAP error")

	// Genuine LDAP-layer signatures still detected.
	assert.True(t, containsLDAPError(`LDAP: error code 49 - 80090308: LdapErr: DSID-0C0903A9`), "standard LDAP error-code envelope must match")
	assert.True(t, containsLDAPError(`com.sun.jndi.ldap.LdapCtx.processReturnCode`), "JNDI LDAP driver class must match")
	assert.True(t, containsLDAPError(`javax.naming.directory.InvalidSearchFilterException`), "JNDI naming exception must match")
}
