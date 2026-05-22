package ldap_injection

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
