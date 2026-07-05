package xpath_injection

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

const xpathErr = "javax.xml.xpath.XPathExpressionException: unexpected token in expression"

// TestErrorBased_DetectsXPathError: an endpoint that leaks an XPath engine error
// when the value corrupts the expression (odd quote count) but not for benign
// input is reported.
func TestErrorBased_DetectsXPathError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if strings.Count(v, "'")%2 == 1 || strings.ContainsAny(v, `"]|`) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<html><body>" + xpathErr + "</body></html>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>user profile</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/lookup?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected an error-based XPath finding")
	assert.Equal(t, "XPath Injection", res[0].Info.Name)
}

// TestBoolean_DetectsOracle: an XML-auth endpoint where an always-true predicate
// returns the record and an always-false predicate does not is reported via the
// boolean oracle.
func TestBoolean_DetectsOracle(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.WriteHeader(http.StatusOK)
		switch {
		case strings.Contains(v, "or "): // always-true injection
			_, _ = w.Write([]byte("<html><body>Welcome — all records: alice, bob, carol</body></html>"))
		case strings.Contains(v, "and "): // always-false injection
			_, _ = w.Write([]byte("<html><body>No matching record found</body></html>"))
		default: // baseline
			_, _ = w.Write([]byte("<html><body>record: " + v + "</body></html>"))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/lookup?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected a boolean-oracle XPath finding")
}

// TestNoFalsePositive_StaticShell: a SPA/static page that returns the same body
// for every input must not be flagged (no error, no true/false differential).
func TestNoFalsePositive_StaticShell(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><div id=app>loading…</div></body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a static SPA shell must not be reported as XPath injection")
}

// TestNoFalsePositive_StaticErrorPage: an endpoint that returns the XPath error
// string for EVERY input (including benign) is a static error page, not injection.
func TestNoFalsePositive_StaticErrorPage(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>" + xpathErr + " (service unavailable)</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/lookup?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a page that always shows the error must not be flagged")
}
