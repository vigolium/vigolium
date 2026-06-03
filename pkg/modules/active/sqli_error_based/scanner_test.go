package sqli_error_based

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// mysqlSyntaxError matches the "SQL syntax.*?MySQL" pattern in errors.go.
const mysqlSyntaxError = "You have an error in your SQL syntax; check the manual that " +
	"corresponds to your MySQL server version for the right syntax near 'x' at line 1"

// TestScanPerInsertionPoint_DetectsMySQLError drives the real scan method
// against a server that emits a MySQL syntax error whenever the injected value
// carries a quote/paren/backslash (the module's fuzz characters).
func TestScanPerInsertionPoint_DetectsMySQLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("id"), `'")\`) {
			_, _ = io.WriteString(w, mysqlSyntaxError)
			return
		}
		_, _ = io.WriteString(w, "<html>normal page, id looked fine</html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	// The module tries multiple fuzz strings; each that triggers the error adds
	// a finding, so one or more is expected.
	require.NotEmpty(t, res, "expected at least one SQLi finding")
	for _, r := range res {
		assert.Contains(t, r.Info.Description, "DBMS", "finding should name the detected DBMS")
		assert.Equal(t, "id", r.FuzzingParameter)
	}
}

// TestScanPerInsertionPoint_NoFalsePositive guards the signal-quality path: a
// server that never emits a SQL error must produce no finding even though the
// module injects its fuzz characters.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html>welcome, nothing to see here</html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "clean responses must not yield a SQLi finding")
}

// TestScanPerInsertionPoint_ErrorAlreadyInBaseline ensures the module suppresses
// findings when the SQL error string is already present in the unfuzzed
// baseline response (i.e. the page always shows that text), avoiding a false
// positive driven by static content rather than injection.
func TestScanPerInsertionPoint_ErrorAlreadyInBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always returns the error text, regardless of the injected value.
		_, _ = io.WriteString(w, mysqlSyntaxError)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "error present in baseline must not be reported as injection")
}

// TestScanPerInsertionPoint_RateLimitChallengeNotSQLi reproduces the reported
// false positive: a Cloudflare 429 "challenge" page (Cf-Mitigated: challenge)
// whose body happened to carry a token matching the TiDB error signature was
// reported as Critical/Certain SQLi. A WAF/CDN/rate-limit response is not the
// application surfacing a database error, so it must yield no finding.
func TestScanPerInsertionPoint_RateLimitChallengeNotSQLi(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusTooManyRequests)
		// The challenge body carries a token that matches the TiDB error pattern.
		_, _ = io.WriteString(w, "<html><body>Just a moment... TiKV / TiDB server</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 429 Cloudflare challenge page must not be reported as SQLi")
}

// TestScanPerInsertionPoint_BareRateLimitNotSQLi covers a plain 429 with no
// vendor headers (a generic rate limiter the vendor detector would not recognize)
// whose body matches a SQL-error pattern. The status gate must still suppress it.
func TestScanPerInsertionPoint_BareRateLimitNotSQLi(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, mysqlSyntaxError)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 429 rate-limit page must not be reported as SQLi even when it contains a SQL-error string")
}

// TestScanPerInsertionPoint_StaleBaselineFreshControl exercises the new
// confirmation gate: the captured baseline is clean (stale), but the live
// endpoint now returns the SQL error for EVERY value, including a benign one (e.g.
// the database is down). The fresh control fetch of the original value reproduces
// the error, proving it is not payload-introduced, so no finding is reported.
func TestScanPerInsertionPoint_StaleBaselineFreshControl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Returns the MySQL error unconditionally now, regardless of the value.
		_, _ = io.WriteString(w, mysqlSyntaxError)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Captured baseline from before: a clean page lacking the error.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/?id=1"),
		"text/html", "<html>welcome</html>",
	)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an error the live page returns for any value (fresh control included) must not be reported as injection")
}
