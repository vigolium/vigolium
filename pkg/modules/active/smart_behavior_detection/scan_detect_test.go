package smart_behavior_detection

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

// sqlStringValid simulates a backend that embeds the parameter value inside a
// single-quoted SQL string literal ('<value>') and reports whether the result
// parses as exactly one well-formed literal. It honors backslash escaping (\')
// and quote doubling (”), the two canonical ways to neutralize an apostrophe.
//
// This is the textbook string-injection oracle the behavioral scanner probes
// for: a lone apostrophe breaks the literal (invalid), while an escaped or
// doubled apostrophe keeps it intact (valid) — producing the differential the
// module confirms over several probe pairs.
func sqlStringValid(value string) bool {
	s := "'" + value + "'" // server wraps the value in a string literal
	if len(s) < 2 || s[0] != '\'' {
		return false
	}
	i := 1
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\\':
			// Backslash escapes the next char; skip both.
			i += 2
		case c == '\'':
			// A doubled quote ('') is an escaped literal quote.
			if i+1 < len(s) && s[i+1] == '\'' {
				i += 2
				continue
			}
			// A lone quote closes the literal. Valid only if it's the last char.
			return i == len(s)-1
		default:
			i++
		}
	}
	// Reached end without a closing quote → unterminated literal.
	return false
}

// sqlHandler returns a handler that serves a normal page when the q value forms
// a valid SQL string literal and a distinct error page (HTTP 500) when it does
// not — the deterministic differential the module needs.
func sqlHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sqlStringValid(r.URL.Query().Get("q")) {
			_, _ = w.Write([]byte("<html><body>results: " + strings.Repeat("row ", 40) + "</body></html>"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("<html><body>SQL syntax error near unterminated quoted string</body></html>"))
	}
}

// TestScanPerInsertionPoint_DetectsStringInjection drives the real scan method
// against a backend whose response depends on whether the injected value breaks
// a single-quoted SQL string. A lone apostrophe yields a 500 error page; an
// escaped/doubled apostrophe yields the normal page — the classic behavioral
// signature of a string-context injection.
func TestScanPerInsertionPoint_DetectsStringInjection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(sqlHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/search?q=widget")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a behavioral finding when an apostrophe breaks the SQL string context")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a backend that treats the
// parameter as inert data (always the same response regardless of quotes) yields
// no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Stable page independent of the q value — no injectable context.
		_, _ = w.Write([]byte("<html><body>results: " + strings.Repeat("row ", 40) + "</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/search?q=widget")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a stable response independent of quoting must not yield a behavioral finding")
}

// TestSQLStringValid sanity-checks the test oracle so the emulated backend
// reproduces the break/escape differential the scanner relies on.
func TestSQLStringValid(t *testing.T) {
	t.Parallel()
	assert.True(t, sqlStringValid("widget"), "plain value is a valid literal")
	assert.False(t, sqlStringValid("widget'"), "lone apostrophe breaks the literal")
	assert.True(t, sqlStringValid("widget\\'"), "backslash-escaped apostrophe stays valid")
	assert.True(t, sqlStringValid("widget''"), "doubled apostrophe stays valid")
	assert.False(t, sqlStringValid("`x'x\"x\\"), "crude fuzz string breaks the literal")
}
