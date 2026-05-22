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
