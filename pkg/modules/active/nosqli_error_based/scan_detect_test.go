package nosqli_error_based

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

// mongoErrorEcho simulates a server that leaks a MongoDB driver error when the
// named parameter carries injection metacharacters — the telltale of an
// error-based NoSQL injection.
func mongoErrorEcho(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		if strings.ContainsAny(v, `'"${`) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("MongoError: unknown top level operator: $gt near the query parser"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}
}

// TestScanPerInsertionPoint_DetectsNoSQLError drives the real scan method
// against a server that leaks a MongoDB error on injection.
func TestScanPerInsertionPoint_DetectsNoSQLError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(mongoErrorEcho("q"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a NoSQLi finding when a MongoDB error is leaked")
	assert.Equal(t, "q", res[0].FuzzingParameter)
	assert.Contains(t, res[0].Info.Description, "MongoDB")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a server that never emits a
// DB error yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>results</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never leaks a DB error must not yield a NoSQLi finding")
}

// TestScanPerInsertionPoint_SkipsWAFChallenge reproduces a real false positive:
// a Cloudflare 403 "Just a moment..." challenge whose base64 token contained the
// substring "bSON", matching the MongoDB error pattern. A WAF/challenge response
// must never be mistaken for an application-emitted DB error.
func TestScanPerInsertionPoint_SkipsWAFChallenge(t *testing.T) {
	t.Parallel()
	// The literal token from the observed Cloudflare challenge body that the
	// (?i)BSON pattern matched: "...WqVZzyifbSONOgi1jV6J...".
	const cfBody = `<!DOCTYPE html><html><head><title>Just a moment...</title></head>` +
		`<body><script>window._cf_chl_opt={md:'iMQ_6kBnAtoBSYBDz0zw...WqVZzyifbSONOgi1jV6JfU_Yj6osB8oy64IDs'};</script></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(cfBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a Cloudflare WAF challenge must not be reported as NoSQLi")
}

// TestCheckNoSQLError exercises the pure error-matching helper, including the
// baseline-suppression branch.
func TestCheckNoSQLError(t *testing.T) {
	t.Parallel()

	dbms, ok := checkNoSQLError("E11000 duplicate key error collection", "")
	require.True(t, ok)
	assert.Equal(t, "MongoDB", dbms)

	_, ok = checkNoSQLError("nothing interesting here", "")
	assert.False(t, ok, "benign body must not match")

	// Error already present in the baseline is suppressed.
	_, ok = checkNoSQLError("E11000 duplicate key", "E11000 duplicate key")
	assert.False(t, ok, "error present in baseline must be suppressed")
}
