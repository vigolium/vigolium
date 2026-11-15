package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// A request with no marker and no position flag is a usage error naming the
// near-miss token; a marker plus --point is one too; a plan above
// --max-requests is refused; none of them sends anything.
func TestFuzzPositionRulesAndCap(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	e := newB5Env(t)

	code, stdout, stderr := e.run(t, nil, "fuzz", srv.URL+"/item?id=FUZ", "-w", "dir-short", "-j")
	require.Equal(t, 2, code, stderr)
	require.Contains(t, stdout+stderr, `"FUZ"`)

	code, _, stderr = e.run(t, nil, "fuzz", srv.URL+"/item?id=FUZZ", "--point", "URL_PARAM:id", "-p", "a", "-j")
	require.Equal(t, 2, code, stderr)

	code, stdout, stderr = e.run(t, nil, "fuzz", srv.URL+"/item?id=FUZZ", "-p", "a", "-p", "b", "-p", "c", "--max-requests", "2", "-j")
	require.Equal(t, 2, code, stderr)
	require.Contains(t, stdout+stderr, "--max-requests")
	require.Zero(t, hits.Load(), "a refused fuzz run sent requests")

	// --fuzz all still reaches every insertion point, but not synthetic headers.
	code, stdout, stderr = e.run(t, nil, "fuzz", srv.URL+"/item?id=1", "--fuzz", "all", "-p", "a", "--dry-run", "-j")
	require.Equal(t, 0, code, stderr)
	require.NotContains(t, stdout, "X-Forwarded-For")
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(stdout)), &doc), stdout)
	require.Zero(t, hits.Load())
}

// The default pace is 100 req/s, not unlimited.
func TestFuzzDefaultRateLimit(t *testing.T) {
	f := fuzzCmd.Flags().Lookup("rate-limit")
	require.Equal(t, "100", f.DefValue)
	require.Equal(t, "10000", fuzzCmd.Flags().Lookup("max-requests").DefValue)
}
