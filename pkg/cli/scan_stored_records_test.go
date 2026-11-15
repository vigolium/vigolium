package cli

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/types"
)

// pathCountingServer counts requests per path.
func pathCountingServer(t *testing.T) (*httptest.Server, func() map[string]int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hello " + r.URL.Query().Get("id") + "</body></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range hits {
			out[k] = v
		}
		return out
	}
}

// With two records already stored for the host, a Runner-path scan-url (-o
// forces the Runner) sends nothing to them by default; --include-stored and
// `scan -t` do.
func TestScanURLTestsOnlyItsInput(t *testing.T) {
	srv, hits := pathCountingServer(t)
	home := a3Home(t, "127.0.0.1")
	db := filepath.Join(t.TempDir(), "s.sqlite")
	for _, p := range []string{"/admin", "/echo"} {
		code, stdout, stderr := runA3(t, home, "scan-url", srv.URL+p, "--db", db, "-m", "security-headers-missing")
		require.Equal(t, 0, code, "seed %s\nstdout:\n%s\nstderr:\n%s", p, stdout, stderr)
	}
	stored := func(h map[string]int) int { return h["/admin"] + h["/echo"] }
	before := stored(hits())

	out := filepath.Join(t.TempDir(), "x.jsonl")
	args := []string{"scan-url", srv.URL + "/item?id=1", "--db", db, "-m", "xss-light-path,cors-misconfiguration", "-o", out}
	code, stdout, stderr := runA3(t, home, args...)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	after := hits()
	assert.Equal(t, before, stored(after), "scan-url must not send to stored records: %v", after)
	assert.Positive(t, after["/item"], "the input itself is scanned")
	assert.Contains(t, stderr, "not tested", "the banner says stored records were left alone")

	code, stdout, stderr = runA3(t, home, append(args, "--include-stored")...)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Greater(t, stored(hits()), stored(after), "--include-stored tests the stored records")
}

func TestStoredRecordsMode(t *testing.T) {
	swapGlobal(t, &scanIncludeStored, false)
	swapGlobal(t, &scanInputOnly, false)
	mk := func(path string) *cobra.Command {
		root := &cobra.Command{Use: "vigolium"}
		c := &cobra.Command{Use: path}
		root.AddCommand(c)
		return c
	}
	assert.Equal(t, types.StoredRecordsExclude, storedRecordsMode(mk("scan-url"), true))
	assert.Equal(t, types.StoredRecordsExclude, storedRecordsMode(mk("scan-request"), true))
	assert.Equal(t, types.StoredRecordsExclude, storedRecordsMode(mk("run"), true))
	assert.Equal(t, "", storedRecordsMode(mk("run"), false), "run over stored records keeps them")
	assert.Equal(t, "", storedRecordsMode(mk("scan"), true), "scan -t names an origin")
	scanInputOnly = true
	assert.Equal(t, types.StoredRecordsExclude, storedRecordsMode(mk("scan"), true))
	scanIncludeStored = true
	assert.Equal(t, types.StoredRecordsInclude, storedRecordsMode(mk("scan-url"), true))
	assert.True(t, strings.HasPrefix(types.StoredRecordsExclude, "ex"))
}
