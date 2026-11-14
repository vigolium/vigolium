package fingerprint

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// ECON-8: an unmatched hit on a clean directory costs the two decisive probes
// (Prefix, Middle), not four; the next hit in the same directory and extension
// within the TTL costs one.
func TestValidationProbeBudget(t *testing.T) {
	var siblings atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/a.php", "/admin/b.php":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, hitPage)
		default:
			siblings.Add(1)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	l := NewLearner(srv.Client(), nil)
	l.SetDelay(0)
	c := NewComparator(NewCache(l), l)

	compare := func(path string) MatchResult {
		req := createTestHTTPRequest(t, http.MethodGet, srv.URL+path, nil)
		resp, err := srv.Client().Get(srv.URL + path)
		require.NoError(t, err)
		rc := responsechain.NewResponseChain(resp, 0)
		require.NoError(t, rc.Fill())
		t.Cleanup(rc.Close)
		got, err := c.Compare(context.Background(), req, rc)
		require.NoError(t, err)
		return got
	}

	assert.Equal(t, TruePositive, compare("/admin/a.php"))
	assert.Equal(t, int64(2), siblings.Load(), "first validation: Prefix + Middle only")
	assert.Equal(t, TruePositive, compare("/admin/b.php"))
	assert.Equal(t, int64(3), siblings.Load(), "clean verdict cached: Middle only")
}

func TestCleanVerdictsExpire(t *testing.T) {
	cv := newCleanVerdicts(2, cleanVerdictTTL)
	now := cv.now()
	cv.now = func() time.Time { return now }
	cv.mark("a")
	assert.True(t, cv.fresh("a"))
	cv.now = func() time.Time { return now.Add(cleanVerdictTTL + 1) }
	assert.False(t, cv.fresh("a"))
	cv.mark("b")
	cv.mark("c")
	cv.mark("d")
	assert.LessOrEqual(t, cv.entries.Len(), 2)
}
