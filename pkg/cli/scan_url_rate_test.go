package cli

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/types"
)

// --rate-limit reaches the options every sender builds, typed or not.
func TestGlobalFlagsToOptionsCopiesRateLimit(t *testing.T) {
	saved := globalRateLimit
	t.Cleanup(func() { globalRateLimit = saved })
	globalRateLimit = 7
	opts := types.DefaultOptions()
	globalFlagsToOptions(opts)
	require.Equal(t, 7, opts.RateLimit)

	stack, err := setupScanHTTPStack(nil, nil)
	require.NoError(t, err)
	defer stack.Close()
	require.NotNil(t, stack.Services.RateLimiter, "direct scan stack has no rate limiter")
	require.InDelta(t, 7, float64(stack.Services.RateLimiter.Limit()), 0.001)
}

// scan-url -r 2 holds the wire at or under 3 requests in any one second.
func TestScanURLHonoursRateLimitOnTheWire(t *testing.T) {
	if testing.Short() {
		t.Skip("sends real requests for a few seconds")
	}
	var mu sync.Mutex
	var hits []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, time.Now())
		mu.Unlock()
		_, _ = w.Write([]byte("<html><body>id=" + r.URL.Query().Get("id") + "</body></html>"))
	}))
	defer srv.Close()

	e := newB5Env(t)
	code, _, stderr := e.run(t, nil, "scan-url", srv.URL+"/item?id=1", "-m", "sqli-error-based",
		"-r", "2", "--max-requests", "8", "--silent")
	require.Contains(t, []int{0, 5}, code, stderr)

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(hits), 4, "too few requests to measure a rate")
	for i := range hits {
		n := 0
		for j := i; j < len(hits) && hits[j].Sub(hits[i]) < time.Second; j++ {
			n++
		}
		require.LessOrEqual(t, n, 3, "more than 3 requests within one second at -r 2")
	}
}
