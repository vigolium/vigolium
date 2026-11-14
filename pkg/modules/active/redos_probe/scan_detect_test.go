package redos_probe

import (
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

// testFloor keeps the timing tests short; production uses defaultMinFloor.
const testFloor = 300 * time.Millisecond

var attackRe = regexp.MustCompile(`^(a+)!$`)

// delayServer sleeps delay(runLength) when the email parameter is a
// backtracking input ("aaaa…!"), and jitter() on every request.
func delayServer(t *testing.T, delay func(n int) time.Duration, jitter func() time.Duration) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		d := time.Duration(0)
		if jitter != nil {
			d += jitter()
		}
		if m := attackRe.FindStringSubmatch(r.URL.Query().Get("email")); m != nil && delay != nil {
			d += delay(len(m[1]))
		}
		time.Sleep(d)
		_, _ = w.Write([]byte("invalid email"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func runProbe(t *testing.T, srv *httptest.Server, param string) []*output.ResultEvent {
	t.Helper()
	m := New()
	m.minFloor = testFloor
	rr := modtest.Request(t, srv.URL+"/subscribe?"+param+"=a%40b.io")
	res, err := m.ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, param), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	return res
}

func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Subset(t, m.Tags(), []string{"risk:high", "intrusive"})
	assert.Equal(t, modkit.ScanScopeInsertionPoint, m.ScanScopes())
}

// TestDetectsExponentialBacktracking: the delay doubles every 8 characters
// (20ms at 16, 80ms at 32, 1.28s at 64), the catastrophic-backtracking shape.
func TestDetectsExponentialBacktracking(t *testing.T) {
	t.Parallel()
	srv, _ := delayServer(t, func(n int) time.Duration {
		return 5 * time.Millisecond * time.Duration(1<<(n/8))
	}, nil)
	res := runProbe(t, srv, "email")
	require.Len(t, res, 1)
	assert.Equal(t, "email", res[0].FuzzingParameter)
	assert.Equal(t, severity.Suspect, res[0].Info.Severity, "timing-only ReDoS oracle: Suspect")
	assert.Equal(t, 64, res[0].Metadata["high_run_length"])
	assert.Equal(t, 32, res[0].Metadata["low_run_length"])
}

// TestLatencyNoise_NoFinding: random 0-100ms jitter on every request, with no
// input-dependent delay, never clears the floor.
func TestLatencyNoise_NoFinding(t *testing.T) {
	t.Parallel()
	srv, _ := delayServer(t, nil, func() time.Duration {
		return time.Duration(rand.Int64N(int64(100 * time.Millisecond)))
	})
	assert.Empty(t, runProbe(t, srv, "email"))
}

// TestConstantStall_NoFinding: a fixed 400ms stall on any "…!" input (a WAF
// or slow error page) adds the same delay at every length.
func TestConstantStall_NoFinding(t *testing.T) {
	t.Parallel()
	srv, _ := delayServer(t, func(int) time.Duration { return 400 * time.Millisecond }, nil)
	assert.Empty(t, runProbe(t, srv, "email"))
}

// TestLinearGrowth_NoFinding: delay proportional to the input length is a slow
// linear path, not catastrophic backtracking.
func TestLinearGrowth_NoFinding(t *testing.T) {
	t.Parallel()
	srv, _ := delayServer(t, func(n int) time.Duration { return time.Duration(n) * 8 * time.Millisecond }, nil)
	assert.Empty(t, runProbe(t, srv, "email"))
}

// TestNonPatternParam_NoRequests: a parameter that names nothing
// pattern-validated is never probed.
func TestNonPatternParam_NoRequests(t *testing.T) {
	t.Parallel()
	srv, hits := delayServer(t, nil, nil)
	rr := modtest.Request(t, srv.URL+"/item?id=42")
	res, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "id"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Zero(t, atomic.LoadInt64(hits))
}

func TestSuperLinear(t *testing.T) {
	t.Parallel()
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	floor := ms(300)
	cases := []struct {
		name               string
		control, low, high time.Duration
		want               bool
	}{
		{"exponential", ms(10), ms(90), ms(1290), true},
		{"quadratic", ms(10), ms(410), ms(1610), true},
		{"linear", ms(10), ms(266), ms(522), false},
		{"constant stall", ms(10), ms(410), ms(410), false},
		{"below floor", ms(10), ms(10), ms(250), false},
		{"low faster than control", ms(50), ms(40), ms(900), true},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, superLinear(tc.control, tc.low, tc.high, 2, floor), tc.name)
	}
}

func TestLooksLikePatternParam(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"email", "", true},
		{"userEmail", "x", true},
		{"redirect_url", "", true},
		{"searchTerm", "", true},
		{"q", "shoes", true},
		{"regex", "", true},
		{"contact", "a@b.io", true},
		{"next", "https://example.com/", true},
		{"id", "42", false},
		{"mailbox_size", "1", false},
		{"queue", "default", false},
	} {
		assert.Equal(t, tc.want, LooksLikePatternParam(tc.name, tc.value), tc.name)
	}
}
