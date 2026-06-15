package memlimit

import (
	"math"
	"os"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gib = 1 << 30

// autoLimit must honor the 1/3-flat cap at low parallelism and the 2/3-aggregate
// cap (÷P) once enough processes run in parallel, and refuse to cap tiny boxes.
func TestAutoLimit(t *testing.T) {
	const total = 16 * gib
	cases := []struct {
		name        string
		total       uint64
		parallelism int
		want        int64
	}{
		{"single process → 1/3", total, 1, total / 3},
		{"two processes → still 1/3 each", total, 2, total / 3},           // min(1/3, 2/3÷2)=1/3
		{"three processes → 2/3 ÷ 3", total, 3, int64(total * 2 / 3 / 3)}, // aggregate cap bites
		{"four processes → 2/3 ÷ 4", total, 4, int64(total * 2 / 3 / 4)},
		{"zero treated as one", total, 0, total / 3},
		{"tiny machine not capped", 1 * gib, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := autoLimit(tc.total, tc.parallelism)
			assert.Equal(t, tc.want, got)
			if tc.want > 0 {
				assert.LessOrEqual(t, got, int64(tc.total), "limit must never exceed total RAM")
			}
		})
	}
}

// autoLimit must never return a pathologically small ceiling.
func TestAutoLimitFloor(t *testing.T) {
	// 2 GiB ÷ many parallel → would be tiny, but floored at minAutoLimit.
	got := autoLimit(2*gib, 64)
	assert.Equal(t, int64(minAutoLimit), got)
}

// saveMemState snapshots and restores the process-global limit + GOMEMLIMIT env
// so Apply's side effects don't leak across tests.
func saveMemState(t *testing.T) {
	t.Helper()
	origLimit := debug.SetMemoryLimit(-1)
	origEnv, hadEnv := os.LookupEnv("GOMEMLIMIT")
	t.Cleanup(func() {
		debug.SetMemoryLimit(origLimit)
		if hadEnv {
			_ = os.Setenv("GOMEMLIMIT", origEnv)
		} else {
			_ = os.Unsetenv("GOMEMLIMIT")
		}
	})
}

func TestApplyExplicitSize(t *testing.T) {
	saveMemState(t)
	require.NoError(t, os.Unsetenv("GOMEMLIMIT"))

	res := Apply(Options{Override: "1GiB"})
	assert.True(t, res.Changed)
	assert.False(t, res.Disabled)
	assert.Equal(t, int64(gib), res.LimitBytes)
	assert.Equal(t, int64(gib), debug.SetMemoryLimit(-1), "runtime limit must be set")
	assert.Equal(t, "1073741824", os.Getenv("GOMEMLIMIT"), "must export bytes for children")
}

func TestApplyPercent(t *testing.T) {
	saveMemState(t)
	require.NoError(t, os.Unsetenv("GOMEMLIMIT"))

	total, _ := DetectRAM()
	if total == 0 {
		t.Skip("RAM not detectable in this environment")
	}
	res := Apply(Options{Override: "10%"})
	assert.True(t, res.Changed)
	assert.Equal(t, int64(float64(total)*0.10), res.LimitBytes)
}

func TestApplyOff(t *testing.T) {
	saveMemState(t)
	require.NoError(t, os.Unsetenv("GOMEMLIMIT"))

	res := Apply(Options{Override: "off"})
	assert.True(t, res.Disabled)
	assert.Equal(t, int64(math.MaxInt64), res.LimitBytes)
	assert.Equal(t, "off", os.Getenv("GOMEMLIMIT"), "opt-out must propagate to children")
}

func TestApplyHonorsInheritedEnv(t *testing.T) {
	saveMemState(t)
	// Simulate a parent/user-provided GOMEMLIMIT already applied by the runtime.
	require.NoError(t, os.Setenv("GOMEMLIMIT", "2147483648"))
	debug.SetMemoryLimit(2 * gib)

	res := Apply(Options{Override: "1GiB"}) // override must be ignored
	assert.False(t, res.Changed, "inherited GOMEMLIMIT must win")
	assert.Equal(t, int64(2*gib), res.LimitBytes)
	assert.Equal(t, int64(2*gib), debug.SetMemoryLimit(-1), "runtime limit must be untouched")
	assert.Contains(t, res.Note, "inherited")
}

func TestApplyInvalidValueIsIgnored(t *testing.T) {
	saveMemState(t)
	require.NoError(t, os.Unsetenv("GOMEMLIMIT"))
	before := debug.SetMemoryLimit(-1)

	res := Apply(Options{Override: "banana"})
	assert.False(t, res.Changed)
	assert.Contains(t, res.Note, "ignored")
	assert.Equal(t, before, debug.SetMemoryLimit(-1), "an unparseable value must not change the limit")
}

func TestDetectRAMReturnsSomething(t *testing.T) {
	total, src := DetectRAM()
	assert.Positive(t, total, "should detect physical RAM on the test host")
	assert.Contains(t, []string{"physical", "cgroup"}, src)
}
