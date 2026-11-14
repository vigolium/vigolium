package runner

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ECON-9: the initial spidering phase crawls independent host groups up to
// the host parallelism (default 2) at once, and stops starting groups once
// the phase budget is spent.
func TestRunHostGroups(t *testing.T) {
	t.Setenv("VIGOLIUM_SPIDER_HOST_PARALLELISM", "")
	groups := [][]string{{"a"}, {"b"}, {"c"}, {"d"}}
	var cur, peak atomic.Int64
	var mu sync.Mutex
	var ran []string
	runHostGroups(groups, reSpiderHostParallelism(len(groups)), func() bool { return false }, func(g []string) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		cur.Add(-1)
		mu.Lock()
		ran = append(ran, g[0])
		mu.Unlock()
	})
	if peak.Load() != 2 {
		t.Errorf("peak concurrency = %d, want the default 2", peak.Load())
	}
	if len(ran) != 4 {
		t.Errorf("ran %v, want all four groups", ran)
	}

	var started atomic.Int64
	stopAfter := int64(1)
	runHostGroups(groups, 1, func() bool { return started.Load() >= stopAfter }, func([]string) { started.Add(1) })
	if started.Load() != 1 {
		t.Errorf("sequential run started %d groups after the budget was spent, want 1", started.Load())
	}
}
