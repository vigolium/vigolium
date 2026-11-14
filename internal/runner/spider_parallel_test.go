package runner

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The initial spidering phase crawls independent host groups up to
// the host parallelism (default 2) at once, and stops starting groups once
// the phase budget is spent.
func TestRunHostGroups(t *testing.T) {
	t.Setenv("VIGOLIUM_SPIDER_HOST_PARALLELISM", "")
	groups := [][]string{{"a"}, {"b"}, {"c"}, {"d"}}
	var cur, peak atomic.Int64
	var mu sync.Mutex
	var ran []string
	results := runHostGroups(groups, reSpiderHostParallelism(len(groups)), func() bool { return false }, func(g []string) spiderGroupResult {
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
		return spiderGroupResult{processed: 1}
	})
	if peak.Load() != 2 {
		t.Errorf("peak concurrency = %d, want the default 2", peak.Load())
	}
	if len(ran) != 4 {
		t.Errorf("ran %v, want all four groups", ran)
	}
	for i, res := range results {
		if res.processed != 1 {
			t.Errorf("results[%d] = %+v, want the group's result at its index", i, res)
		}
	}

	var started atomic.Int64
	stopAfter := int64(1)
	runHostGroups(groups, 1, func() bool { return started.Load() >= stopAfter }, func([]string) spiderGroupResult { started.Add(1); return spiderGroupResult{} })
	if started.Load() != 1 {
		t.Errorf("sequential run started %d groups after the budget was spent, want 1", started.Load())
	}
}
