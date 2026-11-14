package core

import (
	"fmt"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/work"
)

// Concurrent tasks of many modules resolving on one item never race on the
// ledger bookkeeping (run with -race), and the outcome is exact.
func TestItemProgressConcurrent(t *testing.T) {
	p := newItemProgress()
	var wg sync.WaitGroup
	for m := 0; m < 8; m++ {
		id := fmt.Sprintf("m%d", m)
		for i := 0; i < 50; i++ {
			p.begin(id)
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				p.end(id, id != "m3" || i != 7, id == "m5" && i == 0)
			}(i)
		}
	}
	wg.Wait()
	for m := 0; m < 8; m++ {
		id := fmt.Sprintf("m%d", m)
		if p.pending[id] != 0 {
			t.Fatalf("%s pending %d", id, p.pending[id])
		}
		if p.failed[id] != (id == "m3") {
			t.Fatalf("%s failed=%v", id, p.failed[id])
		}
	}
	if p.timedOut != 1 {
		t.Fatalf("timedOut = %d", p.timedOut)
	}
}

func TestCoverageModuleDone(t *testing.T) {
	c := &work.Coverage{DoneBits: []byte{0b00000101, 0b1}}
	for ord, want := range map[int]bool{0: true, 1: false, 2: true, 8: true, 9: false, 30: false, -1: false} {
		if got := c.ModuleDone(ord); got != want {
			t.Errorf("ModuleDone(%d) = %v, want %v", ord, got, want)
		}
	}
}
