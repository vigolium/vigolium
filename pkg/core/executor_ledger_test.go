package core

import (
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/work"
)

// Concurrent tasks of many modules resolving on one item never race on the
// ledger bookkeeping (run with -race), and the outcome is exact.
func TestItemProgressConcurrent(t *testing.T) {
	p := newItemProgress(8)
	var wg sync.WaitGroup
	for m := 0; m < 8; m++ {
		for i := 0; i < 50; i++ {
			p.begin(m)
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				p.end(m, m != 3 || i != 7, m == 5 && i == 0)
			}(i)
		}
	}
	p.begin(-1) // an untracked module is ignored
	p.end(8, false, true)
	wg.Wait()
	for m := 0; m < 8; m++ {
		if p.pending[m] != 0 {
			t.Fatalf("m%d pending %d", m, p.pending[m])
		}
		if p.failed[m] != (m == 3) {
			t.Fatalf("m%d failed=%v", m, p.failed[m])
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

func TestCoverageSetModuleDone(t *testing.T) {
	var c work.Coverage
	c.SetModuleDone(9)
	c.SetModuleDone(0)
	c.SetModuleDone(-1)
	if len(c.DoneBits) != 2 || !c.ModuleDone(9) || !c.ModuleDone(0) || c.ModuleDone(1) {
		t.Fatalf("DoneBits = %08b", c.DoneBits)
	}
}

// tier_done advances over every tier whose modules (and all lower tiers') are
// done, keeps a stored tier, and waits on the passive stage for tier 0.
func TestLedgerPlanTierDone(t *testing.T) {
	spec := &LedgerSpec{
		Ordinals: map[string]int{"a": 0, "b": 1, "c": 2, "untiered": 3},
		Tiers:    map[string]int{"a": 0, "b": 1, "c": 2, "unordered": 0},
		MaxTier:  2,
	}
	plan := newLedgerPlan(spec, nil)
	cov := func(tier int, ords ...int) *work.Coverage {
		c := &work.Coverage{TierDone: tier}
		for _, o := range ords {
			c.SetModuleDone(o)
		}
		return c
	}
	cases := []struct {
		name    string
		cov     *work.Coverage
		passive bool
		want    int
	}{
		{"nothing done", cov(-1), false, -1},
		{"tier 0 done", cov(-1, 0), false, 0},
		{"tier 0 waits on passives", cov(-1, 0, 1), true, -1},
		{"stored tier skips the passive wait", cov(0, 0, 1), true, 1},
		{"gap stops the walk", cov(-1, 0, 2), false, 0},
		{"all done", cov(-1, 0, 1, 2), false, 2},
		{"stored tier kept when a lower bit is missing", cov(1, 1, 2), false, 1},
	}
	for _, tc := range cases {
		if got := plan.tierDone(tc.cov, tc.passive); got != tc.want {
			t.Errorf("%s: tierDone = %d, want %d", tc.name, got, tc.want)
		}
	}
}
