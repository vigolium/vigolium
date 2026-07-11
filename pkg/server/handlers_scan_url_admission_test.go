package server

import (
	"testing"
	"time"
)

// TestTryStartNativeScan_BoundsConcurrency verifies the url/request scan
// admission gate: it admits up to the semaphore size, rejects beyond it, and
// re-admits once a running scan releases its slot.
func TestTryStartNativeScan_BoundsConcurrency(t *testing.T) {
	h := &Handlers{nativeScanSem: make(chan struct{}, 1)}

	block := make(chan struct{})
	if !h.tryStartNativeScan(func() { <-block }) {
		t.Fatal("first scan should be admitted")
	}
	// The slot is held synchronously by the admitted (still-blocked) scan.
	if h.tryStartNativeScan(func() {}) {
		t.Fatal("second scan should be rejected while the only slot is held")
	}

	close(block) // let the first scan finish and release its slot

	deadline := time.Now().Add(2 * time.Second)
	for !h.tryStartNativeScan(func() {}) {
		if time.Now().After(deadline) {
			t.Fatal("slot was never released after the first scan finished")
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.nativeScanWG.Wait()
}
