package jstangle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newRealWorkerService(t *testing.T, maxJobs int) (*Service, *WorkerPool) {
	t.Helper()
	service, err := NewService(&ServiceConfig{
		MemoryBudgetBytes: 512 * 1024 * 1024,
		MaxWeight:         4,
		CacheBytes:        -1,
		WorkerCount:       1,
		WorkerMaxJobs:     maxJobs,
		WorkerMaxRSSBytes: 2 * 1024 * 1024 * 1024,
		ScannerConfig:     &Config{MaxConcurrent: 1},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	pool, ok := service.backend.(*WorkerPool)
	if !ok {
		_ = service.Close()
		t.Fatalf("backend = %T, want *WorkerPool", service.backend)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service, pool
}

func TestWorkerPoolReusesProcessAcrossJobs(t *testing.T) {
	service, _ := newRealWorkerService(t, 100)
	// Twenty small jobs should pay for one Bun startup, not twenty.
	for i := 0; i < 20; i++ {
		endpoint := fmt.Sprintf("/api/item-%d", i)
		result, err := service.ScanWithOptions(context.Background(), []byte("fetch('"+endpoint+"')"), ScanOptions{Profile: ProfileEndpoints})
		if err != nil {
			t.Fatalf("scan %s: %v", endpoint, err)
		}
		if len(result.Requests) != 1 || result.Requests[0].URL != endpoint {
			t.Fatalf("requests for %s = %#v", endpoint, result.Requests)
		}
	}
	stats := service.Stats()
	if stats.Workers != 1 || stats.WorkerJobs != 20 || stats.WorkerRestarts != 0 {
		t.Fatalf("unexpected worker reuse stats: %+v", stats)
	}
}

func TestWorkerPoolRecyclesAtJobLimit(t *testing.T) {
	service, _ := newRealWorkerService(t, 1)
	for _, endpoint := range []string{"/api/first", "/api/after-recycle"} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, err := service.ScanWithOptions(ctx, []byte("fetch('"+endpoint+"')"), ScanOptions{Profile: ProfileEndpoints})
		cancel()
		if err != nil {
			t.Fatalf("scan %s: %v", endpoint, err)
		}
	}
	stats := service.Stats()
	if stats.Workers != 1 || stats.WorkerRestarts < 2 {
		t.Fatalf("worker did not recycle at the configured limit: %+v", stats)
	}
}

func TestWorkerPoolRetriesOnceAfterCrash(t *testing.T) {
	service, pool := newRealWorkerService(t, 10)
	if err := pool.ensureStarted(); err != nil {
		t.Fatalf("start pool: %v", err)
	}
	worker := <-pool.available
	worker.stop(false)
	pool.available <- worker

	result, err := service.ScanWithOptions(context.Background(), []byte("fetch('/api/recovered')"), ScanOptions{Profile: ProfileEndpoints})
	if err != nil {
		t.Fatalf("scan after worker crash: %v", err)
	}
	if len(result.Requests) != 1 || result.Requests[0].URL != "/api/recovered" {
		t.Fatalf("unexpected recovered result: %#v", result.Requests)
	}
	stats := service.Stats()
	if stats.WorkerRetries != 1 || stats.WorkerRestarts < 1 || stats.Workers != 1 {
		t.Fatalf("unexpected crash recovery stats: %+v", stats)
	}
}

func TestWorkerPoolCancellationKillsAndReplacesActiveWorker(t *testing.T) {
	service, pool := newRealWorkerService(t, 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	largeSource := strings.Repeat("const sufficientlyLongName = 123456;\n", 100_000)
	go func() {
		_, err := service.ScanWithOptions(ctx, []byte(largeSource), ScanOptions{Profile: ProfileFull})
		done <- err
	}()

	deadline := time.Now().Add(20 * time.Second)
	for pool.Stats().ActiveJobs == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if pool.Stats().ActiveJobs == 0 {
		t.Fatal("worker job did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan error = %v, want context.Canceled", err)
	}

	recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer recoveryCancel()
	result, err := service.ScanWithOptions(recoveryCtx, []byte("fetch('/api/after-cancel')"), ScanOptions{Profile: ProfileEndpoints})
	if err != nil {
		t.Fatalf("scan after cancellation: %v", err)
	}
	if len(result.Requests) != 1 || result.Requests[0].URL != "/api/after-cancel" {
		t.Fatalf("unexpected post-cancellation result: %#v", result.Requests)
	}
	if stats := service.Stats(); stats.WorkerRestarts < 1 || stats.Workers != 1 {
		t.Fatalf("cancelled worker was not replaced: %+v", stats)
	}
}
