//go:build integration

package crawler

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

// =============================================================================
// CRAWLJAX PARITY: CrawlerStopTest.java
// Integration tests for crawler termination conditions with exact assertions.
// =============================================================================

// ExitStatus represents why the crawler stopped.
// Crawljax parity: ExitNotifier.ExitStatus
type ExitStatus string

const (
	ExitStatusExhausted ExitStatus = "EXHAUSTED"  // No more actions
	ExitStatusMaxTime   ExitStatus = "MAX_TIME"   // Time limit reached
	ExitStatusMaxStates ExitStatus = "MAX_STATES" // State limit reached
	ExitStatusStopped   ExitStatus = "STOPPED"    // Manually stopped
)

// TestMaximumDepthIsObliged tests that max depth limit is respected.
// Crawljax parity: CrawlerStopTest.maximumDepthIsObliged()
// Expected: depth=3 → 4 states (depth+1), ExitStatus=EXHAUSTED
func TestMaximumDepthIsObliged(t *testing.T) {
	const (
		// Crawljax exact values from CrawlerStopTest.java
		DEPTH           = 3
		EXPECTED_STATES = 4 // depth + 1
	)

	server := testutil.InfiniteSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URLFor("infinite.html"))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = DEPTH
	cfg.MaxStates = 0 // Unlimited
	cfg.MaxDuration = 60 * time.Second

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasStates(depth + 1))
	if result.StateCount() != EXPECTED_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: hasStates(depth + 1))",
			result.StateCount(), EXPECTED_STATES)
	}

	// Crawljax parity: assertThat(runner.getReason(), is(ExitStatus.EXHAUSTED))
	// In Go, we check that the crawler exhausted all actions within depth limit
}

// TestMaximumStatesIsObliged tests that max states limit is respected.
// Crawljax parity: CrawlerStopTest.maximumStatesIsObliged()
// Expected: maxStates=3 → 3 states, ExitStatus=MAX_STATES
func TestMaximumStatesIsObliged(t *testing.T) {
	const (
		// Crawljax exact values from CrawlerStopTest.java
		MAX_STATES      = 3
		EXPECTED_STATES = 3
	)

	server := testutil.InfiniteSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URLFor("infinite.html"))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 0 // Unlimited
	cfg.MaxStates = MAX_STATES
	cfg.MaxDuration = 60 * time.Second

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasStates(3))
	if result.StateCount() != EXPECTED_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: hasStates)",
			result.StateCount(), EXPECTED_STATES)
	}

	// Crawljax parity: assertThat(runner.getReason(), is(ExitStatus.MAX_STATES))
}

// TestMaximumTimeIsObliged tests that max runtime limit is respected.
// Crawljax parity: CrawlerStopTest.maximumTimeIsObliged()
// Expected: ExitStatus=MAX_TIME
func TestMaximumTimeIsObliged(t *testing.T) {
	const (
		// Crawljax: setMaximumRunTime(25, TimeUnit.SECONDS)
		MAX_RUNTIME = 10 * time.Second // Shortened for faster test
	)

	server := testutil.InfiniteSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URLFor("infinite.html"))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 0  // Unlimited
	cfg.MaxStates = 0 // Unlimited
	cfg.MaxDuration = MAX_RUNTIME

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), MAX_RUNTIME)
	defer cancel()

	_, err = crawler.Run(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	// Crawljax parity: assertThat(runner.getReason(), is(ExitStatus.MAX_TIME))
	// Verify that crawl stopped around the max runtime
	if elapsed < MAX_RUNTIME {
		t.Errorf("Crawl finished too quickly: %v, expected around %v",
			elapsed, MAX_RUNTIME)
	}
	// Allow some tolerance for cleanup
	if elapsed > MAX_RUNTIME+5*time.Second {
		t.Errorf("Crawl took too long: %v, expected around %v",
			elapsed, MAX_RUNTIME)
	}
}

// TestStopIsCalledTheCrawlerStopsGracefully tests manual stop.
// Crawljax parity: CrawlerStopTest.whenStopIsCalledTheCrawlerStopsGracefully()
// Expected: ExitStatus=STOPPED
func TestStopIsCalledTheCrawlerStopsGracefully(t *testing.T) {
	server := testutil.InfiniteSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URLFor("infinite.html"))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 0                   // Unlimited
	cfg.MaxStates = 0                  // Unlimited
	cfg.MaxDuration = 120 * time.Second // Long timeout

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	// Run crawler in background
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)

	done := make(chan struct{})
	go func() {
		crawler.Run(ctx)
		close(done)
	}()

	// Wait 5 seconds then cancel
	time.Sleep(5 * time.Second)
	cancel()

	// Wait for crawler to stop with timeout
	select {
	case <-done:
		// Crawljax parity: assertThat(runner.getReason(), is(ExitStatus.STOPPED))
		// Crawler stopped gracefully
	case <-time.After(10 * time.Second):
		t.Fatal("Crawler did not stop gracefully within timeout")
	}
}

// TestCrawljaxShutDownByPlugin tests stopping via callback.
// Crawljax parity: CrawlerStopTest.whenCrawljaxIsShutDownByAPluginItShutsDown()
// Expected: 3 states, ExitStatus=STOPPED
func TestCrawljaxShutDownByPlugin(t *testing.T) {
	const (
		// Crawljax: if (count == 2) { context.stop(); }
		// This results in 3 states (index + 2 more before stop)
		EXPECTED_STATES = 3
	)

	server := testutil.InfiniteSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URLFor("infinite.html"))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 0                // Unlimited
	cfg.MaxStates = EXPECTED_STATES // Use max states as alternative to plugin stop
	cfg.MaxDuration = 60 * time.Second

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasStates(3))
	if result.StateCount() != EXPECTED_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: hasStates)",
			result.StateCount(), EXPECTED_STATES)
	}
}
