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
// CRAWLJAX PARITY: PopUpTest.java
// Integration tests for popup handling with exact state/edge count assertions.
// =============================================================================

// TestPopups tests crawling pages with JavaScript popups (alert, confirm, prompt).
// Crawljax parity: PopUpTest.testPopups()
// Expected: NUMBER_OF_STATES = 3, NUMBER_OF_EDGES = 3
func TestPopups(t *testing.T) {
	const (
		// Crawljax exact values from PopUpTest.java
		NUMBER_OF_STATES = 3
		NUMBER_OF_EDGES  = 3
	)

	server := testutil.PopupSiteServer()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 3
	cfg.MaxDuration = 60 * time.Second
	cfg.WaitAfterEvent = 100 * time.Millisecond
	cfg.WaitAfterReload = 100 * time.Millisecond

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
	if result.StateCount() != NUMBER_OF_STATES {
		t.Errorf("StateCount() = %d, want %d (Crawljax: hasStates)",
			result.StateCount(), NUMBER_OF_STATES)
	}

	// Crawljax parity: assertThat(session.getStateFlowGraph(), hasEdges(3))
	if result.EdgeCount() != NUMBER_OF_EDGES {
		t.Errorf("EdgeCount() = %d, want %d (Crawljax: hasEdges)",
			result.EdgeCount(), NUMBER_OF_EDGES)
	}
}
