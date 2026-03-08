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
// CRAWLJAX PARITY: PassBasicHttpAuthTest.java
// Integration tests for HTTP Basic Authentication with exact state assertions.
// =============================================================================

// TestProvidedCredentialsAreUsedInBasicAuth tests basic auth credentials.
// Crawljax parity: PassBasicHttpAuthTest.testProvidedCredentialsAreUsedInBasicAuth()
// Expected: NUMBER_OF_STATES = 3 with valid credentials
func TestProvidedCredentialsAreUsedInBasicAuth(t *testing.T) {
	const (
		// Crawljax exact values from PassBasicHttpAuthTest.java
		USERNAME        = "test"
		PASSWORD        = "test#&"
		MAX_STATES      = 3
		EXPECTED_STATES = 3
	)

	server := testutil.BasicAuthServer(USERNAME, PASSWORD)
	defer server.Close()

	cfg, err := config.New(server.URLFor("infinite.html"))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = MAX_STATES
	cfg.BasicAuthUser = USERNAME
	cfg.BasicAuthPass = PASSWORD
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

// TestBasicAuthWithWrongCredentialsFails tests basic auth with wrong credentials.
// This is the inverse test - verifying that wrong credentials don't work.
func TestBasicAuthWithWrongCredentialsFails(t *testing.T) {
	const (
		CORRECT_USERNAME = "test"
		CORRECT_PASSWORD = "test#&"
		WRONG_USERNAME   = "wrong"
		WRONG_PASSWORD   = "wrong"
	)

	server := testutil.BasicAuthServer(CORRECT_USERNAME, CORRECT_PASSWORD)
	defer server.Close()

	cfg, err := config.New(server.URLFor("infinite.html"))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 3
	cfg.BasicAuthUser = WRONG_USERNAME
	cfg.BasicAuthPass = WRONG_PASSWORD
	cfg.MaxDuration = 30 * time.Second

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)

	// With wrong credentials, crawler should either fail or find minimal states
	// because it can't access the protected pages
	if err == nil && result != nil {
		// If no error, should have very few states (just index or error page)
		if result.StateCount() >= 3 {
			t.Errorf("StateCount() = %d with wrong credentials, expected < 3",
				result.StateCount())
		}
	}
	// If there's an error, that's also acceptable behavior
}

// TestBasicAuthWithNoCredentialsFails tests basic auth without credentials.
func TestBasicAuthWithNoCredentialsFails(t *testing.T) {
	const (
		USERNAME = "test"
		PASSWORD = "test#&"
	)

	server := testutil.BasicAuthServer(USERNAME, PASSWORD)
	defer server.Close()

	cfg, err := config.New(server.URLFor("infinite.html"))
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 3
	// No basic auth credentials set
	cfg.MaxDuration = 30 * time.Second

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := crawler.Run(ctx)

	// Without credentials, crawler should either fail or find minimal states
	if err == nil && result != nil {
		if result.StateCount() >= 3 {
			t.Errorf("StateCount() = %d without credentials, expected < 3",
				result.StateCount())
		}
	}
}
