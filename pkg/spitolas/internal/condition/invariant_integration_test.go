//go:build integration

package condition

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// setupInvariantBrowser creates a browser for invariant integration tests.
func setupInvariantBrowser(t *testing.T, serverURL string) *browser.Browser {
	t.Helper()
	cfg, err := config.New(serverURL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true

	b, err := browser.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create browser: %v", err)
	}
	t.Cleanup(func() {
		b.Close()
	})
	return b
}

// TestIntegrationInvariantWithRealPage tests invariants against real HTML pages.
func TestIntegrationInvariantWithRealPage(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := setupInvariantBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Invariant that should pass
	inv := NewInvariant(
		"Page should have required element",
		ElementExists("#SHOULD_ALWAYS_BE_ON_THIS_PAGE"),
	)

	if !inv.Check(page) {
		t.Error("Invariant should pass when element exists")
	}

	// Invariant that should fail
	inv2 := NewInvariant(
		"Page should have nonexistent element",
		ElementExists("#nonexistent"),
	)

	if inv2.Check(page) {
		t.Error("Invariant should fail when element doesn't exist")
	}
}

// TestIntegrationInvariantChecker tests checker with multiple invariants.
func TestIntegrationInvariantChecker(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := setupInvariantBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	checker := NewInvariantChecker()

	// Add invariants
	checker.Add(NewInvariant(
		"Required element exists",
		ElementExists("#SHOULD_ALWAYS_BE_ON_THIS_PAGE"),
	))
	checker.Add(NewInvariant(
		"URL contains testInvariants",
		URLContains("testInvariants"),
	))
	checker.Add(NewInvariant(
		"Violation element exists",
		ElementExists("#INVARIANT_VIOLATION"),
	))

	// All should pass
	if !checker.CheckAll(page) {
		t.Error("All invariants should pass")
	}

	violated := checker.Check(page)
	if len(violated) != 0 {
		t.Errorf("Expected 0 violations, got %d", len(violated))
	}
}

// TestIntegrationInvariantDetailed tests detailed invariant results.
func TestIntegrationInvariantDetailed(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := setupInvariantBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	checker := NewInvariantChecker()

	// Passing invariant
	checker.Add(NewInvariant(
		"Element exists",
		ElementExists("#SHOULD_ALWAYS_BE_ON_THIS_PAGE"),
	))

	// Failing invariant
	checker.Add(NewInvariant(
		"Nonexistent element",
		ElementExists("#nonexistent"),
	))

	// Not applicable invariant (precondition fails)
	inv3 := NewInvariant(
		"Conditional check",
		ElementExists("#something"),
	).WithPrecondition(URLContains("other-page"))
	checker.Add(inv3)

	results := checker.CheckDetailed(page)

	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	// First: applicable and passed
	if !results[0].Applicable || !results[0].Passed {
		t.Errorf("Result[0] should be applicable and passed: %+v", results[0])
	}

	// Second: applicable but failed
	if !results[1].Applicable || results[1].Passed {
		t.Errorf("Result[1] should be applicable but failed: %+v", results[1])
	}

	// Third: not applicable
	if results[2].Applicable {
		t.Errorf("Result[2] should not be applicable: %+v", results[2])
	}
}

// TestIntegrationNoServerError tests NoServerError invariant.
func TestIntegrationNoServerError(t *testing.T) {
	// Create a server that returns 500 error page
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("<html><body>500 Internal Server Error</body></html>"))
	}))
	defer errorServer.Close()

	// Create a normal server
	normalServer := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer normalServer.Close()

	// Test against error page
	t.Run("error page", func(t *testing.T) {
		b := setupInvariantBrowser(t, errorServer.URL)
		page, err := b.NewPage()
		if err != nil {
			t.Fatalf("Failed to create page: %v", err)
		}

		if err := page.Navigate(errorServer.URL); err != nil {
			t.Fatalf("Failed to navigate: %v", err)
		}

		inv := NoServerError()

		if inv.Check(page) {
			t.Error("NoServerError should fail on 500 error page")
		}
	})

	// Test against normal page
	t.Run("normal page", func(t *testing.T) {
		b := setupInvariantBrowser(t, normalServer.URL)
		page, err := b.NewPage()
		if err != nil {
			t.Fatalf("Failed to create page: %v", err)
		}

		if err := page.Navigate(normalServer.URL + "/testInvariants.html"); err != nil {
			t.Fatalf("Failed to navigate: %v", err)
		}

		inv := NoServerError()

		if !inv.Check(page) {
			t.Error("NoServerError should pass on normal page")
		}
	})
}

// TestIntegrationInvariantWithPrecondition tests precondition behavior.
func TestIntegrationInvariantWithPrecondition(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := setupInvariantBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testCrawlconditions.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Invariant only applies to crawlconditions page
	inv := NewInvariant(
		"No DONT_CRAWL_ME text",
		DOMRegex("DONT_CRAWL_ME").Not(),
	).WithPrecondition(URLContains("testCrawlconditions"))

	// Precondition met, condition fails (text is present)
	if inv.Check(page) {
		t.Error("Invariant should fail when precondition met and condition fails")
	}

	// Navigate to different page
	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Precondition not met, invariant should pass (N/A)
	if !inv.Check(page) {
		t.Error("Invariant should pass when precondition not met")
	}

	if inv.IsApplicable(page) {
		t.Error("Invariant should not be applicable on different page")
	}
}

// TestIntegrationCrawlConditionsPage tests conditions on crawlconditions page.
func TestIntegrationCrawlConditionsPage(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := setupInvariantBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testCrawlconditions.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Test DOM regex for DONT_CRAWL_ME text
	cond := DOMRegex("DONT_CRAWL_ME")
	if !cond.Check(page) {
		t.Error("Should find DONT_CRAWL_ME in page")
	}

	// Test that the link text can be found
	cond2 := DOMRegex("DONT_CLICK_ME_BECAUSE_OF_CRAWLCONDITION")
	if !cond2.Check(page) {
		t.Error("Should find link text in page")
	}

	// Create an invariant to prevent crawling this type of page
	inv := NewInvariant(
		"Should not crawl pages with DONT_CRAWL_ME",
		DOMRegex("DONT_CRAWL_ME").Not(),
	)

	if inv.Check(page) {
		t.Error("Invariant should fail on page with DONT_CRAWL_ME")
	}
}
