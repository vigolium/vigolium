package crawler

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/condition"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// =============================================================================
// CRAWLJAX PARITY: CrawlerTest.java
// Tests for crawler initialization, reset behavior, invariant handling,
// and form trainer configuration.
// =============================================================================

// TestCrawlerNew tests crawler initialization.
// Crawljax parity: CrawlerTest setup() verifies crawler is properly initialized
// Expected: crawler != nil, graph initialized, queue initialized, config set
func TestCrawlerNew(t *testing.T) {
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New failed: %v", err)
	}

	crawler, err := New(cfg)

	// Crawljax: crawler should be created successfully
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Crawljax: crawler != null
	if crawler == nil {
		t.Fatal("New() returned nil crawler")
	}

	// Crawljax: graph is initialized (via graphProvider.get())
	if crawler.graph == nil {
		t.Error("crawler.graph is nil, want initialized graph")
	}

	// Crawljax: candidates is initialized (via candidateActionCache)
	if crawler.candidates == nil {
		t.Error("crawler.candidates is nil, want initialized candidates")
	}

	// Crawljax: config is set
	if crawler.config == nil {
		t.Error("crawler.config is nil, want config set")
	}

	// Crawljax: config URL matches
	if crawler.config.URL.String() != "http://example.com" {
		t.Errorf("crawler.config.URL = %s, want http://example.com",
			crawler.config.URL.String())
	}
}

// TestCrawlerNewInvalidConfig tests crawler rejects invalid config.
// Crawljax parity: CrawljaxConfiguration.builderFor validates URL
func TestCrawlerNewInvalidConfig(t *testing.T) {
	// Empty URL should fail validation
	cfg := &config.Config{}

	_, err := New(cfg)

	// Crawljax: invalid config should throw exception
	if err == nil {
		t.Error("New() with invalid config returned nil error, want error")
	}
}

// TestCrawlerAddInvariant tests adding invariants.
// Crawljax parity: StateMachine invariants via config.getCrawlRules().getInvariants()
// Expected: invariants are stored and retrievable
func TestCrawlerAddInvariant(t *testing.T) {
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New failed: %v", err)
	}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Crawljax: initial invariant count = 0
	initialCount := len(crawler.invariants)
	if initialCount != 0 {
		t.Errorf("initial invariant count = %d, want 0", initialCount)
	}

	// Add an invariant using correct API: condition.New(condType, value)
	inv := condition.New(config.CondElementExists, "#app")
	crawler.AddInvariant(inv)

	// Crawljax: invariant count increases by 1
	afterCount := len(crawler.invariants)
	expectedCount := 1
	if afterCount != expectedCount {
		t.Errorf("invariant count after AddInvariant = %d, want %d",
			afterCount, expectedCount)
	}

	// Crawljax: added invariant is the same object
	if crawler.invariants[0] != inv {
		t.Error("invariants[0] != added invariant, want same object")
	}
}

// TestCrawlerSetFormTrainer tests form trainer configuration.
// Crawljax parity: CrawlerTest.trainingFormHandler setup
// Expected: form trainer can be set and retrieved
func TestCrawlerSetFormTrainer(t *testing.T) {
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New failed: %v", err)
	}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Crawljax: initial trainer is null
	if crawler.GetFormTrainer() != nil {
		t.Error("initial GetFormTrainer() != nil, want nil")
	}

	// Create and set form trainer with correct API: NewFormTrainer(mode, outputDir)
	trainer := form.NewFormTrainer(form.FillRandom, "")
	crawler.SetFormTrainer(trainer)

	// Crawljax: trainer is set correctly
	if crawler.GetFormTrainer() != trainer {
		t.Error("GetFormTrainer() != trainer, want same object")
	}
}

// TestCrawlerSetClusterManager tests ND cluster manager configuration.
// Crawljax parity: Near-duplicate state handling configuration
func TestCrawlerSetClusterManager(t *testing.T) {
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New failed: %v", err)
	}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Initial cluster manager is nil
	if crawler.GetClusterManager() != nil {
		t.Error("initial GetClusterManager() != nil, want nil")
	}

	// Create and set cluster manager
	mgr := state.NewNDClusterManager()
	crawler.SetClusterManager(mgr)

	// Cluster manager is set correctly
	if crawler.GetClusterManager() != mgr {
		t.Error("GetClusterManager() != mgr, want same object")
	}
}

// TestCrawlerIsRunning tests running state tracking.
// Crawljax parity: CrawlSession running state via CrawlerContext
// Expected: initial state is not running
func TestCrawlerIsRunning(t *testing.T) {
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New failed: %v", err)
	}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Crawljax: initial running state is false
	if crawler.running {
		t.Error("crawler.running = true initially, want false")
	}
}

// TestCrawlerAddEventableCondition tests eventable condition configuration.
// Crawljax parity: EventableConditionChecker for form-to-element linking
func TestCrawlerAddEventableCondition(t *testing.T) {
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New failed: %v", err)
	}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Initial eventable conditions checker is initialized
	ec := crawler.GetEventableConditions()
	if ec == nil {
		t.Fatal("GetEventableConditions() returned nil, want initialized checker")
	}

	// Initial count is 0
	if ec.Count() != 0 {
		t.Errorf("initial eventable condition count = %d, want 0", ec.Count())
	}

	// Add an eventable condition using correct API: NewEventableCondition()
	cond := condition.NewEventableCondition().
		InXPathScope("//form").
		WithDescription("Test form condition")
	crawler.AddEventableCondition(cond)

	// Count increases by 1
	expectedCount := 1
	if ec.Count() != expectedCount {
		t.Errorf("eventable condition count after Add = %d, want %d",
			ec.Count(), expectedCount)
	}
}

// TestCrawlerSetInvariantChecker tests structured invariant checker.
// Crawljax parity: Invariant management via checker
func TestCrawlerSetInvariantChecker(t *testing.T) {
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New failed: %v", err)
	}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Initial invariant checker is nil
	if crawler.invariantChecker != nil {
		t.Error("initial invariantChecker != nil, want nil")
	}

	// Create and set invariant checker
	checker := condition.NewInvariantChecker()
	crawler.SetInvariantChecker(checker)

	// Invariant checker is set correctly
	if crawler.invariantChecker != checker {
		t.Error("invariantChecker != checker, want same object")
	}
}

// TestCrawlerMultipleInvariants tests adding multiple invariants.
// Crawljax parity: Multiple invariants in config.getCrawlRules().getInvariants()
func TestCrawlerMultipleInvariants(t *testing.T) {
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New failed: %v", err)
	}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Add multiple invariants using correct API
	inv1 := condition.New(config.CondElementExists, "#header")
	inv2 := condition.New(config.CondElementExists, "#footer")
	inv3 := condition.New(config.CondElementExists, "#nav")

	crawler.AddInvariant(inv1)
	crawler.AddInvariant(inv2)
	crawler.AddInvariant(inv3)

	// Crawljax: all invariants are stored
	expectedCount := 3
	if len(crawler.invariants) != expectedCount {
		t.Errorf("invariant count = %d, want %d", len(crawler.invariants), expectedCount)
	}

	// Crawljax: invariants are in order
	if crawler.invariants[0] != inv1 {
		t.Error("invariants[0] != inv1")
	}
	if crawler.invariants[1] != inv2 {
		t.Error("invariants[1] != inv2")
	}
	if crawler.invariants[2] != inv3 {
		t.Error("invariants[2] != inv3")
	}
}

// TestCrawlerStateMachineNotInitializedBeforeCrawl tests StateMachine is nil before crawl.
// CRAWLJAX PARITY: StateMachine is created in initializeIndexState(), not in New()
func TestCrawlerStateMachineNotInitializedBeforeCrawl(t *testing.T) {
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New failed: %v", err)
	}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// CRAWLJAX PARITY: StateMachine is nil before crawl starts
	// It gets initialized in initializeIndexState() during Crawl()
	if crawler.stateMachine != nil {
		t.Error("crawler.stateMachine should be nil before Crawl() is called")
	}

	// Session and crawlPath are also nil before crawl
	if crawler.session != nil {
		t.Error("crawler.session should be nil before Crawl() is called")
	}
	if crawler.crawlPath != nil {
		t.Error("crawler.crawlPath should be nil before Crawl() is called")
	}
}

// TestCrawlerStatsInitialized tests stats are initialized.
// Crawljax parity: CrawlSession stats tracking
func TestCrawlerStatsInitialized(t *testing.T) {
	cfg, err := config.New("http://example.com")
	if err != nil {
		t.Fatalf("config.New failed: %v", err)
	}

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// All stats should be 0 initially
	if crawler.stats.StatesDiscovered != 0 {
		t.Errorf("StatesDiscovered = %d, want 0", crawler.stats.StatesDiscovered)
	}
	if crawler.stats.StatesDuplicate != 0 {
		t.Errorf("StatesDuplicate = %d, want 0", crawler.stats.StatesDuplicate)
	}
	if crawler.stats.ActionsExecuted != 0 {
		t.Errorf("ActionsExecuted = %d, want 0", crawler.stats.ActionsExecuted)
	}
	if crawler.stats.ActionsFailed != 0 {
		t.Errorf("ActionsFailed = %d, want 0", crawler.stats.ActionsFailed)
	}
	if crawler.stats.FormsSubmitted != 0 {
		t.Errorf("FormsSubmitted = %d, want 0", crawler.stats.FormsSubmitted)
	}
	if crawler.stats.BacktrackCount != 0 {
		t.Errorf("BacktrackCount = %d, want 0", crawler.stats.BacktrackCount)
	}
	if crawler.stats.InvariantFails != 0 {
		t.Errorf("InvariantFails = %d, want 0", crawler.stats.InvariantFails)
	}
}
