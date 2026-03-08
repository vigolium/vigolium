package metrics

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Collector aggregates all metrics for a single experiment run.
// Integrates with the crawler to track per-step metrics.
type Collector struct {
	mu sync.Mutex

	csvWriter     *CSVWriter
	linkTracker   *LinkCoverageTracker
	codeCovClient *CodeCoverageClient // nil for Node.js apps

	step      int
	startTime time.Time
	strategy  string
	outputDir string

	// Tracking for final stats
	statesDiscovered int
	actionsExecuted  int
	actionsFailed    int
	formsSubmitted   int
}

// NewCollector creates a new metrics collector.
func NewCollector(cfg *CollectorConfig) (*Collector, error) {
	// Create output directories
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create subdirectories
	coverageDir := filepath.Join(cfg.OutputDir, "coverage")
	reportDir := filepath.Join(cfg.OutputDir, "report")
	if err := os.MkdirAll(coverageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create coverage directory: %w", err)
	}
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create report directory: %w", err)
	}

	// Create CSV writer
	csvWriter, err := NewCSVWriter(cfg.OutputDir, cfg.Strategy)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSV writer: %w", err)
	}

	// Create link tracker
	linkTracker, err := NewLinkCoverageTracker(cfg.OutputDir)
	if err != nil {
		_ = csvWriter.Close()
		return nil, fmt.Errorf("failed to create link tracker: %w", err)
	}

	// Create code coverage client (only for PHP apps)
	var codeCovClient *CodeCoverageClient
	if cfg.HasCodeCoverage && cfg.CoverageURL != "" {
		codeCovClient, err = NewCodeCoverageClient(cfg.CoverageURL, cfg.OutputDir)
		if err != nil {
			_ = csvWriter.Close()
			return nil, fmt.Errorf("failed to create code coverage client: %w", err)
		}
	}

	return &Collector{
		csvWriter:     csvWriter,
		linkTracker:   linkTracker,
		codeCovClient: codeCovClient,
		step:          0,
		strategy:      cfg.Strategy,
		outputDir:     cfg.OutputDir,
	}, nil
}

// StepContext holds info needed to record a step.
type StepContext struct {
	// Action info
	ActionID   string // Action identifier
	ActionType string // "BF", "DF", "RAND" for MAK, or empty for other strategies

	// Rewards
	RewardEnv float64 // Environment reward (new links/coverage discovered)
	RewardRL  float64 // Normalized RL reward

	// Links discovered this step
	NewLinks []string

	// MAK stats (nil if not using MAK)
	MAKStats *DetailedMAKStats

	// Crawl stats
	StateDiscovered bool // Whether a new state was discovered
	ActionSucceeded bool
	FormSubmitted   bool
}

// OnCrawlStart called when crawl begins.
func (c *Collector) OnCrawlStart() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.startTime = time.Now()

	// Write initial step (step 0) with initial state
	// This matches Python behavior of writing step 0 at reset
}

// OnStepComplete called after each action execution.
// Records metrics to CSV and coverage files.
func (c *Collector) OnStepComplete(ctx *StepContext) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update tracking
	c.actionsExecuted++
	if !ctx.ActionSucceeded {
		c.actionsFailed++
	}
	if ctx.StateDiscovered {
		c.statesDiscovered++
	}
	if ctx.FormSubmitted {
		c.formsSubmitted++
	}

	// Add links and save snapshot
	if len(ctx.NewLinks) > 0 {
		c.linkTracker.AddLinks(ctx.NewLinks)
	}
	if err := c.linkTracker.SaveSnapshot(c.step); err != nil {
		return fmt.Errorf("failed to save link coverage: %w", err)
	}

	// Fetch and save code coverage (PHP apps only)
	var codeCoverage int
	if c.codeCovClient != nil {
		count, _, err := c.codeCovClient.FetchAndSave(c.step)
		if err != nil {
			// Log but don't fail - coverage might not be available
			fmt.Printf("Warning: failed to fetch code coverage: %v\n", err)
		}
		codeCoverage = count
	}

	// Build step metrics
	action := ctx.ActionType
	if action == "" {
		action = ctx.ActionID
	}

	m := &StepMetrics{
		Time:            time.Now(),
		Step:            c.step,
		Action:          action,
		RewardEnv:       ctx.RewardEnv,
		RewardRL:        ctx.RewardRL,
		LinksDiscovered: c.linkTracker.GetCount(),
		CodeCoverage:    codeCoverage,
	}

	// Add MAK-specific fields
	if ctx.MAKStats != nil {
		m.Epoch = ctx.MAKStats.Epoch
		m.Gamma = ctx.MAKStats.Gamma
		if len(ctx.MAKStats.Gains) >= 3 {
			m.GainBF = ctx.MAKStats.Gains[0]
			m.GainDF = ctx.MAKStats.Gains[1]
			m.GainRAND = ctx.MAKStats.Gains[2]
		}
		if len(ctx.MAKStats.Weights) >= 3 {
			m.WeightBF = ctx.MAKStats.Weights[0]
			m.WeightDF = ctx.MAKStats.Weights[1]
			m.WeightRAND = ctx.MAKStats.Weights[2]
		}
		if len(ctx.MAKStats.Probs) >= 3 {
			m.ProbBF = ctx.MAKStats.Probs[0]
			m.ProbDF = ctx.MAKStats.Probs[1]
			m.ProbRAND = ctx.MAKStats.Probs[2]
		}
	} else {
		// Default values for non-MAK strategies
		m.WeightBF = 1
		m.WeightDF = 1
		m.WeightRAND = 1
		m.ProbBF = 0.333
		m.ProbDF = 0.333
		m.ProbRAND = 0.333
	}

	// Write to CSV
	if err := c.csvWriter.WriteStep(m); err != nil {
		return fmt.Errorf("failed to write step metrics: %w", err)
	}

	c.step++
	return nil
}

// OnCrawlEnd called when crawl finishes.
func (c *Collector) OnCrawlEnd() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close CSV writer
	if err := c.csvWriter.Close(); err != nil {
		return fmt.Errorf("failed to close CSV writer: %w", err)
	}

	// Write runtime file
	runtime := time.Since(c.startTime)
	runtimeFile := filepath.Join(c.outputDir, "runtime.txt")
	if err := os.WriteFile(runtimeFile, []byte(fmt.Sprintf("%.2f", runtime.Seconds())), 0644); err != nil {
		return fmt.Errorf("failed to write runtime file: %w", err)
	}

	return nil
}

// GetFinalStats returns aggregate statistics.
func (c *Collector) GetFinalStats() *FinalStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	var codeCov int
	if c.codeCovClient != nil {
		codeCov = c.codeCovClient.GetLastCount()
	}

	return &FinalStats{
		TotalSteps:        c.step,
		StatesDiscovered:  c.statesDiscovered,
		LinksDiscovered:   c.linkTracker.GetCount(),
		ActionsExecuted:   c.actionsExecuted,
		ActionsFailed:     c.actionsFailed,
		FormsSubmitted:    c.formsSubmitted,
		FinalCodeCoverage: codeCov,
		Duration:          time.Since(c.startTime),
	}
}

// WriteCommandFile writes the command used to run this experiment.
func (c *Collector) WriteCommandFile(command string) error {
	cmdFile := filepath.Join(c.outputDir, "command.txt")
	return os.WriteFile(cmdFile, []byte(command), 0644)
}

// GetStep returns the current step number.
func (c *Collector) GetStep() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.step
}

// GetOutputDir returns the output directory.
func (c *Collector) GetOutputDir() string {
	return c.outputDir
}
