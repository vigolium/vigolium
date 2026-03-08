// Package metrics provides per-step metrics tracking for benchmark experiments.
// Output format is compatible with Python analysis scripts from the reference implementation.
package metrics

import "time"

// StepMetrics holds per-step metrics for CSV output.
// Format is compatible with Python scripts (generate_coverage_over_time_report.py).
type StepMetrics struct {
	// Core fields (all strategies)
	Time      time.Time // ISO timestamp of action execution
	Step      int       // Global step counter (0-indexed)
	Action    string    // Action identifier ("BF", "DF", "RAND" for MAK, or element ID)
	RewardEnv float64   // Environment reward (new links/coverage discovered)
	RewardRL  float64   // Normalized RL reward (for MAK: z-score + sigmoid)

	// MAK-specific fields (3 arms: BF=Head, DF=Tail, RAND=Random)
	// Cumulative estimated gains per arm (r_X)
	GainBF   float64
	GainDF   float64
	GainRAND float64

	// Weights per arm (w_X)
	WeightBF   float64
	WeightDF   float64
	WeightRAND float64

	// Probabilities per arm (p_X)
	ProbBF   float64
	ProbDF   float64
	ProbRAND float64

	// Additional tracking (not in CSV but useful for analysis)
	Epoch           int // MAK epoch number
	Gamma           float64
	LinksDiscovered int // Total unique links discovered so far
	CodeCoverage    int // Total lines covered (PHP apps only)
}

// DetailedMAKStats holds MAK selector statistics for CSV output.
// This mirrors the Python MAB_Exp3_31_Policy return_values format.
type DetailedMAKStats struct {
	Epoch int     // Current epoch (r in paper)
	Gamma float64 // Exploration parameter (η_r in paper)
	Gm    float64 // Current threshold (g_m in paper)

	// Per-arm stats [BF, DF, RAND] = [Head, Tail, Random]
	Weights []float64 // w_i for each arm
	Gains   []float64 // Cumulative estimated gains (Ĝ_i)
	Probs   []float64 // Selection probabilities π(i)

	// Last action info
	LastAction string  // "head", "tail", or "random"
	LastProb   float64 // Probability of last selected action
}

// LinkCoverageSnapshot for JSON output (Python script compatible).
// File: link_coverage_{step}.txt
type LinkCoverageSnapshot struct {
	Links []string `json:"links"`
}

// CodeCoverageSnapshot for JSON output (Python script compatible).
// File: coverage_{step}.txt
// Maps filename -> list of covered line numbers/ranges.
// Example: {"file.php": [1, 2, 3, 10, 11, 12]}
type CodeCoverageSnapshot map[string][]int

// ExperimentResult holds the outcome of a single experiment.
type ExperimentResult struct {
	App        string
	Strategy   string
	Success    bool
	Error      error
	Runtime    time.Duration
	OutputDir  string
	FinalStats *FinalStats
}

// FinalStats holds aggregate statistics at the end of an experiment.
type FinalStats struct {
	TotalSteps        int
	StatesDiscovered  int
	LinksDiscovered   int
	ActionsExecuted   int
	ActionsFailed     int
	FormsSubmitted    int
	FinalCodeCoverage int
	Duration          time.Duration
}

// CollectorConfig holds configuration for the metrics collector.
type CollectorConfig struct {
	OutputDir       string // Base output directory (experiments/{app}/spitolas/{id}/)
	Strategy        string // Crawl strategy name
	HasCodeCoverage bool   // Whether to fetch code coverage (PHP apps only)
	CoverageURL     string // Arachnarium endpoint URL (e.g., "http://web/arachnarium/coverage")
}
