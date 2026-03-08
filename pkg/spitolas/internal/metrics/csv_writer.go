package metrics

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CSVWriter writes step metrics in format compatible with Python scripts.
// Format: time,step,action,reward_env,reward_rl,r_BF,w_BF,p_BF,r_DF,w_DF,p_DF,r_RAND,w_RAND,p_RAND
type CSVWriter struct {
	mu       sync.Mutex
	file     *os.File
	writer   *csv.Writer
	strategy string
}

// CSV header matching Python format (results_{crawler}_{seed}.csv).
var csvHeader = []string{
	"time",
	"step",
	"action",
	"reward_env",
	"reward_rl",
	"r_BF",
	"w_BF",
	"p_BF",
	"r_DF",
	"w_DF",
	"p_DF",
	"r_RAND",
	"w_RAND",
	"p_RAND",
}

// NewCSVWriter creates a new CSV writer.
// Creates the file at: {outputDir}/report/results_{strategy}.csv
func NewCSVWriter(outputDir, strategy string) (*CSVWriter, error) {
	// Ensure report directory exists
	reportDir := filepath.Join(outputDir, "report")
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create report directory: %w", err)
	}

	// Create CSV file
	filename := filepath.Join(reportDir, fmt.Sprintf("results_%s.csv", strategy))
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSV file: %w", err)
	}

	w := &CSVWriter{
		file:     file,
		writer:   csv.NewWriter(file),
		strategy: strategy,
	}

	// Write header
	if err := w.writer.Write(csvHeader); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}
	w.writer.Flush()

	return w, nil
}

// WriteStep writes a single step's metrics.
func (w *CSVWriter) WriteStep(m *StepMetrics) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Format timestamp as ISO 8601 (Python datetime.fromisoformat compatible)
	timeStr := m.Time.Format("2006-01-02T15:04:05")

	record := []string{
		timeStr,
		fmt.Sprintf("%d", m.Step),
		m.Action,
		fmt.Sprintf("%.6f", m.RewardEnv),
		fmt.Sprintf("%.6f", m.RewardRL),
		fmt.Sprintf("%.6f", m.GainBF),
		fmt.Sprintf("%.6f", m.WeightBF),
		fmt.Sprintf("%.6f", m.ProbBF),
		fmt.Sprintf("%.6f", m.GainDF),
		fmt.Sprintf("%.6f", m.WeightDF),
		fmt.Sprintf("%.6f", m.ProbDF),
		fmt.Sprintf("%.6f", m.GainRAND),
		fmt.Sprintf("%.6f", m.WeightRAND),
		fmt.Sprintf("%.6f", m.ProbRAND),
	}

	if err := w.writer.Write(record); err != nil {
		return fmt.Errorf("failed to write CSV record: %w", err)
	}
	w.writer.Flush()

	return w.writer.Error()
}

// WriteStepFromMAKStats writes a step using DetailedMAKStats.
func (w *CSVWriter) WriteStepFromMAKStats(step int, action string, rewardEnv, rewardRL float64, stats *DetailedMAKStats) error {
	now := time.Now()

	if stats == nil {
		// Non-MAK strategy, use defaults
		return w.WriteStep(&StepMetrics{
			Time:       now,
			Step:       step,
			Action:     action,
			RewardEnv:  rewardEnv,
			RewardRL:   rewardRL,
			GainBF:     0,
			WeightBF:   1,
			ProbBF:     0.333,
			GainDF:     0,
			WeightDF:   1,
			ProbDF:     0.333,
			GainRAND:   0,
			WeightRAND: 1,
			ProbRAND:   0.333,
		})
	}

	m := &StepMetrics{
		Time:      now,
		Step:      step,
		Action:    action,
		RewardEnv: rewardEnv,
		RewardRL:  rewardRL,
	}

	// Extract per-arm stats
	if len(stats.Gains) >= 3 {
		m.GainBF = stats.Gains[0]
		m.GainDF = stats.Gains[1]
		m.GainRAND = stats.Gains[2]
	}
	if len(stats.Weights) >= 3 {
		m.WeightBF = stats.Weights[0]
		m.WeightDF = stats.Weights[1]
		m.WeightRAND = stats.Weights[2]
	}
	if len(stats.Probs) >= 3 {
		m.ProbBF = stats.Probs[0]
		m.ProbDF = stats.Probs[1]
		m.ProbRAND = stats.Probs[2]
	}

	return w.WriteStep(m)
}

// Close flushes and closes the file.
func (w *CSVWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.writer.Flush()
	if err := w.writer.Error(); err != nil {
		_ = w.file.Close()
		return err
	}
	return w.file.Close()
}

// Filename returns the path to the CSV file.
func (w *CSVWriter) Filename() string {
	return w.file.Name()
}
