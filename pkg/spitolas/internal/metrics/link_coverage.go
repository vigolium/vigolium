package metrics

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// LinkCoverageTracker tracks discovered links per step.
// Outputs JSON files compatible with Python scripts.
// File format: link_coverage_{step}.txt with {"links": [...]}
type LinkCoverageTracker struct {
	mu        sync.Mutex
	seenLinks map[string]struct{} // All discovered links (deduped)
	outputDir string              // Directory for link_coverage_N.txt files
}

// NewLinkCoverageTracker creates a new tracker.
func NewLinkCoverageTracker(outputDir string) (*LinkCoverageTracker, error) {
	// Ensure coverage directory exists
	coverageDir := filepath.Join(outputDir, "coverage")
	if err := os.MkdirAll(coverageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create coverage directory: %w", err)
	}

	return &LinkCoverageTracker{
		seenLinks: make(map[string]struct{}),
		outputDir: coverageDir,
	}, nil
}

// AddLinks adds newly discovered links.
// Returns the number of new links added (not previously seen).
func (t *LinkCoverageTracker) AddLinks(links []string) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	newCount := 0
	for _, link := range links {
		if _, exists := t.seenLinks[link]; !exists {
			t.seenLinks[link] = struct{}{}
			newCount++
		}
	}
	return newCount
}

// SaveSnapshot writes link_coverage_{step}.txt JSON file.
// Format: {"links": ["http://...", "http://...", ...]}
func (t *LinkCoverageTracker) SaveSnapshot(step int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Convert map to slice
	links := make([]string, 0, len(t.seenLinks))
	for link := range t.seenLinks {
		links = append(links, link)
	}

	snapshot := LinkCoverageSnapshot{Links: links}

	filename := filepath.Join(t.outputDir, fmt.Sprintf("link_coverage_%d.txt", step))
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create link coverage file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(snapshot); err != nil {
		return fmt.Errorf("failed to encode link coverage: %w", err)
	}

	return nil
}

// GetCount returns total unique links discovered.
func (t *LinkCoverageTracker) GetCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.seenLinks)
}

// GetLinks returns a copy of all discovered links.
func (t *LinkCoverageTracker) GetLinks() []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	links := make([]string, 0, len(t.seenLinks))
	for link := range t.seenLinks {
		links = append(links, link)
	}
	return links
}

// Reset clears all tracked links.
func (t *LinkCoverageTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seenLinks = make(map[string]struct{})
}
